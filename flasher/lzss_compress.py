"""
flasher/lzss_compress.py — VW flashdaten LZSS (faithful port)

Faithful port of bri3d/VW_Flash lib/lzss/lzss.c (Michael Dipperstein's LZSS,
as modified by VW). This is the algorithm real VW flashdaten actually use.

NOTE — this replaces an earlier implementation that was self-consistent (its
own compress/decompress round-tripped) but used the WRONG parameters versus
real VW. The old version decoded AES-decrypted Simos18.1 data into ~10x
oversized garbage. This version decodes real flashdaten so that the recomputed
VW-CRC32 matches the stored 0x300 block-checksum header (verified for the
CBOOT/ASW1/CAL blocks of Simos18.1 5G0906259K).

Algorithm parameters (these MUST match the ECU's on-board decompressor):
  WINDOW_SIZE = 1023   sliding window, INITIALISED TO 0x20 (space) — NOT 0x00
  MAX_UNCODED = 2      matches of <= 2 bytes are emitted as literals
  MAX_CODED   = 64     lookahead buffer size; encoded length is capped at 0x3F

Flag byte (8 bits, consumed MSB first):
  bit SET   (1) => the next item is an ENCODED 2-byte (offset,length) reference
  bit CLEAR (0) => the next item is a raw LITERAL byte
  (This is the INVERSE of the convention the old buggy code used.)

Encoded reference — 2 bytes, where `offset` is the match position (0..1022) in
the window returned by FindMatch:
  byte1 = (length << 2) | ((1023 - offset) >> 8)
  byte2 = (1023 - offset) & 0xFF
  decode: off10       = byte2 + ((byte1 & 0x03) << 8)
          real_offset = 1023 - off10
          length      = byte1 >> 2
          copy `length` bytes from window[(nextChar + real_offset + i) % 1023]

The decoder OVER-RUNS the true output by a few bytes (the encoder pads the
final flag group). Callers MUST truncate to the ODX UNCOMPRESSED-SIZE — this is
VW's `-e` exact-length behaviour. read_block() does this with blk.length.
"""
from __future__ import annotations
import logging

log = logging.getLogger("SimosSuite.LZSS")

WINDOW_SIZE = 1023
MAX_UNCODED = 2
MAX_CODED   = 61 + MAX_UNCODED + 1   # == 64
WINDOW_FILL = 0x20                   # ' ' — EncodeLZSS/DecodeLZSS window init


def lzss_decompress(data: bytes) -> bytes:
    """
    Decompress a VW-LZSS stream (faithful DecodeLZSS port).

    Used by read_block() to decode block data uploaded from the ECU, and by the
    pack-verify path. The output over-runs the real image by a few bytes; the
    caller truncates to the block's UNCOMPRESSED-SIZE (see module docstring).
    """
    out       = bytearray()
    window    = bytearray([WINDOW_FILL]) * WINDOW_SIZE
    next_char = 0
    flags     = 0
    flags_used = 7
    p = 0
    n = len(data)

    while True:
        flags = (flags << 1) & 0xFFFF
        flags_used += 1
        if flags_used == 8:
            # shifted out all 8 flag bits — read the next flag byte
            if p >= n:
                break
            flags = data[p]; p += 1
            flags_used = 0

        if (flags & 0x80) == 0:
            # clear bit → raw literal byte
            if p >= n:
                break
            c = data[p]; p += 1
            out.append(c)
            window[next_char] = c
            next_char = (next_char + 1) % WINDOW_SIZE
        else:
            # set bit → encoded 2-byte (length, offset) reference
            if p >= n:
                break
            length_b = data[p]; p += 1
            if p >= n:
                break
            offset_b = data[p]; p += 1
            offset = WINDOW_SIZE - (offset_b + ((length_b & 0x03) << 8))
            length = length_b >> 2
            # Dipperstein reads the whole match from the PRE-copy window, then
            # writes it back — so overlapping / run-length references reproduce
            # the bytes the encoder matched against, not bytes written mid-copy.
            tmp = bytearray(length)
            for i in range(length):
                c = window[(next_char + offset + i) % WINDOW_SIZE]
                out.append(c)
                tmp[i] = c
            for i in range(length):
                window[(next_char + i) % WINDOW_SIZE] = tmp[i]
            next_char = (next_char + length) % WINDOW_SIZE

    log.debug("LZSS decompress: %d -> %d bytes (truncate to UNCOMPRESSED-SIZE)",
              n, len(out))
    return bytes(out)


def _find_match(window, window_head, lookahead, uncoded_head, look_len):
    """
    Search the sliding window for the longest match of the lookahead buffer
    (faithful FindMatch port). Returns (offset, length); length 0 means no match.
    Ties prefer the larger window offset (matches the C `>=` comparison).
    """
    best_off = 0
    best_len = 0
    i = 0
    while i < WINDOW_SIZE:
        if window[(window_head + i) % WINDOW_SIZE] == lookahead[uncoded_head % MAX_CODED]:
            j = 1
            while j < MAX_CODED:
                if (i + j) == WINDOW_SIZE:
                    break
                if j >= look_len:
                    break
                if window[(window_head + i + j) % WINDOW_SIZE] != \
                        lookahead[(uncoded_head + j) % MAX_CODED]:
                    break
                j += 1
            if j >= best_len:
                best_len = j
                best_off = i
                if best_len >= MAX_CODED:
                    break
        i += 1
    return best_off, best_len


def lzss_compress(data: bytes, exact_pad: bool = True) -> bytes:
    """
    Compress with the faithful VW LZSS (faithful EncodeLZSS port).

    exact_pad mirrors VW's `-e` flag: the final flag group is padded with no-op
    (0,0) references so the decoder reproduces an exact-length image without
    trailing literal garbage. Callers that AES-encrypt the result still pad the
    ciphertext to a 16-byte boundary separately (uds_flash._prepare_block_data).

    The output is not guaranteed to be byte-identical to VW's own stream — LZSS
    has many valid encodings — but it decompresses back to the input image
    exactly, which is what the ECU's decompressor requires.
    """
    window       = bytearray([WINDOW_FILL]) * WINDOW_SIZE
    lookahead    = bytearray(MAX_CODED)
    window_head  = 0
    uncoded_head = 0
    out          = bytearray()
    flags        = 0
    flag_pos     = 0x80
    encoded      = bytearray()
    compressed_size = 0
    src = data
    sp  = 0

    # Prime the lookahead buffer with up to MAX_CODED bytes from the input.
    look_len = 0
    while look_len < MAX_CODED and sp < len(src):
        lookahead[look_len] = src[sp]; sp += 1; look_len += 1
    if look_len == 0:
        return b""   # empty input

    moff, mlen = _find_match(window, window_head, lookahead, uncoded_head, look_len)

    while look_len > 0:
        if mlen > 0x3F:
            # length field is 6 bits (byte1 >> 2); clamp to 0x3F
            mlen = 0x3F

        if mlen <= MAX_UNCODED:
            # not worth encoding — emit one literal byte, leave flag bit clear
            mlen = 1
            encoded.append(lookahead[uncoded_head % MAX_CODED])
        else:
            # encode as (length, offset): byte1 = (len<<2)|((1023-off)>>8),
            # byte2 = (1023-off)&0xFF; set the flag bit for this slot
            encoded.append(((WINDOW_SIZE - moff) >> 8 | (mlen << 2)) & 0xFF)
            encoded.append((WINDOW_SIZE - moff) & 0xFF)
            flags |= flag_pos

        if flag_pos == 0x01:
            # 8 flag bits filled — emit the flag byte then its 8 coded units
            out.append(flags); compressed_size += 1
            for b in encoded:
                out.append(b); compressed_size += 1
            flags = 0; flag_pos = 0x80; encoded = bytearray()
        else:
            flag_pos >>= 1

        # Slide the window: pull `mlen` new bytes into the lookahead, shifting the
        # consumed lookahead bytes into the window.
        i = 0
        while i < mlen and sp < len(src):
            c = src[sp]; sp += 1
            window[window_head] = lookahead[uncoded_head % MAX_CODED]
            lookahead[uncoded_head % MAX_CODED] = c
            window_head  = (window_head + 1) % WINDOW_SIZE
            uncoded_head = (uncoded_head + 1) % MAX_CODED
            i += 1
        # Ran out of input mid-match — drain the lookahead into the window.
        while i < mlen:
            window[window_head] = lookahead[uncoded_head % MAX_CODED]
            window_head  = (window_head + 1) % WINDOW_SIZE
            uncoded_head = (uncoded_head + 1) % MAX_CODED
            look_len -= 1
            i += 1

        moff, mlen = _find_match(window, window_head, lookahead, uncoded_head, look_len)

    # Flush any remaining coded units.
    if len(encoded) != 0:
        total_size = compressed_size + len(encoded) + 1
        if exact_pad and (total_size % 16 != 0):
            # Pad with no-op (0,0) references — they decode to length 0, so the
            # output length is unaffected, but the stream reaches a 16-byte block.
            while (compressed_size + len(encoded) + 1) % 16 != 0:
                if flag_pos == 0x00:
                    break
                encoded.append(0); encoded.append(0)
                flags |= flag_pos
                flag_pos >>= 1
        out.append(flags)
        for b in encoded:
            out.append(b)

    log.debug("LZSS compress: %d -> %d bytes (exact_pad=%s)",
              len(data), len(out), exact_pad)
    return bytes(out)
