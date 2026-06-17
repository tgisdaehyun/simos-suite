"""
cp_tools/bcb_compress.py — BCB compressor (inverse of sgo_unpack._bcb_decompress).

_bcb_decompress token model (the oracle this satisfies):
    token = u16 BE: flag = tok >> 14 (top 2 bits), ln = tok & 0x3FFF (low 14 bits)
        flag 0 = literal : copy `ln` bytes from the stream
        flag 1 = RLE     : repeat the next single byte `ln` times
        flag 3 = end     : followed by a 24-bit BE checksum = sum(output) & 0xFFFFFF
        flag 2 = invalid
    max ln per token = 0x3FFF (16383).
The decompressor also requires len(output) in (declen, declen+1) and the END
checksum to match, so this emits the END token with that 24-bit checksum and
prepends the BCB header bytes (1A 01); the result is a complete block body ready
to be 0xFF-XOR'd into the container.

⚠ IMPORTANT CAVEAT — NOT VW's real on-disk BCB. This compressor is the exact
inverse of cp_tools.sgo_unpack._bcb_decompress (its mandated oracle) and round-
trips through it byte-exact. However, VW's actual crypt=0x10 BCB streams use a
*different* token scheme (a 1A-escape model, e.g. recurring 1A 04 04 / 1A 06 06);
NO block in the surveyed corpus decodes through _bcb_decompress (real BCB blocks
fall to the plain path in the current unpacker). So a block built here re-decodes
correctly through sgo_unpack, but a real ECU expecting VW-format BCB would reject
it. Reproducing VW's exact stream requires the 1A-escape codec to be reversed
first (open work). For flashing today, prefer the plain (crypt=0x00) path.
"""
import struct

BCB_HEADER = b"\x1A\x01"
MAX_LEN = 0x3FFF  # 14-bit length field


def _checksum24(data: bytes) -> int:
    return sum(data) & 0xFFFFFF


def _emit_end(out: bytearray, data: bytes) -> None:
    chk = _checksum24(data)
    out += struct.pack(">H", 3 << 14)            # flag 3, len 0
    out += bytes([(chk >> 16) & 0xFF, (chk >> 8) & 0xFF, chk & 0xFF])  # 24-bit BE


def bcb_compress_literal(data: bytes, header: bool = True) -> bytes:
    """All-literals encoding (trivial correctness proof). Chunks of <=16383, then END."""
    out = bytearray()
    if header:
        out += BCB_HEADER
    p, n = 0, len(data)
    while p < n:
        ln = min(MAX_LEN, n - p)
        out += struct.pack(">H", (0 << 14) | ln)
        out += data[p:p + ln]
        p += ln
    _emit_end(out, data)
    return bytes(out)


def bcb_compress(data: bytes, header: bool = True, min_run: int = 4) -> bytes:
    """Greedy RLE + literal encoder.

    Runs of an identical byte of length >= min_run become RLE tokens; everything
    else accumulates into literal tokens. Lengths are capped at MAX_LEN per token.
    """
    out = bytearray()
    if header:
        out += BCB_HEADER
    n = len(data)
    i = 0
    lit_start = 0

    def flush_literals(end: int):
        nonlocal lit_start
        p = lit_start
        while p < end:
            ln = min(MAX_LEN, end - p)
            out.extend(struct.pack(">H", (0 << 14) | ln))
            out.extend(data[p:p + ln])
            p += ln
        lit_start = end

    while i < n:
        j = i + 1
        while j < n and data[j] == data[i]:
            j += 1
        run = j - i
        if run >= min_run:
            flush_literals(i)               # emit pending literals first
            r, b = run, data[i]
            while r > 0:
                ln = min(MAX_LEN, r)
                out.extend(struct.pack(">H", (1 << 14) | ln))
                out.append(b)
                r -= ln
            i = j
            lit_start = i
        else:
            i = j
    flush_literals(n)
    _emit_end(out, data)
    return bytes(out)
