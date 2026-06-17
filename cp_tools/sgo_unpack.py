"""
sgo_unpack.py — VAG "SGML Object File" (.sgo) flashdaten unpacker.

The SGO / "SGML Object File" container is the flashdaten format ODIS/VAS-PC use
for VAG control units (engine ECUs, transmission, and body modules such as the
4H0907064 BCM2). This module parses the container and decodes each flash block,
auto-detecting the per-block transform:

  plain    — block is XOR'd with 0xFF only.
  bcb-xor  — XOR 0xFF, then BCB decompression; the compressed stream is XOR'd
             with a repeating ASCII key. Known community keys are tried first
             (e.g. "GEHEIM", "CodeRobert"); otherwise the key is recovered by
             frequency analysis and *verified by the block's own 24-bit
             checksum* — so a reported decode is always checksum-correct.
  aes      — block is AES-encrypted (post-~2013 body modules). Flagged, not
             decoded (no key); the container metadata is still extracted.

Container metadata recovered regardless of block encryption: part number,
SW version, and the SA2 security-access bytecode.

BCB block format and the keyless approach were cross-checked against
prj/unpacksgo (AGPL-3.0) purely as a format reference; this is an independent
implementation that shares no source with it.

Part of Simos-Suite (GPL-3.0).
"""
from __future__ import annotations

import argparse
import collections
import math
import os
import struct
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple

_MAGIC = b"SGML Object File"

# Public, community-known repeating-XOR keys for BCB-crypted SGO blocks. Tried
# before frequency analysis purely as a fast path; any hit is still checksum-verified.
KNOWN_KEYS: List[bytes] = [
    b"GEHEIM", b"CodeRobert", b"MILKYWAY", b"BiWbBuD101", b"Mst2Bosch",
]


class Crypto(str, Enum):
    PLAIN = "plain"
    BCB = "bcb"
    BCB_XOR = "bcb-xor"
    AES = "aes"
    UNKNOWN = "unknown"


@dataclass
class Block:
    addr: int
    crypt_byte: int
    declen: int            # the container's size field (end-start; often actual-1)
    blob_len: int
    erase: Tuple[int, int]
    prog: Tuple[int, int]
    data: bytes = b""      # decoded payload (b"" if undecodable, e.g. AES)
    mode: Crypto = Crypto.UNKNOWN
    key: bytes = b""
    note: str = ""

    @property
    def decoded(self) -> bool:
        return bool(self.data)


@dataclass
class SgoFile:
    part_number: str = ""
    sw_version: str = ""
    sa2: bytes = b""
    container: str = "sgml-v2"
    blocks: List[Block] = field(default_factory=list)

    def to_image(self, fill: int = 0xFF, max_span: int = 0x200000
                 ) -> Tuple[bytes, int]:
        """Assemble decoded blocks within `max_span` of the lowest block into a
        flat image. High/EEPROM blocks beyond the span are left to the caller
        (use `.blocks`). Returns (image, base_address)."""
        decoded = [b for b in self.blocks if b.decoded]
        if not decoded:
            return b"", 0
        base = min(b.addr for b in decoded)
        end = max((b.addr + len(b.data)) for b in decoded
                  if b.addr - base < max_span)
        img = bytearray([fill]) * (end - base)
        for b in decoded:
            off = b.addr - base
            if 0 <= off < max_span:
                img[off:off + len(b.data)] = b.data
        return bytes(img), base


# ── byte helpers ──────────────────────────────────────────────────────────────

def _w32(d: bytes, p: int) -> int:
    return struct.unpack_from("<I", d, p)[0]


def _w24(d: bytes, p: int) -> int:
    return struct.unpack(">I", b"\x00" + d[p:p + 3])[0]


def _xor(s: bytes, k: bytes) -> bytes:
    if not k:
        return s
    return bytes(s[i] ^ k[i % len(k)] for i in range(len(s)))


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def _xorstr(data: bytes) -> str:
    """Decode a null-terminated, 0xFF-XOR'd ASCII string (IDENT fields)."""
    out = []
    for b in data:
        if b == 0:
            break
        out.append(b ^ 0xFF)
    return bytes(out).decode("ascii", errors="replace")


# ── BCB decompression + keyless XOR recovery ──────────────────────────────────

def _bcb_decompress(stream: bytes) -> Tuple[Optional[bytes], Optional[int]]:
    """Decompress a BCB stream. Token = u16 BE: top 2 bits = flag, low 14 = len.
        flag 0 = literal (copy len bytes)
        flag 1 = RLE   (repeat next byte len times)
        flag 3 = end   (followed by a 24-bit checksum of the output)
    Returns (output, end_checksum) or (None, None) on a malformed stream."""
    p, out = 0, bytearray()
    while p + 2 <= len(stream):
        tok = struct.unpack_from(">H", stream, p)[0]
        p += 2
        flag, ln = tok >> 14, tok & 0x3FFF
        if flag == 0:
            out += stream[p:p + ln]
            p += ln
        elif flag == 1:
            out += bytes([stream[p]]) * ln
            p += 1
        elif flag == 3:
            return bytes(out), _w24(stream, p)
        else:
            return None, None
    return None, None


def _shortest_period(key: bytes) -> bytes:
    """Reduce a repeating key to its fundamental period (operating on bytes, so
    the boundary is always byte-aligned)."""
    if not key:
        return key
    d = (key + key).find(key, 1, -1)
    return key if d == -1 else key[:d]


def _crack_xor_key(stream: bytes, target: int, klen: int) -> bytes:
    cols = [collections.Counter() for _ in range(klen)]
    for i, b in enumerate(stream):
        cols[i % klen][b] += 1
    return bytes(cols[p].most_common(1)[0][0] ^ target for p in range(klen))


def _decode_bcb_block(x: bytes) -> Optional[Tuple[bytes, Crypto, bytes]]:
    """Given the 0xFF-XOR'd block (with a `1A 01` BCB header), return
    (data, mode, key) with the decode checksum-verified, or None."""
    i = x.find(b"\x1A\x01")
    if i < 0:
        return None
    stream0 = x[i + 2:]

    def verify(stream: bytes) -> Optional[bytes]:
        out, chk = _bcb_decompress(stream)
        if out is not None and chk is not None and (sum(out) & 0xFFFFFF) == chk:
            return out
        return None

    # no key
    out = verify(stream0)
    if out is not None:
        return out, Crypto.BCB, b""
    # known keys
    for k in KNOWN_KEYS:
        out = verify(_xor(stream0, k))
        if out is not None:
            return out, Crypto.BCB_XOR, k
    # frequency analysis (checksum is the oracle)
    for target in (0x00, 0xFF):
        for klen in range(1, 33):
            k = _shortest_period(_crack_xor_key(stream0, target, klen))
            out = verify(_xor(stream0, k))
            if out is not None:
                return out, Crypto.BCB_XOR, k
    return None


def _decode_block(blob: bytes, declen: int) -> Tuple[bytes, Crypto, bytes, str]:
    """Decode one raw block blob. Returns (data, mode, key, note)."""
    x = _xor(blob, b"\xFF")
    bcb = _decode_bcb_block(x)
    if bcb is not None:
        data, mode, key = bcb
        note = "key=%r" % key.decode("latin1") if key else "no-key"
        return data, mode, key, note + " csum-OK"
    # no BCB header: AES vs plain
    if declen % 16 == 0 and len(blob) == declen and _entropy(x[:8192]) > 7.5:
        return b"", Crypto.AES, b"", "AES-encrypted (key required)"
    return x, Crypto.PLAIN, b"", "plain"


# ── container parsing ─────────────────────────────────────────────────────────

def is_sgml(data: bytes) -> bool:
    return len(data) >= 16 and data[:16] == _MAGIC


def parse(data: bytes, decode: bool = True) -> SgoFile:
    """Parse an SGML Object File. With decode=True, each block is decoded."""
    if not is_sgml(data):
        raise ValueError("not an SGML Object File (bad magic)")

    sgo = SgoFile()
    idx_ident = _w32(data, 0x19)
    sgo.part_number = (_xorstr(data[idx_ident:idx_ident + 260])
                       .replace(".sgm", "").replace(".sgo", ""))
    sgo.sw_version = _xorstr(data[idx_ident + 260:idx_ident + 265])

    meta_start = _w32(data, 0x29)
    meta_len = _w32(data, meta_start)
    sgo.sa2 = data[meta_start + 4: meta_start + 4 + meta_len]

    end = _w32(data, 0x2D)            # block data ends here (block-index trailer)
    pos = meta_start + meta_len + 4   # blocks start right after the SA2 section
    while pos + 0x19 <= end:
        addr = _w24(data, pos)
        crypt = data[pos + 3]
        declen = _w24(data, pos + 4)
        erase = (_w24(data, pos + 7), _w24(data, pos + 0xA))
        prog = (_w24(data, pos + 0xD), _w24(data, pos + 0x10))
        blob_len = _w32(data, pos + 0x15)
        blob = data[pos + 0x19: pos + 0x19 + blob_len]
        blk = Block(addr=addr, crypt_byte=crypt, declen=declen,
                    blob_len=blob_len, erase=erase, prog=prog)
        if decode:
            blk.data, blk.mode, blk.key, blk.note = _decode_block(blob, declen)
        sgo.blocks.append(blk)
        pos += 0x19 + blob_len
    return sgo


# ── CLI ───────────────────────────────────────────────────────────────────────

def _fmt(sgo: SgoFile) -> str:
    enc = sum(1 for b in sgo.blocks if b.mode == Crypto.AES)
    dec = sum(1 for b in sgo.blocks if b.decoded)
    lines = [
        "Part Number : %s" % sgo.part_number,
        "SW Version  : %s" % sgo.sw_version,
        "SA2         : %s" % sgo.sa2.hex(),
        "Blocks      : %d  (%d decoded, %d AES-encrypted)"
        % (len(sgo.blocks), dec, enc),
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="VAG SGO / SGML Object File unpacker.")
    ap.add_argument("file")
    ap.add_argument("--out", help="output dir for unpacked block .bin files")
    ap.add_argument("--image", help="also write a flat code image to this path")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)

    data = open(a.file, "rb").read()
    if not is_sgml(data):
        print("Not an SGML Object File:", a.file, file=sys.stderr)
        return 2
    sgo = parse(data)
    print(_fmt(sgo))
    if not a.quiet:
        print("\n  addr      crypt  declen     mode      detail")
        for b in sgo.blocks:
            print("  0x%06X  0x%02X   0x%-7X  %-8s  %s"
                  % (b.addr, b.crypt_byte, b.declen, b.mode.value, b.note))

    if a.out:
        os.makedirs(a.out, exist_ok=True)
        stem = os.path.splitext(os.path.basename(a.file))[0]
        for b in sgo.blocks:
            if b.decoded:
                p = os.path.join(a.out, "%s_0x%06X.bin" % (stem, b.addr))
                open(p, "wb").write(b.data)
        print("\nWrote %d block file(s) to %s"
              % (sum(1 for b in sgo.blocks if b.decoded), a.out))
    if a.image:
        img, base = sgo.to_image()
        open(a.image, "wb").write(img)
        print("Wrote flat image %d B @ base 0x%06X -> %s" % (len(img), base, a.image))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
