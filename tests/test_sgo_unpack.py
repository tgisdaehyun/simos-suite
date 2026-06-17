"""Unit tests for cp_tools/sgo_unpack.py — synthetic vectors, no firmware needed."""
import os
import struct
import unittest

from cp_tools.sgo_unpack import (
    Crypto, is_sgml, parse, _xor, _bcb_decompress, _decode_block, _shortest_period,
)


def bcb_encode(data: bytes) -> bytes:
    """Minimal valid BCB stream: literal token(s) + end token with 24-bit sum."""
    out = b""
    i = 0
    while i < len(data):
        chunk = data[i:i + 0x3FFF]
        out += struct.pack(">H", len(chunk)) + chunk   # flag 0 = literal
        i += len(chunk)
    out += struct.pack(">H", 0x3 << 14) + (sum(data) & 0xFFFFFF).to_bytes(3, "big")
    return out


def make_block(plaintext: bytes, key: bytes = b"") -> bytes:
    """Build a raw block blob the way the container stores a BCB section:
    XOR0xFF( <header> + 1A01 + XOR(key, bcb_stream) )."""
    stream = _xor(bcb_encode(plaintext), key)
    x = b"\x00" * 8 + b"\x1A\x01" + stream
    return _xor(x, b"\xFF")


class TestBCB(unittest.TestCase):
    def test_roundtrip_literal_and_end(self):
        data = bytes(range(200)) * 3
        out, chk = _bcb_decompress(bcb_encode(data))
        self.assertEqual(out, data)
        self.assertEqual(chk, sum(data) & 0xFFFFFF)

    def test_rle(self):
        stream = struct.pack(">H", (1 << 14) | 5) + b"\xAB"
        stream += struct.pack(">H", 0x3 << 14) + (0xAB * 5 & 0xFFFFFF).to_bytes(3, "big")
        out, _ = _bcb_decompress(stream)
        self.assertEqual(out, b"\xAB" * 5)

    def test_shortest_period(self):
        self.assertEqual(_shortest_period(b"GEHEIMGEHEIM"), b"GEHEIM")
        self.assertEqual(_shortest_period(b"ABCD"), b"ABCD")

    def test_shortest_period_byte_aligned(self):
        # regression: byte keys whose hex repeat-search could land on an odd
        # index used to crash unhexlify. Period must be byte-aligned + correct.
        for key in (b"\x21\x12", b"\x12\x21\x12", bytes(range(7)),
                    b"GEHEIM" * 3, bytes([1, 2]) * 5, b"\xff\x00\xff"):
            p = _shortest_period(key)
            self.assertEqual(len(key) % len(p), 0)
            self.assertEqual(p * (len(key) // len(p)), key)


class TestDecodeBlock(unittest.TestCase):
    def test_known_key(self):
        pt = bytes(256) + b"hello world" * 50 + bytes(256)
        blob = make_block(pt, b"GEHEIM")           # GEHEIM is in KNOWN_KEYS
        data, mode, key, note = _decode_block(blob, len(pt))
        self.assertEqual(data, pt)
        self.assertEqual(mode, Crypto.BCB_XOR)
        self.assertEqual(key, b"GEHEIM")

    def test_freqcrack_unknown_key(self):
        # plaintext dominated by 0x00 so frequency analysis recovers the key
        pt = bytes(4000) + bytes(range(256)) + bytes(2000)
        blob = make_block(pt, b"ZxQ")              # NOT in KNOWN_KEYS -> must crack
        data, mode, key, note = _decode_block(blob, len(pt))
        self.assertEqual(data, pt)
        self.assertEqual(mode, Crypto.BCB_XOR)
        self.assertEqual(_shortest_period(key), b"ZxQ")

    def test_no_key_bcb(self):
        pt = b"plain bcb data" * 100
        blob = make_block(pt, b"")
        data, mode, key, note = _decode_block(blob, len(pt))
        self.assertEqual(data, pt)
        self.assertEqual(mode, Crypto.BCB)

    def test_aes_flagged(self):
        os.urandom  # noqa
        blob = bytes((i * 167 + 13) % 256 for i in range(0x4000))  # 16-aligned, high entropy
        data, mode, key, note = _decode_block(blob, 0x4000)
        self.assertEqual(mode, Crypto.AES)
        self.assertEqual(data, b"")

    def test_plain(self):
        blob = _xor(b"\x00" * 512, b"\xFF")        # low entropy, no BCB header
        data, mode, key, note = _decode_block(blob, 512)
        self.assertEqual(mode, Crypto.PLAIN)
        self.assertEqual(data, b"\x00" * 512)


def build_sgml(pn: str, sw: str, sa2: bytes, blocks):
    """Assemble a minimal valid SGML Object File for parse() testing.
    Blocks begin at meta_start + meta_len + 4 (meta_len == len(sa2))."""
    IDENT, META = 0x40, 0x200
    pos = META + 4 + len(sa2)                        # == meta_start + meta_len + 4
    hdr = bytearray(pos)
    hdr[0:16] = b"SGML Object File"
    struct.pack_into("<I", hdr, 0x11, 2)             # compat
    struct.pack_into("<I", hdr, 0x19, IDENT)         # idx_ident
    struct.pack_into("<I", hdr, 0x29, META)          # meta/sa2 index
    pnb = bytes(c ^ 0xFF for c in (pn + ".sgo").encode()) + b"\x00"
    hdr[IDENT:IDENT + len(pnb)] = pnb                # 260B part number (0xFF-xor)
    swb = bytes(c ^ 0xFF for c in sw.encode()) + b"\x00"
    hdr[IDENT + 260:IDENT + 260 + len(swb)] = swb    # 5B SW version
    struct.pack_into("<I", hdr, META, len(sa2))      # SA2 section: len + bytes
    hdr[META + 4:META + 4 + len(sa2)] = sa2
    body = bytearray()
    for addr, blob in blocks:
        desc = bytearray(0x19)
        desc[0:3] = addr.to_bytes(3, "big")
        desc[4:7] = len(blob).to_bytes(3, "big")     # declen
        struct.pack_into("<I", desc, 0x15, len(blob))  # blob_len
        body += desc + blob
    out = bytearray(hdr) + body
    struct.pack_into("<I", out, 0x2D, len(out))      # block-data end
    return bytes(out)


class TestParse(unittest.TestCase):
    def test_parse_metadata_and_block(self):
        sa2 = bytes.fromhex("6805814a05875fbd5dbd494c")
        plain = b"\x00" * 64
        blob = _xor(plain, b"\xFF")                 # a plain block
        data = build_sgml("4H0907064", "0582", sa2, [(0x010000, blob)])
        self.assertTrue(is_sgml(data))
        sgo = parse(data)
        self.assertEqual(sgo.part_number, "4H0907064")
        self.assertEqual(sgo.sw_version, "0582")
        self.assertEqual(sgo.sa2, sa2)
        self.assertEqual(len(sgo.blocks), 1)
        self.assertEqual(sgo.blocks[0].addr, 0x010000)
        self.assertEqual(sgo.blocks[0].mode, Crypto.PLAIN)
        self.assertEqual(sgo.blocks[0].data, plain)


if __name__ == "__main__":
    unittest.main()
