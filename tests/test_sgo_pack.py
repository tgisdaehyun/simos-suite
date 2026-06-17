"""Unit tests for cp_tools/sgo_pack.py + cp_tools/bcb_compress.py.

Synthetic vectors (always run) validate the BCB compressor against the real
sgo_unpack decoder oracle and the container-checksum rule. Corpus tests
(repack==original byte-exact) run only when real .sgo files are present.
"""
import glob
import os
import struct
import unittest

from cp_tools.sgo_unpack import _bcb_decompress
from cp_tools.bcb_compress import bcb_compress, bcb_compress_literal
from cp_tools import sgo_pack

# Real .sgo corpus locations (owner's flashdaten; not shipped with the repo).
_SGO_DIRS = [r"D:\CP\Flash",
             r"D:\ECU FLASH\FlashDaten\Flashdaten_Audi_20201020_6ZtF7"]


def _find_sgo(limit=6):
    found = []
    for d in _SGO_DIRS:
        if os.path.isdir(d):
            found += sorted(glob.glob(os.path.join(d, "*.sgo")))
    return found[:limit]


class TestBCBCompress(unittest.TestCase):
    """The compressor must be the exact inverse of sgo_unpack._bcb_decompress."""

    CASES = [
        b"",
        b"A",
        bytes(range(256)) * 4,
        b"\x00" * 5000,
        b"\xFF" * 40000,                       # > 16383 -> multi-token split
        b"AB" * 1000 + b"\x00" * 200 + bytes(range(50)),
        bytes((i * 37 + 11) & 0xFF for i in range(9001)),
    ]

    def _check(self, encoder):
        for data in self.CASES:
            stream = encoder(data, header=False)      # _bcb_decompress wants no 1A01
            out, chk = _bcb_decompress(stream)
            self.assertEqual(out, data, "decode mismatch len=%d" % len(data))
            self.assertEqual(chk, sum(data) & 0xFFFFFF, "checksum mismatch")

    def test_literal_encoder_roundtrip(self):
        self._check(bcb_compress_literal)

    def test_rle_encoder_roundtrip(self):
        self._check(bcb_compress)

    def test_rle_actually_compresses(self):
        self.assertLess(len(bcb_compress(b"\x00" * 5000, header=False)), 32)

    def test_header_present_by_default(self):
        self.assertEqual(bcb_compress(b"x")[:2], b"\x1A\x01")


class TestContainerChecksum(unittest.TestCase):
    def _buf(self, n=256):
        # a buffer big enough to hold the 0x15 checksum field
        return bytearray((i * 7 + 3) & 0xFF for i in range(n))

    def test_fix_then_verify(self):
        b = self._buf()
        sgo_pack.fix_checksum(b)
        self.assertTrue(sgo_pack.verify_checksum(bytes(b)))

    def test_fix_is_idempotent(self):
        b = self._buf()
        sgo_pack.fix_checksum(b)
        first = bytes(b)
        sgo_pack.fix_checksum(b)
        self.assertEqual(first, bytes(b))

    def test_rule_matches_spec(self):
        b = self._buf()
        sgo_pack.fix_checksum(b)
        stored = struct.unpack_from("<I", b, sgo_pack.CK_OFF)[0]
        z = bytearray(b)
        z[sgo_pack.CK_OFF:sgo_pack.CK_OFF + 4] = b"\x00\x00\x00\x00"
        self.assertEqual(stored, (sum(z) - sgo_pack.CK_BIAS) & 0xFFFFFFFF)


@unittest.skipUnless(_find_sgo(), "no real .sgo flashdaten on this host")
class TestRepackCorpus(unittest.TestCase):
    def test_structural_repack_byte_exact(self):
        for path in _find_sgo():
            with open(path, "rb") as f:
                src = f.read()
            if not src.startswith(sgo_pack.MAGIC):
                continue
            self.assertTrue(sgo_pack.verify_checksum(src),
                            "original checksum invalid: %s" % path)
            self.assertEqual(sgo_pack.repack(src), src,
                             "repack not byte-exact: %s" % path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
