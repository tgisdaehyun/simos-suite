"""Unit tests for flasher/frf_pack.py.

- The rolling-XOR cipher is self-inverse (encrypt == decrypt).
- A synthetic ODX packs and re-extracts to the edited blocks, with CRC32 updated.
- Corpus test: a real C7 FRF round-trips (extract -> pack -> extract == original).
"""
import os
import pathlib
import tempfile
import unittest
import zlib

from flasher.frf_loader import FrfLoader, _decrypt_frf
from flasher.frf_pack import frf_pack

_REPO = pathlib.Path(__file__).resolve().parent.parent
_KEY = _REPO / "data" / "frf.key"

# A minimal but FrfLoader-parseable ODX: 2 raw blocks + CRC32 SECURITY each.
_TEMPLATE_ODX = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<ODX MODEL-VERSION="2.0.1"><FLASH ID="FL_TEST">'
    '<ECU-MEMS><ECU-MEM><MEM><SESSIONS><SESSION ID="S1">'
    '<SECURITYS>'
    '<SECURITY><SECURITY-METHOD>CRC32</SECURITY-METHOD>'
    '<FW-CHECKSUM TYPE="A_BYTEFIELD">00000000</FW-CHECKSUM>'
    '<VALIDITY-FOR TYPE="A_ASCIISTRING">DB_1</VALIDITY-FOR></SECURITY>'
    '<SECURITY><SECURITY-METHOD>CRC32</SECURITY-METHOD>'
    '<FW-CHECKSUM TYPE="A_BYTEFIELD">00000000</FW-CHECKSUM>'
    '<VALIDITY-FOR TYPE="A_ASCIISTRING">DB_2</VALIDITY-FOR></SECURITY>'
    '</SECURITYS>'
    '<DATABLOCKS>'
    '<DATABLOCK ID="EMEM.DB_1"><SHORT-NAME>DB_1</SHORT-NAME>'
    '<FLASHDATA-REF ID-REF="EMEM.FD_1"/>'
    '<SEGMENTS><SEGMENT ID="SEG1"><SOURCE-START-ADDRESS>1</SOURCE-START-ADDRESS>'
    '<UNCOMPRESSED-SIZE>4</UNCOMPRESSED-SIZE></SEGMENT></SEGMENTS></DATABLOCK>'
    '<DATABLOCK ID="EMEM.DB_2"><SHORT-NAME>DB_2</SHORT-NAME>'
    '<FLASHDATA-REF ID-REF="EMEM.FD_2"/>'
    '<SEGMENTS><SEGMENT ID="SEG2"><SOURCE-START-ADDRESS>2</SOURCE-START-ADDRESS>'
    '<UNCOMPRESSED-SIZE>4</UNCOMPRESSED-SIZE></SEGMENT></SEGMENTS></DATABLOCK>'
    '</DATABLOCKS>'
    '<FLASHDATAS>'
    '<FLASHDATA ID="EMEM.FD_1"><SHORT-NAME>FD_1</SHORT-NAME>'
    '<DATAFORMAT SELECTION="BINARY"/>'
    '<ENCRYPT-COMPRESS-METHOD TYPE="A_BYTEFIELD">00</ENCRYPT-COMPRESS-METHOD>'
    '<DATA>DEADBEEF</DATA></FLASHDATA>'
    '<FLASHDATA ID="EMEM.FD_2"><SHORT-NAME>FD_2</SHORT-NAME>'
    '<DATAFORMAT SELECTION="BINARY"/>'
    '<ENCRYPT-COMPRESS-METHOD TYPE="A_BYTEFIELD">00</ENCRYPT-COMPRESS-METHOD>'
    '<DATA>CAFEBABE</DATA></FLASHDATA>'
    '</FLASHDATAS>'
    '</SESSION></SESSIONS></MEM></ECU-MEM></ECU-MEMS></FLASH></ODX>'
).encode("utf-8")

_C7_FRF = r"D:\CP\Flash\FL_4G0820043LO_0096_S.frf"   # HVAC, raw payload


@unittest.skipUnless(_KEY.exists(), "data/frf.key not present")
class TestCipherSelfInverse(unittest.TestCase):
    def test_double_decrypt_is_identity(self):
        key = _KEY.read_bytes()
        import random
        rng = random.Random(7)
        for n in (0, 1, 15, 16, 4095, 4096, 10000):
            x = bytes(rng.randrange(256) for _ in range(n))
            self.assertEqual(_decrypt_frf(key, _decrypt_frf(key, x)), x)


@unittest.skipUnless(_KEY.exists(), "data/frf.key not present")
class TestSyntheticPack(unittest.TestCase):
    def test_pack_extract_and_crc(self):
        key = _KEY.read_bytes()
        b1 = b"\x11\x22\x33\x44"
        b2 = b"\xCA\xFE\xBA\xBE"
        frf = frf_pack({1: b1, 2: b2}, _TEMPLATE_ODX, key, "FL_TEST.odx")

        loader = FrfLoader(str(_KEY))
        with tempfile.NamedTemporaryFile(suffix=".frf", delete=False) as tf:
            tf.write(frf)
            tmp = tf.name
        try:
            blocks = loader.extract_blocks(tmp)
            self.assertEqual(blocks, {1: b1, 2: b2})
            # CRC32 for DB_1 must be recomputed over the edited block
            odx = loader.get_odx(tmp).decode("utf-8")
            want = format(zlib.crc32(b1) & 0xFFFFFFFF, "08X")
            self.assertIn(want, odx)
        finally:
            os.unlink(tmp)


@unittest.skipUnless(_KEY.exists() and os.path.exists(_C7_FRF),
                     "real C7 FRF not present")
class TestCorpusRoundtrip(unittest.TestCase):
    def test_real_frf_roundtrip(self):
        loader = FrfLoader(str(_KEY))
        orig = loader.extract_blocks(_C7_FRF)
        template = loader.get_odx(_C7_FRF)
        name = pathlib.Path(_C7_FRF).stem + ".odx"
        frf = frf_pack(orig, template, _KEY.read_bytes(), name)
        with tempfile.NamedTemporaryFile(suffix=".frf", delete=False) as tf:
            tf.write(frf)
            tmp = tf.name
        try:
            self.assertEqual(loader.extract_blocks(tmp), orig)
        finally:
            os.unlink(tmp)


if __name__ == "__main__":
    unittest.main(verbosity=2)
