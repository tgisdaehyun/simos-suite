"""Unit tests for cp_tools/can_decode.py — ISO-TP + VW TP 2.0 reassembly + CP labeling."""
import os
import unittest

from cp_tools.can_decode import label, decode_frames, find_tp20_channels, decode_csv

h = bytes.fromhex


class TestLabel(unittest.TestCase):
    def test_ika_write(self):
        lab, cp = label(h("2E00BE" + "E62B41D11C44AF202177FB1F274B0AC2"))
        self.assertIn("WriteDID", lab)
        self.assertIn("IKA-WRITE", cp)

    def test_trainica_kwp(self):
        lab, cp = label(h("3BBE0102"))
        self.assertIn("WriteLocalID", lab)
        self.assertIn("KWP-WRITE", cp)

    def test_securityaccess(self):
        lab, cp = label(h("2701"))
        self.assertEqual(cp, "SecurityAccess")

    def test_readdtc_35b_not_flagged(self):
        # regression: a 35-byte ReadDTC (0x59) response must NOT be flagged as an IKA blob
        lab, cp = label(h("59060000be0801030102ed0357c6000069a0be537102860c3226020000260506260998"))
        self.assertIsNone(cp)

    def test_readdid_resp(self):
        lab, cp = label(h("62F1874142"))
        self.assertTrue(lab.startswith("ReadDID+"))
        self.assertIsNone(cp)


class TestISOTP(unittest.TestCase):
    def test_single_frame(self):
        msgs = decode_frames([(0, 0x77A, h("0562F1874142"))])
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0].payload, h("62F1874142"))
        self.assertEqual(msgs[0].transport, "ISO")

    def test_multi_frame(self):
        frames = [(0, 0x77A, h("100A62F190574155")), (1, 0x77A, h("214747413132"))]
        msgs = decode_frames(frames)
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0].payload, h("62F19057415547474131"))


class TestTP20(unittest.TestCase):
    def test_channel_discovery(self):
        fr = [(0, 0x200, h("26C00010000301")), (1, 0x226, h("00D00003C60401"))]
        self.assertEqual(find_tp20_channels(fr), {0x300, 0x4C6})

    def test_tp20_message(self):
        fr = [(0, 0x200, h("26C00010000301")), (1, 0x226, h("00D00003C60401")),
              (2, 0x4C6, h("10000322F187"))]
        msgs = [m for m in decode_frames(fr) if m.transport == "TP20"]
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0].payload, h("22F187"))
        self.assertEqual(msgs[0].can_id, 0x4C6)


_CPCAP = r"C:\Users\Power\Documents\CerberusCAN\host\cpcap.csv"


@unittest.skipUnless(os.path.exists(_CPCAP), "real capture not present on this host")
class TestCorpus(unittest.TestCase):
    def test_decode_real_capture(self):
        msgs = decode_csv(_CPCAP)
        self.assertGreater(len(msgs), 50)
        # this capture is a read/scan session -> no CP-relevant writes (no false positives)
        self.assertEqual([m.label for m in msgs if m.cp], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
