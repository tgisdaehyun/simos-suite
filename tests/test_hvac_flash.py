"""
tests/test_hvac_flash.py — unit tests for the HVAC (J255 V850) flash helpers.

Covers the pure logic only (CRC-16/XMODEM, block-1 patch + CRC fixup, and the
firmware-mismatch safety guard). No hardware, no large binaries — a small
synthetic block is constructed in-memory.
"""

import unittest

from flasher.hvac_flash import (
    crc16_xmodem,
    patch_block1,
    verify_block1_crc,
    FirmwareMismatch,
    HVAC_HI0113_PATCH,
    HVAC_LO0113_PATCH,
    select_patch_set,
)


def _synthetic_block(sites=HVAC_HI0113_PATCH) -> bytes:
    """Build a minimal block-1 image carrying a patch set's validated original
    bytes at the right offsets and a correct trailing CRC, so patch_block1
    accepts it. Defaults to the 4-zone (HI) set."""
    size = 0x70000  # large enough to contain both HI and LO patch sites + CRC trailer
    buf = bytearray(b"\xFF" * size)
    for site in sites:
        buf[site.offset:site.offset + len(site.orig)] = site.orig
    crc = crc16_xmodem(bytes(buf[:-2]))
    buf[-2] = crc & 0xFF
    buf[-1] = (crc >> 8) & 0xFF
    return bytes(buf)


class TestCrc16Xmodem(unittest.TestCase):
    def test_known_check_vector(self):
        # CRC-16/XMODEM standard check value for b"123456789" is 0x31C3
        self.assertEqual(crc16_xmodem(b"123456789"), 0x31C3)

    def test_empty(self):
        self.assertEqual(crc16_xmodem(b""), 0x0000)


class TestPatchBlock1(unittest.TestCase):
    def setUp(self):
        self.block = _synthetic_block()

    def test_input_crc_valid(self):
        ok, stored, computed = verify_block1_crc(self.block)
        self.assertTrue(ok)
        self.assertEqual(stored, computed)

    def test_patch_applies_new_bytes(self):
        out = patch_block1(self.block)
        for site in HVAC_HI0113_PATCH:
            self.assertEqual(out[site.offset:site.offset + len(site.new)], site.new)

    def test_patch_fixes_crc(self):
        out = patch_block1(self.block)
        ok, stored, computed = verify_block1_crc(out)
        self.assertTrue(ok, f"patched CRC invalid: stored {stored:#06x} computed {computed:#06x}")

    def test_patch_only_touches_expected_bytes(self):
        out = patch_block1(self.block)
        changed = [i for i in range(len(out)) if out[i] != self.block[i]]
        # cand1 (3 of 4 bytes differ — last byte 0x00 unchanged), cand3 (4), CRC (2)
        expected = set()
        for site in HVAC_HI0113_PATCH:
            for i in range(len(site.new)):
                if site.new[i] != site.orig[i]:
                    expected.add(site.offset + i)
        expected.add(len(out) - 2)
        expected.add(len(out) - 1)
        self.assertEqual(set(changed), expected)

    def test_mismatch_guard_refuses(self):
        bad = bytearray(self.block)
        # corrupt the first patch site's original bytes
        site = HVAC_HI0113_PATCH[0]
        bad[site.offset] ^= 0xFF
        with self.assertRaises(FirmwareMismatch):
            patch_block1(bytes(bad))

    def test_double_patch_refused(self):
        out = patch_block1(self.block)
        with self.assertRaises(FirmwareMismatch):
            patch_block1(out)  # already patched -> originals absent -> refuse


class TestPatchBlock1LO(unittest.TestCase):
    """The 2-zone (LO) patch — same checks against an LO synthetic image."""
    def setUp(self):
        self.block = _synthetic_block(HVAC_LO0113_PATCH)

    def test_input_crc_valid(self):
        ok, stored, computed = verify_block1_crc(self.block)
        self.assertTrue(ok)

    def test_patch_applies_and_fixes_crc(self):
        out = patch_block1(self.block)            # must auto-select LO
        for site in HVAC_LO0113_PATCH:
            self.assertEqual(out[site.offset:site.offset + len(site.new)], site.new)
        ok, _, _ = verify_block1_crc(out)
        self.assertTrue(ok)

    def test_lo_sites_are_entry_force_return(self):
        # both LO sites overwrite the first instruction with "mov <v>,r10 ; jmp [lp]"
        for site in HVAC_LO0113_PATCH:
            self.assertEqual(site.new[2:], bytes.fromhex("7f00"))  # jmp [lp]


class TestAutoSelect(unittest.TestCase):
    def test_hi_block_selects_hi(self):
        name, _ = select_patch_set(_synthetic_block(HVAC_HI0113_PATCH))
        self.assertTrue(name.startswith("HI"), name)

    def test_lo_block_selects_lo(self):
        name, _ = select_patch_set(_synthetic_block(HVAC_LO0113_PATCH))
        self.assertTrue(name.startswith("LO"), name)

    def test_variants_do_not_cross_match(self):
        # an HI synthetic image must NOT be mistaken for LO and vice-versa
        self.assertTrue(select_patch_set(_synthetic_block(HVAC_HI0113_PATCH))[0].startswith("HI"))
        self.assertTrue(select_patch_set(_synthetic_block(HVAC_LO0113_PATCH))[0].startswith("LO"))

    def test_unknown_image_selects_none(self):
        name, sites = select_patch_set(b"\xFF" * 0x70000)
        self.assertIsNone(name); self.assertIsNone(sites)

    def test_patch_unknown_image_raises(self):
        with self.assertRaises(FirmwareMismatch):
            patch_block1(b"\x00" * 0x70000)


if __name__ == "__main__":
    unittest.main()
