"""
tests/test_module_db.py — C7 module DB integrity + the module_scan↔DB wiring.
"""

import unittest

from core.module_db import (
    load_module_db, all_modules, get_module,
    crc_only_modules, signed_modules, patch_candidates,
)
from core.module_scan import MODULE_MAP

REQUIRED = ("part", "name", "arch", "supplier", "format", "signed", "sa2", "flash_profile", "patch")
VALID_SIGNED = {"rsa", "crc"}
VALID_FORMAT = {"plain", "xor_lzss", "aes"}


class TestModuleDb(unittest.TestCase):
    def test_loads(self):
        db = load_module_db()
        self.assertEqual(db["schema"], "c7-module-db-v1")
        self.assertEqual(len(db["modules"]), 36)

    def test_required_fields_present(self):
        for m in all_modules():
            for f in REQUIRED:
                self.assertIn(f, m, f"{m.get('part')}: missing {f}")

    def test_field_value_domains(self):
        for m in all_modules():
            self.assertIn(m["signed"], VALID_SIGNED, m["part"])
            self.assertIn(m["format"], VALID_FORMAT, m["part"])

    def test_parts_unique_and_4g0(self):
        parts = [m["part"] for m in all_modules()]
        self.assertEqual(len(parts), len(set(parts)))
        for p in parts:
            self.assertTrue(p.startswith("4G0"), p)

    def test_get_module(self):
        hvac = get_module("4G0820043")
        self.assertIsNotNone(hvac)
        self.assertEqual(hvac["signed"], "rsa")
        self.assertEqual(hvac["arch"], "V850")
        # case/space-insensitive
        self.assertEqual(get_module("4g0 820 043"), hvac)
        self.assertIsNone(get_module("4G0000000"))

    def test_signed_split(self):
        # 31 CRC-only (incl. the J533 gateway), 5 RSA-signed (the security/safety set)
        self.assertEqual(len(crc_only_modules()), 31)
        self.assertEqual(len(signed_modules()), 5)
        self.assertEqual(len(crc_only_modules()) + len(signed_modules()), 36)

    def test_patch_candidates_include_hvac(self):
        cand_parts = {m["part"] for m in patch_candidates()}
        self.assertIn("4G0820043", cand_parts)            # the done one
        self.assertIn("4G0959655", cand_parts)            # airbag candidate


class TestScanDbWiring(unittest.TestCase):
    def test_db_parts_resolve(self):
        """Every MODULE_MAP db_part must point at a real DB module, and .db() must return it."""
        for e in MODULE_MAP:
            if e.db_part:
                rec = get_module(e.db_part)
                self.assertIsNotNone(rec, f"{e.name}: db_part {e.db_part} not in DB")
                self.assertEqual(e.db().get("part"), e.db_part)

    def test_unmapped_entries_return_none(self):
        for e in MODULE_MAP:
            if not e.db_part:
                self.assertIsNone(e.db())

    def test_hvac_link(self):
        hvac = next(e for e in MODULE_MAP if e.vcds_addr == "08")
        self.assertEqual(hvac.db_part, "4G0820043")
        self.assertEqual(hvac.db()["signed"], "rsa")


if __name__ == "__main__":
    unittest.main()
