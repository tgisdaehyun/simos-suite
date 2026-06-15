"""
tests/test_module_scan.py — module-discovery map + response-ID logic (no hardware).
"""

import unittest

from core.module_scan import (
    response_id, MODULE_MAP, ModuleEntry, DetectedModule,
)
from core.ecu_defs import ECU_REGISTRY


class TestResponseId(unittest.TestCase):
    def test_vw_range(self):
        self.assertEqual(response_id(0x746), 0x7B0)   # HVAC
        self.assertEqual(response_id(0x710), 0x77A)   # gateway
        self.assertEqual(response_id(0x74C), 0x7B6)   # seat driver
        self.assertEqual(response_id(0x732), 0x79C)   # KESSY
        self.assertEqual(response_id(0x714), 0x77E)   # cluster

    def test_obd_legislated_range(self):
        self.assertEqual(response_id(0x7E0), 0x7E8)   # engine
        self.assertEqual(response_id(0x7E1), 0x7E9)   # TCU


class TestModuleMap(unittest.TestCase):
    def test_requests_in_valid_range(self):
        for e in MODULE_MAP:
            self.assertTrue(0x700 <= e.req <= 0x7EF, f"{e.name}: req {e.req:#x} out of range")

    def test_request_ids_unique(self):
        reqs = [e.req for e in MODULE_MAP]
        self.assertEqual(len(reqs), len(set(reqs)), "duplicate request IDs in MODULE_MAP")

    def test_resp_property_matches_helper(self):
        for e in MODULE_MAP:
            self.assertEqual(e.resp, response_id(e.req))

    def test_ecu_keys_resolve(self):
        for e in MODULE_MAP:
            if e.ecu_key is not None:
                self.assertIn(e.ecu_key, ECU_REGISTRY,
                              f"{e.name}: ecu_key {e.ecu_key!r} not in ECU_REGISTRY")

    def test_hvac_entry_has_patch(self):
        hvac = next(e for e in MODULE_MAP if e.vcds_addr == "08")
        self.assertTrue(hvac.have_patch)
        self.assertTrue(hvac.cp_slave)
        self.assertEqual(hvac.ecu_key, "J255_LOW")

    def test_bus_values(self):
        for e in MODULE_MAP:
            self.assertIn(e.bus, ("DRIVE", "CONV"))


class TestDetectedModule(unittest.TestCase):
    def test_flashable_reflects_ecu_key(self):
        with_key = DetectedModule(entry=next(e for e in MODULE_MAP if e.ecu_key))
        without  = DetectedModule(entry=next(e for e in MODULE_MAP if e.ecu_key is None))
        self.assertTrue(with_key.flashable)
        self.assertFalse(without.flashable)

    def test_str_renders(self):
        dm = DetectedModule(entry=MODULE_MAP[0], present=True, part_number="4G0907551D")
        s = str(dm)
        self.assertIn("4G0907551D", s)
        self.assertIn("●", s)


if __name__ == "__main__":
    unittest.main()
