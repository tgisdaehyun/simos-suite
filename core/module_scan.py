"""
core/module_scan.py — VAG module discovery ("the gateway installed list")

The home screen of the module-centric retool. Pings each known control module on
the bus and, for the ones that answer, reads its part number + system name, and
flags whether the suite can flash it (has an ECUDef) and whether we hold a CP patch
for it. This is the read-only foundation the new "Vehicle" page is built on.

Response-ID convention (VW):
    req in 0x7E0..0x7EF  → resp = req + 0x08   (OBD legislated range)
    otherwise            → resp = req + 0x6A   (VW diagnostic range)
Verified: 0x746→0x7B0 (HVAC), 0x710→0x77A (gateway), 0x7E0→0x7E8 (engine).

The CAN IDs below are the confident set for the C7 (A6/A7 4G); editing MODULE_MAP is
the supported way to extend coverage. A wrong/absent ID simply shows "not present" —
the scan never writes anything.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

log = logging.getLogger("SimosSuite.ModuleScan")


def response_id(req: int) -> int:
    """VW response CAN ID for a given request ID."""
    return req + 0x08 if 0x7E0 <= req <= 0x7EF else req + 0x6A


# ─── Known module map (C7 A6/A7 4G) ──────────────────────────────────────────

@dataclass(frozen=True)
class ModuleEntry:
    vcds_addr: str            # VCDS address byte, e.g. "08"
    name:      str            # human name incl. VAG component code
    req:       int            # request CAN ID
    bus:       str            # "DRIVE" (500k pins 6+14) or "CONV" (100k pins 3+11)
    ecu_key:   Optional[str]  # ECU_REGISTRY key if flashable, else None
    cp_slave:  bool = False   # participates in Component Protection
    have_patch: bool = False  # we hold a validated CP-bypass patch
    note:      str = ""
    db_part:   Optional[str] = None  # c7_module_db.json part number, if mapped

    @property
    def resp(self) -> int:
        return response_id(self.req)

    def db(self) -> Optional[dict]:
        """The c7_module_db.json firmware record for this module, or None.
        Gives arch / data-format / signed(rsa|crc) / SA2 / flash_profile."""
        if not self.db_part:
            return None
        from core.module_db import get_module
        return get_module(self.db_part)


# Confident set. ecu_key links into core.ecu_defs.ECU_REGISTRY.
MODULE_MAP: List[ModuleEntry] = [
    ModuleEntry("01", "J623 Engine (Simos8.5)",      0x7E0, "DRIVE", "S85",        note="3.0T TFSI",
                db_part="4G0907551"),
    ModuleEntry("02", "J217 Transmission (ZF8HP)",   0x7E1, "DRIVE", None,         cp_slave=False,
                note="TCU — verify coupling before assuming CP vs immobilizer", db_part="4G0927153"),
    ModuleEntry("03", "J104 ABS/ESP",                0x713, "DRIVE", None,         db_part="4G0907379"),
    ModuleEntry("15", "J234 Airbag",                 0x715, "DRIVE", None,         cp_slave=True,
                db_part="4G0959655"),
    ModuleEntry("17", "J285 Instrument Cluster",     0x714, "DRIVE", None,         cp_slave=True,
                db_part="4G0919158"),
    ModuleEntry("19", "J533 Gateway (Lear)",         0x710, "DRIVE", "GATEW_LEAR", cp_slave=True,
                note="CP router; stock reflash supported (flashware 4H0907468)"),
    ModuleEntry("05", "J518 KESSY",                  0x732, "CONV",  None,         cp_slave=True,
                note="immobilizer-adjacent — do not patch CP here"),
    ModuleEntry("08", "J255 Climatronic HVAC",       0x746, "CONV",  "J255_LOW",   cp_slave=True,
                have_patch=True, note="CP-bypass patched (HI 4-zone + LO 2-zone)", db_part="4G0820043"),
    ModuleEntry("09", "J519 Body Electronics (BCM)", 0x70E, "CONV",  None,         cp_slave=True,
                db_part="4G0907107"),
    ModuleEntry("46", "J393 Central Convenience",    0x70D, "CONV",  None,         cp_slave=True),
    ModuleEntry("36", "J136 Memory Seat Driver",     0x74C, "CONV",  None,         cp_slave=True,
                note="next CP-patch target (task B)"),
    ModuleEntry("06", "J521 Memory Seat Passenger",  0x74D, "CONV",  None,         cp_slave=True),
]


# ─── Scan result ─────────────────────────────────────────────────────────────

@dataclass
class DetectedModule:
    entry:       ModuleEntry
    present:     bool = False
    part_number: str = ""
    system_name: str = ""
    error:       str = ""

    @property
    def flashable(self) -> bool:
        return self.entry.ecu_key is not None

    def __str__(self) -> str:
        dot = "●" if self.present else "○"
        flags = []
        if self.flashable:       flags.append("flashable")
        if self.entry.have_patch: flags.append("patch")
        if self.entry.cp_slave:   flags.append("CP")
        tail = f"  [{', '.join(flags)}]" if flags else ""
        pid = f"  {self.part_number}" if self.part_number else ""
        return f"{dot} {self.entry.vcds_addr} {self.entry.name}{pid}{tail}"


# Minimal connection target — _make_connection only reads .can_tx / .can_rx
@dataclass
class _ScanTarget:
    can_tx: int
    can_rx: int


def scan_module(entry: ModuleEntry,
                interface: str = "J2534",
                interface_path: Optional[str] = None,
                timeout: float = 2.0) -> DetectedModule:
    """Probe a single module: extended session + read part number (0xF187) and
    system name (0xF197). Absent modules fail fast and are returned present=False."""
    import udsoncan
    from udsoncan.client import Client
    from udsoncan import services, configs
    from flasher.uds_flash import _make_connection

    result = DetectedModule(entry=entry)
    target = _ScanTarget(can_tx=entry.req, can_rx=entry.resp)

    class _Str(udsoncan.DidCodec):
        def encode(self, v): return bytes(v)
        def decode(self, p):
            try:
                s = p.decode("ascii").strip("\x00 \t\r\n")
                if s and all(32 <= ord(c) < 127 for c in s):
                    return s
            except Exception:
                pass
            return p.hex().upper()
        def __len__(self): raise udsoncan.DidCodec.ReadAllRemainingData

    try:
        conn = _make_connection(target, interface, interface_path)
    except Exception as e:
        result.error = f"connection: {e}"
        return result

    cfg = dict(configs.default_client_config)
    cfg["data_identifiers"] = {0xF187: _Str, 0xF197: _Str}
    cfg["request_timeout"] = timeout
    try:
        with Client(conn, request_timeout=timeout, config=cfg) as client:
            client.change_session(services.DiagnosticSessionControl.Session.extendedDiagnosticSession)
            result.present = True
            try: result.part_number = str(client.read_data_by_identifier_first(0xF187))
            except Exception: pass
            try: result.system_name = str(client.read_data_by_identifier_first(0xF197))
            except Exception: pass
    except Exception as e:
        # NRC / timeout → module not present (or asleep / wrong bus)
        result.error = type(e).__name__
    return result


def scan_modules(interface: str = "J2534",
                 interface_path: Optional[str] = None,
                 entries: Optional[List[ModuleEntry]] = None,
                 only_bus: Optional[str] = None,
                 timeout: float = 2.0,
                 callback: Optional[Callable[[DetectedModule], None]] = None
                 ) -> List[DetectedModule]:
    """
    Scan all known modules and return the detected list (the 'installed list').

    only_bus: restrict to "DRIVE" or "CONV" (a single-bus cable can't see the other).
    callback: called with each DetectedModule as it completes (for live UI updates).
    """
    entries = entries if entries is not None else MODULE_MAP
    if only_bus:
        entries = [e for e in entries if e.bus == only_bus.upper()]
    out: List[DetectedModule] = []
    for e in entries:
        dm = scan_module(e, interface, interface_path, timeout)
        out.append(dm)
        if callback:
            try: callback(dm)
            except Exception as cbe:
                log.debug("scan callback: %s", cbe)
        log.info("scan %s req=%#05x resp=%#05x -> %s",
                 e.vcds_addr, e.req, e.resp, "present" if dm.present else "absent")
    return out


# ─── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser(description="Scan the VAG bus for installed modules.")
    ap.add_argument("--iface", default="J2534")
    ap.add_argument("--path", default=None, help="J2534 DLL path or COM port")
    ap.add_argument("--bus", choices=["DRIVE", "CONV"], default=None)
    ap.add_argument("--timeout", type=float, default=2.0)
    args = ap.parse_args()
    print(f"Scanning {len(MODULE_MAP)} known modules…\n")
    found = scan_modules(args.iface, args.path, only_bus=args.bus,
                         timeout=args.timeout, callback=lambda m: print("  " + str(m)))
    present = [m for m in found if m.present]
    print(f"\n{len(present)}/{len(found)} modules present; "
          f"{sum(1 for m in present if m.flashable)} flashable, "
          f"{sum(1 for m in present if m.entry.have_patch)} with a CP patch.")
