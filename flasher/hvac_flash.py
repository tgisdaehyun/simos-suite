"""
flasher/hvac_flash.py — DIY UDS flasher for the J255 Climatronic (Continental V850)

Why this is separate from uds_flash.py
──────────────────────────────────────
The Simos engine flasher (uds_flash.py) is deeply Simos-specific: every block is
ECM3/CRC32-checksummed, LZSS-compressed, then XOR/AES-encrypted, and announced with
DataFormatIdentifier 0xA/0xA. The Continental V850 HVAC is none of that:

  * ENCRYPT-COMPRESS-METHOD = 0x00 in the ODX → blocks are sent **plain** (DFI 0x00/0x00)
  * Integrity is a single **CRC-16/XMODEM** word at the END of block 1 (the bootloader
    checks it). It is recomputable — patch_block1() recomputes it.
  * There is no LZSS, no XOR/AES, no ECM3.

What this module does NOT rely on
─────────────────────────────────
The flashware FRF carries a 128-byte SIG_SHA1-RSA1024 signature per block. That is an
ODIS/SVM tester-side check and is **unforgeable**. This flasher never produces or sends
it — it pushes the patched block directly and lets the ECU validate its own CRC-16. The
make-or-break unknown is whether the *bootloader itself* also verifies the RSA signature
(secure boot). For a 2013 Continental comfort module that is unlikely, but it is exactly
what the first bench flash settles: a CRC-valid block that is cleanly rejected ⇒ the ECU
checks the signature ⇒ escalate to BDM/glitch. A clean reject is non-destructive.

SAFETY MODEL (read this)
────────────────────────
  * Every write entry point defaults to dry_run=True.
  * The recommended workflow is read_identify_patch_flash(): it identifies the unit,
    reads ITS firmware, patches THAT image (verifying the exact RE'd getter bytes are
    present before touching anything), and only then writes it back. This sidesteps the
    variant question entirely — you patch exactly what is on your unit.
  * patch_block1() REFUSES to patch if the validated original bytes are not present
    (i.e. the unit runs a different SW than FL_4G0820043HI_0113). In that case the
    firmware must be re-analysed to locate the getter — we do not pattern-guess a
    cryptographic-gate patch.

CONFIRMED for FL_4G0820043HI_0113 (Renesas V850, link base 0x10000):
  cand1 getter  FUN_00079580 @ file 0x69580 : 80 07 21 00 -> 0c 52 7f 00 (return 0x0C)
  cand3 enum    FUN_00079572 @ file 0x6957a : e3 4f 14 53 -> 01 52 00 00 (StateOfAuthe=1)
  boot CRC      CRC-16/XMODEM over block1[0:-2], stored little-endian at the last 2 bytes
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional, Dict, List, Tuple

import udsoncan
from udsoncan.client import Client
from udsoncan import services, configs, exceptions

from core.ecu_defs import ECUDef, J255_2ZONE, J255_4ZONE
from flasher.uds_flash import (
    _make_connection, _make_security_algo, FlashProgress, ProgressCallback, _noop,
)

log = logging.getLogger("SimosSuite.HVACFlash")


# ─── CRC-16/XMODEM (the ECU-side block integrity check) ──────────────────────

def crc16_xmodem(data: bytes) -> int:
    """CRC-16/XMODEM: poly 0x1021, init 0x0000, no reflection, no xorout."""
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc


# ─── The CP-bypass patch (validated for FL_4G0820043HI_0113) ─────────────────

@dataclass(frozen=True)
class PatchSite:
    name:   str
    offset: int      # file offset within block 1
    orig:   bytes
    new:    bytes


# 4-zone (HIGH) — FL_4G0820043HI_0113, block1 = 1,003,520 B
HVAC_HI0113_PATCH: List[PatchSite] = [
    PatchSite("cand1 getter FUN_00079580 -> return 0x0C",
              0x69580, bytes.fromhex("80072100"), bytes.fromhex("0c527f00")),
    PatchSite("cand3 enum FUN_00079572 -> StateOfAuthe Valid",
              0x6957a, bytes.fromhex("e34f1453"), bytes.fromhex("01520000")),
]

# 2-zone (LOW) — FL_4G0820043LO_0113, block1 = 741,376 B.
# CORRECTED 2026-06-16 (adversarial verify wmd8amokk + producer derivation wx44j6x3o).
# The earlier 2-site (cand1 + cand3) patch was WRONG and is replaced:
#   * cand3 (FUN_00069d08 -> 1) was COUNTERPRODUCTIVE — FUN_00069d08 returns {0,3} (a
#     pending-request latch over gp-0x7c72, NOT a StateOfAuthe enum; the HI 0..3 enum does
#     not exist in LO). Its only consumer, the auth state machine FUN_0006dd54, needs ==3
#     to set the valid flag -0x7c17=1; forcing it to 1 JAMMED -0x7c17 at 0 forever.
#   * The 2-site patch also missed the direct -0x7c17 readers (flap solver FUN_00069362,
#     actuator gate FUN_0006afb8, UDS FUN_0006f32a/FUN_000752f8) and boot-reset re-clear.
# Correct fix = keep cand1 (getter -> 0x0C) + NOP the two BNE guards in FUN_0006dd54's
# default case (phase!=2 and FUN_00069d08()!=3 early-outs) so the firmware's OWN auth-grant
# (mov 1,r9; st.b r9,-0x7c17  /  mov 3,r8; st.b r8,-0x7c16) runs unconditionally. Then ALL
# readers see authenticated and it re-establishes every power-on. Bench-confirm the brief
# key-on limp transient before the state-walk reaches the grant (~20 heartbeats).
HVAC_LO0113_PATCH: List[PatchSite] = [
    PatchSite("cand1 getter FUN_00069d16 -> return 0x0C",
              0x59d16, bytes.fromhex("80072100"), bytes.fromhex("0c527f00")),
    PatchSite("guard1 NOP: phase!=2 early-out in FUN_0006dd54 (force auth-grant)",
              0x5e118, bytes.fromhex("da0d"), bytes.fromhex("0000")),
    PatchSite("guard2 NOP: FUN_00069d08()!=3 early-out in FUN_0006dd54 (force auth-grant)",
              0x5e120, bytes.fromhex("9a0d"), bytes.fromhex("0000")),
]

# OPTIONAL erase-gate-open patch (LO_0113) — OPT-IN for the bench/recovery workflow only.
# Forces FUN_00061e04 @0x61e04 to always return 0 ('mov r29,r10' 0x501d -> 'mov r0,r10' 0x5000),
# so the EraseMemory gate FUN_0005ce44 always takes its proceed path ({0,0x18}) regardless of
# CP-record state. Lets a bench-flashed unit then accept FUTURE in-car UDS reflashes (no re-pull).
# Derived + adversarially verified (workflow w1193w22j 2026-06-16). Polarity facts that this
# corrects: the gate proceeds ONLY on FUN_00061e04 in {0,0x18} (NOT {3,8}); the limp blocks via
# gp-0x6930=0 -> FUN_0005625a=8 -> gate 0x21/0x22. FUN_00056414 is a CP-RECORD integrity scanner,
# NOT AES. The prior '0x22->0x21' idea was WRONG (0x21 is also non-proceed).
# TRADE-OFF: removes the CP-record integrity interlock before erase (brick risk LOW; the actual
# write is still gated elsewhere). No upside on a healthy unit — include only deliberately.
HVAC_LO0113_ERASEGATE: List[PatchSite] = [
    PatchSite("erase-gate: FUN_00061e04 always return 0 (open EraseMemory)",
              0x51e44, bytes.fromhex("1d50"), bytes.fromhex("0050")),
]

# Known patch sets, tried in order. Auto-selected by which set's original bytes
# all match the loaded image (HI sites land in a 2-zone image but won't match, and
# vice-versa), so the right patch is chosen for whichever variant is loaded.
PATCH_SETS = [
    ("HI_0113 (4-zone)", HVAC_HI0113_PATCH),
    ("LO_0113 (2-zone)", HVAC_LO0113_PATCH),
]


class FirmwareMismatch(Exception):
    """The unit's firmware does not match any validated RE target — refuse to patch."""


def select_patch_set(block1: bytes):
    """Return (name, sites) of the patch set whose original bytes all match this
    image, or (None, None) if none does (unknown firmware → must be re-analysed)."""
    for name, sites in PATCH_SETS:
        if all(s.offset + len(s.orig) <= len(block1)
               and bytes(block1[s.offset:s.offset + len(s.orig)]) == s.orig
               for s in sites):
            return name, sites
    return None, None


def patch_block1(block1: bytes,
                 sites: Optional[List[PatchSite]] = None,
                 recompute_crc: bool = True,
                 extra_sites: Optional[List[PatchSite]] = None) -> bytes:
    """
    Apply the CP-bypass patch to a block-1 image and fix the boot CRC.

    With sites=None (default) the correct patch set (4-zone HI / 2-zone LO) is
    auto-selected by matching original bytes. Raises FirmwareMismatch if the image
    matches no known target — meaning it must be re-analysed before patching (we
    never pattern-guess a crypto-gate patch).

    extra_sites (optional) are appended after the auto-selected set — used for the
    opt-in HVAC_LO0113_ERASEGATE patch (open EraseMemory for future in-car reflash).
    Each extra site's original bytes are verified like any other (FirmwareMismatch
    if absent), so passing the wrong-variant erase-gate sites is rejected, not silently
    mis-applied.
    """
    if sites is None:
        name, sites = select_patch_set(block1)
        if sites is None:
            raise FirmwareMismatch(
                f"image ({len(block1)} B) matches no known patch set "
                f"(not FL_4G0820043HI_0113 4-zone nor LO_0113 2-zone). Read it back "
                f"and re-locate the getter with the V850 static analysis before flashing.")
        log.info("auto-selected patch set: %s", name)
    if extra_sites:
        sites = list(sites) + list(extra_sites)
        log.info("appended %d extra patch site(s)", len(extra_sites))
    data = bytearray(block1)
    for s in sites:
        cur = bytes(data[s.offset:s.offset + len(s.orig)])
        if cur != s.orig:
            raise FirmwareMismatch(
                f"{s.name}: expected {s.orig.hex()} at file 0x{s.offset:05x}, "
                f"found {cur.hex()}. This unit runs a different SW than "
                f"FL_4G0820043HI_0113 — read it back and re-locate the getter "
                f"with the V850 static analysis before flashing."
            )
    for s in sites:
        data[s.offset:s.offset + len(s.new)] = s.new
        log.info("patched %s @0x%05x: %s -> %s", s.name, s.offset, s.orig.hex(), s.new.hex())
    if recompute_crc:
        crc = crc16_xmodem(bytes(data[:-2]))
        data[-2] = crc & 0xFF
        data[-1] = (crc >> 8) & 0xFF
        log.info("recomputed boot CRC-16/XMODEM = 0x%04X (stored LE at end)", crc)
    return bytes(data)


def verify_block1_crc(block1: bytes) -> Tuple[bool, int, int]:
    """Return (ok, stored_crc, computed_crc) for a block-1 image."""
    stored = block1[-2] | (block1[-1] << 8)
    computed = crc16_xmodem(block1[:-2])
    return (stored == computed, stored, computed)


# ─── Identify (read-only) — resolves the variant question ────────────────────

_ID_DIDS = {
    0xF190: "VIN",
    0xF187: "Part Number",
    0xF189: "SW Version",
    0xF191: "HW Number",
    0xF1A3: "HW Version",
    0xF197: "System Name",
    0xF18C: "ECU Serial",
    0xF17C: "FAZIT",
    0xF186: "Active Session",
    0x0405: "Flash State",
    0x0407: "Program Attempts",
    0x0408: "Successful Programs",
}


def identify_hvac(ecu: ECUDef = J255_2ZONE,
                  interface: str = "J2534",
                  interface_path: Optional[str] = None) -> Dict[str, str]:
    """
    Read identification DIDs from the HVAC (extended session, read-only, no SA2).
    Use this FIRST to confirm the unit's part number / SW version before any flash.
    """
    conn = _make_connection(ecu, interface, interface_path)

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

    cfg = dict(configs.default_client_config)
    cfg["data_identifiers"] = {d: _Str for d in _ID_DIDS}
    cfg["request_timeout"] = 8

    out: Dict[str, str] = {}
    with Client(conn, request_timeout=8, config=cfg) as client:
        client.change_session(services.DiagnosticSessionControl.Session.extendedDiagnosticSession)
        try: client.session_timing["p2_server_max"] = 12
        except TypeError: client.session_timing.p2_server_max = 12
        for did, label in _ID_DIDS.items():
            try:
                out[label] = str(client.read_data_by_identifier_first(did))
            except Exception as e:
                out[label] = f"<{type(e).__name__}>"
    log.info("identify_hvac: %s", {k: out[k] for k in ("Part Number", "SW Version") if k in out})
    return out


# ─── Read the unit's firmware (RequestUpload, plain) ─────────────────────────

def read_hvac_block(ecu: ECUDef,
                    block_num: int,
                    expected_len: int,
                    interface: str = "J2534",
                    interface_path: Optional[str] = None,
                    sa2_level: int = 0x11,
                    callback: ProgressCallback = _noop) -> Optional[bytes]:
    """
    Read a flash block from the HVAC via UDS RequestUpload (plain — no decrypt,
    no decompress; ENCRYPT-COMPRESS-METHOD=0x00). Requires SA2 programming unlock.

    expected_len must be the block size for THIS unit's SW (read it from a known
    FRF, or pass a generous size and trim). Returns raw bytes, or None on failure.
    """
    conn = _make_connection(ecu, interface, interface_path)
    cfg = dict(configs.default_client_config)
    cfg["security_algo"] = _make_security_algo(ecu.sa2_script)
    cfg["security_algo_params"] = None
    cfg["data_identifiers"] = {}
    cfg["request_timeout"] = 30

    callback(FlashProgress("CONNECT", f"Reading block {block_num} from {ecu.name}…", 0))
    with Client(conn, request_timeout=30, config=cfg) as client:
        def _st(t=30):
            try: client.session_timing["p2_server_max"] = t
            except TypeError: client.session_timing.p2_server_max = t
            client.config["request_timeout"] = t

        try:
            client.change_session(services.DiagnosticSessionControl.Session.extendedDiagnosticSession)
            _st(30)
            try: client.start_routine(0x0203)
            except Exception as e: log.debug("precondition 0x0203: %s", e)
            client.tester_present()
            client.change_session(services.DiagnosticSessionControl.Session.programmingSession)
            _st(30); client.tester_present()
            client.unlock_security_access(sa2_level)
            client.tester_present()
        except exceptions.NegativeResponseException as e:
            callback(FlashProgress("ERROR", f"Setup failed: {e}", 0)); return None

        try:
            dfi = udsoncan.DataFormatIdentifier(compression=0x0, encryption=0x0)
            mem = udsoncan.MemoryLocation(address=block_num, memorysize=expected_len,
                                          address_format=8, memorysize_format=32)
            resp = client.request_upload(mem, dfi)
            max_block = resp.service_data.max_length
        except Exception as e:
            callback(FlashProgress("ERROR", f"RequestUpload failed: {e}", 0)); return None

        block_size = max_block - 2
        counter = 1
        rx = bytearray()
        while len(rx) < expected_len:
            pct = int(100 * len(rx) / expected_len)
            callback(FlashProgress("TRANSFER",
                                   f"Reading {len(rx):#08x}/{expected_len:#08x}", pct))
            try:
                r = client.transfer_data(counter, b"")
                rx.extend(bytes(r.service_data.parameter_records))
            except exceptions.NegativeResponseException as e:
                callback(FlashProgress("ERROR", f"TransferData read failed at {len(rx):#x}: {e}", 0))
                return None
            counter = (counter + 1) & 0xFF
            if counter == 0: counter = 1
            if len(rx) % (50 * block_size) < block_size:
                try: client.tester_present()
                except Exception: pass
        try: client.request_transfer_exit()
        except Exception as e: log.warning("transfer exit: %s", e)
        callback(FlashProgress("DONE", f"read {len(rx):,} bytes", 100))
        return bytes(rx[:expected_len])


# ─── Flash one plain block ───────────────────────────────────────────────────

def flash_hvac_block(ecu: ECUDef,
                     block_num: int,
                     data: bytes,
                     interface: str = "J2534",
                     interface_path: Optional[str] = None,
                     sa2_level: int = 0x11,
                     erase_routine: int = 0xFF00,
                     checksum_routine: Optional[int] = 0x0202,
                     dry_run: bool = True,
                     callback: ProgressCallback = _noop) -> bool:
    """
    Flash one PLAIN block to the HVAC (no compression/encryption — DFI 0x00/0x00).
    `data` must already carry a valid boot CRC (use patch_block1()).

    dry_run=True (default) walks the whole sequence and logs every step WITHOUT
    erasing or writing — use it to validate addressing/timing on the bench first.

    erase_routine / checksum_routine are best-effort and parameterised because the
    HVAC's exact routine IDs are unconfirmed; checksum failures are logged, not fatal.
    """
    if block_num not in ecu.blocks:
        callback(FlashProgress("ERROR", f"Block {block_num} not defined for {ecu.name}", 0)); return False

    conn = _make_connection(ecu, interface, interface_path)
    cfg = dict(configs.default_client_config)
    cfg["security_algo"] = _make_security_algo(ecu.sa2_script)
    cfg["security_algo_params"] = None
    cfg["data_identifiers"] = {}
    cfg["request_timeout"] = 30

    tag = "DRY-RUN " if dry_run else ""
    callback(FlashProgress("CONNECT", f"{tag}Flashing block {block_num} to {ecu.name}…", 0))

    with Client(conn, request_timeout=30, config=cfg) as client:
        def _st(t=30):
            try: client.session_timing["p2_server_max"] = t
            except TypeError: client.session_timing.p2_server_max = t
            client.config["request_timeout"] = t

        # session + SA2
        try:
            client.change_session(services.DiagnosticSessionControl.Session.extendedDiagnosticSession)
            _st(30)
            try: client.start_routine(0x0203)
            except Exception as e: log.debug("precondition 0x0203: %s", e)
            client.tester_present()
            callback(FlashProgress("CONNECT", "Programming session…", 8))
            client.change_session(services.DiagnosticSessionControl.Session.programmingSession)
            _st(30); client.tester_present()
            callback(FlashProgress("CONNECT", "SA2 security access…", 12))
            client.unlock_security_access(sa2_level)
            client.tester_present()
        except exceptions.NegativeResponseException as e:
            callback(FlashProgress("ERROR", f"Session/SA2 failed: {e}", 0)); return False

        # erase
        callback(FlashProgress("ERASE", f"{tag}Erase block {block_num}…", 15))
        if not dry_run:
            try:
                client.start_routine(erase_routine, data=bytes([0x01, block_num]))
            except exceptions.NegativeResponseException as e:
                callback(FlashProgress("ERROR", f"Erase failed: {e}", 0)); return False
        client.tester_present()

        # request download (plain)
        callback(FlashProgress("TRANSFER", f"{tag}RequestDownload ({len(data):,} B)…", 18))
        max_block = 0xFFD
        if not dry_run:
            try:
                dfi = udsoncan.DataFormatIdentifier(compression=0x0, encryption=0x0)
                mem = udsoncan.MemoryLocation(address=block_num, memorysize=len(data),
                                              address_format=8, memorysize_format=32)
                resp = client.request_download(mem, dfi)
                max_block = resp.service_data.max_length
            except Exception as e:
                callback(FlashProgress("ERROR", f"RequestDownload failed: {e}", 0)); return False

        # transfer
        chunk_size = max_block - 2
        counter, offset, n = 1, 0, len(data)
        while offset < n:
            chunk = data[offset:offset + chunk_size]
            pct = 18 + int(75 * offset / n)
            callback(FlashProgress("TRANSFER", f"{tag}{offset:#08x}/{n:#08x}", pct))
            if not dry_run:
                try:
                    client.transfer_data(counter, chunk)
                except exceptions.NegativeResponseException as e:
                    callback(FlashProgress("ERROR", f"TransferData failed at {offset:#x}: {e}", 0))
                    return False
            offset += len(chunk)
            counter = (counter + 1) & 0xFF
            if counter == 0: counter = 1
            if (offset // chunk_size) % 50 == 0 and not dry_run:
                try: client.tester_present()
                except Exception: pass

        if not dry_run:
            try: client.request_transfer_exit()
            except exceptions.NegativeResponseException as e:
                callback(FlashProgress("ERROR", f"TransferExit failed: {e}", 0)); return False
            client.tester_present()

        # checksum (best-effort — routine ID unconfirmed for HVAC)
        if checksum_routine is not None and not dry_run:
            callback(FlashProgress("VERIFY", "Checksum routine…", 95))
            try:
                client.start_routine(checksum_routine,
                                     data=bytes([0x01, block_num, 0x00, 0x04]) + bytes(4))
            except Exception as e:
                log.warning("checksum routine 0x%04X: %s (continuing — verify on the unit)",
                            checksum_routine, e)

        # dependencies + reset
        if not dry_run:
            try: client.start_routine(0xFF01)   # CheckProgrammingDependencies
            except Exception as e: log.debug("CheckProgrammingDependencies: %s", e)
            client.tester_present()
            callback(FlashProgress("DONE", "Resetting module…", 99))
            try: client.ecu_reset(services.ECUReset.ResetType.hardReset)
            except Exception as e: log.debug("ECU reset: %s", e)

    callback(FlashProgress("DONE", f"{tag}block {block_num} {'simulated' if dry_run else 'flashed'}", 100))
    return True


# ─── Safe end-to-end orchestrator ────────────────────────────────────────────

def read_identify_patch_flash(ecu: ECUDef = J255_2ZONE,
                              interface: str = "J2534",
                              interface_path: Optional[str] = None,
                              block_len: int = 0xF5000,
                              dry_run: bool = True,
                              callback: ProgressCallback = _noop) -> bool:
    """
    The recommended, safe workflow:
      1. identify the unit (part number / SW) and log it,
      2. read block 1 off the unit,
      3. verify its CRC, patch it (refuses if it isn't the RE'd firmware),
      4. flash the patched block back (dry_run by default),
      5. (caller) confirm climate works, then clear any gateway CP DTC.

    block_len defaults to 0xF5000 (FL_4G0820043HI_0113). If your unit's SW differs,
    identify() will show it and read/patch will tell you to re-RE.
    """
    info = identify_hvac(ecu, interface, interface_path)
    callback(FlashProgress("CONNECT",
                           f"Unit: {info.get('Part Number','?')} SW {info.get('SW Version','?')}", 2))
    log.info("identify: %s", info)

    raw = read_hvac_block(ecu, 1, block_len, interface, interface_path, callback=callback)
    if raw is None:
        return False

    ok, stored, comp = verify_block1_crc(raw)
    callback(FlashProgress("VERIFY",
                           f"read-back CRC {'OK' if ok else 'MISMATCH'} "
                           f"(stored 0x{stored:04X} / computed 0x{comp:04X})", 50))
    if not ok:
        log.warning("read-back block-1 CRC mismatch — read may be truncated or wrong length")

    try:
        patched = patch_block1(raw)
    except FirmwareMismatch as e:
        callback(FlashProgress("ERROR", str(e), 0))
        return False

    return flash_hvac_block(ecu, 1, patched, interface, interface_path,
                            dry_run=dry_run, callback=callback)


# ─── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    ap = argparse.ArgumentParser(description="DIY UDS flasher for the J255 Climatronic (V850).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_id = sub.add_parser("identify", help="read part number / SW (read-only)")
    p_pf = sub.add_parser("patchfile", help="patch a block-1 .bin on disk (+ fix CRC)")
    p_pf.add_argument("infile"); p_pf.add_argument("outfile")
    p_rd = sub.add_parser("read", help="read block 1 off the unit to a .bin")
    p_rd.add_argument("outfile"); p_rd.add_argument("--len", default="0xF5000")
    p_fl = sub.add_parser("flash", help="flash a patched block-1 .bin (dry-run unless --go)")
    p_fl.add_argument("infile"); p_fl.add_argument("--go", action="store_true")
    p_rpf = sub.add_parser("auto", help="identify→read→patch→flash (dry-run unless --go)")
    p_rpf.add_argument("--go", action="store_true")

    for p in (p_id, p_rd, p_fl, p_rpf):
        p.add_argument("--zone", choices=["2", "4"], default="2")
        p.add_argument("--iface", default="J2534")
        p.add_argument("--path", default=None, help="J2534 DLL path or COM port")

    args = ap.parse_args()
    ecu = J255_2ZONE if getattr(args, "zone", "2") == "2" else J255_4ZONE

    if args.cmd == "patchfile":
        data = open(args.infile, "rb").read()
        try:
            out = patch_block1(data)
        except FirmwareMismatch as e:
            print("REFUSED:", e); sys.exit(2)
        open(args.outfile, "wb").write(out)
        ok, s, c = verify_block1_crc(out)
        print(f"patched -> {args.outfile} ({len(out)} B); CRC 0x{c:04X} {'VALID' if ok else 'BAD'}")
    elif args.cmd == "identify":
        for k, v in identify_hvac(ecu, args.iface, args.path).items():
            print(f"  {k:18s}: {v}")
    elif args.cmd == "read":
        raw = read_hvac_block(ecu, 1, int(args.len, 0), args.iface, args.path)
        if raw: open(args.outfile, "wb").write(raw); print(f"read {len(raw)} B -> {args.outfile}")
        else: sys.exit(1)
    elif args.cmd == "flash":
        data = open(args.infile, "rb").read()
        ok, s, c = verify_block1_crc(data)
        if not ok:
            print(f"WARNING: input CRC bad (stored 0x{s:04X} computed 0x{c:04X})")
        flash_hvac_block(ecu, 1, data, args.iface, args.path, dry_run=not args.go)
    elif args.cmd == "auto":
        read_identify_patch_flash(ecu, args.iface, args.path, dry_run=not args.go)
