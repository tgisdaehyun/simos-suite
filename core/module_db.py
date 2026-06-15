"""
core/module_db.py — C7 (4G0) module firmware database.

Loads `data/c7_module_db.json`, the flashdaten-derived inventory of every C7
(Audi A6/A7 4G0) control module. Per module it records: part number, name (from
the embedded EV_ diagnostic-system strings), arch, supplier, data format
(plain / xor_lzss / aes), whether the flashware is RSA-signed vs CRC-only, the
SA2 script, a flash profile, and CP-patch status.

Used by `core.module_scan` to enrich detected modules and by the flasher to pick
a per-module flash profile.

  signed = "rsa" → flashware carries an unforgeable SIG_SHA1-RSA1024 per-block
                   signature (modified-firmware flash needs the bootloader NOT to
                   verify it, or BDM/glitch).
  signed = "crc" → only a recomputable checksum guards the image → modified
                   flash is tractable.
"""

from __future__ import annotations

import functools
import json
import pathlib
from typing import Dict, List, Optional

_DB_PATH = pathlib.Path(__file__).parent.parent / "data" / "c7_module_db.json"


@functools.lru_cache(maxsize=4)
def load_module_db(path: Optional[str] = None) -> dict:
    """Load and cache the module DB. Pass `path` to load an alternate file."""
    p = pathlib.Path(path) if path else _DB_PATH
    return json.loads(p.read_text(encoding="utf-8"))


def all_modules(path: Optional[str] = None) -> List[dict]:
    return load_module_db(path)["modules"]


def get_module(part: str, path: Optional[str] = None) -> Optional[dict]:
    """Look up a module record by part number (case/space-insensitive)."""
    key = part.upper().replace(" ", "")
    for m in all_modules(path):
        if m["part"].upper() == key:
            return m
    return None


def modules_where(path: Optional[str] = None, **filters) -> List[dict]:
    """Return modules matching all field==value filters, e.g. signed='crc'."""
    return [m for m in all_modules(path)
            if all(m.get(k) == v for k, v in filters.items())]


def crc_only_modules(path: Optional[str] = None) -> List[dict]:
    """Modules whose flashware is CRC-only (modified-flash tractable)."""
    return modules_where(path, signed="crc")


def signed_modules(path: Optional[str] = None) -> List[dict]:
    """Modules whose flashware is RSA-signed (modified flash needs a bypass)."""
    return modules_where(path, signed="rsa")


def patch_candidates(path: Optional[str] = None) -> List[dict]:
    """Modules flagged as CP firmware-patch candidates (or already patched)."""
    return [m for m in all_modules(path) if m.get("patch") not in (None, "na")]


# ─── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Query the C7 module firmware DB.")
    ap.add_argument("part", nargs="?", help="part number to look up (e.g. 4G0820043)")
    ap.add_argument("--signed", choices=["rsa", "crc"], help="filter by signing")
    ap.add_argument("--candidates", action="store_true", help="list patch candidates")
    args = ap.parse_args()
    if args.part:
        m = get_module(args.part)
        print(json.dumps(m, indent=2) if m else f"{args.part}: not found")
    elif args.candidates:
        for m in patch_candidates():
            print(f"  {m['part']}  {m['name']}  [{m['patch']}]")
    elif args.signed:
        for m in modules_where(signed=args.signed):
            print(f"  {m['part']}  {m['name']}")
    else:
        mods = all_modules()
        print(f"{len(mods)} modules; "
              f"{len(crc_only_modules())} crc-only, {len(signed_modules())} rsa-signed, "
              f"{len(patch_candidates())} patch candidates")
