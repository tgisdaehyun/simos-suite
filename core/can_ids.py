"""
core/can_ids.py — VAG C7 module diagnostic CAN-ID map.

Loads data/can_ids.properties (the ODIS request/response CAN-ID list) and maps a
diagnostic CAN id -> short module name, so captures/scans can label modules instead
of showing raw hex. `module_for(0x7B0) -> "AirCondi"`, `module_for(0x710) -> "Gatew"`.
"""
from __future__ import annotations

import pathlib
import re

_DEFAULT = pathlib.Path(__file__).resolve().parent.parent / "data" / "can_ids.properties"
_MAP = None   # {can_id:int -> name:str}, lazily loaded


def _short(key: str) -> str:
    """'request_can_id.LL_AirCondiUDS' -> 'AirCondi'."""
    n = key.split(".")[-1]
    if n.startswith("LL_"):
        n = n[3:]
    if n.endswith("UDS"):
        n = n[:-3]
    return n


def load_map(path=None) -> dict:
    """Parse the properties file into {can_id: name}. Cached when using the default."""
    global _MAP
    if _MAP is not None and path is None:
        return _MAP
    p = pathlib.Path(path) if path else _DEFAULT
    m = {}
    if p.exists():
        for line in p.read_text(errors="replace").splitlines():
            line = line.strip()
            if "=" not in line or line.startswith("#"):
                continue
            key, val = (x.strip() for x in line.split("=", 1))
            if not (key.startswith("request_can_id.") or key.startswith("response_can_id.")):
                continue
            name = _short(key)
            for tok in re.split(r"[/,]", val):           # handle "730/748" multi-id rows
                tok = tok.strip()
                if re.fullmatch(r"[0-9A-Fa-f]{3}", tok):
                    m.setdefault(int(tok, 16), name)
    if path is None:
        _MAP = m
    return m


def module_for(can_id: int):
    """Short module name for a diagnostic CAN id, or None."""
    return load_map().get(can_id)


if __name__ == "__main__":
    import sys
    mp = load_map()
    print("%d CAN ids mapped" % len(mp))
    if len(sys.argv) > 1:
        cid = int(sys.argv[1], 16)
        print("0x%03X -> %s" % (cid, module_for(cid)))
    else:
        for cid in sorted(mp):
            print("  0x%03X  %s" % (cid, mp[cid]))
