"""
transport/cerberus_serial.py — host driver for the CerberusCAN (Teensy 4.1 tri-CAN) firmware.

CerberusCAN speaks a simple ASCII line protocol at 115200 (see CerberusCAN/src/main.cpp):

    PING                           -> PONG
    INFO                           -> CERBERUS:<ver> CAN1=.. CAN2=.. tmo=.. respmax=..
    <TXID>:<RXID>:<HEX>            UDS on Head 1 (shorthand)        -> OK:<resphex> | ERR:..
    UDS:<bus>:<TXID>:<RXID>:<HEX>  UDS on bus 1|2 (full ISO-TP)     -> OK:<resphex> | ERR:..
    RAW:<bus>:<ID>:<HEX>          send ONE raw frame (<=8B)        -> OK:sent | ERR:..
    SCAN:<bus>[:lo:hi[:winms]]     TesterPresent sweep              -> FOUND:<tx>:<rx>:<data> .. DONE:<n>
    SNIFF:<bus>:<ms>               passive dump (ms=0 = until any byte) -> RX:<ms>:<id>:<data> .. DONE:<n>
    TP:<bus>:<TXID>:<ms>          background TesterPresent keep-alive | TP:STOP

It is a *request-level* VCI: the firmware runs the full ISO-TP transaction (incl. flow
control) on-device and returns the assembled response. So `uds()` is request->response,
not raw-frame send/recv. Head 1 = Powertrain/Diag CAN (500k, OBD 6/14); Head 2 = Comfort
CAN (100k, OBD 3/11 — needs an FT transceiver to actually read LS-FT).

Pair with cp_tools.can_decode to turn a sniff into labeled UDS/KWP exchanges, and see
transport.cerberus_bridge for a udsoncan-compatible Connection built on top of this.
"""
from __future__ import annotations

import time

try:
    import serial  # pyserial
except Exception:  # pragma: no cover
    serial = None

BUS_DRIVE = 1   # Head 1 — Powertrain/Diagnostic CAN, 500k (OBD 6/14)
BUS_CONV = 2    # Head 2 — Comfort/Convenience CAN, 100k (OBD 3/11)
TEENSY_VID = 0x16C0


class CerberusError(Exception):
    pass


def detect_ports():
    """[(label, port)] for serial ports that look like a Teensy / CerberusCAN board."""
    found = []
    try:
        import serial.tools.list_ports
        for p in serial.tools.list_ports.comports():
            desc = (p.description or "").lower()
            if p.vid == TEENSY_VID or "teensy" in desc or "cerberus" in desc:
                lab = "%s  %s" % (p.device, p.description or "")
                if p.vid:
                    lab += "  [%04X:%04X]" % (p.vid, p.pid)
                found.append((lab.strip(), p.device))
    except Exception:
        pass
    return found


class Cerberus:
    """Host-side driver for the CerberusCAN firmware over USB serial."""

    def __init__(self, port, baud=115200, timeout=0.2):
        if serial is None:
            raise CerberusError("pyserial not installed (pip install pyserial)")
        self.port = port
        self._s = serial.Serial(port, baud, timeout=timeout)
        time.sleep(0.3)
        self._s.reset_input_buffer()

    # ── low level ──────────────────────────────────────────────────────────────
    def _send(self, line: str):
        self._s.reset_input_buffer()
        self._s.write((line + "\n").encode())

    def _readline(self) -> str:
        return self._s.readline().decode(errors="replace").strip()

    def _read_reply(self, deadline: float):
        """Return the first OK:/ERR: line (ignoring blanks) before deadline."""
        while time.time() < deadline:
            ln = self._readline()
            if not ln:
                continue
            if ln.startswith("OK:") or ln.startswith("ERR"):
                return ln
        raise CerberusError("timeout waiting for reply")

    # ── commands ───────────────────────────────────────────────────────────────
    def ping(self) -> bool:
        self._send("PING")
        t = time.time() + 1.0
        while time.time() < t:
            if "PONG" in self._readline():
                return True
        return False

    def info(self) -> str:
        self._send("INFO")
        t = time.time() + 1.0
        while time.time() < t:
            ln = self._readline()
            if ln.startswith("CERBERUS:"):
                return ln
        return ""

    def uds(self, bus: int, tx: int, rx: int, req: bytes, timeout: float = 7.0) -> bytes:
        """Run a full UDS request on `bus`; return the response payload bytes.
        Raises CerberusError on ERR (tx-fail / no-flow-control / no-response / partial)."""
        self._send("UDS:%d:%X:%X:%s" % (bus, tx, rx, req.hex().upper()))
        ln = self._read_reply(time.time() + timeout)
        if ln.startswith("OK:"):
            return bytes.fromhex(ln[3:].strip())
        raise CerberusError(ln)

    def uds1(self, tx: int, rx: int, req: bytes, timeout: float = 7.0) -> bytes:
        """UDS on Head 1 via the TXID:RXID:HEX shorthand."""
        self._send("%X:%X:%s" % (tx, rx, req.hex().upper()))
        ln = self._read_reply(time.time() + timeout)
        if ln.startswith("OK:"):
            return bytes.fromhex(ln[3:].strip())
        raise CerberusError(ln)

    def raw(self, bus: int, can_id: int, data: bytes):
        self._send("RAW:%d:%X:%s" % (bus, can_id, data.hex().upper()))
        return self._read_reply(time.time() + 2.0)

    def scan(self, bus: int = BUS_DRIVE, lo: int = 0x700, hi: int = 0x7EF, winms: int = 120):
        """TesterPresent sweep -> [(tx_id, rx_id, resp_bytes)]."""
        self._send("SCAN:%d:%X:%X:%d" % (bus, lo, hi, winms))
        out = []
        # window: each id gets ~winms; allow generous total
        deadline = time.time() + (hi - lo + 1) * (winms / 1000.0) + 5
        while time.time() < deadline:
            ln = self._readline()
            if not ln:
                continue
            if ln.startswith("FOUND:"):
                p = ln.split(":")
                if len(p) >= 4:
                    out.append((int(p[1], 16), int(p[2], 16),
                                bytes.fromhex(p[3]) if p[3] else b""))
            elif ln.startswith("DONE"):
                break
        return out

    def sniff(self, bus: int = BUS_DRIVE, ms: int = 0, on_frame=None, stop=None):
        """Passive capture. ms=0 = run until stop() returns True (or KeyboardInterrupt).
        on_frame(t, can_id, data) called per frame. Returns [(t, can_id, data)]."""
        self._send("SNIFF:%d:%d" % (bus, ms))
        frames = []
        buf = b""
        t0 = time.time()
        stopped = False
        try:
            while True:
                if ms and (time.time() - t0) > ms / 1000.0 + 5:
                    break
                if ms == 0 and not stopped and stop is not None and stop():
                    self._s.write(b"\n")          # ms=0 sniff halts on any serial byte
                    stopped = True
                    stop_deadline = time.time() + 1.5
                if stopped and time.time() > stop_deadline:
                    break
                chunk = self._s.read(self._s.in_waiting or 1)
                if chunk:
                    buf += chunk
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    ln = raw.decode(errors="replace").strip()
                    if ln.startswith("RX:"):
                        p = ln.split(":")
                        if len(p) >= 4:
                            t, cid = int(p[1]), int(p[2], 16)
                            data = bytes.fromhex(p[3]) if p[3] else b""
                            frames.append((t, cid, data))
                            if on_frame:
                                on_frame(t, cid, data)
                    elif ln.startswith("DONE"):
                        return frames
        except KeyboardInterrupt:
            try:
                self._s.write(b"\n")
                time.sleep(0.2)
            except Exception:
                pass
        return frames

    def tp_start(self, bus: int, tx: int, ms: int = 1000):
        self._send("TP:%d:%X:%d" % (bus, tx, ms))
        return self._read_reply(time.time() + 1.5)

    def tp_stop(self):
        self._send("TP:STOP")
        return self._read_reply(time.time() + 1.5)

    # ── lifecycle ────────────────────────────────────────────────────────────────
    def close(self):
        try:
            self._s.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
