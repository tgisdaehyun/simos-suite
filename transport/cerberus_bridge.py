"""
transport/cerberus_bridge.py — udsoncan Connection over the CerberusCAN serial VCI.

CerberusCAN (Teensy 4.1 tri-CAN) is a *request-level* VCI: its firmware runs the full
ISO-TP/UDS transaction on-device and returns the assembled response over the text line
protocol in transport.cerberus_serial. This wraps that as a udsoncan BaseConnection so
the suite's UDS stack (read DIDs, write, routines, SecurityAccess, the CP probe) can
drive a module through Cerberus.

NOTE — this REPLACES an earlier version that modeled Cerberus on the ESP32 0xF1 ISO-TP
framing; the real firmware does NOT speak that. Because the device assembles the response
itself, this connection maps udsoncan send/wait_frame to one `UDS:` request->response.

Limitation: suppress-positive-response requests (TesterPresent 3E 80) get no reply and
read as a timeout — use Cerberus.tp_start() for keep-alive instead. Fine for the
read/write/routine/CP-probe flows. For passive capture use Cerberus.sniff() +
cp_tools.can_decode.
"""
from __future__ import annotations

from udsoncan.connections import BaseConnection
from udsoncan.exceptions import TimeoutException

from transport.cerberus_serial import (  # noqa: F401  (BUS_*/TEENSY_VID re-exported)
    Cerberus, CerberusError, detect_ports, BUS_DRIVE, BUS_CONV, TEENSY_VID,
)

# Back-compat alias — transport.interfaces imports this name for registry auto-detect.
detect_cerberus_ports = detect_ports


class CerberusConnection(BaseConnection):
    """udsoncan connection backed by the CerberusCAN serial VCI (request-level)."""

    def __init__(self, port=None, tx_id=None, rx_id=None, bus=BUS_DRIVE,
                 cerberus=None, name=None):
        BaseConnection.__init__(self, name or "Cerberus")
        self.port = port
        self.tx_id = tx_id
        self.rx_id = rx_id
        self.bus = bus
        self._dev = cerberus           # an existing Cerberus, or None to open by port
        self._owns = cerberus is None
        self._pending = None
        self._last_resp = None

    def open(self):
        if self._dev is None:
            self._dev = Cerberus(self.port)
        return self

    def is_open(self):
        return self._dev is not None

    def close(self):
        if self._owns and self._dev is not None:
            self._dev.close()
        self._dev = None

    def specific_send(self, payload):
        self._pending = bytes(payload)
        self._last_resp = None

    def specific_wait_frame(self, timeout=7):
        if self._dev is None:
            raise RuntimeError("CerberusConnection not open")
        if self._pending is None:
            raise TimeoutException("no request queued")
        try:
            self._last_resp = self._dev.uds(self.bus, self.tx_id, self.rx_id,
                                            self._pending, timeout=timeout)
        except CerberusError as e:
            raise TimeoutException("Cerberus: %s" % e)
        finally:
            self._pending = None
        return self._last_resp

    def empty_rxqueue(self):
        self._pending = None
        self._last_resp = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *a):
        self.close()
