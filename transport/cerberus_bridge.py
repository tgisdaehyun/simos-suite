"""
transport/cerberus_bridge.py — CerberusCAN (Teensy 4.x tri-CAN) host connection.

CerberusCAN is a user-built Teensy 4.x board with 3× FlexCAN channels, intended to
sit on more than one VAG bus at once (Drive-Train 500k, Convenience 100k LS-FT, and
an aux channel) for Component-Protection bench experiments — see
`research/cerberuscan-cp-bench-plan.md`.

PROTOCOL (intended). The board speaks the SAME `0xF1` ISO-TP framing as the ESP32
bridge (`lib/connections/usb_isotp_connection.py`) over its USB CDC port, plus one
extra setting — "select active FlexCAN channel" — so a single connection can target
whichever bus the module lives on. Because it reuses the ESP32 framing, this class
subclasses `USBISOTPConnection` and only adds the channel select.

⚠ SCAFFOLDING / HONEST SCOPE
  • The ISO-TP path here is complete: any module reachable by ISO-TP on a high-speed
    bus works exactly like the ESP32 bridge.
  • The Convenience-CAN (100k LS-FT) CP capture this board is ultimately for needs a
    **VW TP 2.0** transport, which does NOT exist anywhere in this repo yet. The
    channel select routes frames to the right FlexCAN, but TP 2.0 framing on the
    comfort bus is future work — comfort-bus CP capture is NOT functional yet.
  • The CerberusCAN **firmware lives outside this repo**. This module defines the
    host side of the protocol the firmware is expected to implement; if the firmware
    instead emits the plain ESP32 framing, the board also works as a `USBISOTP`
    interface (the Teensy VID is auto-detected either way).
"""
from lib.connections.usb_isotp_connection import USBISOTPConnection

# FlexCAN channel selectors (payload of the _SET_CHANNEL setting command).
BUS_DRIVE = 0   # Drive-Train / High-Speed CAN, 500 kbps (OBD pins 6+14)
BUS_CONV  = 1   # Convenience / Comfort CAN, 100 kbps LS-FT (OBD pins 3+11)
BUS_AUX   = 2   # third FlexCAN channel (bench / spare)

_SET_CHANNEL = 0x0A   # device value id: select the active FlexCAN channel

# PJRC / Teensy USB vendor id (Teensy 4.x enumerates here).
TEENSY_VID = 0x16C0


class CerberusConnection(USBISOTPConnection):
    """ISO-TP over the CerberusCAN Teensy bridge, with FlexCAN channel select."""

    def __init__(self, interface_name, rxid, txid, channel=BUS_DRIVE,
                 name=None, **kwargs):
        super().__init__(interface_name, rxid, txid, name=name or "Cerberus", **kwargs)
        self.channel = channel

    def setup(self):
        # Select the FlexCAN channel first, then the standard ISO-TP settings.
        try:
            self.set_device_value(_SET_CHANNEL, bytes([self.channel & 0xFF]))
        except Exception:
            self.logger.debug("Cerberus channel-select not acked (older firmware?)")
        super().setup()


def detect_cerberus_ports():
    """Serial ports that look like a Teensy 4.x / CerberusCAN board.

    Returns a list of (label, port). Matches the PJRC vendor id or a 'teensy' /
    'cerberus' description string."""
    found = []
    try:
        import serial.tools.list_ports
        for p in serial.tools.list_ports.comports():
            desc = (p.description or "").lower()
            if p.vid == TEENSY_VID or "teensy" in desc or "cerberus" in desc:
                label = f"{p.device}  {p.description or ''}".strip()
                if p.vid:
                    label += f"  [{p.vid:04X}:{p.pid:04X}]"
                found.append((label, p.device))
    except Exception:
        pass
    return found
