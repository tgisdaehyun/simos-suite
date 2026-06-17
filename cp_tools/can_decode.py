"""
cp_tools/can_decode.py — reassemble a CAN capture into labeled UDS / KWP exchanges.

Handles BOTH transports that appear on a VAG diagnostic CAN:
  * ISO-TP (ISO 15765-2)  — the 0x7xx UDS request/response pairs (direct + gateway-routed)
  * VW TP 2.0             — KWP modules routed by the gateway (where TrainICA rides)

and labels the services, flagging the Component-Protection-relevant ones (TrainICA/GVA
KWP writes, the 0x00BE IKA write, SecurityAccess) and any 34-byte blob that looks like
an IKA. Input is a CerberusCAN sniff CSV (ms,id,data) or a list of (t, can_id, bytes).

Proven against a real C7 capture (driver-seat identity read decoded byte-exact over
VW TP 2.0 on the 500k diag CAN — i.e. sub-bus modules are visible there via gateway
routing). See research/cerberuscan-cp-bench-plan.md.

CLI:  python -m cp_tools.can_decode capture.csv
"""
from __future__ import annotations

from collections import namedtuple

UDS = {
    0x10: "DiagSession", 0x50: "DiagSession+",
    0x27: "SecurityAccess", 0x67: "SecurityAccess+",
    0x22: "ReadDID", 0x62: "ReadDID+",
    0x2E: "WriteDID", 0x6E: "WriteDID+",
    0x2F: "IOControl", 0x6F: "IOControl+",
    0x31: "Routine", 0x71: "Routine+",
    0x3E: "TesterPresent", 0x7E: "TesterPresent+",
    0x14: "ClearDTC", 0x54: "ClearDTC+",
    0x19: "ReadDTC", 0x59: "ReadDTC+",
    0x1A: "ReadECUId(KWP)", 0x5A: "ReadECUId+",
    0x21: "ReadLocalID(KWP)", 0x61: "ReadLocalID+",
    0x3B: "WriteLocalID(KWP)", 0x7B: "WriteLocalID+",
    0x23: "ReadMem", 0x63: "ReadMem+",
    0x34: "RequestDownload", 0x74: "RequestDownload+",
    0x36: "TransferData", 0x76: "TransferData+",
    0x37: "ReqXferExit", 0x77: "ReqXferExit+",
    0x7F: "NegativeResponse",
}
NRC = {0x11: "serviceNotSupported", 0x12: "subFuncNotSupported", 0x13: "wrongLength",
       0x22: "conditionsNotCorrect", 0x24: "requestSequenceError", 0x31: "requestOutOfRange",
       0x33: "securityAccessDenied", 0x35: "invalidKey", 0x36: "exceedAttempts",
       0x78: "responsePending", 0x7F: "serviceNotSupportedInSession"}

# CAN IDs / payload shapes that matter for Component Protection.
Msg = namedtuple("Msg", "t can_id transport payload label cp")


def ascii_of(b: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def label(payload: bytes):
    """Return (label_str, cp_flag) for a reassembled UDS/KWP payload."""
    if not payload:
        return "", None
    sid = payload[0]
    name = UDS.get(sid, "svc:0x%02X" % sid)
    extra = ""
    cp = None
    if sid == 0x7F and len(payload) >= 3:
        extra = " (%s, NRC=0x%02X %s)" % (UDS.get(payload[1], "0x%02X" % payload[1]),
                                          payload[2], NRC.get(payload[2], "?"))
    elif sid in (0x22, 0x62, 0x2E, 0x6E) and len(payload) >= 3:
        extra = " DID=%02X%02X" % (payload[1], payload[2])
        if sid == 0x2E and payload[1] == 0x00 and payload[2] == 0xBE:
            cp = "IKA-WRITE"
        elif sid in (0x22, 0x2E) and payload[1] == 0x00 and payload[2] in (0xBD, 0xBE):
            cp = "IKA/GKA"
    elif sid in (0x21, 0x61, 0x3B, 0x7B) and len(payload) >= 2:
        extra = " LID=%02X" % payload[1]
        if sid == 0x3B:
            cp = "KWP-WRITE(TrainICA?)"
    elif sid in (0x27, 0x67) and len(payload) >= 2:
        extra = " level=%02X" % payload[1]
        cp = "SecurityAccess"
    if cp and len(payload) in (34, 35):
        cp += "+34B"          # a 34-byte IKA-shaped blob strengthens an already-CP hit
    return name + extra, cp


# ── transport reassembly ────────────────────────────────────────────────────────

def isotp_reassemble(frames):
    """frames: [(t, payload_bytes)] for ONE CAN id. Yields (t, message_bytes)."""
    buf = bytearray()
    need = 0
    for t, d in frames:
        if not d:
            continue
        pci = d[0] >> 4
        if pci == 0:                                  # single frame
            n = d[0] & 0x0F
            yield (t, bytes(d[1:1 + n]))
            buf, need = bytearray(), 0
        elif pci == 1:                                # first frame
            need = ((d[0] & 0x0F) << 8) | d[1]
            buf = bytearray(d[2:])
        elif pci == 2:                                # consecutive frame
            if need:
                buf += d[1:]
                if len(buf) >= need:
                    yield (t, bytes(buf[:need]))
                    buf, need = bytearray(), 0
        # pci 3 = flow control -> ignore


def tp20_reassemble(frames):
    """VW TP 2.0 data frames for ONE channel id. Length-based reassembly.
    frames: [(t, payload_bytes)]. Yields (t, message_bytes)."""
    buf = bytearray()
    need = 0
    for t, d in frames:
        if not d:
            continue
        op = d[0] >> 4
        if op in (0xA, 0xB):                           # connection setup / ACK -> not data
            continue
        body = d[1:]
        if need == 0:                                  # first frame of a message
            if len(body) < 2:
                continue
            need = (body[0] << 8) | body[1]            # 2-byte big-endian KWP length
            buf = bytearray(body[2:])
        else:
            buf += body
        if need and len(buf) >= need:
            yield (t, bytes(buf[:need]))
            buf, need = bytearray(), 0


def find_tp20_channels(frames):
    """frames: [(t, can_id, bytes)]. Return the set of TP 2.0 data CAN ids learned
    from channel-setup (0x200 req C0 / 0x2xx resp D0)."""
    ids = set()
    for _t, cid, d in frames:
        if cid == 0x200 and len(d) >= 6 and d[1] == 0xC0:
            ids.update({((d[3] << 8) | d[2]) & 0x7FF, ((d[5] << 8) | d[4]) & 0x7FF})
        elif 0x200 < cid <= 0x2FF and len(d) >= 6 and d[1] == 0xD0:
            ids.update({((d[3] << 8) | d[2]) & 0x7FF, ((d[5] << 8) | d[4]) & 0x7FF})
    ids.discard(0)
    return ids


def decode_frames(frames, skip_tester_present=True):
    """frames: [(t, can_id, bytes)] -> sorted list[Msg]."""
    tp_ids = find_tp20_channels(frames)
    by_id = {}
    for t, cid, d in frames:
        by_id.setdefault(cid, []).append((t, d))

    out = []
    for cid, fr in by_id.items():
        if cid in tp_ids:
            it = ((t, m) for t, m in tp20_reassemble(fr))
            tp = "TP20"
        elif 0x600 <= cid <= 0x7FF:                    # UDS diag range -> ISO-TP
            it = ((t, m) for t, m in isotp_reassemble(fr))
            tp = "ISO"
        else:
            continue
        for t, m in it:
            if skip_tester_present and m[:1] in (b"\x3E", b"\x7E"):
                continue
            lab, cp = label(m)
            out.append(Msg(t, cid, tp, m, lab, cp))
    out.sort(key=lambda x: x.t)
    return out


def parse_csv(path):
    """Read a CerberusCAN sniff CSV (ms,id,data) -> [(t, can_id, bytes)]."""
    rows = []
    with open(path) as f:
        next(f, None)  # header
        for line in f:
            p = line.strip().split(",")
            if len(p) >= 3 and p[0].isdigit():
                rows.append((int(p[0]), int(p[1], 16),
                             bytes.fromhex(p[2].replace(" ", "")) if p[2] else b""))
    return rows


def decode_csv(path, **kw):
    return decode_frames(parse_csv(path), **kw)


def _main():
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "cpcap.csv"
    frames = parse_csv(path)
    print("loaded %d frames from %s" % (len(frames), path))
    tp = find_tp20_channels(frames)
    if tp:
        print("VW TP 2.0 channel IDs: %s" % ", ".join("0x%03X" % i for i in sorted(tp)))
    msgs = decode_frames(frames)
    print("\n%-9s %-5s %-5s  %-46s %s" % ("ms", "id", "tp", "decoded", "ascii"))
    print("-" * 100)
    cp_hits = []
    for m in msgs:
        asc = ascii_of(m.payload) if any(32 <= c < 127 for c in m.payload) else ""
        flag = ("  <<<<< " + m.cp) if m.cp else ""
        print("%-9d %-5s %-5s  %-46s %s%s" % (m.t, "%03X" % m.can_id, m.transport,
                                              m.label, asc[:36], flag))
        if m.cp:
            cp_hits.append(m)
    if cp_hits:
        print("\n=== %d Component-Protection-relevant message(s) ===" % len(cp_hits))
        for m in cp_hits:
            print("  %8d ms  %03X  %-22s  %s" % (m.t, m.can_id, m.cp, m.payload.hex()))
    else:
        print("\n(no CP-relevant services in this capture — reads/scan only)")


if __name__ == "__main__":
    _main()
