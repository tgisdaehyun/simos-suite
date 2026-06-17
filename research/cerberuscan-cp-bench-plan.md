# CerberusCAN — Component-Protection bench / emulation plan

Turnkey plan for the next real step in the no-patch local-CP effort: use **CerberusCAN**
(Teensy 4.x, 3× CAN) on the Audi C7 **Convenience CAN (100 kbps)** to (A) observe how the J533
gateway/immobilizer treats a fresh/un-paired module, (B) capture one live Component-Protection
handshake to recover the per-vehicle **challenge**, and (C) confirm whether
`challenge = f(CS)` so an IKA can be computed + written locally — **no firmware patch, no GeKo**.

Grounded in `seat-ika-cp-verdict.md` (the credential is a local symmetric-AES known-answer test:
`verify_pass ⇔ stored_block0 == AES(challenge, K)`, K on-module, write path open) and
`cp-firmware-re-deepdive.md`.

---

## Why this experiment is the gate

Static RE took it as far as the firmware allows. The one remaining unknown — the verify
**challenge** — is an *input*, on the wire / in the chip, not in the code:

- **If `challenge = f(CS)`** (the immobilizer secret the owner's key carries via Kessy) →
  compute `block0 = AES(f(CS), K)` offline and write it via the module's own `0x3B`/`0xBE` path.
  Fully local, no patch, no server.
- **If it's an external nonce** → fall back to the already-derived status patch (violates no-patch).

One bus capture settles it.

---

## Hardware

- **CerberusCAN** (Teensy 4.x, FlexCAN, 3 channels). For this work: one channel on the
  **Convenience CAN** (OBD pins 3+11, **100 kbps**, low-speed fault-tolerant / TJA1055 — *measure
  before assuming the transceiver*). Optionally a 2nd channel on Drivetrain CAN (500 kbps) to keep
  the gateway happy / bridge.
- A bench seat (J136) or HVAC (J255) module + 12 V, OR the experiment run in-car.
- For Experiment C: a V850 bench programmer (Xhorse/VVDI-class) to read the module data-flash.

---

## Software stack — what to pull (from the link scout) + what's custom

| Layer | Pull | License | Notes |
|---|---|---|---|
| CAN TX/RX + HW filter (Teensy 4.x) | **FlexCAN_T4** | MIT | the 4.x lib (the awesome-list's collin80/FlexCAN is the 3.x one) |
| ISO-TP (ISO 15765-2) | **lishen2/isotp-c** | MIT | complete multi-frame (needed — the 34-byte IKA is multi-frame); implement its 3 callbacks against FlexCAN_T4 |
| UDS **responder** core | **driftregion/iso14229** | MIT | UDS server, static-alloc, ARM/Arduino-tested; one event callback answers arbitrary services incl. `0x10/0x27/0x22/0x2E/0x31` and proprietary **`0x00BE`**; built-in `0x27` SecurityAccess seed/key hooks |
| Linux/vcan **prototype** | lbenthins/ecu-simulator (ref), zombieCraig/uds-server | MIT / GPL-2.0 | build + debug the responder on a PC + `vcan` before flashing the Teensy |
| **Tester** side (drive/probe our fake module, collect `0x27` seeds) | CaringCaribou + Scapy (CAN/ISOTP/UDS) | GPL | use to poke the emulated module and to brute/observe SecurityAccess |
| **VW TP 2.0** transport (Convenience CAN) | **CUSTOM** — none of the references implement it | — | port from the Wireshark TP 2.0 dissector / VAG forums; the comfort bus still uses legacy VAG TP 2.0, *not* ISO-TP |
| VAG **CP** logic | **CUSTOM** — ours (the RE in this repo) | — | the `AES(challenge,K)` model + the `0x3B/0xBE` write path |

Not-relevant (do **not** pull): hackaday #6288 (TX-only cluster animator, all-rights-reserved) and
AugustoS97/CanBus-Radio-VAG (TX-only broadcast/sniff, no transport/UDS). Only fact worth keeping:
both confirm VAG comfort CAN = 100 kbps.

> Licensing note: Simos-Suite is GPL-3.0. The MIT pulls (iso14229, isotp-c, FlexCAN_T4,
> ecu-simulator) are GPL-compatible. Keep GPL-2.0 (uds-server) as reference only, or isolate it.

---

## Experiment A — emulate a fresh module, watch the gateway

**Setup:** CerberusCAN on the Convenience CAN, running the iso14229 responder configured to answer
as J136 (or J255) — respond to the gateway's identity/wake queries but present as **un-paired**
(no valid IKA). Watch the bus.

**Resolves (one shot):**
1. **Does the gateway issue a CP challenge** (unsolicited `0x00BE`/`0x27` to our module), or does it
   only mark us "present" and let the module self-police? — settles the "gateway is not the CP lock"
   vs "gateway verifies" contradiction across all prior work.
2. **The exact framing** (session change / `0x27` preamble) the gateway expects → tells us how to
   reach the TrainICA path in a real flow.
3. Generalizes to the **J525 amp** "who verifies" open question (same NVM + KAT family).

---

## Experiment B — capture a live CP handshake → recover the challenge

**Setup:** passively **sniff** the Convenience CAN during a legitimate pairing — either an ODIS/
dealer CP-removal run, or trigger it by reconnecting a real (un-paired) module. Log the full
`0x00BE` (IKA) + `0x27` (SecurityAccess) exchange and the VW TP 2.0 frames.

**Capture:** the **challenge bytes** the CP master presents, the seed/key pair, and the order of ops
(TrainICA → TrainGVA → write). The Kessy hands the per-vehicle CS to the module here — capturing
this transaction is the way to obtain the CS/challenge the static RE can't recover.

---

## Experiment C — data-flash dump + replay (the proof)

1. **Bench-read the module data-flash** (seat record `0x03FF9000`, rows `0x11–0x15`) → the real
   `(K, stored_block0)` pair. (K is already extracted from flash; this confirms layout + gives a
   live answer.)
2. **Replay** the Experiment-B challenge through the FIPS-197 AES tool (`hvac_ika_cipher.py`-class)
   with the extracted key: does `AES(challenge, K) == stored_block0`? → confirms the exact chain
   (single AES vs slot cascade).
3. **Correlate** the challenge to the Kessy CS (from Exp B). If `challenge = f(CS)` → derive `f`,
   compute `block0` offline, write via `0x3B/0xBE`. **Done — local CP, no patch.**

---

## Decision tree

```
Exp A: gateway challenges our fake module?
  ├─ yes → challenge is on the wire (Exp B captures it directly)
  └─ no  → module self-polices; challenge generated internally (Exp C data-flash + B still needed)

Exp B+C: challenge == f(CS)?
  ├─ yes → compute block0 = AES(f(CS), K), write via 0x3B/0xBE → LOCAL CP, NO PATCH ✓
  └─ no (server nonce) → fall back to the derived status-patch (last resort, violates no-patch)
```

---

*Bench-pending. Mechanism + tooling map only; exact keys/constants live in
`seat-ika-cp-verdict.md` / `cp-firmware-re-deepdive.md`. Owner's-own-vehicle, right-to-repair.*
