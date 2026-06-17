# Audi C7 (4G) Component-Protection parts — inventory & status

**Vehicle:** 2013 Audi A6 C7 3.0T (VIN WAUGGA**********8), gateway J533 = 4G0907468AC, LEAR gateway.
**Scope:** Module-by-module CP documentation. Classifies every enrolled / present module as **true-CP**, **IMMO (not CP)**, **present-not-CP**, or **unknown**, and records flashdaten availability + crypto so the team knows which CP parts are extractable now vs. bench-only.

> **Address-space caveat:** the "enrolled" set comes from the **J533 constellation/allocation bytes (DID 0x2A2A)**, which are **not 1:1** with the **VCDS diagnostic addresses** the autoscan reports. Several constellation slots are platform template placeholders that are **not physically populated** on this US 2013 A6 3.0T (no AFS, no Night Vision, no TV). Part numbers tagged `inference`/`module-db` are **not** confirmed installed on this car. The VCDS address column below follows the task's classification labels (constellation-style); the part-number column reflects what each VCDS address actually answered on this VIN where known.

---

## Master table (sorted: TRUE-CP → likely-CP → IMMO → present-not-CP → unknown)

| VCDS addr | Module (J-number) | CP status | Part number(s) | Flashdaten? | Container | Crypto | Extractable? | Notes |
|---|---|---|---|---|---|---|---|---|
| 08 | HVAC / Climatronic (J255) | **CP** | 4G0820043AH (running, 2-zone); canonical 4G0820043 | yes | .frf | RSA-signed, plain blocks | **yes** (patchable; reflash gated by RSA → bench/ISP) | **Only fully CP-confirmed + firmware-verified part.** Cleared as CP slave in Feb-2024 ODIS (WDBI 0x00BE). Live scan: DTC 0xEA62 status 0x09 (CompoProteActiv); 0x00BE→7F2231 on 2-zone variant. **THE repair target.** |
| 1E | MMI / Info Electronics 1 (J794) | **CP** | unknown on this car; module-db family 4G0919604 | yes (4G0919604) | .frf | plain (+LZSS) / CRC-only | yes | Confirmed CP slave (Feb-2024, 0x00BE). Stores IKA, sets U110100. Addr-1E not separately enumerated by VCDS on this car; MMI head answers at 5F/56. |
| 47 | Sound System 2 (J525, Bose amp) | **CP** | 4G0035223C (running; HW 4G0035223A, BOSE-G3-C7) | yes (amp 4G0907441) | .sgo | plain | yes | Confirmed CP slave (Feb-2024, TrainICA/TrainGVA). Amp/DSP self-polices CP; BV_SoundSysteUDS owns TheftProteData + IKA. |
| 09 | Central Electronics / BCM (J519) | **CP** | 4H0907063CG (running, BCM1 2.0); db equiv 4G0907107 | yes (4G0907107) | .frf | plain / CRC-only | yes | Confirmed CP slave (Feb-2024). Comfort/body controller; sets U110100 when swapped. |
| 15 | Airbag (J234) | **CP** | 4G0959655A | yes | .frf | RSA-signed, plain blocks | yes (modified image buildable; RSA gates UDS reflash → bench) | Cleared as CP slave (Feb-2024, UDS). String-DB didn't surface a dedicated TheftProte owner, but live session proves self-policing here (crash-data/coding bound). Treat as true-CP. |
| 06 | Seat Passenger memory (J521) | **CP** | unknown (not enumerated; likely 4G8959770-family) | n/a (this exact part unconfirmed) | — | likely plain (seat class) | likely yes | True-CP by VAG class (seat memory stores IKA, sets U110100 — the owner's case). Returned ECF_OPEN_LOGICAL_LINK_FAILED in Feb-2024 (not installed then); enrolled in current constellation. Part left unknown — VCDS never enumerated addr 06. |
| 17 | Instrument Cluster (J285) | **CP** | 4G8920983E (running at VCDS 17); flashdaten 4G0919158 | yes (4G0919158) | .frf | RSA-signed | yes (RSA gates reflash → bench) | Canonical CP (stores IKA, sets U110100). Cleared as CP slave (Feb-2024, 0x00BE); live 0x00BE→7F2231. **Currently NOT enrolled** (slot-map 0x17 'no') — classify CP regardless. |
| 28 | Driver Seat / Memory (J136) | **CP** | 4H0959760A (running, MEM-FS at VCDS 36) | yes (4G8959760) | .sgo | plain | yes | Gave the **only unmasked IKA blob** in Feb-2024 (0x00BE = E62B41D1…2600, 34 bytes, TrainICA). Textbook CP module that triggered the case. **Currently NOT enrolled** (slot-map 'no') — classify CP regardless. |
| 18 | Auxiliary Heater (J604) | likely-CP | unknown (not enumerated; no 4G0 flashdaten on hand) | unknown | — | unknown | unknown | Comfort class consistent with CP; enrolled. Not in Feb-2024 12-module clear list, no 0x00BE owner confirmed. Mark likely pending 0x00BE/U110100 read. |
| 20 | Rear/Reversing Camera (J772) | likely-CP | 4G0907441B (rear cam, answers VCDS 6C) | yes (amp/cam 4G0907441) | .sgo | plain | yes | Camera/assist is a canonical CP class; enrolled. No module-specific TheftProte owner surfaced, not in Feb-2024 list → class-inferred. |
| 2E | Night Vision (J852) | likely-CP | 4G0907547 (db; not enumerated → not confirmed fitted) | yes | .frf | **AES + RSA** | **NO** (ciphertext only; plaintext unrecoverable w/o key) | IR-camera/assist CP class. **Most-secured ECU in the car** — only genuinely opaque part. Not in Feb-2024 list; CP class-inferred. Likely not physically fitted on this car. |
| 30 | Lane Assist (J769 SWA master) | likely-CP | 4G0907566D (running master; HW 4G0907568D; VCDS 3C) | yes (4G0907217 front cam; 4G0907566 LCA radar) | .frf / .sgo | plain / CRC-only | yes | Front-camera/assist CP class; enrolled. No module-specific 0x00BE owner, not in Feb-2024 list → class-inferred. |
| 46 | Central Convenience (J393) | likely-CP | 4H0907064CR (BCM2 2.0; same controller as addr 05) | yes (4G0907107 BCM family) | .frf | plain / CRC-only | yes | Convenience controller, CP-class; enrolled. Not individually confirmed → class-inferred. |
| 52 | Adaptive Headlight L (J745/AFS) | likely-CP | unknown — **no AFS fitted** (Headlamp Range w/o AFS); pair 4G0907159 | yes (4G0907159/160) | .frf | plain / CRC-only | yes | Adaptive-lighting CP class; slot enrolled in template but **not populated** (car has no curve headlights). Class-inferred; effectively likely present-not-CP here. |
| 53 | Adaptive Headlight R | likely-CP | unknown — **no AFS fitted**; pair 4G0907160(B) | yes (4G0907160) | .frf | plain / CRC-only | yes | Same as 0x52 (R side). Slot unpopulated on this car. Class-inferred. |
| 55 | Headlight Range Control L (J431) | likely-CP | 4H0907357B (running, LWR12, "Range w/o AFS") | yes (4G0907159) | .frf | plain / CRC-only | yes | Lighting/leveling; enrolled. No IKA owner confirmed, not in Feb-2024 list. Could be present-not-CP if a dumb leveling node. |
| 56 | Headlight Range Control R | likely-CP | 4G0035082H (**answers the radio/MMI 3G on this car**, not a R-range module) | yes (4G0907160 for the leveling part) | .frf | plain / CRC-only | yes | On this VIN VCDS 56 = "Radio U SIRIUS" MMI 3G, not a right-headlight node. Lighting-class label is template; class-inferred. |
| 84 | Headlight R (matrix/main) | likely-CP | unknown (no master/HD-Matrix module fitted on this non-AFS car) | unknown | — | unknown | unknown | Lighting CP class label; not populated on this car. Class-inferred. |
| 57 | TV Tuner | likely-CP | unknown (not enumerated; not confirmed installed) | unknown | — | unknown | unknown | Infotainment CP class; enrolled in template. No TheftProte owner, not in Feb-2024 list. Likely not fitted. Class-inferred. |
| 5F | Info Electronics 2 / Rear Display (J829) | likely-CP | 4G0035746D (running, H-BNT-NA; HW 4G0035746B) | yes (MMI 4G0919604 family) | .frf | plain / CRC-only | yes | Infotainment/display CP class; enrolled. Unlike MMI/Unit1, no IKA owner surfaced in DVR → class-inferred. |
| 48 | Sound System 3 | likely-CP | unknown (no separate addr-48 amp; Bose answers at 47) | yes (4G0907441) | .sgo | plain | yes | Same audio class as J525 (which IS confirmed CP); BV_SoundSysteUDS owns TheftProte+IKA. This second amp not individually cleared in Feb-2024 → likely. |
| 69 | Trailer (J345) | likely-CP | unknown (not enumerated; not confirmed installed) | unknown | — | unknown | unknown | Convenience controller; enrolled. No IKA owner, not in Feb-2024 list. Could be present-not-CP. |
| 6C | Rear Spoiler | likely-CP | 4G0907441B (**VCDS 6C answers the rear-view camera on this car**) | yes (4G0907441) | .sgo | plain | yes | Comfort actuator label; on this VIN 6C = rear cam, no dedicated spoiler controller enumerated. Class-inferred, low confidence. |
| 88 | Driver Assistance (SARA front sensor) | likely-CP | 4G0907637K (running, SARA 6D; HW 4G0907637F; VCDS 3B) | yes (4G0907637 DCU) | .frf | plain / CRC-only | yes | Driver-assist domain (CP class); enrolled. No module-specific IKA owner → class-inferred. |
| 8A | Driver Assistance 3 | likely-CP | 4G0907637K (same SARA family answers assist slots; db 4G0907637) | yes (4G0907637) | .frf | plain / CRC-only | yes | Assist domain CP class; class-inferred, not individually confirmed. |
| 8D | Pedestrian Protection | likely-CP | unknown (not enumerated; not confirmed installed) | unknown | — | unknown | unknown | Active-safety/assist actuator; enrolled. Not individually confirmed. If it behaves as a pyro/safety node it could be CP via the airbag path. |
| 05 | Access/Start Kessy (J518) | IMMO | 4H0907064CR | yes (BCM family) | .frf | plain | yes (but **excluded from CP work**) | **IMMO anchor, not CP.** Was the SOURCE of GEKO inputs (F190 VIN, F17C FAZIT, F191 HW=4H0907064CR, fob transponder) used to derive every module's IKA key. Flag separately. |
| 01 | Engine (J623, Simos8.5 3.0T) | IMMO | 4G0907551D (running; HW 4G0907551A) | n/a here (immo path) | — | — | — (excluded) | Immobilizer-bound (immo via J518/cluster), **not** comfort-CP/IKA. Not in Feb-2024 CP clear list. Exclude from CP parts. |
| 1B | Immobilizer 2 | IMMO | unknown (immo lives in J518 4H0907064CR; no separate module) | — | — | — | — (excluded) | IMMO by definition. Not a comfort-CP/IKA slot. Exclude. |
| 02 | Transmission (J217, TCU) | IMMO | 4G1927158A (HW 0BK927156AM) | — | — | — | — (excluded) | **Not enrolled** in constellation; immo-class (engine/trans immo), not CP. Notable non-enrolled immo module. Exclude. |
| 0E | Electronic Steering Lock (ELV) | IMMO | unknown (part of immo/steering-lock chain) | — | — | — | — (excluded) | IMMO. Part of the immobilizer chain, not comfort-CP. Not enrolled. Flag separately. |
| 03 | ABS / Brakes (J104, ESP9) | present-not-CP | 4G0907379H | yes (related) | .frf | plain / CRC-only | yes (but not CP) | Safety/chassis, merely in install list. ABS/ESP is immo/CP-neutral on VAG; not in Feb-2024 clear list; no 0x00BE owner. |
| 04 | Steering Angle Sensor (G85) | present-not-CP | unknown (integrated in ESP/steering; no standalone flashdaten) | unknown | — | — | — | Chassis sensor in install list only. No IKA, no U110100 ownership. |
| 10 | Parking Aid (J446) | present-not-CP | 4H0919475AA (running at VCDS 10) | unknown | — | — | — | **Not enrolled.** Convenience sensor without IKA/CP enrollment on this car. |
| 13 | Adaptive Cruise ACC (J428 radar) | present-not-CP | 4G0907561 (db; TP-Ident 0x0757) | yes (4G0907561/4G0907541) | .frf | plain / CRC-only | yes (but not CP) | **Not enrolled.** Radar/assist sensor; AU57X AdaptCruisContrUDS has no TheftProte/IKA owner. Not CP on this car. |
| 34 | Steering Assist (J500, EPS) | present-not-CP | 4G0909144L (running; db 4G0909144; TP-Ident 0x0755) | yes (4G0909144) | .frf | plain / CRC-only | yes (but not CP) | **Not enrolled.** EPS is chassis/steering, immo/CP-neutral; no IKA download. |
| 8B | Unknown 0x8B (enrolled, TP-Ident 0x0756) | **unknown** | unknown (no identity returned; slot-map marks Unknown) | unknown | — | unknown | unknown | Enrolled with direct ISO-TP CAN TX 0x0756. Identity unresolved (near steering-assist 0x0755 / ped-protect 0x0758). No CP/IKA evidence either way. Identify before classifying. |

---

## Summary

### 1. TRUE CP parts on this car

**8 confirmed true-CP modules** (each stores a 34-byte IKA key in UDS DID 0x00BE and sets DTC U110100 / VAG 7465 = DTC_15360256, CP-active params 0xEA61–0xEA64, when swapped). All 8 are corroborated by the **Feb-2024 ODIS CP-removal session on this VIN** (J533 "determine CP control modules" returned 12 CP slaves incl. master + belt tensioners J854/J855):

1. **HVAC / Climatronic — J255 — 4G0820043** (08) — enrolled + **live-confirmed** (DTC 0xEA62/0x09). The repair target.
2. **MMI / Info Electronics 1 — J794** (1E)
3. **Sound System 2 / Bose amp — J525** (47) — 4G0035223C
4. **Central Electronics / BCM — J519** (09)
5. **Airbag — J234 — 4G0959655A** (15)
6. **Passenger Seat memory — J521** (06) — enrolled now; not installed at Feb-2024 session
7. **Instrument Cluster — J285** (17) — session-confirmed; **currently not enrolled** (slot 'no')
8. **Driver Seat memory — J136 — 4H0959760A** (28) — gave the only unmasked IKA blob; **currently not enrolled**

> Plus the **belt tensioners J854/J855** appeared in the Feb-2024 CP-slave list but were not returned as discrete rows in the classification input, so they are noted here for completeness rather than tabled.

A further **16 modules are likely-CP** (CP-class + enrolled, but not individually proven by session or AU57X IKA owner): aux heater (18), rear camera (20), night vision (2E), lane assist (30), central convenience (46), adaptive HL L/R (52/53), headlight range L/R (55/56), headlight R (84), TV tuner (57), info2/rear display (5F), sound3 (48), trailer (69), rear spoiler (6C), driver-assist 88/8A, pedestrian protect (8D). Several lighting/infotainment slots (52/53/57/84) are almost certainly **template placeholders not physically fitted** on this non-AFS US car.

### 2. CP parts we HAVE flashdaten for: extractable (plain/keyless) vs locked (AES/RSA → bench)

**Confirmed-CP parts, by extractability of a *modified* image:**

| CP part | Flashdaten | Crypto | Reflash path |
|---|---|---|---|
| **MMI / J794** (4G0919604 family) | yes | plain + LZSS, **CRC-only** | **Soft** — UDS reflash tractable (recompute checksum) |
| **BCM / J519** (4G0907107) | yes | plain, **CRC-only** | **Soft** — UDS reflash tractable |
| **Sound2 / J525** (4G0907441 amp) | yes | plain `.sgo` | **Soft** — extractable/patchable |
| **Driver Seat / J136** (4G8959760) | yes | plain `.sgo` | **Soft** — extractable/patchable |
| **HVAC / J255** (4G0820043) | yes | **RSA-signed**, plain blocks | Readable + patchable, but **RSA blocks naive UDS reflash → bench/ISP or signature-bypass** (route already in memory) |
| **Cluster / J285** (4G0919158) | yes | **RSA-signed** | Readable; **RSA → bench** |
| **Airbag / J234** (4G0959655) | yes | **RSA-signed**, plain blocks | Readable; **RSA → bench** |

- **Plain / keyless / CRC-only (softest, modified-flash tractable):** MMI, BCM, Sound2 amp, Driver Seat — plus the likely-CP comfort/assist set (lane assist front cam 4G0907217, DCU 4G0907637, headlight controllers 4G0907159/160, etc.) which are all plain + CRC-only.
- **RSA-signed → bench/ISP (readable, but signature gates UDS reflash):** **HVAC (J255), Cluster (J285), Airbag (J234)** — the three confirmed-CP RSA parts.
- **AES-locked → opaque (bench + key, not extractable):** **Night Vision 4G0907547** (likely-CP) — the only genuinely non-extractable part: every block ECM=0A (AES, entropy 7.999) + SHA1-RSA1024 signed; container parses to ciphertext only.
- **Passenger Seat J521 (06):** confirmed-CP by class but its exact part was never enumerated → **flashdaten unknown** (likely a plain seat-family `.sgo` if 4G8959770-family, but unverified).

> No keyless-BCB (GEHEIM/CodeRobert) XOR blocks were hit in any C7 `.sgo` sample — all C7 `.sgo` decoded plain.

### 3. IMMO-not-CP (exclude from CP work) and merely present

**IMMO-only — exclude from CP parts (5):**
- Engine J623 (01) — 4G0907551D
- Transmission J217 TCU (02) — 4G1927158A — *also not enrolled*
- Kessy J518 (05) — 4H0907064CR — *the IMMO/GEKO anchor that derives the IKA keys; participates in the session but is not a CP slave*
- Immobilizer 2 (1B)
- Electronic Steering Lock / ELV (0E)

**Present-not-CP — in the install list but no IKA/CP enrollment (5):**
- ABS / Brakes J104 (03) — 4G0907379H
- Steering Angle Sensor G85 (04)
- Parking Aid J446 (10) — 4H0919475AA — *not enrolled*
- Adaptive Cruise ACC J428 (13) — 4G0907561 — *not enrolled*
- Steering Assist EPS J500 (34) — 4G0909144L — *not enrolled*

**Unknown (1):** slot **0x8B** (enrolled, CAN TX 0x0756) — identify before classifying.

---

### Key takeaways / honesty notes

- **J533 (gateway, 4G0907468AC, VCDS 19) is the CP MASTER** — it holds the install list / constellation and runs "determine CP control modules". It is **not a CP slave**. Its own flashdaten (4G0907468) is **in neither collection**; sibling-platform gateways are present but the C7 image is missing, so **C7 gateway crypto is empirically unverified** (treat as unknown — bench/BDM read or the enrollment-forge path in memory).
- **Only ONE part is firmware-verified end-to-end: HVAC J255 4G0820043** (2-zone, running 4G0820043AH). Everything else's CP status rests on the Feb-2024 session (confirmed) or VAG class inference (likely).
- **"likely-CP" means class-inferred, not proven** — promote to CP only with a per-module 0x00BE read or an observed U110100 on swap. Several likely-CP lighting/TV slots are probably unpopulated template entries on this car.
- **Two address spaces do not align** — constellation bytes (DID 0x2A2A) ≠ VCDS diagnostic addresses. Where the part column shows a module answering a different VCDS address (e.g., 56=radio, 6C=rear cam, 36=driver seat), that reflects what physically responded on this VIN, not the constellation label.