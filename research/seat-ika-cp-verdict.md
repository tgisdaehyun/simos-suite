# Seat IKA-Lifecycle Verdict: Can CP Be Introduced + Handled Locally?

## TL;DR

**VERDICT (b → leaning a): NEEDS ONE BENCH READ, THEN LOCAL-WRITE IS VIABLE.** The seat is provably **not** GeKo/asymmetric-locked. Both the write path and the verify key live entirely on-module (data-flash, owner-writable, no SecurityAccess), so there is **no server in the loop and no firmware patch required**. The single remaining gate is the same one the HVAC left open — *whether the verify challenge is derived from the owner-accessible immobilizer CS or is an external nonce* — and unlike the HVAC, the seat traces now make that gate **resolvable with one bench data-flash dump** rather than a live server capture.

---

## 1. The Full IKA Lifecycle

| Phase | Mechanism | Evidence |
|---|---|---|
| **Introduce** | UDS service **`0x3B` (WriteDataByLocalIdentifier), LID `0xBE`**, 34-byte blob. *Not* `0x2E` — DID `0x00BE` is absent from the `0x2E` DID table (`tp-0x7bcc`), which returns `0x31`. The `0xBE` LID is also absent from the `0x3B` table (`tp-0x7dc2`) and falls through to a **hardcoded `movhi+movea` branch** (`*param_1 == -0x42`) routing to `FUN_000367ba` (TrainICA). | `FUN_0000c8ba` line 810-813; WRITE trace |
| **Store** | TrainICA (`FUN_000367ba`) runs the 2-pass stream+AES handshake (`FUN_00035eba`, len ≥ 0x21), then **enqueues the store unconditionally** — the commit is *not* gated on any compare. Persisted to **data-flash KV rows IDs `0x11`–`0x15`** (redundant primary/backup) via `FUN_00034282 → FUN_00019eac`. | `FUN_00036b42` compare SKIPPED when `gp-0x7e30==4`; `FUN_0003670a → FUN_00036534` |
| **Verify** | Separate **runtime** FSM `FUN_00036cda`: AES the live challenge, then case 7 = 16-byte memcmp of AES result (`gp-0x509c`) vs stored expected (`*gp-0x506c`); `FUN_0003729c(0, equal)` sets the **CP-limp status byte** (`gp-0x5048`). It is the **consumer** of the stored IKA, *not* part of the write-accept path. Fail → `0xEA62 / U110100` (identical to HVAC). | VERIFY + CS-SOURCE traces |

**Key architectural finding:** the seat is a **STORE-then-status** module, not a verify-before-accept gate. Writing the blob and *making verify pass* are two independent problems. The write is trivially reachable; correctness of the blob is the whole game.

---

## 2. The Credential Equation

```
verify_pass  ⇔  stored_block0  ==  AES-128( challenge , K )
```

| Term | Source | Owner-accessible? |
|---|---|---|
| **K** (AES key) | Two conflicting reads — see below | n/a (on-module either way) |
| **challenge** | Received **over the bus**, byte-reversed in by `FUN_00035eba` from the inbound `0x00BE/0x00BD` frame; for slot7 it is field `0x65`. Origin = CP master (gateway/immobilizer). | **UNKNOWN** — the decisive gate |
| **stored_block0 ("expected")** | **Per-vehicle**, data-flash rows `0x11`–`0x15`. Real value `E62B41D1…274B0AC2`. **Absent from the 364 KB code image** → confirmed NVM content, not firmware-resident. | Yes — writable via the module's own `0x3B/0xBE` path |

### The one disagreement across the three traces — what is K?

- **VERIFY trace:** K is one of **three module-FIXED flash constants** (`K5/K6/K7` immediately before the S-box: `16f45463…`, `c93e58a1…`, `2d508ab8…`), identical across same-SW modules. Exhaustive sweep showed `block0 ≠ AES/DEC(block1)` under any of them → expected is an *independent* per-vehicle ciphertext.
- **CS-SOURCE trace:** K is the **IKA blob itself** — block1 → `gp-0x5180` (slot `0x66`) is loaded as the AES key from data-flash; the three fixed constants are only the **rw==0 "no row present" factory-default/KAT seed path**, not the live key.

**Reconciliation:** these are consistent if there are *two* AES uses — the fixed `K5/K6/K7` drive the slot5→6→7 transform of the incoming challenge, while the per-vehicle block1 keys a separate transform binding the two halves. Either way the conclusion is the same: **no per-vehicle secret is baked in flash, and nothing is server-held.** The per-vehicle material is entirely in owner-writable data-flash. This sharpens, rather than weakens, the verdict.

---

## 3. THE VERDICT

### (b) NEEDS A SECRET WE LACK — but it is a **bench read, not a server** — and that collapses toward (a).

**Why not (c) GeKo/asymmetric-locked:** Definitively ruled out. There is no RSA/ECC, no signature check, no online challenge-response to a server. The full string scan of `DriverSeat_J136_4H0959760.bin` found no LEAR/IKA/GVA/Train strings and no server key. The verify is a symmetric AES known-answer test whose every term is either on-module-fixed or in writable local NVM.

**Why not yet (a) LOCAL-WRITE VIABLE today:** To make `FUN_00036cda` report no-limp you must store the *correct* per-vehicle `block0` for the challenge the gateway presents at runtime. That requires knowing the **challenge → IKA derivation**, i.e. answering: *is `challenge = f(CS)` where CS is the Kessy/fob immobilizer secret, or is it an external nonce?*

**What's needed to close it (one bench session, no server):**
1. **Dump data-flash `0x03FF9000`** (the live 36-byte CP record, rows `0x11`–`0x15`) off the bench. This pins the byte layout of block0/block1/tail and gives a real `(key, expected)` pair.
2. **Capture one live `0x00BE` + `0x27` handshake** and record the challenge bytes; check correlation against the known CS.
3. **Replay** the captured `(challenge, expected)` through the already-built, FIPS-197-validated AES tool with the extracted keys to confirm which key/chain is operative (single AES vs slot5→6 cascade).

If step 2 shows `challenge = f(CS)`: **fully (a)** — compute `block0 = AES(f(CS), K)` offline from the Kessy-readable CS and write it via `0x3B/0xBE`/TrainICA. **No firmware patch, no GeKo, no SecurityAccess** (the `0xBE` branch checks only `(1<<session)&5` — accepted in default session 0).

If step 2 shows an external nonce: **firmly (b)** — the *challenge* is server/gateway-issued and you cannot precompute the expected ciphertext; you'd fall back to a firmware status-patch (the `FUN_0003729c` limp branch), which violates the no-patch constraint.

**Confidence:** High that it is *not* GeKo-locked. High that the write path is open without SA. Medium on the final CS-derivation gate — three independent static traces all point at CS-seeding (HVAC 2-pass model) but none is bit-exact without the data-flash read.

---

## 4. Does the Seat Answer the HVAC's Open "IKA == f(CS)?" Question?

**Partially — it makes the question cheaper to answer, and it removes two of the HVAC's confounders, but it does not yet prove `f`.**

- **Structural confirmation:** the seat is **byte-for-byte the same shape** as HVAC J255 — symmetric AES KAT, per-vehicle expected ciphertext in data-flash, identical `U110100` limp DTC, same 2-pass stream+AES handshake. This strongly corroborates the HVAC model rather than treating it as a one-off.
- **What the seat *settles* for the HVAC:**
  - **No server secret exists.** The HVAC's lingering "maybe there's a per-vehicle key only the server knows" fear is killed — the seat proves the per-vehicle material is local NVM, recomputable in principle.
  - **The erase/interlock differs:** the HVAC had a CP-record erase interlock (`FUN_00056414`); the seat's TrainICA **stores unconditionally with no SA and no erase gate**. So the seat write path is *more* open than the HVAC's. (Open Q3: confirm J136 has no equivalent interlock before assuming the path is clean.)
- **What it does *not* settle:** the exact `f(CS) → IKA` bytes. That is *the same single unknown* on both modules. The seat doesn't independently prove `f`, but because its write path is unguarded and its NVM is dumpable, **the seat is the better/cheaper module to run the decisive CS-correlation experiment on.** Resolve it on the seat and the HVAC answer almost certainly follows.

---

## 5. The Bus-Emulation Experiment (CerberusCAN)

**Idea:** emulate a *fresh/virgin* seat (and/or HVAC) on the bus and watch what the gateway does.

**What it would reveal — the central CP-architecture question: does the gateway actively challenge modules, or do modules only self-police?**

| Observation on the bus | Conclusion |
|---|---|
| Gateway/immobilizer **sends an unsolicited `0x00BE` challenge** to the emulated module after wake | CP is **gateway-driven**; challenge origin is external → the `challenge = f(CS)?` question becomes "what does the gateway put on the wire," directly capturable. If those bytes track the CS → **verdict (a) for the whole fleet.** |
| Emulated module sees **no challenge**, yet a real module still limps when mispaired | CP is **module-self-policed**; the module generates/expects its own challenge internally → `f(CS)` lives entirely on-module and the bench dump is the only path. |
| Gateway issues `0x27` SecurityAccess or session change before any `0xBE` | Tells you the exact framing/preamble needed (WRITE open-Q2) to reach TrainICA in a real attack. |

**This single experiment resolves three open questions at once:**
1. **`challenge = f(CS)?`** — by capturing the actual challenge bytes the gateway emits and correlating to the Kessy CS.
2. **Gateway-challenges-vs-self-polices** — the architectural unknown carried since the J533/gateway work (memory: *"gateway is not the CP lock," "who verifies"*).
3. **The J525-amp "who verifies" open question** — the amp shares the same `0x400000` NVM + KAT shape; whatever the bus shows for seat/HVAC generalizes to the amp's verifier ownership. Emulating one module type and watching the gateway's solicitation pattern tells you, for *all three* modules, whether the verifier is upstream (gateway) or local.

**Caveats / what to watch:** CerberusCAN must sit on the **Diagnosis-CAN 500 k (Head 1)** segment where these modules live (per the SSP 971603 bus model), and the comfort-CAN physical layer is still **disputed (measure before TJA1055)**. The HVAC programming path doesn't need the comfort tap, but the *solicitation* you're hunting for may appear on either segment — instrument both. Emulating a *virgin* module (no stored IKA) is the cleanest probe because it forces the gateway to either initiate pairing (gateway-driven) or do nothing (self-policed).

---

## What Remains Unknown (honest confidence)

1. **DECISIVE:** `challenge = f(CS)` vs external nonce. *Everything* hinges on this. Three static traces lean CS-seeded; none is bit-exact. **(Resolve: bench dump `0x03FF9000` + one live handshake, or the bus-emulation experiment above.)** — confidence MEDIUM.
2. **Which key is operative** (`K5/K6/K7` vs per-vehicle block1) and single-AES vs cascade — VERIFY and CS-SOURCE traces disagree on the role of the fixed constants. Resolvable by replaying one real `(challenge, expected)` pair. — confidence MEDIUM.
3. **Erase/write interlock:** confirm J136 has no CP-record erase gate (HVAC had `FUN_00056414`) before assuming TrainICA write is unconditional in practice, and confirm persistence across power-cycle (NVM block ID for the IKA row not yet isolated). — confidence MEDIUM-HIGH (code strongly implies open + persistent).
4. **UDS framing** to physically reach `0x3B/0xBE` (functional vs physical addressing, TesterPresent/session preamble, upstream router pre-checks in `FUN_00032xxx`). — confidence MEDIUM.
5. **The 2-byte tail `0x2600`** and the second challenge lane (field `0x65` → slot7): version/counter or keying material? — UNKNOWN, low impact.

**Bottom line:** This is **not** a GeKo problem and **not** a firmware-patch problem. It is a **one-bench-read problem.** Dump the seat's data-flash CP record and capture a single live handshake — that one session converts the verdict from (b) to a definitive (a) or rules CS-seeding out, and the answer carries over to both the HVAC and the J525 amp.