# VAG Module Flash Layouts — Audi C7 (4G) platform

A memory-map and flash-container reference for the **under-documented** modules on the
Audi C7 (A6/A7, 4G0) — the comfort, body, and gateway control units that the tuning
community routinely ignores in favour of the engine ECU and transmission TCU.

Everything here was derived from flashdaten (FRF/ODX) containers and from firmware read off
the researcher's own hardware. It is **layout/architecture** information — memory maps,
block structure, container format, integrity scheme. The CP key constants that go with these
layouts are collected in [`data/c7_module_db.json`](../data/c7_module_db.json) under
`cp_constants` and in [`flasher/hvac_flash.py`](../flasher/hvac_flash.py); the FRF decrypt key
is [`data/frf.key`](../data/frf.key).

---

## How a VAG flash container is laid out

A `.frf` is a **rolling-XOR-encrypted ZIP** (key: `data/frf.key`, algorithm courtesy of
bri3d/VW_Flash, GPL-3.0) that contains an **ODX** XML file. The ODX holds:

- **`FLASHDATA`** elements — the block binaries (hex-encoded; `ENCRYPT-COMPRESS-METHOD`
  `00`=plain, `01`=XOR+LZSS, `0A`=AES).
- **`DATABLOCK`** elements — each `TYPE=DATA` (a flashed region), `TYPE=ERASE` (an erase
  command), or `TYPE=BOOT`. Each DATA block carries a `SEGMENT` whose `SOURCE-START-ADDRESS`
  is, for most V850/TriCore comfort modules, a **block index** (1, 2, 3…) — *not* a memory
  address. (A few modules — MMI, EPS — use real load addresses there instead.)
- **`SECURITY`** — the SA2 seed/key script and a per-block signature (`SIG_SHA1-RSA1024_S`
  on signed modules).

### The boot-block rule (why most of these omit the bootloader)

A flash container ships **only the regions a separate resident eraser can reprogram in the
field** — and usually *not* the factory bootloader. The reason is the chicken-and-egg of
self-reflash: a module that runs its reprogramming routine *from* its boot block cannot erase
the sector it is executing from. So:

| Module class | Ships boot? | Why |
|---|---|---|
| **Engine ECU** (Simos `4G0907551`) | **Yes** — block 1 = 81,408-B PBL | A tiny resident ROM/SBL (never field-flashed) erases+rewrites the PBL from outside it. |
| **Gateway** (J533 `4G0907468`) | **Yes** — block 3 = 64 KB vector/boot | Same split-bootloader design. |
| **Small comfort modules** (HVAC `4G0820043`) | **No** — app + aux + erase only | Reprograms from its own boot block → factory-resident, written once at end-of-line. |

This is why the HVAC's CP handshake crypto constants (below) can only be read on a bench — they
live in a boot block that **no shipped container contains**.

---

## J255 — Climatronic HVAC (`4G0820043`)

- **MCU:** Renesas/NEC **V850ES/Jx3 µPD70F3634** (LQFP144), ~1 MB internal code flash + a
  separate data-flash NV store, RAM @ `0xFFFFxxxx`.
- **Supplier:** Continental. **Diag address:** `0x08` (Air Conditioning). **SA2:** `93270319464C`.
- **Container:** plain (`00`); `DATABLOCK` types DATA + ERASE, **no BOOT**. Per-block
  `SIG_SHA1-RSA1024` present (tester-side; FBL secure-boot enforcement unconfirmed).
- **Integrity:** a **CRC-16/XMODEM** word at the end of block 1 (bootloader-checked, recomputable).

| Region | Link range | Size | Contents | In FRF? |
|---|---|---|---|---|
| Boot block 0 | `0x00000–0x10000` | 64 KB | reset vectors, FBL, **CP handshake AES tables @ `0xd5b0/d6b0/d7b0`** | **No** (factory-resident) |
| App block (idx 1) | `0x10000–…` | 741,376 B (2-zone) / 1,003,520 B (4-zone) | application; its **own** AES tables @ `0x125b0` | Yes |
| Aux block (idx 3) | — | 2,048 B | small application/patch block | Yes |
| Data-flash | separate | — | per-module CP / SHE key rows (NV) | No |

> **Two AES table sets — don't conflate them.** The application has a standard AES at link
> `0x125b0` (shipped, in block 1). The CP *handshake* uses a **different** table set at `0xd5b0`
> in the un-shipped boot block. Grepping an FRF for `63 7c 77 7b` hits `0x125b0`, not the boot tables.

- **SW history:** 24 builds (`0056`–`0810`) across `LO`/`HI`/`H`/`L`/`R` suffixes; two image
  classes (741,376-B = 2-zone, 1,003,520-B = 4-zone). All ship app+aux+erase, none ship boot.
- **CP enforcement:** **local** to the module (limps to defrost-only when CP is unsatisfied). The
  limp-bypass patch and its SW-portable signature locator are in `flasher/hvac_flash.py`.

---

## J533 — Central gateway (`4G0907468`)

- **MCU:** Renesas/NEC **V850ES D70F3433** (V850 vector table at `0x0`). **Supplier:** LEAR.
- **Diag address:** `0x19`. **Parts:** `4G0907468AA`, `4G1907468`; **shares the
  "LEAR D4 Gateway." codebase** with the D4 (A8) `4H0907468AA`.
- **Container:** plain; the gateway **does** ship its boot/vector region.

| Region | Link range | Size | Contents | In FRF? |
|---|---|---|---|---|
| Vector/boot (idx 3) | `0x00000–0x10000` | 64 KB | V850 vector table (`DEFE`-padded), boot | Yes |
| App block (idx 1) | `0x10000–…` | 983,040 B | main application; **AES-128 tables @ file `0x17FE4`** (runtime `0x27FE4`) | Yes |

- **CP role:** this is the **CP master**. It holds the 32-entry **install-list** and the
  **constellation bitmap** (DID `0x04A3`). The enrollment layer is a standard AES-128 ECB
  known-answer test over a *fixed public sentinel* keyed by the fixed ASCII string
  `LEAR D4 Gateway.` — it carries **no per-vehicle secret** and is forgeable offline. The
  per-module **IKA credential** is a separate, per-vehicle layer. Exact constants:
  `data/c7_module_db.json → cp_constants.gateway_j533`.

---

## C7 module family — flash layout at a glance

Representative block structures (one SW level per part; full per-module data in
`data/c7_module_db.json`). `idx:size` = ODX block index → uncompressed bytes.

| Part | Module | Arch / supplier | Blocks (idx:bytes) | Signed | Ships boot |
|---|---|---|---|---|---|
| `4G0820043` | **Climatronic HVAC (J255)** | V850ES / Continental | `1:741376  3:2048` | rsa | no |
| `4G0907468` | **Central gateway (J533)** | V850ES / LEAR | `1:983040  3:65536` | ? | yes |
| `4G0907107` | **Body control / Bordnetz (J519)** | ? / TRW | `1:851968  2:7340032  30:erase` | crc | no |
| `4G0919158` | Instrument/display controller | ? / Continental | `1:348160  3:2048` | rsa | no |
| `4G0907547` | **Night Vision** (IR camera) | ? | `2:393216  4:2510112  5:131248 …` | rsa + **AES-encrypted** | — |
| `4G0919604` | MMI / central display | ARM / VDO | addressed (`0xC0000000` …) + LZSS | rsa | — |
| `4G0907551` | Engine ECU 3.0T (Simos8.5) | TriCore / Continental | `1:81408(PBL)  2:1572352(ASW)  3:261632(CAL)` | crc | **yes** |
| `4G0906014` | Engine ECU 3.0 TDI (EDC17) | TriCore / Bosch | `1:42318  2:785285  3:583165  4:146664  5:514607  6:272129` | crc | — |
| `4G0927158` | TCU DQ381 (J217) | ? / VDO | `1:~880K  2:1108  3:96508  4:~125K` | crc | — |
| `4G0927153` | TCU mechatronic | ? / Continental | `1:~870K  2:~130K  3:32768  4:131072` | crc | — |
| `4G0909144` | Electric power steering (J500) | ? | addressed sections (`50:~550K` …) | crc | — |
| `4G0907379` | ABS/ESP (Bosch ESP9) | TriCore / Bosch | `10:1998848  + many small  255:erase` | crc | — |
| `4G0959655` | Airbag (J234) | ? | `1:479232  3:2048  4:48 …` | rsa | — |

Patterns worth noting: the **Continental comfort modules** (HVAC, cluster `919158`) share the
same `1:app 3:2KB-aux` two-block shape, RSA signature, and SA2 `93270319464C`. **Night Vision
`907547` is the only AES-encrypted + RSA-signed module** — the most-locked unit in the car. The
**Simos engine ECU is the clearest "ships its bootloader" case** (block 1 = PBL).

---

## Wanted / template — modules not yet mapped

We do **not** hold firmware for **BCM2 `4H0907064`** (A8 D4 onboard-supply control unit). Its
nearest C7 analog that *is* mapped is the **body control / Bordnetz `4G0907107` (J519)** above.
To add a module, fill this template (one row in `data/c7_module_db.json` + a section here):

```jsonc
{"part":"<part>","name":"<module>","arch":"<core>","supplier":"<oem>",
 "format":"plain|xor_lzss|aes","signed":"crc|rsa","sa2":"<seed/key script>",
 "vag_addr":"<hex>","can_req":"0x7??","blocks":{"1":<bytes>,...},"notes":"<...>"}
```

Needed: MCU/core, app link base, block table, container format, integrity (CRC vs RSA),
SA2 script, and whether the boot block ships.

---

*Part of Simos-Suite (see repository `LICENSE`). Derived from firmware and flashdaten the
researcher possesses, on the researcher's own vehicle. This document is flash **layout** — the
CP-bypass specifics live with the tooling (`flasher/`, `data/c7_module_db.json → cp_constants`).*
