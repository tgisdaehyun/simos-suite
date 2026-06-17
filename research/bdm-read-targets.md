# HVAC J255 bench BDM read — target list

**Goal:** one in‑and‑out BDM/N‑Wire read of the 2‑zone Climatronic MCU that yields the two
remaining inputs `hvac_ika_cipher.py` needs, so the IKA forge becomes exact and re‑pair is
computable offline. After this read, no further bench work is needed for the CP math (the
heater limp‑patch is a *separate*, already‑derived flash‑write, deliverable in the same session).

## MCU + access
- **MCU:** Renesas/NEC **µPD70F3634** (V850ES/Jx3, LQFP144). Internal **1 MB code flash** +
  **separate data‑flash** (the NV key store) + RAM at `0xFFFFxxxx`.
- **Tool:** N‑Wire / BDM **read** (not the elm‑chan ISP rig — that path is write‑only).
  Use the gold programming pads on the 2-zone board.
- **Do a full‑device read** (code flash `0x00000–0xFFFFF` + the entire data‑flash region).
  Dumping everything is safest — it guarantees we don't miss an address, and analysis is
  done offline. Save as two files: `hvac_codeflash.bin`, `hvac_dataflash.bin`.

## What the model actually needs from the dump

### 1. Block‑0 cipher tables  (code flash, addresses < 0x10000)
The handshake stream cipher (`FUN_0006e6e0`) and the AES‑like step (`FUN_0006e7d8`) index
tables that live **below** the block‑1 base `0x10000` → in block 0, which we never dumped.
Confirmed program addresses (file offset == program address for block 0):

> **VERIFIED (workflow `wfg27nqjo`, 2026‑06‑16): block 0 is NOT in the FRF.** The
> `FL_4G0820043LO_0113_S.frf` ships only block 1 (application @ base `0x10000`, 741376 B) +
> a 2 KB aux block (index 3, plain app code — *not* the `0xd000` crypto page; tested) + an
> ERASE command. The bench block‑0 read is the **only** source for these tables.
> **TRAP:** the app block *does* contain a standard AES S‑box at file `0x25b0` (= link
> `0x125b0`) — that is the application's OWN AES, a DIFFERENT table set from the CP/handshake
> tables at `0xd5b0`. Grepping the FRF for `63 7c 77 7b` hits `0x125b0`, NOT the boot tables.

| Program addr | Size | Expected (model assumption) |
|---|---|---|
| `0xd5b0` | 256 B | AES forward S‑box (`63 7c 77 7b …`) |
| `0xd6b0` | 256 B | AES inverse S‑box (`52 09 6a d5 …`) |
| `0xd7b0` | 256 B | xtime / GF(2⁸)·2 (`00 02 04 06 …`) |

**The single most important check:** do these match the standard AES tables (which the model
assumed)? `cp_tools/ingest_bdm_dump.py` does it automatically. **Match → the model was right all
along and the handshake is plain AES. Differ → the handshake uses a custom S‑box and the dump
hands us the real one** (the model then uses the dumped table verbatim — still solved, just
needed the bytes).

### 2. Persisted CP key rows  (data‑flash)
`FUN_0005c466` loads AES slots 0–3 from NV via `FUN_0006af34`; these are the per‑module
**SHE key rows**. Each is **16 bytes**:

| Slot | Key |
|---|---|
| 0 | **IKA** — the installation key (the re‑key handshake input; the value the verify compares against) |
| 1/2 | GKA / aux |
| 3 | (counters/version near the rows) |

The **current IKA (slot 0)** is the key for *both* stream+AES passes of the two‑pass
key‑confirm (FUN_00075624: pass 1 → GKA/row 100, pass 2 → IKA/row 0) — the value
OBD cannot read (`2200BE → 7F2231` even SA2‑unlocked, confirmed). It IS in the data‑flash.

### 3. The Component Security (CS) seed
The stream cipher round (`FUN_0006e6e0`) seeds its 4‑byte rolling state from `gp‑0x7f31..34`,
which trace to the immobilizer CS context. The CS (the value the key fob carries via Kessy)
is the per‑vehicle anchor; it is in the engine‑ECU / Kessy immo store, and may also be
mirrored in the HVAC data‑flash. `cp_tools/ingest_bdm_dump.py` searches the data‑flash for it and
accepts a `--cs <hex>` override if you pull it from the engine ECU instead.

## Not needed from the dump (the model computes these)
- AES slots 5/6/7 (`tp‑0x7d00/‑0x7cf0/‑0x7ce0`) — RAM challenge buffers, derived live.
- The verify AES itself — standard AES, already in hand (FIPS‑197 verified).

## After the read
```
py -3 cp_tools/ingest_bdm_dump.py --codeflash hvac_codeflash.bin --dataflash hvac_dataflash.bin [--cs <hex>]
```
It confirms/loads the cipher tables, locates the IKA + CS, splices them into the model, and
runs `validate()` against the known 2024 seat blob — printing the byte‑for‑byte result that
ends the question.
