# BIN → FRF / ODX / SGO Packing — Spec, Tools, and Reality

Reverse of the VAG flashdaten decode pipelines: turn a (tuned/patched) raw `.bin`
back into a factory container (`.frf` / `.odx` / `.sgo`) that a diagnostic flasher
(ODIS-E, VAG CAN PRO, AVDI) can write — the open equivalent of AARK Kommander's
"VAG BIN → FRF/ODX/SGO" feature.

Everything here was validated empirically against the real Audi A6 C7 (`4G0`)
flashdaten corpus. Claims are tagged **PROVEN** (a round-trip reproduced the
stated result) or **PLAUSIBLE** (reasoned, not exercised end-to-end). Owner's-own
vehicle, right-to-repair.

---

## 1. Executive summary

- **The containers are solved.** SGO repacks **byte-for-byte identical** (69/69 real
  files). FRF repacks **functionally** (auto CRC32 recompute; a real block edit
  survives a full pack→re-extract cycle) — the only non-determinism is VAG's DEFLATE
  encoder, which is **cosmetic** (the ECU validates the *decompressed* ODX/blocks,
  which are bit-identical).
- **The payload codecs are mapped.** What transform a tuned BIN needs before it goes
  into the container is selected by the ODX `ENCRYPT-COMPRESS-METHOD` (DFI) byte:
  RAW (`0x00`), Simos counter-XOR (`0x01`), or Bosch LZSS+AES (`0xAA`).
- **The real wall is cryptographic signatures, not containers.** A module either
  checks a **recomputable checksum** (CRC32 / ECM3) — repackable and flashable — or a
  **non-recomputable signature** (RSA) / **AES-encrypted body with an unknown key** —
  repackable structurally but rejected at flash time.
- **ODIS-E's "flash a wrong FRF" is NOT a signature bypass.** It relaxes only
  *tester-side* plausibility/version checks (the `ODS05100` "older version" refusal).
  *Module-side* RSA/AES integrity is untouched. This is the single most-misunderstood
  point online.
- **For this car:** the cluster, plain gateway SGO, and Simos CAL are
  self-flashable (checksum-only). The **HVAC `4G0820043` (RSA-1024)** and
  **BCM2/DSG (AES)** are walls — exactly the modules whose CP fix stays a bench job.

---

## 2. The three containers + proven pack pipelines

### 2.1 FRF = rolling-XOR( ZIP{ one `.odx` } )

The cipher (`flasher/frf_loader._decrypt_frf`) is a rolling XOR whose keystream
derives from **key + position only, never the data** — so it is **self-inverse**:
`_decrypt_frf(KEY, _decrypt_frf(KEY, x)) == x` (PROVEN). The packer "encrypts" by
calling the same function — no separate encrypt routine.

Pipeline — `flasher/frf_pack.frf_pack(blocks, template_odx, frf_key, odx_name)`:
1. start from a template ODX (`FrfLoader.get_odx(orig)`);
2. map `block_number → FLASHDATA-ID / DATABLOCK` via `SOURCE-START-ADDRESS` +
   `FLASHDATA-REF`;
3. replace each edited block's `<DATA>` hex (formatting preserved);
4. recompute the per-DATABLOCK `CRC32` `FW-CHECKSUM` (`VALIDITY-FOR == DB_n`);
5. re-serialize → ZIP (single `.odx` entry, **non-seekable sink** → the VAG
   streaming profile: data-descriptor flag, DOS attrs) → `_decrypt_frf`.

**PROVEN:** `extract_blocks(frf_pack(orig)) == orig` for the HVAC and cluster FRFs;
a 4-byte cluster-block edit re-extracted correctly with its CRC32 auto-updated
(`353DECA0`). **Functional, not byte-exact:** VAG's DEFLATE body isn't reproduced
by any stock zlib (level × memLevel × strategy) — but it decompresses to a
bit-identical ODX (cosmetic; the ECU never sees the compressed bytes).

### 2.2 ODX 2.0.1 FLASH schema (inside the ZIP)

`FLASH > ECU-MEMS > ECU-MEM > MEM > SESSIONS > SESSION > {SECURITYS, DATABLOCKS, FLASHDATAS}`.
- **FLASHDATA** (`INTERN-FLASHDATA`): ordered children `SHORT-NAME`, `LONG-NAME`,
  `<DATAFORMAT SELECTION="BINARY"/>`, `<ENCRYPT-COMPRESS-METHOD>XX</…>` (the **DFI
  byte**, a child element), `<DATA>UPPERCASEHEX</DATA>`.
- **DATABLOCK**: `SHORT-NAME` (`DB_n`), `FLASHDATA-REF`, `SEGMENTS/SEGMENT` with
  `SOURCE-START-ADDRESS` (the decimal block number `FrfLoader` keys on),
  `UNCOMPRESSED-SIZE`, and (Bosch only) `COMPRESSED-SIZE`.
- **SECURITY**: `SA2` (UDS seed/key — content-independent), `CRC32`
  (`zlib.crc32` of the block — **recomputable**), or `SIG_SHA1-RSA1024_S`
  (RSA-1024 over SHA-1(block) — **not recomputable**). A module is *either*
  CRC32-protected *or* RSA-signed.

### 2.3 SGO ("SGML Object File")

`cp_tools/sgo_pack` — full byte layout in its module docstring (magic, header word
table, `IDENT` (0xFF-XOR'd part number/SW), SA2 section, per-block 25-byte
big-endian descriptor, trailing block-offset table). **Container checksum @0x15**
(u32 LE): zero the field, `S = sum(file) & 0xFFFFFFFF`, store `(S-1) & 0xFFFFFFFF`.
`repack(src) == src` **byte-exact on 69/69** files (PROVEN).

---

## 3. The payload-codec matrix

Selected by the per-FLASHDATA DFI byte; `flasher/payload_codec` auto-detects,
decodes, and re-encodes. Decode oracle = recomputed VW-CRC32 == the stored
block-checksum header.

| DFI | Codec | BIN→stored transform | Module families | Round-trip |
|----|-------|----------------------|-----------------|-----------|
| `0x00` | **RAW** | identity | HVAC `4G0820043` (V850), cluster `4G0909144` (NEC), LEAR gateway `4G/4H0907566` FRF | **BYTE-EXACT** |
| `0x01` | **Simos-XOR** | `out[i]=in[i]^(i&0xFF)` (self-inverse, no compression) | Bosch Simos8.5 engine `4G0907551` | **BYTE-EXACT** |
| `0xAA` | **Bosch LZSS+AES** | `AES-128-CBC( VW-LZSS(bin) )` | Bosch Simos18.x (`5G0906259`=18.1, …) | **FUNCTIONAL** (decompressed image identical; compressed stream differs) |
| SGO `0x00` | **SGO PLAIN** | `XOR-0xFF(payload)` | LEAR gateway `4G0907566` SGO | **BYTE-EXACT** |
| SGO `0x01/0x0B` | **SGO AES** | `XOR-0xFF(AES-CBC)` | BCM2 `8K0907064`/`4H0907064`, DSG `v069…` | wall (key unknown) |

**Checksums to recompute when a BIN changes:** internal **VW-CRC32** (poly
`0x4C11DB7`, init 0, no final-xor; `flasher/checksum_simos`) always; **ECM3** 64-bit
summation on Bosch CAL; plus the ODX-layer `CRC32 FW-CHECKSUM` (handled by
`frf_pack`). Signatures (RSA) and AES bodies are **not** recomputable.

> **Bugfix shipped alongside this work:** the previous `flasher/lzss_compress.py`
> used an inverted flag convention + wrong offset/length split + window init `0x00`;
> it round-tripped with itself but produced ~10× oversized garbage on real VW data —
> meaning `uds_flash` would have compressed Simos blocks into a format the ECU can't
> decode. It is now a faithful VW_Flash port (verified: real Simos18.1 CBOOT/ASW1/CAL
> decode to a matching VW-CRC32). `read_block` now truncates the LZSS over-run to the
> block's `UNCOMPRESSED-SIZE`.

---

## 4. Module-side acceptance & existing tooling (web-grounded)

> Forum sources (mhhauto, digital-kaos) are login-gated; their content is
> snippet-level, attributed as forum-sourced.

- **AARK Kommander** (closed-source) does bidirectional BIN⇄FRF/ODX/SGO across DSG,
  Simos12/16/18, and Bosch MDG1/MD1/MED9. It **auto-recomputes checksums** but
  **cannot forge signatures**: for signed ("TPROT") controllers it states the unit
  "must be **unlocked** before flashing a mod" — i.e. it pushes the signature wall
  onto a prior bench step, exactly as our RE concludes
  ([mhhauto AARK thread](https://mhhauto.com/Thread-AARK-Kommander-DTC-EDITOR-VAG-IMMO-FIRMWARE-CONVERT-MERC-SEED-KEY?page=21)).
- **ODIS-E** flashing a wrong/old FRF relaxes only **tester-side** plausibility — an
  admin "disable software version check" toggle defeats the `ODS05100` rollback
  refusal ([mhhauto](https://mhhauto.com/Thread-odis-E-flashing-older-and-other-sw-versions),
  [digital-kaos](https://www.digital-kaos.co.uk/forums/showthread.php/566834)). It does
  **not** bypass module-side RSA/AES — "if flash is one byte wrong your ECU will have
  an error for sure." **This is the key correction:** ODIS-E ≠ signature bypass.
- **bri3d/VW_Flash** (open, the authoritative public RE) flashes blocks **directly
  over UDS** — it does **not** emit a `.frf` (consume-only). `simos_flash_utils.prepare_blocks`
  = checksum → LZSS → encrypt; CBOOT "checks a CRC32 checksum **and** an RSA
  signature." `flash_cal` needs **no** unlock (CAL is checksum-gated); ASW/boot are
  RSA-gated, bypassable only via the bench SBOOT/CBOOT "Sample Mode" in-RAM patch
  (Simos18.1/6/10) ([VW_Flash docs.md](https://github.com/bri3d/VW_Flash/blob/master/docs/docs.md)).

### Acceptance matrix (Audi C7 owner, self-repacked image)

| Module class | Container | Integrity gate | Self-repack flashes? |
|---|---|---|---|
| Instrument cluster `4G0909144` | FRF, RAW | CRC32 + SA2 | **Yes** (checksum-only) |
| Simos8.5 engine `4G0907551` (CAL) | FRF, Simos-XOR | CRC32 (+ECM3) + SA2 | **Yes** for CAL edits |
| Simos18 **CAL** | FRF, LZSS+AES | CRC32 + ECM3 | **Yes** — `flash_cal`, no unlock |
| Simos18 **ASW/CBOOT** | FRF, LZSS+AES | CRC32 **+ RSA** | **No** unless bench-unlocked |
| LEAR gateway `4G0907566` | **SGO, PLAIN** | SA2 (+ device CP) | Container byte-exact; device CP/SA2 still apply |
| **HVAC `4G0820043`** | FRF, RAW | **RSA-1024/SHA-1** | **No** — signature wall (→ bench V850 ISP) |
| BCM2 `8K0907064`/`4H0907064`, DSG | SGO, AES | **AES, unknown key** | **No** without the key |

**Gates regardless of container validity:** UDS SecurityAccess (SA2), version/rollback
plausibility (ODIS-side, defeatable), flash-counter/prerequisites, and gateway CP
enrollment for re-integration.

---

## 5. What's in Simos-Suite now

| File | Role | Status |
|---|---|---|
| `flasher/lzss_compress.py` | VW-faithful LZSS (fixed; back-compat API) | PROVEN (real Simos18.1 decode→CRC32) |
| `flasher/frf_pack.py` | FRF container packer (edit blocks → CRC32 → ZIP → encrypt) | PROVEN functional |
| `flasher/payload_codec.py` | DFI detect + RAW/Simos-XOR/Bosch-LZSS-AES decode/encode | PROVEN (byte-exact RAW/XOR; functional Bosch) |
| `cp_tools/sgo_pack.py` | SGO container packer + checksum | PROVEN 69/69 byte-exact |
| `cp_tools/bcb_compress.py` | BCB compressor (inverse of `sgo_unpack._bcb_decompress`) | PROVEN vs oracle; **not VW-format** |
| `tests/test_frf_pack.py`, `tests/test_sgo_pack.py` | synthetic + corpus-guarded round-trips | green |

Usage sketch (CRC32-gated module, e.g. cluster):
```python
from flasher.frf_loader import FrfLoader
from flasher.frf_pack import frf_pack
from flasher.payload_codec import parse_segments, detect_codec, encode_block

loader = FrfLoader()
blocks   = loader.extract_blocks("orig.frf")      # {block_num: image}
template = loader.get_odx("orig.frf")
# ... edit blocks[60] (recompute internal VW-CRC32/ECM3 first if Simos) ...
# re-encode the payload if the module uses a codec:
#   stored = encode_block(image, detect_codec(dfi, has_comp_size))
new_frf  = frf_pack(blocks, template, loader._key, "orig.odx")  # CRC32 auto-fixed
```

---

## 6. Limitations & open questions

1. **DEFLATE not byte-exact** (FRF): functional only; bit-exact OEM FRF would need
   VAG ODIS's exact deflate encoder (likely Java `Deflater`/zopfli).
2. **Bosch LZSS is non-canonical**: decompressed image identical, compressed bytes
   differ; pure-Python encoder is O(n·window) — slow on >1 MB ASW (port to C for
   production).
3. **SGO BCB compressor ≠ VW on-disk BCB**: matches our decoder oracle, not the real
   `crypt=0x10` 1A-escape stream (no corpus block decodes through it). Reversing that
   codec is open. Use the plain `crypt=0x00` path for flashing.
4. **AES-locked blocks** (BCM2/DSG, Simos18 bodies post-decrypt) need per-platform
   keys; only Simos18.1/18.10 are in hand.
5. **Signature walls** (HVAC RSA-1024, Simos boot RSA): not defeated by any container
   trick. Bench bootloader unlock or an offline data-flash CP-record write remain the
   levers — *not* repacking.
6. **Container validity ≠ flash acceptance**: SA2, rollback, flash-counter, and CP
   enrollment all still apply at flash time.

*Corpus: owner's `4G0` C7 flashdaten (not shipped). Reuses `flasher/frf_loader`,
`flasher/checksum_simos`, `cp_tools/sgo_unpack`. See also
`research/module-flash-layouts.md` and `research/c7-cp-parts-inventory.md`.*
