# Audi C7/MLB CP Firmware Deep-Dive — J519 BCM1, J136 Seat, J525 Amp

*Module-by-module Component-Protection (CP) reverse-engineering documentation. Platform: Audi C7 / MLB. Companion to the J255 HVAC and J533 gateway write-ups. Date: 2026-06-17.*

---

## Scope & method note

This report documents three CP-bearing modules on the LEAR-platform C7/MLB bus, with the explicit goal of testing whether the **symmetric-AES-128 + 16-byte memcmp IKA-verify pattern** established for the J255 HVAC (and the J533 gateway, modulo its fixed-key KAT) generalizes. Each section flags what is **Ghidra-confirmed** (clean decompile / byte-exact table equality) versus **byte-inferred** (pattern/idiom localization without a clean decompile). The confidence ratings are deliberately uneven across modules and are honest about it: the seat (J136) and amp (J525) are high-confidence for opposite reasons (clean V850 decompile vs. a decisive *negative* crypto result), while BCM1 (J519) is medium because the Ghidra V850 SLEIGH desynced on its instruction encodings.

---

## 1. J519 BCM1 — Bordnetz-Steuergerät (central body / onboard supply control)

### Identity & architecture
- **Module:** BCM1 / J519 Bordnetz-Steuergerät, LEAR "D4" platform. Firmware self-IDs as **"BCM1 2.0"** — ASCII `907063ZZ0111BCM1 2.0` @ blob 0x50E9F (flash 0x7F7D9E); `BCM1_D4` label @ blob 0x4D49D (flash 0x7F439C), immediately preceding the AES table block.
- **Part:** 4H0907063, SW 0111 (`4H0907063___0111.sgo`). **SA2** = `68119391570412871a4743f6494c`.
- **Binary:** `D:\CP\re\BCM1_J519_4H0907063.bin`, 360,705 bytes — the address-sorted concatenation of 24 decoded `.sgo` blocks (plain; AES S-box @ blob 0x4D4A9 confirms the decode).
- **Arch:** Renesas/NEC **V850E/E2**, little-endian, 32-bit. Confirmed by PREPARE (0x07xx/0x0Fxx) prologues, DISPOSE (0x06xx) epilogues, register-save idioms (e.g. `a1 0f e6 81 04 …` @0x78DD2E; `cc 07` @0x78D1C2), and SubBytes/MixColumns table-load idioms. Same family lineage as the HVAC (µPD70F338x) and the J533 gateway.
- **Architecture caveat (load-bearing):** Ghidra 11.3.2's single `V850:LE:32:default` SLEIGH — which produced 4,135 clean funcs on the HVAC and 5,721 on the gateway — **desyncs on this image's long-instruction forms** (mulhi/mul/div/satXXX). Auto-analysis yielded near-zero `jarl` and garbage functions. **All findings below are byte-level pattern analysis + targeted region inspection, not a clean decompile.** Likely a slightly different V850E2 sub-variant or a SLEIGH gap on this compiler's mul/ld encodings.

### Load base
**NOT a flat 0x008000 base — the image is sparse**, with two regions:
1. Low data/config blocks at flash **0x003800** (0x601B, cal-like, entropy 4.41) and **0x00EE00** (0xB00B, entropy 6.98).
2. The main code+const window at flash **0x780000–0x7FF000** (22 contiguous 16 KB blocks).

The `.sgo` block address table is authoritative (parsed via `cp_tools.sgo_unpack`). The AES S-box that fingerprints at "blob offset 0x4D4A9" actually lands at **flash 0x7F43A8** once the sparse concat is unwound (blob offset ≠ flash addr because the concat is gap-free while flash is sparse — e.g. 0x794000 ends at 0x798000 then jumps to 0x7C0000). Code executes in the 0x78xxxx–0x7Fxxxx window, *not* a low base; no clean reset/vector with PREPARE entries was found at file start (unlike the gateway at file 0). RAM/.bss is gp/ep-relative internal SRAM (~0xFFFFxxxx); CP state bytes are gp-relative as in the HVAC.

### Memory map
| Region | Flash addr(s) | Character |
|---|---|---|
| **Code** (real prepare/dispose density ~2.6–2.9/KB) | 0x78C000, 0x790000, 0x794000, 0x7CC000, 0x7D0000, 0x7D4000, 0x7DC000, 0x7E0000, 0x7E4000, 0x7E8000, 0x7F0000, 0x7F8000 | V850 functions |
| **Data/tables** (high prepare, ZERO dispose) | 0x780000 (26-byte-record routing table, head `4a ad 22 e0 cc e9 36 7c`), 0x784000, 0x788000 (ent 3.76, 8-byte `XX XX f8 00 0f ..` records), 0x7C0000 (`XX 4a 80 YY` 4-byte coeff table), 0x7C8000, 0x7F4000 (ent 5.37, the CONST block w/ AES tables) | structured records |

**Flash block layout** (addr:len): `0x003800:0x601`, `0x00EE00:0xB00`, then `0x780000,0x784000,0x788000,0x78C000,0x790000,0x794000` each 0x4000, gap, `0x7C0000..0x7F0000` each 0x4000, `0x7F4000,0x7F8000` 0x4000, `0x7FC000:0x3000`.

**DID infrastructure:** DID-list registration table @ **0x7811E0** (sorted BE16 array; includes **0x00BE @ 0x781206**). DID handler dispatch tables @ **0x7FD960** and **0x7FDD30** (4-byte records `f1 00 DID_hi DID_lo` w/ per-sub-index offsets). 0x00BE has multiple consecutive entries (read/write + IKA sub-rows); the two mirrored tables = read-path vs write-path.

### Crypto — STANDARD AES-128 (Ghidra-confirmed by byte equality)
**Standard AES-128 (FIPS-197), NOT custom.** All four tables byte-exact vs reference:
- Forward S-box @ flash **0x7F43A8** (blob 0x4D4A9): `63 7c 77 7b f2 6b 6f c5 … 41 99 2d 0f b0 54 bb 16` — full 256 B == FIPS-197 (**match=True**).
- Inverse S-box @ **0x7F44A8** (blob 0x4D5A9): `52 09 6a d5 30 36 a5 38 …` — 256 B == standard (**match=True**).
- xtime / GF-mul-by-2 @ **0x7F45A8** (blob 0x4D6A9): `00 02 04 06 08 0a …` (**match=True**).
- Rcon @ **0x7F46A8** (blob 0x4D7A9): `01 02 04 08 10 20 40 80 1b 36` (**==standard**).

Tables sit in the 0x7F4000 const block, labeled `BCM1_D4` just before. **AES routine** located in the 0x7E4000 block, span ~**0x7E57CC** (PREPARE entry) to ~**0x7E60A0** (DISPOSE), ≥964 bytes: SubBytes/ShiftRows via the `movhi 0x7F4x; ld.bu Sbox[0x43A8 + state_idx]` idiom (24 S-box refs = SubBytes; 16 xtime refs = MixColumns; inv-S-box refs @ 0x7E5927 / 0x7E5BB1 / 0x7E5CC9 / 0x7E6000 = the decrypt path). No other cipher present. **Unlike the gateway, NO fixed ASCII AES key string** (`"LEAR D4 Gateway."`-style) exists in the code region — consistent with the per-vehicle IKA living in data-flash/EEPROM.

### 0x00BE IKA handler
DID **0x00BE** (the 34-byte IKA credential) is a **registered DID**:
- Present in the sorted DID-list table @ flash **0x781206** (between 0x00BB and 0x00BF).
- Dedicated entries in **both** dispatch tables: 0x7FD960 read-path records `…00 be 16 / 00 be 54 / 00 be 92 / 00 be d0` (sub-offsets step 0x3E); 0x7FDD30 write-path mirror `00 be 30 / 00 be 6e / 00 be ac / 00 be ea`. The multiple consecutive 0x00BE sub-entries match a multi-row credential (HVAC row0..rowN analog).
- Handler **code** lives in the 0x794000 block: a literal `0x00BE` compare embedded in the dispatch @ flash **0x794DA3** (`18 24 00 be 59 05 …`), co-located with the CP DTC setter.
- Other in-code 0x00BE constants (0x786853, 0x78FB9D, 0x7D5057, …) exist but the authoritative IKA handler is the 0x781206 registration + 0x7FDxxx dispatch + the 0x794xxx handler.
- The **IKA key store itself is NOT in this `.sgo`** (factory-default firmware) — it lives in data-flash/EEPROM per the design; only read/write/verify *logic* is here.

### CP-verify mechanism
Same shape as HVAC/gateway: **symmetric AES-128 keyed by the stored IKA/CS, then a 16-byte compare — NOT RSA.** The AES engine @ 0x7E57CC is the primitive; the CP-verify caller sits in the 0x794000 CP region (same block as the 0x00BE handler @0x794DA3 and the EA63 DTC setters @0x794B5A/0x794C31), arming AES over the challenge with the stored IKA and memcmp'ing the 16-byte result against the stored credential row (HVAC analog: `FUN_0006dd54` case 7 = memcmp gp-0x7f64 vs row0 IKA).

**Confidence split:** AES==standard + AES routine location is **high** (byte-exact tables, decoded SubBytes/MixColumns idioms). The exact **memcmp address** and the **precise gp-relative buffers could NOT be pinned** — the V850 SLEIGH desync blocked a clean decompile — so the verify routine is *localized* to the 0x794xxx CP cluster + the 0x7E57CC AES function by structure/byte evidence, **not extracted as C**. **No fixed-key KAT/sentinel forgery path** (like the gateway's `"LEAR D4 Gateway."` known-answer test) was found here; BCM1's check is keyed by the per-vehicle IKA in EEPROM, so an offline forge would need that key or a NOP-the-compare/DTC patch.

### CP-active DTC + lock/limp gate
- **CP-active DTC = 0xEA63** (HVAC used 0xEA62 with params 0xEA61–0xEA64; BCM1's CP-active code is in the same 0xEA6x family). `ea 63` (BE16) @ flash 0x785C1D / 0x785C2D (0x784000 CP code) and 0x794B5E / 0x794C35 (0x794000 CP handler).
- **Set** by a conditional DTC-set call in FUN @ ~**0x794A0E**: idiom `…59 59 b7 46 18 02 ea 63 be XX…` at **two sites** — 0x794B5A (`ea63 be8c`) and 0x794C31 (`ea63 be80`) — where trailing `be XX` carries DTC status/priority and `59 59` is the short/callt call to the DTC-set routine. The two sites are guarded by branch logic (bnh/cmp/bne between them) = the CP pass/fail decision that conditionally raises EA63 and degrades BCM function (lighting/locking/comfort limp = the HVAC defrost-only analog).
- Sibling EA6x codes present: EA60, EA65, EA69, EA6B, EA6C, EA6F.
- CP flag is a gp-relative RAM byte set by this FSM (mirrors the HVAC 0x0C-auth / 0x0B-not getter). **Exact byte offset not extractable** (SLEIGH desync), but the *mechanism* (conditional EA63 set in 0x794xxx on AES/memcmp fail) is confirmed by byte structure.

### Confidence: **medium**
High on: memory map, AES==standard (byte-exact), DID tables, DTC set-sites, AES routine location. Low / unpinned on: clean CP-verify C, memcmp address, gp-relative CP-flag offset and its auth values, and `jarl` linkage proof — all blocked by the SLEIGH desync.

### Open questions
1. Resolve the **V850 SLEIGH desync** (exact V850E2 sub-variant / fixed disassembler / hand-decode) to extract the CP-verify routine as clean C and pin the memcmp address + gp-relative CP-flag byte offset and its 0x0C/0x0B (or BCM-specific) auth values.
2. **AES key source:** confirm round-key load path and that the per-vehicle IKA (data-flash/EEPROM, absent here) is the AES key vs a CS/derived key — needs a bench EEPROM/data-flash read.
3. Whether a fixed-key KAT/sentinel exists elsewhere (none found in code region, unlike the gw) — re-scan 0x788000 / 0x7C0000 data tables and the low 0x003800 / 0x00EE00 blocks.
4. Confirm the 0x794xxx CP function actually **jarls the 0x7E57CC AES routine** (couldn't byte-match V850 `jarl disp22` reliably).
5. Decode the DID dispatch `f1 ..` far-pointer/page semantics to resolve the 0x00BE handler entry precisely.
6. Identify the **limp consumers** (which BCM functions degrade on EA63) for the eventual bypass patch site, analogous to the HVAC defrost-limp producer-side patch.

---

## 2. J136 Driver Seat — MEM-FS / Sitzmemory (memory seat module)

### Identity & architecture
- **Module:** Driver Seat / J136 (memory seat module).
- **Part:** 4H0959760A, SW 0114 (`STANDARD---00010114` @0x01000; `4H0959760` @0x01205; `J136` @0x035cc; supersession list 8K0959760D/E, 8T0959760D, 4H0959760/A).
- **Binary:** `D:\CP\re\DriverSeat_J136_4H0959760.bin`, 364,384 bytes (0x58F60), plain.
- **Arch — CORRECTION to the brief: this is NOT ARM. It is Renesas/NEC V850 (V850E2-class, little-endian), the SAME family as the HVAC J255.** Decisive test: importing as `ARM:LE:32:Cortex` (Thumb forced) and disassembling the densest regions (0x4000, 0x8000, 0x34000, 0x38000) produced **0 instructions**; importing as `V850:LE:32:default` produced clean, coherent code at every seed (jarl/mov/cmp/ld.hu/movea/sld.b/stsr PSW/di), auto-analysis found **2,370 functions**, and the full decompile is internally consistent. Confirming evidence: V850 linker section-name table @ file 0x48864 (`.intvect`/`.intvect2`/`.rsu_option_code`/`.robase`/`.defaultdatensatz`/`.DFALib_Text`/`.EEELib_Text`/`.fixaddr`/`.fixtype`/`.secinfo`/`.syscall`/`.sdabase`/`.tdata`/`.zdata` + German `.dfdatensatz`/`.defaultdatensatz`), gp/ep-relative addressing idioms, heavy `0x80ff`/`0x8007`(jarl) byte signatures. **Use `V850:LE:32:default`, not ARM.**

### Load base
**Link/load base = 0x00000000** (file offset == VMA). Verified: branch targets the V850 decompiler resolved (e.g. `jarl 0x0002cd92`, `jr 0x0003816e`) and the `.secinfo` VMAs all match raw file offsets 1:1. **No ARM-style SP/reset vector at offset 0** — the first 0x400 bytes are a 16-byte-stride flash block/checksum descriptor table (entries `84 07 xx xx 00 00 00 00`, plus signature word `7d6f3e7f` / `0085f565dd86` @0x60). Real V850 interrupt vectors are relocated: `.intvect` VMA 0x8070, `.intvect2` VMA 0x87cf/0x87d0 (jump-vector table of 32-bit handler addrs, e.g. 0x0003145a, 0x00030136, 0x0002ea74). RAM/data-flash @ 0x03FF9000+, syscall/dataflash-lib window @ 0x00FF8000.

### Memory map
Full `.secinfo` section table parsed @ file 0x48864 (record fields = `[secinfo-rec ptr][LMA/init ptr][VMA run-addr][size][align/flag]`):

| Section | VMA | Size | Note |
|---|---|---|---|
| `.intvect` | 0x8070 | — | |
| `.rsu_option_code` | 0x8080 | 0x748 | |
| `.robase` | 0x9000 | 0x1348 | dataset/cal |
| `.defaultdatensatz` | 0xB000 | 0x8A10 | **FACTORY default dataset incl CP defaults** |
| `.rosdata` | 0x13A10 | — | |
| `.romdata` | 0x13A34 | 0x234 | |
| `.rodata` | 0x13C68 | 0x3B1C8 | huge — **AES tables 0x9F5C–0xA300 sit in this rodata span** |
| `.text` | 0x4EE30 | 0x5A4 | |
| `.DFALib_Text` | 0x4F4F4 | — | |
| `.EEELib_Text` | 0x507E0 | — | EEPROM-emulation code |
| `.fixaddr`/`.fixtype`/`.secinfo` | 0x50804–0x50D70 | — | |
| `.syscall` | 0x00FF8000 | — | RAM |
| `.dfdatensatz` | 0x03FF9000 | 0x24 | **36 B persistent CP/IKA data-flash record** |
| `.data` | 0x03FF9024 | — | |
| `.bss`/`.sdabase` | 0x03FF9110 | — | |
| `.sdata` | 0x03FF9348 | 0x4BC0 | gp anchors here (~0x03FF9348) |
| `.WD_ToRam` | 0x03FFDF08 | — | |
| `.EEELib_Data` | 0x03FFDF6C | 0x2C | |
| `.noinit` / `.stack` / `.zdata`/`.tdata` | 0x03FFDF98 / 0x03FFEFE0 / 0x03FFEFE4 | — | |

Code addresses the AES tables via a tp/ep anchor @ 0xB000 (`tp-0x10a4`=sbox 0x9F5C, `tp-0xea4`=mul2 0xA15C). Flash dump runs to 0x58F60 (tail 0x57000–0x58F60 = DTC/text records); 0x48D70–0x50FFF is 0xFF padding.

### Crypto — STANDARD AES-128 (Ghidra-confirmed, byte-exact + clean decompile)
**Standard AES-128, byte-oriented small-footprint implementation — byte-for-byte verified, NOT custom.** Tables (file offset = VMA):
- S-box @ **0x9F5C** (256 B == canonical `63 7c 77 7b f2 6b 6f c5 …`).
- Inverse S-box @ **0xA05C** (`52 09 6a d5 30 36 a5 38 …`).
- GF-mul-by-2 (xtime) @ **0xA15C** (`00 02 04 06 08 0a …`, used by MixColumns).
- Rcon @ **0xA25C** (`01 02 04 08 10 20 40 80 1b 36`).

**Routines (clean decompile):**
- AES round state-machine = **`FUN_000349c2`** (SubBytes+ShiftRows via sbox @ tp-0x10a4; MixColumns via xtime @ tp-0xea4 — the classic `state[i]^=mul2[s^t]^col_parity` form).
- Key-schedule step = **`FUN_0003467e`**.
- AddRoundKey/XOR-block = **`FUN_000347d0`**.
- Block copy = **`FUN_00034612`**.
- AES entry points: **`FUN_00034764(out,state,key)`** = plain ECB single block (16 B); **`FUN_00034872(in,state,key)`** = pre-XOR variant (CBC chaining), selected by the orchestrator when mode==1/2.

No RSA, no second cipher. Same AES as the HVAC J255.

### 0x00BE IKA handler
- The firmware's **primary UDS DID dispatch table** @ file **0x03A40–0x03AC8** (8-byte records `[DID:BE16][2 flag/cfg bytes][handler-ptr:LE32]`) only enumerates the F1xx/04xx ReadDataByIdentifier IDs (0xF1EC..0xF1FF, 0x01F1) → handlers 0x00027B32 / 0x0002C600 / 0x000275BE.
- The manufacturer **0x00BE WDBI/RDBI is NOT in that flat table** and is not reached by a folded 0xBE immediate (V850 builds DIDs/addresses via movhi+movea, so **no literal 0x00BE or 0x9F5C appears anywhere** as an operand or constant-pool word — confirmed by exhaustive scan).
- **IKA key store** = the data-flash record `.dfdatensatz` @ **0x03FF9000** (36 B = 2×16 B AES blocks + 2 B tail), persisted through the Renesas data-flash/EEPROM-emulation library @ base 0x00FF8000 (`FUN_00047f04` + `.EEELib_Text`@0x507E0).
- In-RAM CP key slot exposed via the key/param store **`FUN_00035490`** (slot 0 = 16 B key get/set; commit = `FUN_00036c0a`).
- **Not fully pinned:** the exact **0x2E/0x22 service shim** that routes 0x00BE into `FUN_00035490` slot 0 / the dataflash record — it lives in the UDS service layer, gp-relative, with no literal DID.

### CP-verify mechanism
Same shape as HVAC: **symmetric AES + 16-byte memcmp, CS/immo-keyed, NOT RSA** — and here it is a **clean decompile**:
- **Crypto orchestrator = `FUN_00035950`** (state-byte FSM @ gp-0x51ac / -0x51a4 that copies a 16 B block to gp-0x5228, runs AES via `FUN_00034764`/`FUN_00034872`, and has a complement-and-compare branch: `bVar6 = ~state[i]`, store to gp-0x5160, compare against gp-0x5170, break on mismatch).
- **CP/IKA VERIFY proper = `FUN_00036cda`**: pumps `FUN_00035950`, then **case 7 performs an explicit 16-byte memcmp** (loop count 2 × 8 bytes/iter) of the AES-computed response (gp-0x509c) against the received/expected value (`*(gp-0x506c)`); `FUN_0003668a(3)` gates ready(0x0A)/busy(0x0C).
- On the result it calls **`FUN_0003729c(0, iVar9==0)`**, which writes the **CP authentication STATUS byte @ gp-0x5048** (the 0x0C-authenticated / not-authenticated flag, analog to the HVAC status getter; downstream seat features read it to enable vs limp).
- Top-level periodic CP task = **`FUN_00037164`** (drives `FUN_00036cda`, sets persistent state, commits via `FUN_000369a4`/`FUN_0003729c`). Short-compare memcmp helper = `FUN_0003528a` (returns true on mismatch).
- A 34-byte 0x00BE blob is consumed as: block0(16)=`E62B..0AC2` and block1(16)=`D15B..2C93` as AES key/reference material loaded into the 16 B store slot, with the 2 B tail (`2600`) as a record marker/checksum — **matching the 16 B AES + 16 B memcmp pipeline exactly.**

### CP-active DTC + lock/limp gate
- **All four CP-active DTC constants 0xEA61, 0xEA62, 0xEA63, 0xEA64 present** (as BE16 and LE16). DTC-handling code clusters @ file **0x18600–0x18820** where all four EA6x appear as instruction immediates in the DTC-set path (`e0 61 ea` @0x18613, `41 ea 6a ea` @0x186d2, `61 ea` @0x1878d, `62 ea` @0x187c0, `63 ea` @0x187e8, `64 ea` @0x18803).
- DTC event/snapshot descriptor records (~0x60–0x68 B each, containing DTC LE16 lists e.g. `63 ea` / `58 ea` / `61 ea`) live in the data table ~0x10B50–0x10D00; a second CP DTC group (`eaca`/`ea61`/`ea65`, `eae0`/`ea61`) sits near 0x1EA75, 0x1D7E2, 0x3E339.
- Generic DTC statistics/aging routine = **`FUN_00018518`** (min/max/counter @ gp-0x77xx).
- **CP flag** = the auth-status byte set by `FUN_0003729c` @ gp-0x5048: when CP verify (`FUN_00036cda` case 7) fails / status ≠ authenticated, the periodic task latches **0xEA62** (active CP fault, params 0xEA61–0xEA64) and degrades function. Surfaces on VCDS/ODIS as **U110100 / VAG 7465**, identical to HVAC.

### Confidence: **high**
Clean V850 decompile (2,370 funcs; full dump → `D:\CP\re\j136_all.c`, 1.95 MB), byte-exact AES tables, named CP-verify/memcmp/status functions with concrete gp offsets.

### Open questions
1. Exact **UDS 0x2E/0x22 shim** routing DID 0x00BE → 16 B key store (`FUN_00035490` slot 0) / `.dfdatensatz` not byte-pinned (gp-relative, no literal DID) — needs a live trace or manual walk from the F1xx table @0x03A40 and the SID handler that precedes it.
2. Confirm `FUN_00034872` is **CBC vs a decrypt path** (it pre-XORs via `FUN_000347d0` then runs the forward round FSM → CBC-encrypt, but verify there's no inverse-sbox round driver using 0xA05C).
3. The 2-byte 0x00BE tail (`2600`) role — record version/checksum vs literal — inferred, not proven.
4. Precise byte layout of the 36 B `.dfdatensatz` record (where the 32 B key material vs status/counter bytes sit) — needs a **bench read of data-flash 0x03FF9000** (not in the `.sgo`, as expected).
5. The flat DTC config/aging table mapping 0xEA62 → U110100 located by region, not fully decoded per-entry.

None of these block the conclusion: **the CP gate is AES-128 + 16 B memcmp with the live IKA in data-flash @0x03FF9000.**

---

## 3. J525 Sound System 2 Amplifier (Audi 4G0 / C7)

### Identity & architecture
- **Module:** Sound System 2 amplifier J525.
- **Part:** 4G0907441B, SW 0061 (`4G0907441B__0061.sgo`).
- **Binary:** `D:\CP\re\Sound2_J525_4G0907441.bin`, 643,759 B, plain.
- **Arch:** NEC V850x (Renesas V850), running **OSEK / osCAN RTOS**. PROVEN by the in-band toolchain build-path string `D:\projekte\EFF2-06007\13_Software\rv_common\..\..\28_Tools\osCAN_V319\NECV85x\src\osek.c` (blk 0x20000 +0x13F) plus part string `H4G0907441B` (+0x543). Decoded with `V850:LE:32:default`.
- **The architectural outlier:** the seat (J136) and BCM1 (J519) carry a standard AES S-box; **J525 does not.**

### Load base
**0x0** (the `.sgo` block addresses ARE the absolute flash link addresses). Reasoning: code @ 0x2xxxx makes valid `jarl` calls to 0x000722xx (block 0x70000) and to 0x000079F2 — the latter in a factory-resident bootloader/IVT region **below** the lowest `.sgo` block (0xE000), absent from the flashdaten (V850 reset/IVT live @ 0x0 in bootROM). Top descriptor block @ 0xFFE080 self-references load address 0x03FFE080. NVM/data-flash controller is memory-mapped @ **0x400000** (handlers do `mov 0x400022/24/30,rX; st.b`). **No `movhi 0xffff*` anywhere ⇒ no high-SFR (0xFFFFxxxx) hardware-crypto peripheral.**

### Memory map
17 decoded blocks (sparse, base 0):

| Block | Size | Character |
|---|---|---|
| 0xE000 | 0xA11 | IVT/dispatch descriptors + embedded **SA2 seed/key script** `45 5c f6 9b 02 03 07 05 01 04 00 06 03 00 08 2e 70` |
| 0x15000 | 0x7C6 | cal/timing table (repeats SA2 script) |
| 0x1C000/0x1D000/0x1E000/0x1F000 | 4× 0x50 | descriptors |
| 0x20000 | 0x9F7A | osCAN/RTOS + UDS dispatch pointer tables |
| 0x30000 | 0xC174 | diagnostic/UDS + CP application |
| 0x40000 | 0xC442 | (CP app) |
| 0x50000 | 0xADC0 | handlers 0x52xxx, **NV/IKA path 0x52478** |
| 0x60000 | 0xCCF7 | DTC-status 0x46910 |
| 0x70000/0x80000/0x90000 | ~0x38E each | |
| 0x100000 | 0x30BCD (199 KB) | **DSP/audio code + coeff LUTs** (entropy ~6.5, NOT crypto) |
| 0x300000 | 0x2F9D6 (195 KB) | DSP/audio (NOT crypto) |
| 0xFFE080 | 0xF60 | flash block-descriptor/ID table |

RAM/NVM: data-flash & CP-state controller mapped @ 0x400000–0x40xxxx; CP-status flags are gp-relative RAM bytes. Factory bootloader resides below 0xE000 (not in image). CRC-only image (no RSA per the 4g0 inventory family).

### Crypto — NONE (decisive negative result, HIGH confidence)
**There is no cryptographic primitive of any kind in this firmware.** Exhaustive byte analysis over **all 17 blocks** found:
- **No standard AES S-box** (tested normal, nibble-swapped, XOR-0xFF, bit-reversed variants — all absent).
- No inverse S-box, no Rcon, no Te/Td MixColumns tables.
- **No 256-byte byte-permutation/bijection at any alignment (0 found image-wide).** The single highest-density 256-byte window anywhere has only **194 distinct bytes** (a real S-box needs 256).
- No TEA/XTEA/SHA-1/SHA-256/MD5/DES/Blowfish constants.
- The "high-entropy" region 0x68000–0x6CC00 is an **audio/DSP lookup table** (slowly-changing high byte b4/b3/b2…), not a key or cipher table.
- xor/shl/shr/set1/clr1 density is ordinary and thin across all blocks (CAN frame packing + DTC bit-fields + CRC), with **no concentrated cipher-round loop**.
- No high-SFR hardware-crypto access.

**No custom S-box and no custom software cipher.** This is the fundamental divergence from the standard-AES HVAC/seat/BCM/gateway pattern.

### 0x00BE IKA handler
- DID **0x00BE write path** @ the handler region ~**0x52478** (block 0x50000), which programs the memory-mapped data-flash/NVM controller @ 0x400000 (`movea 0x13,r0,r10; st.b r10` = cmd 0x13, then writes to 0x400022/0x400024/0x400030).
- The 34-byte IKA blob is **STORED** into 0x400000 data-flash; it is **NOT cryptographically verified on write locally** (consistent with the gateway-side observation that `2E 00BE` is accepted with no effect).
- UDS service/sub-function dispatch via LE32 pointer tables in block 0x20000 (@file 0x21044 cnt6, 0x21078 cnt4, 0x21092 cnt24) → handlers @ 0x527xx–0x52Dxx and 0x60380/0x6077A/0x605CA.
- Live per-vehicle IKA key is in 0x400000 data-flash (bench/NV read only, not in the `.sgo`).

### CP-verify mechanism — EXTERNAL to this module
**NOT an AES+memcmp like HVAC/seat — there is no local cipher to do it with.** The J525 is a **"dumb endpoint":**
1. **STORE** the 34-byte IKA blob in 0x400000 data-flash (no local crypto verify), and
2. **READ a CP-status flag** (a gp-relative RAM byte; status-setter handlers ~0x528be–0x528ec do `st.b r0,-0x72f0/-0x1af0/-0x66f0[r19]`-style flag clears/sets), and on "CP active / not-paired" raise the U110100 DTC + degrade audio.

The actual cryptographic challenge-response is performed by the **J533 gateway's periodic keyed-AES self-scan** (see gateway-cp-model: the gateway issues its own challenge, verifies the reply, and never trusts the module's self-report). **The verify mechanism is external to this module.** No 16-byte memcmp / AES caller exists locally (no AES exists). A local firmware patch could only force the status flag / suppress the DTC — **cosmetic at the gateway**, which keeps its CP DTC latched.

### CP-active DTC + lock/limp gate
- **CP-active DTC = U110100** ("Komponentenschutz aktiv"), confirmed in `D:\CP\datadb\data\didb\didb_Base.data` alongside the "Sound2" system; on-car it surfaces in the 0xEA62 family (params 0xEA61–0xEA63).
- **IMPORTANT CORRECTION:** the raw `0xEA61`/`0xEA62`/`0xEA63` BE16 byte-matches inside the firmware are **V850 OPCODES** (byte pair `61 ea` = `cmp r10,r12`, `62 ea` = `mulh`, `63 ea` = `add`), **NOT a literal DTC table.** VW modules store DTCs as internal event/symptom numbers and map them to U-codes at UDS-report time via the ODX — there is no plain 3-byte `EA 62 00` table in the image (verified: **zero hits for `EA 6x 00` in any byte order**).
- DTC status-bit (pending/confirmed) handling @ ~**0x46910** (`ld.hu 0xc[r10],r10; cmp; set1 0x7,0x7[lp]; clr1 0x3,0x0[r8]`).
- The CP flag itself is a gp-relative RAM byte set by the CP/status FSM, consumed by the audio-degrade and the 0x19 DTC reporter.

### Confidence: **high**
High *because the negative crypto result is exhaustive and decisive*, and the store-only / external-verify role is structurally clear. (Decompiler *quality* is poor — see open questions — but that does not weaken the no-crypto / dumb-endpoint conclusion.)

### Open questions
1. The factory-resident bootloader/IVT below 0xE000 is **not in the `.sgo`** — a CP-verify in bootROM is implausible for a comfort amp but unprovable without a bench dump.
2. Ghidra V850 decompiler quality is poor (register-passing convention unrecovered, jump tables unfollowed) → the exact gp-relative offset of the live CP-status flag and the precise audio-degrade consumers are not pinned to a single byte; needs targeted disasm / bench tracing to localize for a patch.
3. Whether the gateway-self-scan reply the J525 must produce is generated by **non-crypto means** (echo/serial) or whether the amp has **no challenge obligation at all** — the absence of any cipher suggests the latter, but read the on-car gateway component-status for J525 to confirm.
4. The 0x400000 data-flash command set (cmd 0x13 etc.) and exact IKA/CP-record offsets only partially mapped.
5. Confirm SW0061 vs the other available `4G0907441__0040.sgo` for per-SW drift of the flag location.

---

## Cross-module comparison

| Module | Arch | Crypto | CP-verify shape | Confidence |
|---|---|---|---|---|
| **J519 BCM1** (4H0907063, SW0111) | V850E/E2, LE, sparse 0x78xxxx code base | **Standard AES-128** (4 tables byte-exact @0x7F43A8) | **AES-128 + 16 B memcmp, per-vehicle IKA** — localized to 0x794xxx CP cluster + 0x7E57CC AES fn; *byte-inferred, not clean C* (SLEIGH desync). No fixed-key KAT. | **medium** |
| **J136 Seat** (4H0959760A, SW0114) | V850E2, LE, base 0x0 (*not ARM*) | **Standard AES-128** (4 tables byte-exact @0x9F5C) | **AES-128 + 16 B memcmp, CS/immo-keyed** — clean decompile: `FUN_00036cda` case7 memcmp, status byte @gp-0x5048, IKA in data-flash @0x03FF9000 | **high** |
| **J525 Amp** (4G0907441B, SW0061) | V850x + OSEK/osCAN, LE, base 0x0 | **NONE** (exhaustive negative; no S-box/permutation/cipher anywhere) | **No local verify** — store-only "dumb endpoint"; IKA written to data-flash @0x400000, challenge-response done by the **J533 gateway** externally | **high** |

---

## Summary — does the HVAC symmetric-AES IKA-verify pattern generalize?

**Partially — it generalizes across the *body/comfort processor* modules but not the *audio endpoint*.**

- **Yes for J519 BCM1 and J136 Seat.** Both are V850 modules carrying a **byte-exact standard AES-128** (S-box, inverse S-box, xtime, Rcon all == FIPS-197) and both implement the **HVAC pattern: AES over a challenge keyed by the per-vehicle IKA, followed by a 16-byte memcmp against a stored credential row, with a gp-relative auth-status byte (0x0C-auth / 0x0B-or-not) gating the limp behavior and an 0xEA6x-family CP DTC.** The seat is a *clean Ghidra-confirmed* instance (named verify/memcmp/status functions, concrete gp offsets, the same dual AES entry points as the HVAC). BCM1 is the *same shape by strong byte evidence* but not yet extracted as C.

- **No for J525 Amp.** It breaks the pattern entirely: **no cipher of any kind exists in the image** (decisive negative). The amp is a passive endpoint — it *stores* the 34-byte IKA in data-flash and *reads a status flag*, while the **actual keyed challenge-response lives in the J533 gateway**, which never trusts the module's self-report. This matches the gateway's "verify the reply yourself" model and means a local amp patch is cosmetic.

**Architectural note:** the brief's "J136 = ARM" was wrong — **all three modules are V850-family**, consistent with the HVAC and gateway. The only true outlier is *J525's absence of crypto*, not its CPU.

### What needs a bench dump (live key) to finish

| Module | Bench requirement | Why |
|---|---|---|
| **J136 Seat** | Read data-flash **0x03FF9000** (36 B `.dfdatensatz`) | The AES key / IKA material and the exact 32 B-key-vs-status/counter layout are *not in the factory `.sgo`*. Logic is fully mapped; only the live key + record layout are missing. Closest to "done." |
| **J519 BCM1** | Read EEPROM/data-flash (per-vehicle IKA) **+** resolve the V850 SLEIGH desync | Two gaps: (a) the IKA key (absent from the factory `.sgo`, as designed) and (b) a clean disassembler to pin the memcmp address and the gp-relative CP-flag offset/auth values. Both block an offline forge; fallback is a NOP-the-compare/DTC patch. |
| **J525 Amp** | Read data-flash **@0x400000** (IKA record) + on-car gateway component-status for J525 | Only to confirm the store-only role and the gateway's challenge obligation — *not* needed for a verify routine (there is none). A local patch can at most suppress the DTC. |

**Bottom line:** the symmetric-AES IKA-verify is a genuine **LEAR-D4 family pattern** (HVAC → seat → BCM1, with the gateway as the keyed verifier and KAT-forge anchor). The seat is essentially solved pending one EEPROM read; BCM1 needs the same EEPROM read plus a disassembler fix; the amp is architecturally a non-participant whose CP is enforced upstream by the gateway. No module here yields a fully offline forge from the `.sgo` alone — the per-vehicle IKA always lives in NV memory that requires a bench read (BCM1, seat), and the only fixed-key KAT-forge path remains the gateway's, not these modules'.