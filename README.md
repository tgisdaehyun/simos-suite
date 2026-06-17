# Simos Tuning Suite

A Windows-first, open-source toolkit for **flashing, reading, diagnosing, and
researching** Volkswagen Auto Group (Audi / VW) engine and transmission control
units. It pairs a full UDS programming engine with a no-install GUI, bidirectional
FRF/ODX/SGO container codecs, and a Component-Protection (CP) research suite —
built for owners who want to service their own cars.

It runs as a single unsigned Windows x64 EXE or from source, talks to cheap
ESP32 ISO-TP bridges (BLE / USB / WiFi) and standard J2534 cables, and runs the
**entire GUI with zero hardware** via a built-in Simos8.5 simulator.

**Primary target:** Simos8.5 — 3.0T TFSI CGWA/B (C7 A6/A7/A8)
**Also supported:** Simos12 / 12.2 / 18.1 / 18.10 / TTRS (EA888/EA855), ZF 8HP, DL501, DQ250, DQ381

Companion repos:
- [esp32-isotp-ble-bridge-c7vag](https://github.com/dspl1236/esp32-isotp-ble-bridge-c7vag) — ESP32 BLE/USB bridge firmware
- [VAG-CP-Docs](https://github.com/dspl1236/VAG-CP-Docs) — Component-Protection research writeups

---

## ⚠️ Status — read before you write

This is built in the open, pre-1.0, **unsigned**, and shipped so the community can
build on it. Maturity is mixed and labeled honestly throughout this README and in
the GUI itself.

- **Read-only paths are mature and safe** — ECU Info, Logger, Trans live data,
  bus scan, DTC read, raw CAN sniff, and all offline container/checksum tooling.
  Worst case they misread something.
- **The ECU/TCU flash *write* path is implemented but GUI-disabled** pending
  hardware validation. The read → checksum → compress → encrypt → write pipeline
  exists end-to-end; the write buttons sit behind a banner. **Read/verify work
  today.**
- **CP write / routine actions are experimental and bench-gated.** The IKA-key
  write, J533 constellation update, and HVAC CP-patch flasher are wired but
  **unconfirmed on hardware** (the HVAC flasher defaults to dry-run).

**Flashing an ECU/TCU can brick it.** Don't run write features on a car you can't
recover — have a bench (boot-mode / BDM) setup and a verified known-good backup
*first*. **No warranty whatsoever** (GPL §15–16). You run this entirely at your
own risk.

This is a right-to-repair project on the author's own vehicle. The CP work is
**research** — it does not, and is not intended to, defeat cryptographic
signatures (see [Status & honesty](#status--honesty)).

---

## Download

**[SimosSuite.exe — latest release](https://github.com/dspl1236/simos-suite/releases/latest)** (Windows x64, single file, no install)

It's an **unsigned build** — SmartScreen will flag it; "More info" → "Run anyway"
if you trust it, or run from source (see [Install](#install)).

---

## Features

### Engine / TCU flashing & reading

- **Full UDS flash engine** (`flasher/uds_flash.py`) for Simos8.5 / 12 / 12.2 /
  18.1 / 18.10 / TTRS: extended → programming session, SA2 seed/key unlock, block
  erase, RequestDownload / TransferData, exit + verify. Drives the complete
  **checksum-fix → LZSS-compress → XOR(Simos8)/AES-CBC(Simos12+) encrypt** pipeline.
  *(Write is GUI-disabled pending hardware validation; read/verify work today.)*
- **Virtual block read** (UDS RequestUpload, `read_block`) pulls CBOOT / ASW1 / CAL
  off a live ECU and decrypts + LZSS-decompresses to a flat image for the
  read → edit → reflash workflow.
- **CAL / multi-block flash UI** in the Flash tab: open `.bin` or `.frf`, read CAL
  from the ECU, verify checksum. Write buttons present but gated.
- **VIN utilities** (`flasher/vin_utils.py`): read / write / validate the ECU VIN
  (DID 0xF190) with SA2-gated write + read-back verify, and an ECU-vs-chassis VIN
  comparison (tuner-lock aware).

### FRF / ODX / SGO decode + repack

- **FRF decrypt + extract** (`flasher/frf_loader.py`): rolling-XOR with `frf.key`
  → ZIP → ODX, extracting flash blocks and the SA2 script. *(This is the codec
  path surfaced in the GUI — Flash tab → "open .frf".)*
- **FRF repack** (`flasher/frf_pack.py`): rebuild an FRF from edited blocks with
  per-DATABLOCK CRC32 recompute, re-zip (VAG profile), re-encrypt. Functional —
  decompressed image is byte-identical; the compressed stream differs. *(CLI/lib.)*
- **Payload-codec matrix** (`flasher/payload_codec.py`): detect + apply the
  per-block transform (RAW `0x00` / Simos counter-XOR `0x01` / Bosch-LZSS-AES
  `0xAA`) that turns a tuned BIN into on-ODX bytes. *(CLI round-trip diagnostic.)*
- **Faithful VW LZSS** (`flasher/lzss_compress.py`): a 1023-window, space-init port
  matching the ECU's on-board decompressor.
- **SGO (SGML Object File) unpack** (`cp_tools/sgo_unpack.py`): parse container
  metadata + decode blocks, auto-detecting plain / BCB / BCB-XOR (keyless
  repeating-XOR crack verified by the block's own 24-bit checksum) / AES.
- **SGO repack** (`cp_tools/sgo_pack.py`): **byte-exact** inverse — proven on
  69/69 real files. *(Plus `cp_tools/bcb_compress.py`, the inverse of the BCB
  oracle; note it is not VW's real on-disk 1A-escape BCB — documented gap.)*

### Component-Protection research tooling

> Right-to-repair research on the author's own car. See
> [Status & honesty](#status--honesty) and `research/`.

- **J533 + J255 CP probe** (`cp_tools/j533_probe.py`): read constellation DID
  `0x04A3`, sub-DIDs `0x2A2x`, and IKA/GKA keys (`0x00BE` / `0x00BD`) across
  enrolled modules; decode the constellation; (experimentally) start the CP
  routine; emit a full JSON report. Backs the **CP Tools** GUI tab.
- **Gateway CP cipher model** (`cp_tools/gw_cp_cipher.py`): a *proven* software
  model of the J533 LEAR gateway CP cipher (standard AES-128, key
  `"LEAR D4 Gateway."`); 8-vector known-answer test **closed**. `enc`/`dec` CLI.
- **HVAC IKA handshake model** (`cp_tools/hvac_ika_cipher.py`): a faithful 1:1 port
  of the J255 V850 stream+AES key-confirm FSM; `validate()` tests
  `IKA == f(CS, identity)`. **Bit-exactness pending a bench block0 BDM read.**
- **BDM-dump ingest** (`cp_tools/ingest_bdm_dump.py`): splice bench-read cipher
  tables / IKA / CS rows into the HVAC model and run `validate()` for a yes/no
  offline-forge verdict. *(Bench-gated.)*
- **Standalone HVAC CP-bypass flasher** (`flasher/hvac_flash.py`): a plain-block
  UDS flasher for the J255 Climatronic V850 — identify, read block1, apply the
  CP-defrost-limp bypass patch (auto HI/LO select + signature-located guard NOP),
  recompute CRC-16/XMODEM, flash. **Refuses unknown firmware; defaults to
  dry-run.** *(Bench-gated.)*
- **ODX + MWB analyzers** (`cp_tools/odx_parser.py`, `cp_tools/mwb_extract.py`):
  extract CP routine ID, security level, SA2 bytecode, DID/routine maps from ASAM
  ODX, and pull the CP RoutineControl ID from ODIS `.sd.db`.

### Checksums

- `flasher/checksum_simos.py` — **CRC32-VW** (poly `0x4C11DB7`), **ECM3** 64-bit
  summation validate/fix (with early/late ASW1 offset auto-detect), and **Simos
  counter-XOR** encrypt/decrypt.
- `flasher/workshop_code.py` — VW flash workshop-code (DID 0xF15A) generator: BCD
  date + CRC8 of ASW + CAL fingerprint bytes.

### Data logging & diagnostics

- **Live DID logger** (`logger/`): threaded multi-channel poll with scaling, ring
  buffer, and CSV export; gauge grid + configurable interval in the Logger tab.
- **Transmission live data** (`ui/trans_tab.py`, `core/trans_defs.py`): read-only
  telemetry for ZF8HP / DL501 / DQ250 / DQ381 — gear, selector, ATF temp, shaft
  speeds, torque, clutch / line pressure, status flags, with a gear visual.
- **Bus scan + DTCs**: probe every known C7 module address to build an installed
  list, read stored/pending DTCs (UDS `0x19`) against a ~692-entry DTC database
  (`data/dtcs.csv`), and clear them (UDS `0x14`).
- **Passive CAN sniffer** (`lib/connections/can_sniffer.py` + Raw Sniff tab):
  receive-only J2534 raw-CAN capture with software ISO-TP reassembly, UDS service
  decode, and PCAP export — sits on an OBD splitter alongside VCDS / ODIS.

### GUI

- Single **Tkinter** app (`ui/main_window.py`, **v0.3.3**), dark "macOS terminal"
  theme, pure stdlib — no Qt, no web.
- One `ttk.Notebook` with **12 tabs**: Connect · Vehicle · ECU Info · Flash ·
  Flashware · Logger · CP Tools · CP Lab · CP Capture · Raw Sniff · Diagnostics · Trans.
  (Vehicle = live bus scan + module DB; Flashware = offline FRF/SGO repack;
  CP Lab = offline gateway/HVAC CP-cipher bench; CP Capture = live CerberusCAN
  sniff + ISO-TP/VW TP 2.0 decode.)
- Ships as one unsigned Windows x64 EXE and runs the **whole GUI with no hardware**
  via the built-in Simos8.5 simulator.

### Connections

- **ESP32 ISO-TP bridge** over **BLE** (GATT UUID `0xABF0`), **USB-serial**
  (250000 baud), and **WiFi WebSocket** ("FunkBridge") — one `0xF1`-header framing,
  one udsoncan-compatible connection abstraction.
- **J2534** PassThru (Tactrix / Mongoose / VNCI / SL1) with a known-path list +
  Windows-registry (`PassThruSupport.04.04`) auto-detect and a cable probe.
- **Linux SocketCAN** (`SocketCAN_<iface>`).
- **MOCK / DEMO** virtual Simos8.5.
- **CerberusCAN** (a user-built Teensy 4.1 tri-CAN OBD tool): a first-class
  **`CERBERUS`** interface — serial driver + udsoncan connection + auto-detect, plus a
  **CP Capture** tab (live sniff → ISO-TP / VW TP 2.0 decode). The board firmware lives
  outside this repo. See [Connections](#connections).

---

## Install

Windows-first, but the Python source runs anywhere Tkinter does.

### From source

```bash
git clone https://github.com/dspl1236/simos-suite
cd simos-suite
pip install -r requirements.txt
pip install git+https://github.com/bri3d/sa2_seed_key.git
```

Runtime deps (`requirements.txt`): `udsoncan>=1.21`, `bleak>=0.21`,
`pyserial>=3.5`, `python-can>=4.0`, `numpy>=1.24`, `pycryptodome>=3.18`,
`websocket-client>=1.6`, plus `sa2_seed_key` from source. J2534 PassThru DLLs are
loaded at runtime via ctypes — install your cable's DLL separately.

> **Headless / CI install** (no BLE/CAN hardware): just `pip install numpy` +
> `sa2_seed_key` is enough to run the simulator and offline tools.

### Build the EXE yourself

```bat
git clone https://github.com/dspl1236/simos-suite
cd simos-suite
build.bat
```

`build.bat` installs dependencies, runs the headless smoke test, and calls
PyInstaller. Output: `dist\SimosSuite.exe`. (`build.sh` does the same on POSIX.)

Manual build:

```bash
pip install pyinstaller udsoncan bleak pyserial websocket-client numpy pycryptodome python-can
pip install git+https://github.com/bri3d/sa2_seed_key.git
python build_exe.py
```

`build_exe.py` wraps `pyinstaller simos_suite.spec --clean --noconfirm` with a
pre-build smoke test and a spec-patch helper (handles missing icon/version and
toggles UPX). The one-file spec produces `SimosSuite` (console off, logs to
`%TEMP%\simos_suite.log`).

---

## Quick start

### GUI

```bash
# No hardware? Run the full GUI in simulation (mock Simos8.5):
python -m tests.sim_runner
python simos_suite.py --sim

# Headless backend smoke test:
python -m tests.sim_runner --headless
python simos_suite.py --headless

# Real hardware (auto-detects interfaces):
python -m ui
python simos_suite.py            # same app, PyInstaller entry point
python simos_suite.py --ecu SC8 --debug
python simos_suite.py --version
```

### CLI one-liners (these entry points actually exist)

```bash
# --- Containers ---------------------------------------------------------------
# Decrypt an FRF and dump its flash blocks to .bin:
python -m flasher.frf_loader  path/to.frf --outdir out/
python -m flasher.frf_loader  path/to.frf --sa2          # print SA2 script only

# Detect + round-trip the FLASHDATA payload codec in an FRF/ODX:
python -m flasher.payload_codec  path/to.frf

# Unpack an SGO/SGML flashdaten container (auto-detect per-block transform):
python -m cp_tools.sgo_unpack  file.sgo --out out/ --image flat.bin

# Parse an ASAM ODX (CP routine ID, security level, SA2, DID/routine maps):
python -m cp_tools.odx_parser  file.odx  out.json

# --- Module database / bus ----------------------------------------------------
# Look up / filter the C7 module firmware DB:
python -m core.module_db  4G0820043
python -m core.module_db  --candidates           # CP-patch candidates
python -m core.module_db  --signed rsa           # filter by signing

# Scan the live bus for installed modules:
python -m core.module_scan  --iface J2534 --bus CONV

# --- CP research (offline cipher models) --------------------------------------
# J533 gateway CP cipher — known-answer self-test, then forge a record:
python -m cp_tools.gw_cp_cipher                  # selftest (KAT)
python -m cp_tools.gw_cp_cipher  enc  <32-hex-block>

# HVAC IKA handshake model self-test:
python -m cp_tools.hvac_ika_cipher

# Splice a bench BDM dump into the HVAC model and run validate():
python -m cp_tools.ingest_bdm_dump  --codeflash cf.bin --dataflash df.bin

# --- HVAC CP-patch flasher (bench-gated; dry-run by default) -------------------
python -m flasher.hvac_flash  patchfile  in.bin out.bin   # offline patch a block
python -m flasher.hvac_flash  flash      in.bin           # dry-run (add --go to write)
```

> `flasher/frf_pack.py`, `cp_tools/sgo_pack.py`, `cp_tools/bcb_compress.py`,
> `flasher/checksum_simos.py`, `flasher/lzss_compress.py`, and
> `flasher/vin_utils.py` are **library APIs** (no CLI `__main__`) — import them or
> drive them via the test suite.

---

## Connections

Selection is via the Connect tab (`ui/interface_panel.py`): auto-detected
interfaces appear as clickable rows with status dots and bus-type badges, plus a
manual-override combobox. Internally everything dispatches through
`flasher/uds_flash.py:_make_connection`.

| Interface | Key | Notes |
|-----------|-----|-------|
| ESP32 BLE bridge | `BLE` | Scan by GATT UUID `0xABF0`, `0xF1` framing. Flag `0x10` routes to Convenience CAN (MCP2515). |
| ESP32 USB bridge | `USBISOTP` | Same hardware over USB serial @250000. Auto-detected by VID/PID (CP2102 / CH340 / ESP32-S3). |
| CerberusCAN | `CERBERUS` | Teensy 4.1 (PJRC VID `0x16C0`), request-level serial VCI. Live sniff + ISO-TP/VW TP 2.0 decode (CP Capture tab) + udsoncan connection. Bus 1 = 500k diag. |
| ESP32 WiFi (FunkBridge) | `WIFI` | WebSocket transport, same framing, auto URL detect. |
| J2534 PassThru | `J2534` | Tactrix / Mongoose / VNCI / SL1. Path-list + registry auto-detect, probed with PassThruOpen. |
| Linux SocketCAN | `SocketCAN_<iface>` | Linux only (`iso-tp` kernel module). |
| Mock / Demo | `MOCK` | Virtual Simos8.5 — drives the whole GUI with no hardware. |

> **J2534 architecture note:** the published EXE is 64-bit and can only load
> 64-bit J2534 DLLs. Classic cables (Tactrix, Mongoose, VNCI) ship 32-bit DLLs and
> fail in the EXE with `WinError 193` — run those from a 32-bit Python
> (`python -m ui`). For the EXE, use the ESP32 bridge (BLE/USB) or a 64-bit shim.

### CerberusCAN — capture + decode integrated

CerberusCAN is a user-built **Teensy 4.1** board with 3× FlexCAN channels that speaks a
simple serial line protocol (firmware in its own repo). Simos-Suite drives it directly:

- `transport/cerberus_serial.py` — host driver for the real text protocol
  (`PING`/`INFO`/`SNIFF`/`SCAN`/`RAW`/`UDS`/`TP`). It's a **request-level VCI**: the
  firmware runs the ISO-TP transaction on-device and returns the assembled response.
- `transport/cerberus_bridge.py` — a udsoncan `CerberusConnection` over that driver, so
  the suite's UDS stack (reads/writes/routines/SecurityAccess/CP probe) can use it;
  `flasher/uds_flash._make_connection` has a `CERBERUS_COMx` branch and the registry
  auto-detects the board by the PJRC/Teensy VID `0x16C0`.
- `cp_tools/can_decode.py` — reassembles a capture (CSV or frames) over **both** ISO-TP
  **and VW TP 2.0**, labeling UDS/KWP services and flagging the CP-relevant ones
  (TrainICA/GVA, the `0x00BE` IKA write, SecurityAccess).
- **CP Capture** GUI tab — live sniff (Bus 1 = 500k diag, OBD 6/14) with a running frame
  counter, save CSV, and one-click decode.

Proven on a real C7 capture: sub-bus comfort modules (seat, HVAC) decode cleanly over VW
TP 2.0 on the **500k diag CAN** — i.e. ODIS's gateway-routed diagnostics (incl. the CP
handshake) are all visible on Bus 1, so the (LS-FT) comfort head isn't required.

Still firmware-side / future: the comfort head needs an FT transceiver to read the raw
LS-FT segment, and an on-bus VW TP 2.0 *responder* (module emulation) is out of scope.
See `research/cerberuscan-cp-bench-plan.md`.

---

## Project layout

```
simos_suite.py          # single-file entry point / launcher (--ecu/--sim/--headless/--version)
build_exe.py, *.spec    # PyInstaller build (build.bat / build.sh wrappers)
ui/                     # Tkinter GUI — main_window.py (8 tabs), interface_panel, trans_tab/logger
flasher/                # UDS flash engine, FRF loader/pack, payload codec, LZSS, checksums,
                        #   workshop code, VIN utils, HVAC CP flasher
cp_tools/               # CP research — j533_probe, gw_cp_cipher, hvac_ika_cipher, sgo_unpack/pack,
                        #   bcb_compress, odx_parser, mwb_extract, ingest_bdm_dump
core/                   # ecu_defs, trans_defs, module_db, module_scan
transport/              # ble_bridge, ws_bridge, interfaces (auto-detect registry)
lib/connections/        # j2534 (ctypes) + j2534_connection, usb_isotp_connection, can_sniffer
logger/                 # live polling logger engine
data/                   # frf.key, c7_module_db.json (36 modules), dtcs.csv, dtc_lookup
tests/                  # sim_runner (no-HW harness), sim_ecu/sim_trans, unit tests
research/               # CP + packing reverse-engineering writeups (incl. CerberusCAN plan)
docs/                   # flash layouts, ODX findings, Simos8.5 tuning guide, Pages site
```

---

## Testing

```bash
python -m tests              # run all suites (smoke + checksums + ECU + trans + VIN)
python -m tests --headless   # skip GUI simulation (backend only)
python -m tests --ecu SC8    # use Simos18 for the sim tests
python -m tests -v           # verbose
```

The harness (`tests/sim_runner.py`) patches the connection layer to a
`MockConnection` so the full GUI and backend run with no hardware. Individual
modules also have unit tests (`test_checksums`, `test_frf_pack`, `test_sgo_pack`,
`test_sgo_unpack`, `test_module_db`, `test_module_scan`, `test_hvac_flash`,
`test_vin_utils`).

---

## ECU / TCU support

| Key | ECU | Engine | Platform |
|-----|-----|--------|----------|
| `S85` | Simos8.5 | 3.0T TFSI CGWA/B (C7 A6/A7) | **primary target** |
| `SC1` | Simos12 | 2.0T EA888 Gen1/2 | PQ46 |
| `SC2` | Simos12.2 | 2.0T EA888 Gen3 | PQ46 |
| `SC8` | Simos18.1 | 2.0T EA888 Gen3b | MQB |
| `SC8_TTRS` | Simos18.1 | 2.5T EA855 (TTRS/TT) | MQB |
| `SCG` | Simos18.10 | 2.0T EA888 Gen3b Evo | MQB Evo |

| Key | TCU | Gearbox |
|-----|-----|---------|
| `ZF8HP` | ZF 8-speed auto (C7 A6/A7/A8 D4) |
| `DL501` | S-Tronic 7-speed DSG (C7 S6/S7) |
| `DQ250` | 6-speed wet DSG (MQB) |
| `DQ381` | 7-speed dry DSG (MQB) |

ECU/TCU definitions (SA2 scripts, block layouts, CAN IDs, crypto keys/IVs) and the
J533 gateway / J255 HVAC entries live in `core/ecu_defs.py`. The 36-module C7
firmware inventory (arch / supplier / data-format / signing / SA2 / flash-profile /
CP-patch status) is in `data/c7_module_db.json`.

---

## Status & honesty

| Area | Maturity |
|------|----------|
| ECU Info / VIN read · Logger · Trans live data · bus scan · DTC read+clear | **mature** |
| Raw CAN sniff + ISO-TP/UDS decode + PCAP export | **mature** |
| FRF decode · SGO unpack/repack (byte-exact) · LZSS · checksums | **mature** |
| Virtual block read (RequestUpload) + decrypt/decompress | working |
| **ECU/TCU flash WRITE** | **implemented, GUI-disabled** pending hardware validation |
| FRF repack · payload codec · BCB compress | new / functional |
| GUI: Vehicle · Flashware · CP Lab tabs | new — surface the offline tools in the GUI |
| J533 gateway CP cipher model | **proven** (known-answer test closed) |
| HVAC IKA handshake model | **modeled** — bit-exactness bench-pending |
| CP IKA-key write · J533 constellation update · CP routine | **experimental** — unconfirmed on hardware |
| HVAC CP-patch flasher · BDM ingest | **bench-gated** (dry-run default) |
| CerberusCAN capture + ISO-TP/TP 2.0 decode | **working** — driver, connection, CP Capture tab; proven on a real C7 capture |
| CerberusCAN comfort *responder* / raw LS-FT read | **future** — needs an FT transceiver + on-bus TP 2.0 |

**On Component Protection.** This is a right-to-repair effort on the author's own
car — e.g. re-authorizing a used HVAC module you already own without a dealer's live
server session. The CP tooling reads owner-writable records, models
locally-checked symmetric ciphers, and patches firmware on the author's own bench
hardware. **It does not defeat cryptographic signatures.** Several modules
(BCM2, the J533 gateway code blocks) are RSA/AES-signed and are **not** flashable
or extractable with this suite — signatures are a wall, and this README does not
claim otherwise. Anything unconfirmed is labeled unconfirmed. Bench reports and
corrections are welcome.

---

## research/

The `research/` directory holds the CP + container-packing reverse-engineering
writeups behind these tools: C7 CP parts inventory, firmware RE deep-dives,
seat/HVAC IKA verdicts, BIN→FRF/SGO packing notes, BDM read targets, the
CerberusCAN bench/emulation plan, and ECU-swap / zero-constellation test
protocols. `docs/` adds per-module flash layouts, ODX findings, and a Simos8.5
tuning guide. Full CP documentation lives in
[VAG-CP-Docs](https://github.com/dspl1236/VAG-CP-Docs).

---

## Credits

- [bri3d/VW_Flash](https://github.com/bri3d/VW_Flash) — foundational VAG flash
  reverse engineering; the `data/frf.key` rolling-XOR key and much of the
  Simos understanding derive from this work.
- [bri3d/sa2_seed_key](https://github.com/bri3d/sa2_seed_key) — SA2 seed/key
  bytecode interpreter.
- [Switchleg1/esp32-isotp-ble-bridge](https://github.com/Switchleg1/esp32-isotp-ble-bridge) — ESP32 ISO-TP bridge firmware lineage.
- [peterGraf/pbl](https://github.com/peterGraf/pbl) — PBL B-tree library (used for
  ODIS `.sd.db` extraction).
- [VAG-CP-Docs](https://github.com/dspl1236/VAG-CP-Docs) — CP research documentation.

## License

**GPL-3.0.** Free for personal use and right-to-repair. Any modified version must
also be open source. See [LICENSE](LICENSE). No warranty (GPL §15–16).

---

*Built for owners. GPL-3.0. github.com/dspl1236/simos-suite*
