r"""
flasher/payload_codec.py — VAG FLASHDATA payload-codec matrix.

Detect and apply the transform that turns a tuned BIN into the bytes that go
INTO the ODX (the per-block half of BIN->FRF). The on-ODX representation is
signalled authoritatively by the per-FLASHDATA <ENCRYPT-COMPRESS-METHOD>
DataFormatIdentifier (DFI) byte, corroborated by <COMPRESSED-SIZE> presence:

  DFI 0x00  RAW             stored bytes ARE the flash bytes (no transform).
                            -> HVAC 4G0820043 (V850), cluster 4G0909144 (NEC),
                               LEAR gateway 4G/4H0907566 FRF blocks.
  DFI 0x01  SIMOS-XOR       counter XOR  out[i]=in[i]^(i&0xFF), self-inverse,
                            NO compression. -> Simos8.5 engine 4G0907551.
  DFI 0xAA  BOSCH LZSS+AES  decode = AES-128-CBC decrypt -> VW-LZSS decompress
                            -> truncate to UNCOMPRESSED-SIZE;
                            encode = VW-LZSS compress -> AES-128-CBC encrypt.
                            -> Bosch Simos18 (5G0906259 = Simos18.1, etc.).

Round-trip (proven against the real corpus):
  RAW / SIMOS-XOR : BYTE-EXACT (identity / self-inverse).
  BOSCH LZSS+AES  : FUNCTIONAL-ONLY — the decompressed image is byte-identical
                    (so the ECU's CRC/length checks pass), but the compressed
                    stream is not byte-identical to VW's (different match-finder).

The LZSS codec used here is flasher.lzss_compress (the VW-faithful port).

CLI:  py -3 -m flasher.payload_codec <file.frf|file.odx> [--aes simos18.1]
"""
from __future__ import annotations

import argparse
import collections
import math
import xml.etree.ElementTree as ET

from flasher.frf_loader import FrfLoader
from flasher.checksum_simos import xor_encrypt
from flasher.lzss_compress import lzss_compress, lzss_decompress

try:
    from Crypto.Cipher import AES
except Exception:                          # pragma: no cover
    AES = None

# Bosch Simos AES keys (from VW_Flash / Simos-Suite research README).
AES_KEYS = {
    "simos18.1":  ("98D31202E48E3854F2CA561545BA6F2F", "E7861278C508532798BCA4FE451D20D1"),
    "simos18.10": ("AE540502E48E3854DBCA1A1545BA6F33", "62F313FA5C08532798BCA452471D20D5"),
}
DEFAULT_AES = "simos18.1"


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def parse_segments(odx_bytes: bytes):
    """Return [{name, block_num, dfi, uncomp, comp}] for non-ERASE DATABLOCKs.

    The DFI <ENCRYPT-COMPRESS-METHOD> lives on the FLASHDATA element; we map it
    via the DATABLOCK's FLASHDATA-REF. SIZE fields live on the SEGMENT."""
    root = ET.fromstring(odx_bytes)
    fd_dfi = {}
    for fd in root.iter("FLASHDATA"):
        ecm = fd.find("ENCRYPT-COMPRESS-METHOD")
        if ecm is not None and ecm.text:
            try:
                fd_dfi[fd.get("ID", "")] = int(ecm.text.strip(), 16)
            except ValueError:
                pass
    segs = []
    for db in root.iter("DATABLOCK"):
        sn = db.find("SHORT-NAME")
        name = sn.text if sn is not None else "?"
        if name and name.endswith("ERASE"):
            continue
        ref = db.find(".//FLASHDATA-REF")
        dfi = fd_dfi.get(ref.get("ID-REF", "")) if ref is not None else None
        block_num = uncomp = comp = None
        seg = db.find(".//SEGMENT")
        if seg is not None:
            sa = seg.find("SOURCE-START-ADDRESS")
            us = seg.find("UNCOMPRESSED-SIZE")
            csz = seg.find("COMPRESSED-SIZE")
            if sa is not None and sa.text:
                try:
                    block_num = int(sa.text)
                except ValueError:
                    block_num = int(sa.text, 16)
            uncomp = int(us.text) if us is not None and us.text else None
            comp = int(csz.text) if csz is not None and csz.text else None
        segs.append({"name": name, "block_num": block_num, "dfi": dfi,
                     "uncomp": uncomp, "comp": comp})
    return segs


def detect_codec(dfi, has_comp_size: bool) -> str:
    """Map the DFI byte (and COMPRESSED-SIZE presence) to a codec name."""
    if dfi == 0xAA or has_comp_size:
        return "bosch-lzss-aes"
    if dfi == 0x01:
        return "simos-xor"
    if dfi == 0x00 or dfi is None:
        return "raw"
    return "unknown(dfi=0x%02X)" % dfi


def decode_block(stored: bytes, codec: str, uncomp: int | None,
                 aes_name: str = DEFAULT_AES) -> bytes:
    """stored ODX bytes -> flat image."""
    if codec == "raw":
        return stored
    if codec == "simos-xor":
        return xor_encrypt(stored)                 # self-inverse
    if codec == "bosch-lzss-aes":
        if AES is None:
            raise RuntimeError("pycryptodome not available")
        k, iv = (bytes.fromhex(x) for x in AES_KEYS[aes_name])
        n = len(stored) - (len(stored) % 16)
        plain = AES.new(k, AES.MODE_CBC, iv).decrypt(stored[:n])
        img = lzss_decompress(plain)
        return img[:uncomp] if uncomp else img
    raise ValueError("cannot decode codec %r" % codec)


def encode_block(image: bytes, codec: str, aes_name: str = DEFAULT_AES) -> bytes:
    """flat image -> ODX bytes (the inverse of decode_block)."""
    if codec == "raw":
        return image
    if codec == "simos-xor":
        return xor_encrypt(image)                  # self-inverse
    if codec == "bosch-lzss-aes":
        if AES is None:
            raise RuntimeError("pycryptodome not available")
        k, iv = (bytes.fromhex(x) for x in AES_KEYS[aes_name])
        comp = lzss_compress(image, exact_pad=True)
        if len(comp) % 16:
            comp += bytes(16 - len(comp) % 16)
        return AES.new(k, AES.MODE_CBC, iv).encrypt(comp)
    raise ValueError("cannot encode codec %r" % codec)


def analyse(path: str, key_path: str | None = None, aes_name: str = DEFAULT_AES,
            max_pack_bytes: int = 0):
    """Detect the codec per block and round-trip it (diagnostic CLI helper)."""
    loader = FrfLoader(key_path)
    odx = open(path, "rb").read() if path.lower().endswith(".odx") else loader.get_odx(path)
    segs = parse_segments(odx)
    blocks = loader.extract_blocks(path)
    seg_by_bn = {s["block_num"]: s for s in segs if s["block_num"] is not None}

    print("file:", path)
    print("%-6s %-16s %5s %10s %10s %7s  round-trip" %
          ("block", "codec", "dfi", "stored", "uncomp", "ent"))
    for bn in sorted(blocks.keys()):
        stored = blocks[bn]
        seg = seg_by_bn.get(bn, {"dfi": None, "uncomp": len(stored), "comp": None})
        codec = detect_codec(seg["dfi"], seg["comp"] is not None)
        img = b""
        try:
            img = decode_block(stored, codec, seg["uncomp"], aes_name)
            if max_pack_bytes and codec == "bosch-lzss-aes" and len(img) > max_pack_bytes:
                rt = "decode-OK (pack skipped, %d B)" % len(img)
            else:
                repacked = encode_block(img, codec, aes_name)
                redec = decode_block(repacked, codec, seg["uncomp"], aes_name)
                rt = ("BYTE-EXACT" if repacked == stored else
                      ("functional (re-decodes equal; len %d vs %d)" % (len(repacked), len(stored))
                       if redec == img else "FAILED"))
        except Exception as e:
            rt = "decode-err:%s" % e
        dfi_s = "0x%02X" % seg["dfi"] if seg["dfi"] is not None else "  ?"
        print("%-6s %-16s %5s %10d %10s %7.3f  %s" %
              (bn, codec, dfi_s, len(stored),
               seg["uncomp"] if seg["uncomp"] else "?",
               entropy(img[:65536]) if img else 0.0, rt))


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="VAG FLASHDATA payload-codec detect + round-trip")
    ap.add_argument("file", help="FRF or ODX")
    ap.add_argument("--key", default=None, help="frf.key path (default: data/frf.key)")
    ap.add_argument("--aes", default=DEFAULT_AES, choices=list(AES_KEYS))
    ap.add_argument("--max-pack-bytes", type=int, default=0,
                    help="skip the slow Bosch LZSS re-pack on images bigger than this")
    a = ap.parse_args()
    analyse(a.file, a.key, a.aes, a.max_pack_bytes)
