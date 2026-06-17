"""
flasher/frf_pack.py — rebuild a VAG FRF container from edited flash blocks.

The inverse of flasher.frf_loader.FrfLoader.extract_blocks:

    blocks_dict ─▶ edit FLASHDATA <DATA> hex in a template ODX
                ─▶ recompute the per-DATABLOCK CRC32 FW-CHECKSUMs
                ─▶ re-serialize the ODX (preserving template formatting)
                ─▶ ZIP it (single .odx entry, VAG streaming profile)
                ─▶ rolling-XOR encrypt (== _decrypt_frf; the cipher is self-inverse)

PROVEN against the real C7 corpus: extract_blocks(frf_pack(blocks)) == blocks, and
a real block edit survives a full pack→re-extract cycle with its CRC32 auto-updated.

LIMITATIONS (see research/bin-to-frf-sgo-packing.md):
  • FUNCTIONAL, not byte-exact: VAG's ODX is DEFLATE-compressed with an encoder no
    stock zlib level reproduces, so the compressed body differs. This is cosmetic —
    the ECU validates the *decompressed* ODX/blocks, which are bit-identical.
  • Raw <DATA> only (ENCRYPT-COMPRESS-METHOD 0x00). Modules whose ODX stores a codec
    (Simos counter-XOR 0x01, Bosch LZSS+AES 0xAA) must re-encode the payload first —
    use flasher.payload_codec to detect+apply the codec before frf_pack.
  • CRC32-protected modules only. RSA-signed blocks (e.g. HVAC SIG_SHA1-RSA1024) are
    repacked structurally but rejected by the module at flash time (signature wall).
"""
from __future__ import annotations

import io
import re
import zlib
import zipfile
import xml.etree.ElementTree as ET

from flasher.frf_loader import _decrypt_frf


def _replace_flashdata_hex(odx_text: str, fd_id: str, new_hex: str) -> str:
    """Replace one FLASHDATA element's <DATA> hex (by ID), preserving all
    surrounding formatting/whitespace."""
    pat = re.compile(
        r'(<FLASHDATA\b[^>]*\bID="' + re.escape(fd_id) + r'"[^>]*>.*?<DATA>)(.*?)(</DATA>)',
        re.S,
    )
    n = [0]

    def repl(m):
        n[0] += 1
        return m.group(1) + new_hex + m.group(3)

    out = pat.sub(repl, odx_text, count=1)
    if n[0] != 1:
        raise KeyError(f"FLASHDATA ID={fd_id!r} <DATA> not found/replaced (n={n[0]})")
    return out


def _recompute_crc32(odx_text: str, validity_for: str, data: bytes):
    """Update the FW-CHECKSUM (CRC32) of the SECURITY block whose VALIDITY-FOR ==
    validity_for. CRC = zlib.crc32 (CRC-32/ISO-HDLC) over the raw block bytes.
    Returns (modified_text, replacements_made, crc_hex)."""
    crc = format(zlib.crc32(data) & 0xFFFFFFFF, "08X")
    pat = re.compile(
        r'(<SECURITY>\s*<SECURITY-METHOD[^>]*>CRC32</SECURITY-METHOD>\s*'
        r'<FW-CHECKSUM[^>]*>)([0-9A-Fa-f]+)(</FW-CHECKSUM>\s*'
        r'<VALIDITY-FOR[^>]*>' + re.escape(validity_for) + r'</VALIDITY-FOR>)',
        re.S,
    )
    cnt = [0]

    def repl(m):
        cnt[0] += 1
        return m.group(1) + crc + m.group(3)

    out = pat.sub(repl, odx_text)
    return out, cnt[0], crc


def _zip_odx(odx_name: str, odx_bytes: bytes, date_time, ext_attr: int = 0) -> bytes:
    """Produce a ZIP byte-stream matching the VAG profile: single deflate entry,
    data-descriptor flag (0x08), DOS attrs, no extra field. Python's zipfile
    emits exactly this when writing to a NON-SEEKABLE sink (otherwise it
    back-patches the local header and clears the descriptor flag)."""

    class _NonSeek(io.RawIOBase):
        def __init__(self):
            self.buf = bytearray()

        def writable(self):
            return True

        def write(self, b):
            self.buf += b
            return len(b)

        def seekable(self):
            return False

        def tell(self):
            return len(self.buf)

    sink = _NonSeek()
    zi = zipfile.ZipInfo(odx_name, date_time=date_time)
    zi.compress_type = zipfile.ZIP_DEFLATED
    zi.create_system = 0          # DOS/FAT
    zi.external_attr = ext_attr
    with zipfile.ZipFile(sink, "w") as zf:
        with zf.open(zi, "w") as fp:
            fp.write(odx_bytes)
    return bytes(sink.buf)


def frf_pack(blocks_dict: dict, template_odx: bytes, frf_key: bytes,
             odx_name: str, zip_date_time=None, recompute_crc: bool = True) -> bytes:
    """Rebuild an FRF from edited flash blocks.

    Args:
        blocks_dict:  {block_number(int): raw bytes} keyed by SOURCE-START-ADDRESS
                      (the same numbering FrfLoader.extract_blocks returns).
        template_odx: ODX XML bytes to start from (FrfLoader.get_odx(orig_frf)).
        frf_key:      frf.key bytes.
        odx_name:     filename stored inside the ZIP (e.g. 'FL_xxx.odx').
        zip_date_time: (y,m,d,H,M,S) tuple; default (1980,1,1,0,0,0).
        recompute_crc: update the CRC32 FW-CHECKSUM for each edited block.

    Returns: encrypted FRF bytes.
    """
    text = template_odx.decode("utf-8")
    root = ET.fromstring(template_odx)

    # Map block_number -> FLASHDATA id  AND  block_number -> DATABLOCK short-name.
    num_to_fd, num_to_db = {}, {}
    for db in root.iter("DATABLOCK"):
        sn = db.find("SHORT-NAME")
        if sn is None or (sn.text or "").endswith("ERASE"):
            continue
        segs = db.find("SEGMENTS")
        num = None
        if segs is not None:
            for seg in segs:
                a = seg.find("SOURCE-START-ADDRESS")
                if a is not None and a.text:
                    try:
                        num = int(a.text)
                    except ValueError:
                        num = int(a.text, 16)
                    break
        ref = db.find(".//FLASHDATA-REF")
        if num is not None and ref is not None:
            num_to_fd[num] = ref.get("ID-REF")
            num_to_db[num] = sn.text

    for num, data in blocks_dict.items():
        fd_id = num_to_fd.get(num)
        if fd_id is None:
            raise KeyError(f"block {num} has no FLASHDATA in template")
        text = _replace_flashdata_hex(text, fd_id, data.hex().upper())
        if recompute_crc:
            text, _cnt, _crc = _recompute_crc32(text, num_to_db[num], data)

    new_odx = text.encode("utf-8")
    if zip_date_time is None:
        zip_date_time = (1980, 1, 1, 0, 0, 0)
    zip_bytes = _zip_odx(odx_name, new_odx, zip_date_time)
    return _decrypt_frf(frf_key, zip_bytes)   # encrypt == decrypt
