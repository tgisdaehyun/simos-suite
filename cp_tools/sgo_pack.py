"""
cp_tools/sgo_pack.py — SGML Object File (.sgo) CONTAINER packer.

Inverse of cp_tools.sgo_unpack at the container level. PROVEN byte-exact: a
structural re-pack reproduces the original file bit-for-bit on 69/69 real .sgo
files (gateway 4G0907566, BCM2 8K0907064, DSG v069*, Bentley, VW), and a decoded
block re-encoded through cp_tools.bcb_compress re-parses identically.

=== SGML Object File container layout (reverse-engineered, byte-exact) ===

  0x00  16   magic         b"SGML Object File"
  0x10  u16  format/ver    0x0002 (LE)            (constant across corpus)
  0x12  u16  reserved      0x0000
  0x14  u8   reserved      0x00                    (NOT part of the checksum)
  0x15  u32  CHECKSUM      LE 32-bit container checksum (see below)
                           -- stored bytes are d[0x15:0x19]; byte 0x18 is the
                              high byte of this same word, so to a naive reader
                              d[0x14:0x18] "looks" like the field.
  0x19  u32  idx_ident     LE file offset of the IDENT section (always 0x31)
  0x1D  u32  ptr_A         LE offset (->0x13E; a zero/reserved sub-block)
  0x21  u32  ptr_B         LE offset (->0x192; the 0d/10/0c size-triplet area)
  0x25  u32  ptr_C         LE offset (->0x1B2; the 01-flag area)
  0x29  u32  meta_start    LE offset of the SA2/security section
  0x2D  u32  end           LE offset of the trailing block-index table
  0x31  ...  IDENT         per-block-independent identity blob (len 0x186):
                 +0x000  PN   260 bytes, 0xFF-XOR'd ASCII, null-padded ("...sgm")
                 +0x104  SW     5 bytes, 0xFF-XOR'd ASCII
                 +0x109  u32  a count/flag (e.g. 0x14, 0x28, 0x1E, 0x1AF)
                 ...     zero padding + the ptr_A/B/C target structures
  meta_start    u32  meta_len ; then meta_len bytes of SA2 bytecode
  meta_start+4+meta_len .. end : the BLOCK DATA region (sequential blocks)
  end           u32  block_count ; then block_count * u32 absolute file offsets

  Per-block descriptor (0x19 = 25 bytes), big-endian 24-bit words:
    +0x00  u24 BE  load address
    +0x03  u8      crypt byte (0x00 plain, 0x01 AES, 0x0B AES-EEPROM,
                               0x10 BCB-compressed)
    +0x04  u24 BE  declen (decoded/logical size; end-start, sometimes actual-1)
    +0x07  u24 BE  erase_start
    +0x0A  u24 BE  erase_end
    +0x0D  u24 BE  prog_start
    +0x10  u24 BE  prog_end
    +0x13  u16     (reserved / flags — copied verbatim)
    +0x15  u32 LE  blob_len  (length of the block body that follows)
    +0x19  ...     blob_len bytes of block body (0xFF-XOR'd payload)

=== Container checksum (offset 0x15, u32 LE) ===
  Operational rule (verified byte-exact over 18 real files, valid on 69/69):
      1. zero the 4 checksum bytes d[0x15:0x19]
      2. S = sum(every byte in the file) & 0xFFFFFFFF
      3. store (S - 1) & 0xFFFFFFFF, little-endian, into d[0x15:0x19]
  (d[0x14] is a separate reserved 0x00 byte, NOT part of the field.) The earlier
  "whole-file byte-sum equals 1" framing was an artifact of reading the wrong
  4-byte window [0x14:0x18]; the rule above is the empirically-correct one and
  matches fix_checksum()/verify_checksum() below.

This packer's default mode rebuilds a container from a *parsed* source by
re-emitting blocks and recomputing the trailer + checksum, preserving the
header/IDENT region verbatim -> byte-exact round-trip.

CAVEAT — a repacked .sgo will NOT flash a real ECU as-is: the module still
enforces UDS SecurityAccess and, where present, per-block signature/CP gates that
live in firmware, not in the container. AES-locked blocks (crypt 0x01/0x0B, e.g.
BCM2/DSG) can only be re-packed verbatim (no key to re-encrypt). And the
crypt=0x10 BCB path here matches cp_tools.sgo_unpack's decoder oracle, NOT VW's
real on-disk 1A-escape BCB stream — see cp_tools.bcb_compress.
"""
import struct

MAGIC = b"SGML Object File"
CK_OFF = 0x15          # checksum u32 LE offset (bytes d[0x15:0x19])
CK_BIAS = 1            # field = (sum_of_file_with_field_zeroed - CK_BIAS) & 0xFFFFFFFF


def _w24be(v: int) -> bytes:
    return bytes([(v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])


def fix_checksum(buf: bytearray) -> None:
    """Set the u32-LE container checksum at d[0x15:0x19] (see module docstring)."""
    buf[CK_OFF:CK_OFF + 4] = b"\x00\x00\x00\x00"
    s = sum(buf) & 0xFFFFFFFF
    ck = (s - CK_BIAS) & 0xFFFFFFFF
    buf[CK_OFF:CK_OFF + 4] = struct.pack("<I", ck)


def verify_checksum(buf: bytes) -> bool:
    """True if d[0x15:0x19] holds the correct checksum for the file."""
    stored = struct.unpack_from("<I", buf, CK_OFF)[0]
    z = bytearray(buf)
    z[CK_OFF:CK_OFF + 4] = b"\x00\x00\x00\x00"
    s = sum(z) & 0xFFFFFFFF
    return stored == ((s - CK_BIAS) & 0xFFFFFFFF)


def repack(src: bytes, block_bodies: list | None = None) -> bytes:
    """Rebuild an .sgo from raw source bytes.

    If block_bodies is None: re-emit each block body byte-for-byte from src
    (pure structural round-trip -> byte-exact).
    If block_bodies is given: substitute each block's body (already 0xFF-XOR'd,
    BCB/plain as appropriate); descriptor blob_len + trailer + checksum are
    recomputed. declen is preserved from the source descriptor unless the caller
    patched it.
    """
    def w32(d, p):
        return struct.unpack_from("<I", d, p)[0]

    meta_start = w32(src, 0x29)
    meta_len = w32(src, meta_start)
    end_old = w32(src, 0x2D)
    blk_region_start = meta_start + 4 + meta_len

    # parse descriptors + bodies from src
    descs, bodies = [], []
    pos = blk_region_start
    while pos + 0x19 <= end_old:
        blob_len = w32(src, pos + 0x15)
        descs.append(src[pos:pos + 0x19])      # 25-byte descriptor verbatim
        bodies.append(src[pos + 0x19: pos + 0x19 + blob_len])
        pos += 0x19 + blob_len

    if block_bodies is not None:
        assert len(block_bodies) == len(bodies), "body count mismatch"
        bodies = list(block_bodies)

    # emit header+IDENT+meta region verbatim up to blk_region_start
    out = bytearray(src[:blk_region_start])

    # emit blocks, record offsets, patch blob_len in each descriptor
    offsets = []
    for desc, body in zip(descs, bodies):
        offsets.append(len(out))
        d = bytearray(desc)
        struct.pack_into("<I", d, 0x15, len(body))   # blob_len
        out += d
        out += body

    # trailer (block index): u32 count, then u32 offset per block
    struct.pack_into("<I", out, 0x2D, len(out))      # update 'end' pointer
    out += struct.pack("<I", len(offsets))
    for o in offsets:
        out += struct.pack("<I", o)

    # checksum last
    fix_checksum(out)
    return bytes(out)
