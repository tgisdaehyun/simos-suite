#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hvac_ika_cipher.py -- Faithful standalone Python model of the Audi C7 (4G0820043
2-zone "LO" Climatronic) HVAC Component-Protection IKA / key-confirm handshake.

SOURCE OF TRUTH
  Decompile : D:\\CP\\datadb\\hvac_LO_all.c   (installed 2-zone "LO" variant)
  Binary    : D:\\CP\\datadb\\hvac_LO_block1.bin
  Base      : 0x10000  (file_off = program_addr - 0x10000)   CONFIRMED
              file 0x59d16 == program addr 0x69d16
  Tables    : verified present & STANDARD in hvac_LO_block1.bin
                file 0x25b0 (addr 0x125b0)  AES forward S-box
                file 0x26b0 (addr 0x126b0)  AES inverse S-box
                file 0x27b0 (addr 0x127b0)  xtime  (GF(2^8) mul-by-2)
                file 0x28e0 (addr 0x128e0)  Rcon   01 02 04 08 10 20 40 80 1b 36

CRITICAL ADDRESSING NOTE (read before trusting any output)
  The cipher functions index a table at PROGRAM ADDRESS 0xd5b0 (and 0xd6b0,
  0xd7b0). 0xd5b0 < 0x10000 => that table lives in the UNDUMPED block0
  bootloader. The bytes at *file* 0xd5b0 are NOT that table.
  Because:
    - FUN_0006e7d8 performs textbook AES ShiftRows / MixColumns,
    - the three tables it uses sit at 0xd5b0 / 0xd6b0 / 0xd7b0 -- the same
      +0x100 spacing as the verified file tables 0x25b0 / 0x26b0 / 0x27b0,
    - the sibling J533 gateway CP cipher was independently confirmed to be
      plain AES-128 (see gw_cp_cipher.py),
  we MODEL:
        table @ 0xd5b0  ==  standard AES S-box      (file 0x25b0 bytes)
        table @ 0xd6b0  ==  standard AES inverse S-box (file 0x26b0 bytes)
        table @ 0xd7b0  ==  xtime / GF mul-by-2      (file 0x27b0 bytes)
  This is an ASSUMPTION (block0 not dumped). validate() confirms or refutes it.

  A SECOND, HARDER unknown: the AES *round keys*. FUN_0005c466 -> FUN_0006af34
  -> FUN_0006ae50 loads a 16-byte round key from `slot*0x10 - 0xb000`
  (program addr; also undumped block0) and hands the heavy lifting to
  FUN_000800c4. The handshake AddRoundKey (FUN_0006e6be) XORs the working
  buffer with `*(gp-0x7e48)` = the IKA row0 buffer (gp-0x7e90). So the IKA is
  used as the AES key for the handshake, but the static key SCHEDULE for the
  CP-verify slots 5/6/7 (FUN_0006dd54) lives in block0 and is NOT recoverable
  from block1 alone. This module therefore computes the *handshake* derivation
  faithfully (key = IKA/CS), and clearly flags the slot5/6/7 CP-verify path as
  needing block0.

PORTED FUNCTIONS (hvac_LO_all.c line numbers cited per method docstring)
  FUN_0006e6be @47341   16/N-byte XOR                       -> _xor_into
  FUN_0006e6a0 @47324   N-byte copy                          -> _memcpy
  FUN_0006e670 @47304   8/N-byte compare (early-exit)        -> _memcmp_neq
  FUN_0006e6e0 @47358   stream forward round                 -> stream_round_fwd
  FUN_0006e75e @47392   stream reverse round                 -> stream_round_rev
  FUN_0006e7d8 @47426   2462B AES-like resumable state mc.   -> aes_step / aes_run
  FUN_0006f176 @47758   wrapper: init encrypt path           -> drv_init_enc
  FUN_0006f1d6 @47781   3-round stream driver                -> drv_three_stream
  FUN_00075624 @53587   2-round key-confirm handshake        -> key_confirm
  FUN_0006f282 @47860   message handler / buffer wiring      -> msg_setup
  FUN_0006dd54 @46633   CP verify FSM                        -> cp_verify_fsm
  FUN_0005c452 @27941   AES dispatch (set slot/dir/buf)      -> aes_dispatch_set
  FUN_0005c466 @27956   AES engine driver                    -> aes_engine_step
  FUN_0006ae50 @43745   AES enc round-key load + FUN_800c4    -> (aes_engine_step)
  FUN_0006e258 @46983   row index -> ptr map (row0->gp-7f8c) -> row_map_get
  FUN_0006e42e @47173   row write (row0=gp-7e90, etc.)       -> row_write
  FUN_0006e3e2 @47146   bounded copy w/ zero-pad             -> bounded_copy

SHARED gp-RELATIVE STATE  (modeled as the `State` class; see state_model below)
  gp-0x7f40  working buffer (16B)      -- AES/stream working register
  gp-0x7f31..34 (4 state bytes)        -- stream round S-box selectors
  gp-0x7f30  pointer-to-working (=gp-0x7f40 region used as the 16B AES block)
  gp-0x7f28  stream byte pointer (++ fwd / -- rev)
  gp-0x7f22  AES resumable state counter
  gp-0x7f20/21/24/23/1f  AES round / scratch counters
  gp-0x7e90  IKA / current master key V (row 0)   <- the KEY
  gp-0x7e70  V (new key produced by round 1 of key-confirm)
  gp-0x7e60  reversed/inverted scratch copy
  gp-0x7e48  KEY pointer (-> gp-0x7e90 = IKA)
  gp-0x7ef8  message / challenge buffer (16B)
  gp-0x7f64  CP-verify AES output buffer (AES(challenge, slot6))
  gp-0x7f8c  pointer to stored IKA row0 (set by row_map_get(0,...))
  gp-0x7eb0 / 7ea0 / 7e80  rows 100 / 0x65 / 0x66

SCOPE: RE of firmware the researcher owns, on the researcher's own vehicle.
"""

import struct

# ---------------------------------------------------------------------------
# Verified standard AES tables (the 0xd5b0/0xd6b0/0xd7b0 model -- see header).
# These are the literal bytes at file 0x25b0 / 0x26b0 / 0x27b0 / 0x28e0 of
# hvac_LO_block1.bin (confirmed standard FIPS-197 values).
# ---------------------------------------------------------------------------
SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")

# INV_SBOX is built programmatically from SBOX (faithfully equal to the file
# bytes at 0x26b0, which were verified to be exactly this inverse) so there is
# no risk of a transcription error.
_inv = bytearray(256)
for _i, _v in enumerate(SBOX):
    _inv[_v] = _i
INV_SBOX = bytes(_inv)

# xtime table @ 0xd7b0 == file 0x27b0 == GF(2^8) multiply-by-2 (verified 00 02 04 06 ...)
XTIME = bytes(((i << 1) ^ 0x1b) & 0xff if (i & 0x80) else (i << 1) & 0xff
              for i in range(256))

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _gmul(a, b):
    """GF(2^8) multiply (used only by the standalone reference AES below)."""
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return r


# ===========================================================================
# Shared gp-relative state.  Every buffer below is a fixed slice of one flat
# byte array indexed by the SAME negative offsets the firmware uses, so the
# 1:1 ports can read/write exactly as the decompile does.
# ===========================================================================
class State:
    """Models the gp-relative RAM window the HVAC cipher operates on.

    The firmware addresses everything as *(gp + neg_off).  We allocate a flat
    buffer and translate each named region to a (base,len) slice.  Offsets are
    the literal gp-relative offsets from hvac_LO_all.c.
    """

    OFF_WORK   = -0x7f40   # 16B working buffer (FUN_0006e6e0 / FUN_0006e7d8)
    OFF_S31    = -0x7f31   # stream state byte (selector)  bVar4
    OFF_S32    = -0x7f32   # bVar2/bVar3
    OFF_S33    = -0x7f33   # bVar1
    OFF_S34    = -0x7f34   # bVar5
    OFF_PWORK  = -0x7f30   # pointer: the 16B AES block (piVar14)
    OFF_STREAM = -0x7f28   # stream byte pointer (++/--)
    OFF_STATE  = -0x7f22   # AES resumable state counter
    OFF_RND    = -0x7f20   # AES round counter
    OFF_LAST   = -0x7f21   # final-round flag
    OFF_TMP24  = -0x7f24   # scratch
    OFF_TMP23  = -0x7f23   # scratch
    OFF_I1F    = -0x7f1f   # inner loop counter
    OFF_MIX    = -0x7f2c   # MixColumns 4-byte scratch (-0x7f2c..-0x7f29)

    OFF_IKA    = -0x7e90   # row 0 : IKA / current master key V   (the KEY)
    OFF_V      = -0x7e70   # round-1 produced key V
    OFF_VNEG   = -0x7e60   # ~challenge scratch
    OFF_ROW100 = -0x7eb0   # row 100
    OFF_ROW65  = -0x7ea0   # row 0x65
    OFF_ROW66  = -0x7e80   # row 0x66
    OFF_MSG    = -0x7ef8   # message / challenge buffer
    OFF_CPOUT  = -0x7f64   # CP-verify AES(challenge,slot6) output
    OFF_STORED = -0x7f8c   # pointer slot: stored IKA row0 pointer

    SIZE = 0x8000

    def __init__(self):
        self.mem = bytearray(self.SIZE)
        self._block_off = -0x7e20            # scratch home for the 16B AES block
        self.stream_bytes = b""
        self.stream_pos = 0
        self.aes_dir = 0                     # 0=enc 1=dec  (gp-0x7fec/-0x7fed)
        self.aes_slot = 0                    # key slot     (gp-0x7fea/-0x7feb)
        self.aes_outptr = None               # output buffer (gp-0x7ffc/-0x8000)
        self.aes_inbuf = bytearray(16)       # working AES buf (gp-0x7fdc)
        self.round_keys = None               # dict slot -> 16B round key

    # ---- gp-relative byte access (the firmware primitive) -----------------
    def _i(self, gpoff):
        return gpoff + 0x8000

    def gb(self, gpoff):                      # *(byte*)(gp+gpoff)
        return self.mem[self._i(gpoff)]

    def sb(self, gpoff, val):                 # *(byte*)(gp+gpoff) = val
        self.mem[self._i(gpoff)] = val & 0xff

    def gbuf(self, gpoff, n):                 # read n bytes at gp+gpoff
        b = self._i(gpoff)
        return bytes(self.mem[b:b + n])

    def sbuf(self, gpoff, data):              # write bytes at gp+gpoff
        b = self._i(gpoff)
        self.mem[b:b + len(data)] = data

    # ---- the 16-byte AES block (what *(gp-0x7f30) points at) --------------
    @property
    def block(self):
        b = self._i(self._block_off)
        return self.mem[b:b + 16]

    def block_get(self, idx):
        return self.mem[self._i(self._block_off) + idx]

    def block_set(self, idx, val):
        self.mem[self._i(self._block_off) + idx] = val & 0xff

    def block_load(self, data16):
        self.sbuf(self._block_off, data16[:16])
        self.sb(self.OFF_PWORK, self._block_off & 0xff)

    # ---- stream byte source (gp-0x7f28 pointer) ---------------------------
    def stream_init(self, data):
        self.stream_bytes = bytes(data)
        self.stream_pos = 0

    def stream_next_fwd(self):
        """FUN_0006e6e0: read *ptr then ptr++."""
        if self.stream_pos < len(self.stream_bytes):
            b = self.stream_bytes[self.stream_pos]
        else:
            b = 0
        self.stream_pos += 1
        return b

    def stream_next_rev(self):
        """FUN_0006e75e: ptr-- then read *ptr."""
        self.stream_pos -= 1
        if 0 <= self.stream_pos < len(self.stream_bytes):
            return self.stream_bytes[self.stream_pos]
        return 0


# ===========================================================================
# 1:1 PORTS
# ===========================================================================
def _xor_into(st, dst_off, src_off, n):
    """FUN_0006e6be @47341 -- *dst[i] ^= *src[i] for i in 0..n-1.

      for (; param_3 != 0; param_3--) { *p1 ^= *p2; p1++; p2++; }
    """
    for i in range(n):
        st.sb(dst_off + i, st.gb(dst_off + i) ^ st.gb(src_off + i))


def _xor_block_with_key(st, key16):
    """AddRoundKey form used in FUN_0006e7d8: block ^= key (16B).
    (FUN_0006e6be(*piVar14, gp-0x7f40, 0x10) XORs the AES block with the
    working buffer gp-0x7f40.)"""
    for i in range(16):
        st.block_set(i, st.block_get(i) ^ key16[i])


def _memcpy(st, dst_off, src_bytes, n):
    """FUN_0006e6a0 @47324 -- byte copy, n bytes."""
    st.sbuf(dst_off, bytes(src_bytes[:n]))


def _memcmp_neq(a, b, n):
    """FUN_0006e670 @47304 -- returns True (nonzero) on first mismatch within
    n&0xff bytes, else False (equal).  Early-exit compare.

      uVar2=0; do { bVar1 = a[uVar2]!=b[uVar2];
                    uVar2=(uVar2+1)&0xff;
                    if ((param_3&0xff) <= uVar2) return bVar1;
                  } while(!bVar1); return bVar1;
    """
    n &= 0xff
    u = 0
    bVar1 = False
    while True:
        bVar1 = (a[u] != b[u])
        u = (u + 1) & 0xff
        if n <= u:
            return bVar1
        if bVar1:
            return bVar1


def bounded_copy(st, src_off, src_len, dst_off, dst_len):
    """FUN_0006e3e2 @47146 -- copy src_len bytes to dst, zero-padding /
    truncating to dst_len (both masked to 0xff)."""
    src_len &= 0xff
    dst_len &= 0xff
    if src_len <= dst_len:
        for u in range(dst_len):
            v = st.gb(src_off + u) if u < src_len else 0
            st.sb(dst_off + u, v)
    else:
        for u in range(dst_len):
            st.sb(dst_off + u, st.gb(src_off + u))


# ---- stream rounds --------------------------------------------------------
def stream_round_fwd(st):
    """FUN_0006e6e0 @47358 -- forward stream round.

    bVar1 = SBOX[ state(-0x7f33) ]
    bVar2 = *stream++             (gp-0x7f28)
    bVar3 = SBOX[ state(-0x7f32) ]
    bVar4 = SBOX[ state(-0x7f31) ]
    bVar5 = SBOX[ state(-0x7f34) ]
    work[0] ^= bVar2 ^ bVar1
    work[1] ^= bVar3
    work[3] ^= bVar5
    work[2] ^= bVar4
    for i in 0..0xb:  work[i+4] ^= work[i]      (forward diffusion)
    """
    bVar1 = SBOX[st.gb(State.OFF_S33)]            # -0x7f33
    bVar2 = st.stream_next_fwd()                   # *gp-0x7f28; ptr++
    bVar3 = SBOX[st.gb(State.OFF_S32)]            # -0x7f32
    bVar4 = SBOX[st.gb(State.OFF_S31)]            # -0x7f31
    bVar5 = SBOX[st.gb(State.OFF_S34)]            # -0x7f34
    w0 = State.OFF_WORK                            # -0x7f40
    st.sb(w0 + 0, st.gb(w0 + 0) ^ bVar2 ^ bVar1)
    st.sb(w0 + 1, st.gb(w0 + 1) ^ bVar3)
    st.sb(w0 + 3, st.gb(w0 + 3) ^ bVar5)
    st.sb(w0 + 2, st.gb(w0 + 2) ^ bVar4)
    for i in range(0xc):                           # 0..0xb
        st.sb(w0 + i + 4, st.gb(w0 + i + 4) ^ st.gb(w0 + i))


def stream_round_rev(st):
    """FUN_0006e75e @47392 -- reverse stream round.

    for i = 0xb downto 0:  work[i+4] ^= work[i]   (backward diffusion)
    ptr--  (gp-0x7f28); b = *ptr
    bVar2 = SBOX[state(-0x7f32)]
    bVar3 = SBOX[state(-0x7f31)]
    bVar4 = SBOX[state(-0x7f34)]
    work[0] ^= *ptr ^ SBOX[state(-0x7f33)]
    work[2] ^= bVar3
    work[1] ^= bVar2
    work[3] ^= bVar4
    """
    w0 = State.OFF_WORK
    iVar5 = 0xb
    while True:
        iVar1 = iVar5 - 1
        st.sb(w0 + iVar5 + 4, st.gb(w0 + iVar5 + 4) ^ st.gb(w0 + iVar5))
        iVar5 -= 1
        if not (-1 < iVar1):
            break
    b = st.stream_next_rev()                       # ptr--; *ptr
    bVar2 = SBOX[st.gb(State.OFF_S32)]
    bVar3 = SBOX[st.gb(State.OFF_S31)]
    bVar4 = SBOX[st.gb(State.OFF_S34)]
    st.sb(w0 + 0, st.gb(w0 + 0) ^ b ^ SBOX[st.gb(State.OFF_S33)])
    st.sb(w0 + 2, st.gb(w0 + 2) ^ bVar3)
    st.sb(w0 + 1, st.gb(w0 + 1) ^ bVar2)
    st.sb(w0 + 3, st.gb(w0 + 3) ^ bVar4)


# ---- AES-like resumable state machine pieces -----------------------------
def _sub_shift_fwd(st):
    """SubBytes + forward ShiftRows on the 16B AES block, as the inline code in
    FUN_0006e7d8 state 1/3 (column-major AES layout, S-box @0xd5b0)."""
    b = [st.block_get(i) for i in range(16)]
    b[0] = SBOX[b[0]]; b[4] = SBOX[b[4]]; b[8] = SBOX[b[8]]; b[12] = SBOX[b[12]]
    t = b[1]
    b[1] = SBOX[b[5]]; b[5] = SBOX[b[9]]; b[9] = SBOX[b[13]]; b[13] = SBOX[t]
    t = b[2]; b[2] = SBOX[b[10]]; b[10] = SBOX[t]
    t = b[6]; b[6] = SBOX[b[14]]; b[14] = SBOX[t]
    t = b[3]; b[3] = SBOX[b[15]]; b[15] = SBOX[b[11]]; b[11] = SBOX[b[7]]; b[7] = SBOX[t]
    for i in range(16):
        st.block_set(i, b[i])


def _sub_shift_inv(st):
    """SubBytes(inv) + inverse ShiftRows -- FUN_0006e7d8 state 6/8 (inv S-box
    @0xd6b0; inverse row rotates)."""
    b = [st.block_get(i) for i in range(16)]
    b[0] = INV_SBOX[b[0]]; b[4] = INV_SBOX[b[4]]; b[8] = INV_SBOX[b[8]]; b[12] = INV_SBOX[b[12]]
    t = b[1]
    b[1] = INV_SBOX[b[13]]; b[13] = INV_SBOX[b[9]]; b[9] = INV_SBOX[b[5]]; b[5] = INV_SBOX[t]
    t = b[2]; b[2] = INV_SBOX[b[10]]; b[10] = INV_SBOX[t]
    t = b[6]; b[6] = INV_SBOX[b[14]]; b[14] = INV_SBOX[t]
    t = b[3]; b[3] = INV_SBOX[b[7]]; b[7] = INV_SBOX[b[11]]; b[11] = INV_SBOX[b[15]]; b[15] = INV_SBOX[t]
    for i in range(16):
        st.block_set(i, b[i])


def _mixcolumns_fwd(st):
    """Forward MixColumns, FUN_0006e7d8 state-2 block @47521.
    Uses xtime table (0xd7b0): for each column (a0..a3):
       tmp = a0^a1^a2^a3
       a0' = a0 ^ tmp ^ xtime(a0^a1)
       a1' = a1 ^ tmp ^ xtime(a1^a2)
       a2' = a2 ^ tmp ^ xtime(a2^a3)
       a3' = a3 ^ tmp ^ xtime(a3^a0)
    (standard xtime optimization of MixColumns).
    """
    b = [st.block_get(i) for i in range(16)]
    for col in range(4):
        i = col * 4
        a0, a1, a2, a3 = b[i], b[i + 1], b[i + 2], b[i + 3]
        tmp = a0 ^ a1 ^ a2 ^ a3
        b[i + 0] = a0 ^ tmp ^ XTIME[a0 ^ a1]
        b[i + 1] = a1 ^ tmp ^ XTIME[a1 ^ a2]
        b[i + 2] = a2 ^ tmp ^ XTIME[a2 ^ a3]
        b[i + 3] = a3 ^ tmp ^ XTIME[a3 ^ a0]
    for i in range(16):
        st.block_set(i, b[i])


def _mixcolumns_inv(st):
    """Inverse MixColumns, FUN_0006e7d8 state-7 block @47691.  The decompile
    builds the 9/11/13/14 multiplies by chained xtime (bVar10=xtime, bVar1=^2,
    bVar2=^3); net effect is the standard inverse MixColumns matrix."""
    b = [st.block_get(i) for i in range(16)]
    out = list(b)
    m = [[14, 11, 13, 9],
         [9, 14, 11, 13],
         [13, 9, 14, 11],
         [11, 13, 9, 14]]
    for col in range(4):
        i = col * 4
        a = b[i:i + 4]
        col_out = [0, 0, 0, 0]
        for r in range(4):
            acc = 0
            for c in range(4):
                acc ^= _gmul(a[c], m[r][c])
            col_out[r] = acc
        out[i:i + 4] = col_out
    for i in range(16):
        st.block_set(i, out[i])


def aes_run(st, key16, decrypt=False):
    """Drive the FUN_0006e7d8 state machine to completion for ONE 16-byte block,
    with `key16` as the AddRoundKey key (= IKA in the handshake).

    This is the closed-form equivalent of repeatedly calling FUN_0006e7d8 with
    its gp-0x7f22 state counter advancing 1->...->done (init by FUN_0006f176
    for encrypt; FUN_0006f1d6 pre-streams 3 rounds then state=4).  Because the
    block0 round-key schedule is NOT available, this models the handshake AES
    as standard AES-128 keyed by `key16` -- the documented assumption.

    Faithful to structure (SubBytes/ShiftRows/MixColumns/AddRoundKey via the
    0xd5b0/0xd6b0/0xd7b0 tables), NOT a guarantee of the round-key source.
    """
    if decrypt:
        return _ref_aes_decrypt(bytes(st.block), key16)
    return _ref_aes_encrypt(bytes(st.block), key16)


# ---- a clean reference AES-128 (column-major, matches the inline ops) -----
def _key_expansion(key):
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[x] for x in t]
            t[0] ^= RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return w


def _to_state(b):
    return [[b[r + 4 * c] for c in range(4)] for r in range(4)]


def _from_state(s):
    return bytes(s[r][c] for c in range(4) for r in range(4))


def _ref_aes_encrypt(pt, key):
    s = _to_state(pt)
    w = _key_expansion(key)
    for c in range(4):
        for r in range(4):
            s[r][c] ^= w[c][r]
    for rnd in range(1, 10):
        for r in range(4):
            for c in range(4):
                s[r][c] = SBOX[s[r][c]]
        for r in range(1, 4):
            s[r] = s[r][r:] + s[r][:r]
        for c in range(4):
            a = [s[r][c] for r in range(4)]
            s[0][c] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
            s[1][c] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
            s[2][c] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
            s[3][c] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)
        for c in range(4):
            for r in range(4):
                s[r][c] ^= w[rnd * 4 + c][r]
    for r in range(4):
        for c in range(4):
            s[r][c] = SBOX[s[r][c]]
    for r in range(1, 4):
        s[r] = s[r][r:] + s[r][:r]
    for c in range(4):
        for r in range(4):
            s[r][c] ^= w[40 + c][r]
    return _from_state(s)


def _ref_aes_decrypt(ct, key):
    s = _to_state(ct)
    w = _key_expansion(key)
    for c in range(4):
        for r in range(4):
            s[r][c] ^= w[40 + c][r]
    for r in range(1, 4):
        s[r] = s[r][-r:] + s[r][:-r]
    for r in range(4):
        for c in range(4):
            s[r][c] = INV_SBOX[s[r][c]]
    for rnd in range(9, 0, -1):
        for c in range(4):
            for r in range(4):
                s[r][c] ^= w[rnd * 4 + c][r]
        for c in range(4):
            a = [s[r][c] for r in range(4)]
            s[0][c] = _gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9)
            s[1][c] = _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13)
            s[2][c] = _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11)
            s[3][c] = _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)
        for r in range(1, 4):
            s[r] = s[r][-r:] + s[r][:-r]
        for r in range(4):
            for c in range(4):
                s[r][c] = INV_SBOX[s[r][c]]
    for c in range(4):
        for r in range(4):
            s[r][c] ^= w[c][r]
    return _from_state(s)


# ---- stream driver wrappers ----------------------------------------------
def drv_init_enc(st, in16, out_off, key16):
    """FUN_0006f176 @47758 -- init the encrypt path.

      *(gp-0x7f28) = stream base
      memcpy(gp-0x7f40, key16, 0x10)          (working buf <- key/IV)
      *(gp-0x7f30) = out buffer (the 16B AES block)
      memcpy(out, in16, 0x10)
      FUN_0006e6be(out, gp-0x7f40, 0x10)      (block ^= working)
      state(-0x7f21)=0; round(-0x7f20)=1; STATE(-0x7f22)=1
    """
    _memcpy(st, State.OFF_WORK, key16, 16)
    st.block_load(in16)
    _xor_block_with_key(st, st.gbuf(State.OFF_WORK, 16))
    st.sb(State.OFF_LAST, 0)
    st.sb(State.OFF_RND, 1)
    st.sb(State.OFF_STATE, 1)


def drv_three_stream(st, in16, key16, ika16):
    """FUN_0006f1d6 @47781 -- 3-round stream driver.

      *(gp-0x7f28)=stream base
      memcpy(gp-0x7f40, key16, 0x10)
      *(gp-0x7f30)=block
      for i in 0..2: FUN_0006e6e0()           (3 forward stream rounds)
      memcpy(out, block, 0x10)
      round=1; last=0; STATE=4
    Returns the 16B working buffer after the 3 stream rounds.
    """
    _memcpy(st, State.OFF_WORK, key16, 16)
    st.block_load(in16)
    st.stream_init(ika16)              # stream bytes come from the key material
    st.sb(State.OFF_I1F, 0)
    for _ in range(3):
        stream_round_fwd(st)
    st.sb(State.OFF_RND, 1)
    st.sb(State.OFF_LAST, 0)
    st.sb(State.OFF_STATE, 4)
    return st.gbuf(State.OFF_WORK, 16)


# ---- AES dispatch (FUN_0005c452 / FUN_0005c466) ---------------------------
def aes_dispatch_set(st, direction, slot, out_off):
    """FUN_0005c452 @27941 -- latch (direction, key slot, output ptr).
       *(gp-0x7fed)=dir; *(gp-0x7feb)=slot; *(gp-0x8000)=out; *(gp-0x7fe9)=1
    """
    st.aes_dir = direction
    st.aes_slot = slot
    st.aes_outptr = out_off


def aes_engine_step(st, challenge16):
    """FUN_0005c466 @27956 (+ FUN_0006af34 @43806 / FUN_0006ae50 @43745) -- run
    the latched AES op.  For slots 0..3 it would call the resumable FUN_0006e7d8
    path; for slots 5/6/7 it loads a STATIC round key from `slot*0x10 - 0xb000`
    (block0, UNDUMPED) and processes via FUN_000800c4.

    Faithful behavior:
      - direction 0 = encrypt, 1 = decrypt
      - the static key for the slot is taken from st.round_keys[slot] if the
        caller supplied the block0 schedule; otherwise this raises, because the
        slot-5/6/7 key material is NOT in block1 and must not be guessed.
    """
    slot = st.aes_slot
    if st.round_keys is not None and slot in st.round_keys:
        key = st.round_keys[slot]
    else:
        raise RuntimeError(
            "AES slot %d round key lives in UNDUMPED block0 "
            "(slot*0x10-0xb000); supply State.round_keys[%d] to proceed."
            % (slot, slot))
    if st.aes_dir == 0:
        return _ref_aes_encrypt(challenge16, key)
    return _ref_aes_decrypt(challenge16, key)


# ---- row map / row write --------------------------------------------------
def row_map_get(st, row, ptr_off):
    """FUN_0006e258 @46983 -- bind a row index to a gp-relative pointer slot.
       row 0   -> gp-0x7f8c   (stored IKA row0 pointer)
       row 0x50-> gp-0x7f7c ; row 0x51 -> gp-0x7f78
       row 0x64-> gp-0x7f88 ; row 0x65 -> gp-0x7f80 ; row 0x66 -> gp-0x7f84
    """
    table = {0: -0x7f8c, 0x50: -0x7f7c, 0x51: -0x7f78,
             0x65: -0x7f80, 0x66: -0x7f84}
    if row in table:
        st.sbuf(table[row], struct.pack("<i", ptr_off))
        return 1
    if 100 <= row < 0x65:                       # default <0x65 bucket
        st.sbuf(-0x7f88, struct.pack("<i", ptr_off))
        return 1
    return 0


def row_write(st, direction, row, buf_off):
    """FUN_0006e42e @47173 -- read/write a CP row.
       row 0   <-> gp-0x7e90 (IKA row0 / key V)
       row 100 <-> gp-0x7eb0
       row 0x65<-> gp-0x7ea0
       row 0x66<-> gp-0x7e80
     direction 0 = read (row -> buf), 1 = write (buf -> row).
    """
    row_off = {0: State.OFF_IKA, 100: State.OFF_ROW100,
               0x65: State.OFF_ROW65, 0x66: State.OFF_ROW66}
    if row not in row_off:
        return 0
    ro = row_off[row]
    if direction == 0:
        bounded_copy(st, ro, 16, buf_off, 16)
        return 1
    if direction == 1:
        bounded_copy(st, buf_off, 16, ro, 16)
        return 1
    return 0


# ---- message handler / wiring (FUN_0006f282) ------------------------------
def msg_setup(st, challenge16):
    """FUN_0006f282 @47860 -- reverse the 16-byte challenge into gp-0x7e70 and
    gp-0x7e60, and wire the handshake pointers:
       *(gp-0x7e50)=gp-0x7e70 (stream input)
       *(gp-0x7e4c)=gp-0x7ef8 (message buffer)
       *(gp-0x7e48)=gp-0x7e90 (KEY = IKA)

      for u in 0..0xf:
         gp-0x7e70[u] = src[0x0f - u]
         gp-0x7e60[u] = src[0x1f - u]
    (byte-reversed copy of the two 16-byte halves of the incoming frame.)
    """
    src = bytes(challenge16)
    rev = bytes(src[0x0f - u] for u in range(16))
    st.sbuf(State.OFF_V, rev)              # gp-0x7e70
    if len(src) >= 32:
        rev2 = bytes(src[0x1f - u] for u in range(16))
    else:
        rev2 = bytes(16)
    st.sbuf(State.OFF_VNEG, rev2)          # gp-0x7e60
    return rev


# ===========================================================================
# KEY-CONFIRM HANDSHAKE  (FUN_00075624 @53587)
# ===========================================================================
def key_confirm(st, ika16, challenge16):
    """FUN_00075624 @53587 -- 2-PASS key-confirm handshake (model).

    The firmware is a resumable FSM keyed off gp-0x7e43 (engine arm) and
    gp-0x7e41 (substate).  Verified byte-for-byte identical in the HI variant
    (FUN_00085af6) -- only callee addresses + two .bss slots differ.

    Success path, substates 4->7 (decompile L53668-53722):

       PASS 1 (substate 4 -> 5):
         * substate 4 (L53672-53675): copy reversed-challenge gp-0x7e70 into the
           msg buffer gp-0x7ef8, set stream-input *(gp-0x7e50)=gp-0x7e60, ARM the
           stream/AES engine (*(gp-0x7e43)=2).
         * the engine runs drv (FUN_0006f1d6) + AES (FUN_0006e7d8), key=IKA
           (*(gp-0x7e48)=gp-0x7e90), producing V in gp-0x7e70.
         * substate 5 (L53678-53695): GATE  V == NOT(msg) per byte
           (gp-0x7e60[i]=~gp-0x7ef8[i]; compare gp-0x7e70[i]).  On match,
           FUN_0006e42e(1,100,V) stores V to ROW 100 (GKA), mirror -> gp-0x7eb0.

       PASS 2 (substate 6 -> 7):
         * substate 6 (L53699-53702): re-arm the SAME engine, stream-input again
           gp-0x7e60 (now holding the ~challenge built in pass 1), key=IKA.
         * substate 7 (L53705-53721): GATE  V == NOT(msg) again.  On match,
           FUN_0006e42e(1,0,V) stores V to ROW 0 (IKA), mirror -> gp-0x7e90.

    *** PORT-ERROR FIX (2026-06-16): the previous model collapsed this into one
    pass plus a literal `v = v_round1 ^ ika16` inter-round XOR.  That XOR does
    NOT exist in the firmware -- confirmed by the HI<->LO diff.  The real
    mechanism is TWO independent drv+AES passes, each keyed by IKA, each gated by
    V==NOT(challenge), storing GKA then IKA.  Replaced below. ***

    RESIDUAL CAVEATS (documented, not bugs):
      * aes_run() substitutes FIPS-197 AES for the block0 round-key schedule;
        the 0xd5b0/d6b0/d7b0 tables are modeled as standard.  Bit-exactness
        needs the bench BDM read (see BDM_READ_TARGETS.md).
      * the exact per-pass stream input (reversed-challenge gp-0x7e70 vs the
        ~challenge gp-0x7e60 vs ~V1) aliases across the resumable FSM entries;
        the structure below follows the synth trace (pass1=reversed-challenge,
        pass2=~challenge) but the alias is only nailed by a dynamic trace or
        block0-backed re-derivation.  Flagged so it is re-checked at the bench.
    """
    ika16 = bytes(ika16)
    challenge16 = bytes(challenge16)
    not_chal = bytes((~challenge16[i]) & 0xff for i in range(16))
    rev_chal = bytes(challenge16[0x0f - u] for u in range(16))   # gp-0x7e70

    def _stream_aes_pass(stream_input):
        """One drv+AES pass keyed by IKA (FUN_0006f1d6 -> FUN_0006e7d8)."""
        st.block_load(stream_input)
        st.sb(State.OFF_S31, ika16[0]); st.sb(State.OFF_S32, ika16[1])
        st.sb(State.OFF_S33, ika16[2]); st.sb(State.OFF_S34, ika16[3])
        drv_three_stream(st, stream_input, ika16, ika16)
        return aes_run(st, ika16, decrypt=False)

    # --- PASS 1: stream over reversed-challenge (gp-0x7e70), key=IKA -------
    v1 = _stream_aes_pass(rev_chal)
    matched1 = (v1 == not_chal)
    if matched1:
        st.sbuf(State.OFF_ROW100, v1)    # FUN_0006e42e(1,100,V): GKA row100
        st.sbuf(State.OFF_V, v1)

    # --- PASS 2: stream over ~challenge (gp-0x7e60), key=IKA ---------------
    v2 = _stream_aes_pass(not_chal)
    matched2 = (v2 == not_chal)
    if matched2:
        st.sbuf(State.OFF_IKA, v2)       # FUN_0006e42e(1,0,V): write V to row0
        st.sbuf(State.OFF_V, v2)

    return {
        "v1": v1,                # pass-1 product (-> GKA on match)
        "v2": v2,                # pass-2 product (-> IKA/row0 on match)
        "not_challenge": not_chal,
        "rev_challenge": rev_chal,
        "matched_round1": matched1,
        "matched_round2": matched2,
        "matched": matched2,     # the IKA-installing gate is pass 2
    }


# ===========================================================================
# CP-VERIFY FSM  (FUN_0006dd54 @46633)  -- slot6 path
# ===========================================================================
def cp_verify_fsm(st, challenge16, stored_ika16):
    """FUN_0006dd54 @46633 -- CP verify finite-state machine (relevant cases).

      case 2: FUN_0005c452(0,6,gp-0x7f64)  -> latch AES(enc, slot6, out=7f64)
      case 3: run engine; AES(challenge, slot6) lands at gp-0x7f64
      case 7 (~L46695): 16-byte memcmp gp-0x7f64 vs *(gp-0x7f8c)=stored IKA row0
              equal -> CP pass (FUN_00069dc2(0,1)), else fail.

    Requires the slot-6 round key (block0).  If st.round_keys is unset this
    raises -- by design, since the slot key is NOT in block1.
    """
    st.sbuf(State.OFF_STORED, struct.pack("<i", State.OFF_IKA))  # bind gp-0x7f8c -> row0
    st.sbuf(State.OFF_IKA, bytes(stored_ika16))

    aes_dispatch_set(st, 0, 6, State.OFF_CPOUT)       # FUN_0005c452(0,6,gp-0x7f64)
    cp_out = aes_engine_step(st, bytes(challenge16))  # may raise w/o block0 key
    st.sbuf(State.OFF_CPOUT, cp_out)

    stored = st.gbuf(State.OFF_IKA, 16)               # *(gp-0x7f8c) -> row0
    equal = (bytes(cp_out) == bytes(stored))          # FUN_0006e670 / memcmp
    return {"cp_out": bytes(cp_out), "stored": bytes(stored), "pass": equal}


# ===========================================================================
# VALIDATION ENTRY POINT
# ===========================================================================
def validate(cs16, identity, known_blob, round_keys=None, verbose=True):
    """Run the handshake/derivation and test whether it reproduces the known
    2024 seat IKA blob.

    Parameters
    ----------
    cs16 : bytes
        Owner's 16-byte Component Security value (the IKA / CP master key
        candidate).  Used as the handshake key (gp-0x7e90 / *(gp-0x7e48)).
    identity : bytes
        Identity / challenge material (serial, VIN-derived nonce, or the
        16/32-byte challenge frame the tester sent).  First 16 bytes are the
        handshake challenge; if 32 bytes, both halves feed msg_setup().
    known_blob : bytes
        Captured seat IKA blob to test against (16-byte row0, or the full ~34B
        CP record; first 16 bytes are compared as the IKA row0).
    round_keys : dict | None
        Optional {slot: 16-byte key} from the UNDUMPED block0 schedule.  If
        provided, the slot-6 CP-verify path is also exercised.

    Returns
    -------
    dict: handshake, derived_ika, blob_row0, reproduces, cp_verify
    """
    cs16 = bytes(cs16)
    assert len(cs16) == 16, "CS must be 16 bytes"
    ident = bytes(identity)
    chal = (ident + b"\x00" * 16)[:16]
    blob_row0 = bytes(known_blob)[:16]

    st = State()
    st.round_keys = round_keys

    if verbose:
        print("=== HVAC IKA handshake validation ===")
        print(" CS (key)       :", cs16.hex())
        print(" identity       :", ident.hex())
        print(" challenge[:16] :", chal.hex())
        print(" known blob row0:", blob_row0.hex())

    # Stage A: wire buffers / reverse challenge (FUN_0006f282).
    msg_setup(st, (ident + b"\x00" * 32)[:32])
    if verbose:
        print(" rev(challenge) :", st.gbuf(State.OFF_V, 16).hex())

    # Stage B: install CS as the current IKA (row 0 / key).
    st.sbuf(State.OFF_IKA, cs16)

    # Stage C: run the key-confirm derivation (two-pass).
    hs = key_confirm(st, cs16, chal)
    if verbose:
        print(" pass1 V (->GKA):", hs["v1"].hex(), "match:", hs["matched_round1"])
        print(" pass2 V (->IKA):", hs["v2"].hex(), "match:", hs["matched_round2"])
        print(" NOT(challenge) :", hs["not_challenge"].hex())
        print(" gate matched   :", hs["matched"])

    derived = hs["v2"] if hs["matched"] else hs["v2"]
    reproduces = (derived == blob_row0)
    if verbose:
        print(" derived IKA    :", derived.hex())
        print(" REPRODUCES BLOB:", reproduces)

    cp = None
    if round_keys is not None:
        try:
            cp = cp_verify_fsm(st, chal, blob_row0)
            if verbose:
                print(" CP slot6 out   :", cp["cp_out"].hex())
                print(" CP verify pass :", cp["pass"])
        except RuntimeError as e:
            if verbose:
                print(" CP verify      : SKIPPED --", e)

    return {
        "handshake": hs,
        "derived_ika": derived,
        "blob_row0": blob_row0,
        "reproduces": reproduces,
        "cp_verify": cp,
    }


# ===========================================================================
# SELF-TEST
# ===========================================================================
def _selftest():
    print("########## hvac_ika_cipher self-test ##########\n")

    # 0. primitive sanity: FIPS-197 AES-128 ECB enc vector
    fips = _ref_aes_encrypt(bytes.fromhex("00112233445566778899aabbccddeeff"),
                            bytes.fromhex("000102030405060708090a0b0c0d0e0f")).hex()
    fok = (fips == "69c4e0d86a7b0430d8cdb78070b4c55a")
    print("[FIPS-197 enc]  ", "PASS" if fok else "FAIL", fips)
    rt = _ref_aes_decrypt(bytes.fromhex(fips),
                          bytes.fromhex("000102030405060708090a0b0c0d0e0f")).hex()
    print("[AES round-trip]", "PASS" if rt == "00112233445566778899aabbccddeeff" else "FAIL")

    # 1. table sanity
    print("[SBOX[0]=63]    ", "PASS" if SBOX[0] == 0x63 else "FAIL")
    print("[INV_SBOX o S]  ",
          "PASS" if all(INV_SBOX[SBOX[i]] == i for i in range(256)) else "FAIL")
    print("[XTIME[0x80]=1b]", "PASS" if XTIME[0x80] == 0x1b else "FAIL")

    # 2. stream round determinism
    st = State()
    st.sbuf(State.OFF_WORK, bytes(range(16)))
    st.sb(State.OFF_S31, 0x11); st.sb(State.OFF_S32, 0x22)
    st.sb(State.OFF_S33, 0x33); st.sb(State.OFF_S34, 0x44)
    st.stream_init(bytes([0xAA] * 8))
    before = st.gbuf(State.OFF_WORK, 16)
    stream_round_fwd(st)
    after = st.gbuf(State.OFF_WORK, 16)
    print("[stream fwd]    ", "PASS" if before != after else "FAIL", after.hex())

    # 3. row_write read/write round-trip
    st2 = State()
    payload = bytes.fromhex("0011223344556677889900aabbccddee")
    st2.sbuf(State.OFF_MSG, payload)
    row_write(st2, 1, 0, State.OFF_MSG)        # write msg -> row0(IKA)
    rd = State.OFF_CPOUT
    row_write(st2, 0, 0, rd)                    # read row0 -> CPOUT region
    got = st2.gbuf(rd, 16)
    print("[row_write r/w] ", "PASS" if got == payload else "FAIL", got.hex())

    # 4. end-to-end derivation with a DROP-IN CS (placeholders below)
    CS       = bytes.fromhex("000102030405060708090a0b0c0d0e0f")   # 16B CS
    IDENTITY = bytes.fromhex("deadbeefcafebabe0011223344556677")   # challenge
    KNOWN    = bytes.fromhex(                                       # ~34B blob
        "00112233445566778899aabbccddeeff"     # row0 (IKA) <-- compared
        "0102030405060708090a0b0c0d0e0f10"     # row1 / mac
        "1234")                                # 2-byte trailer/CRC
    print("\n--- validate() with PLACEHOLDER CS/identity/blob ---")
    res = validate(CS, IDENTITY, KNOWN, round_keys=None, verbose=True)
    print("\nRESULT reproduces blob:", res["reproduces"],
          "(expected False for placeholder data)")

    # 5. CP-verify path with a SUPPLIED block0 slot6 key (illustrative)
    print("\n--- cp_verify_fsm() demo with a SUPPLIED slot6 key (illustrative) ---")
    demo_rk = {6: bytes.fromhex("4c45415220443420476174657761792e")}
    res2 = validate(CS, IDENTITY, KNOWN, round_keys=demo_rk, verbose=True)
    cp = res2["cp_verify"]
    if cp is not None:
        print("CP verify pass:", cp["pass"], "(slot6 key was illustrative)")

    print("\n########## end self-test ##########")
    print("Drop the owner's real CS (16B), identity/challenge, and the captured")
    print("2024 seat IKA blob into _selftest()'s CS/IDENTITY/KNOWN to test")
    print("whether  IKA == f(CS, identity)  under the documented assumptions.")


if __name__ == "__main__":
    _selftest()