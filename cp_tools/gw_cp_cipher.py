#!/usr/bin/env python3
"""
gw_cp_cipher.py  --  Software model of the Audi C7 J533 (LEAR D4) gateway
                     Component-Protection authentication cipher.

RESULT OF STREAM-B REVERSE ENGINEERING (validated 2026-06-16):
  The gateway CP "cipher" is *standard* AES-128 (FIPS-197), NOT a custom block
  cipher.  The earlier "custom S-box / custom AES" conclusion was an artifact of
  the Ghidra image base being 0x10000: every flash *file* offset is 0x10000
  BELOW the program address the firmware actually references.

  Firmware fact          program addr      file offset     content
  -----------------------------------------------------------------------------
  AES key (ASCII)        0x27bfc           0x17bfc         "LEAR D4 Gateway."
  AES S-box (standard)   0x27fe4           0x17fe4         63 7c 77 7b ...
  AES inverse S-box      0x280e4           0x180e4         52 09 6a d5 ...
  xtime (GF mul-by-2)    0x281e4           0x181e4         00 02 04 06 ...
  Rcon                   0x27fd8           0x17fd8         01 02 04 08 10 20 40 80 1b 36
  KAT expected output    0x27c2c           0x17c2c         97 19 c9 52 ...

  The gateway routine FUN_0009091e -> FUN_00091bfe computes:
        out16 = AES128_DECRYPT_ECB( in16 , key="LEAR D4 Gateway." )
  (confirmed by PCode emulation of the real firmware over 8 vectors; this module
  reproduces all 8 byte-for-byte.)

  Embedded power-on self-test (firmware FUN_0008f082):
        DEC( 0xFF * 16 ) == 0x9719c9524d41e9a1a98c9793b6517e7d   (stored @0x27c2c)

USAGE
  from gw_cp_cipher import gw_dec, gw_enc, KEY
  gw_dec(block16)  -> what the gateway computes for a given CP input block
  gw_enc(block16)  -> inverse; the input block that makes the gateway emit block16
                      (use this to forge a CP record so the auth check passes)
"""

KEY = b"LEAR D4 Gateway."          # 16 ASCII bytes, firmware constant @ prog 0x27bfc

SBOX = bytes.fromhex(
 "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
 "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
 "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd"
 "0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd"
 "0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0"
 "323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba"
 "78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1"
 "f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
INV_SBOX = bytes(256)
_inv = bytearray(256)
for _i, _v in enumerate(SBOX):
    _inv[_v] = _i
INV_SBOX = bytes(_inv)
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _gmul(a, b):
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


def _add_round_key(s, w, rnd):
    for c in range(4):
        for r in range(4):
            s[r][c] ^= w[rnd * 4 + c][r]


def _to_state(b):                       # column-major (standard AES)
    return [[b[r + 4 * c] for c in range(4)] for r in range(4)]


def _from_state(s):
    return bytes(s[r][c] for c in range(4) for r in range(4))


def aes128_encrypt(pt, key=KEY):
    assert len(pt) == 16 and len(key) == 16
    s = _to_state(pt)
    w = _key_expansion(key)
    _add_round_key(s, w, 0)
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
        _add_round_key(s, w, rnd)
    for r in range(4):
        for c in range(4):
            s[r][c] = SBOX[s[r][c]]
    for r in range(1, 4):
        s[r] = s[r][r:] + s[r][:r]
    _add_round_key(s, w, 10)
    return _from_state(s)


def aes128_decrypt(ct, key=KEY):
    assert len(ct) == 16 and len(key) == 16
    s = _to_state(ct)
    w = _key_expansion(key)
    _add_round_key(s, w, 10)
    for r in range(1, 4):
        s[r] = s[r][-r:] + s[r][:-r]
    for r in range(4):
        for c in range(4):
            s[r][c] = INV_SBOX[s[r][c]]
    for rnd in range(9, 0, -1):
        _add_round_key(s, w, rnd)
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
    _add_round_key(s, w, 0)
    return _from_state(s)


# ---- gateway-facing aliases ----------------------------------------------
def gw_dec(block16):
    """Exactly what gateway FUN_0009091e computes: AES128-DEC(block, KEY)."""
    return aes128_decrypt(block16, KEY)


def gw_enc(block16):
    """Inverse of the gateway transform. The 16-byte input you must feed the
       gateway (or store as the CP record) so that gw_dec() emits `block16`."""
    return aes128_encrypt(block16, KEY)


# ---- self-test (matches firmware bytes + PCode emulation) -----------------
_KAT = {  # input : expected gw_dec() output  (8 vectors verified vs emulator)
 "ffffffffffffffffffffffffffffffff": "9719c9524d41e9a1a98c9793b6517e7d",  # POST const @0x27c2c
 "00000000000000000000000000000000": "c6e4d85f4cf9b21a6935f79576a529fb",
 "01020304050607080807060504030201": "8a9e0e9b0dc3d556ae9b49ec27d1f416",
 "9719c9524d41e9a1a98c9793b6517e7d": "5c1cc23b4522e559f454e09267dbab6f",
 "000102030405060708090a0b0c0d0e0f": "f35d85c5acedd60437e6456700c45948",
 "0f0e0d0c0b0a09080706050403020100": "e64dc08792038e96f4c6e2b03ca94221",
 "4c45415220443420476174657761792e": "1460e3404f205f0f189a3718f47b9220",
 "deadbeef00112233cafebabe99887766": "802f337d88ca1895af7019d13abae00b",
}


def selftest():
    ok = True
    for ic, oc in _KAT.items():
        got = gw_dec(bytes.fromhex(ic)).hex()
        good = (got == oc)
        ok &= good
        print(("PASS " if good else "FAIL ") + ic + " -> " + got)
    # FIPS-197 sanity on the primitive itself
    fips = aes128_encrypt(bytes.fromhex("00112233445566778899aabbccddeeff"),
                          bytes.fromhex("000102030405060708090a0b0c0d0e0f")).hex()
    fok = (fips == "69c4e0d86a7b0430d8cdb78070b4c55a")
    ok &= fok
    print(("PASS " if fok else "FAIL ") + "FIPS-197 ECB enc vector")
    # round-trip
    rok = all(gw_enc(gw_dec(bytes([i] * 16))) == bytes([i] * 16) for i in range(256))
    ok &= rok
    print(("PASS " if rok else "FAIL ") + "enc/dec round-trip over 256 blocks")
    print("\nSELFTEST:", "ALL PASS" if ok else "FAILURE")
    return ok


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1:
        selftest()
    elif len(sys.argv) == 3 and sys.argv[1] in ("dec", "enc"):
        blk = bytes.fromhex(sys.argv[2])
        fn = gw_dec if sys.argv[1] == "dec" else gw_enc
        print(fn(blk).hex())
    else:
        print("usage: gw_cp_cipher.py [dec|enc <32-hex-block>]   (no args = selftest)")
