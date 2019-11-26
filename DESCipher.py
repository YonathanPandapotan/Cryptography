#
# The DES (Data Encryption Standard) block cipher.
# Note: The key length is 64 bits but 8 of them are ignored, so the effective key length is 56 bits.
#
# Copyright (c) 2018 Project Nayuki. (MIT License)
# https://www.nayuki.io/page/cryptographic-primitives-in-plain-python
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
# - The Software is provided "as is", without warranty of any kind, express or
#   implied, including but not limited to the warranties of merchantability,
#   fitness for a particular purpose and noninfringement. In no event shall the
#   authors or copyright holders be liable for any claim, damages or other
#   liability, whether in an action of contract, tort or otherwise, arising from,
#   out of or in connection with the Software or the use or other dealings in the
#   Software.
#

import cryptocommon
import binascii

# ---- Public functions ----

# Computes the encryption of the given block (8-element bytelist) with
# the given key (8-element bytelist), returning a new 8-element bytelist.
def encrypt(block, key, printdebug=False):
    return _crypt(block, key, "encrypt", printdebug)


# Computes the decryption of the given block (8-element bytelist) with
# the given key (8-element bytelist), returning a new 8-element bytelist.
def decrypt(block, key, printdebug=False):
    return _crypt(block, key, "decrypt", printdebug)


# ---- Private functions ----

def _crypt(block, key, direction, printdebug):
    # Check input arguments
    assert isinstance(block, list) and len(block) == 8
    assert isinstance(key, list) and len(key) == 8
    assert direction in ("encrypt", "decrypt")
    if printdebug: print(
        "descipher.{}(block = {}, key = {})".format(direction, cryptocommon.bytelist_to_debugstr(block),
                                                    cryptocommon.bytelist_to_debugstr(key)))

    # Pack key bytes into uint64 in big endian
    # DISINILAH LETAK KEY NYA
    # BELUM DI PERMUTASIKAN ATAU SHIFTING
    print()
    k = 0
    for b in key:
        assert 0 <= b <= 0xFF
        k = (k << 8) | b
    assert 0 <= k < (1 << 64)
    print("Bentuk bit key = {0:064b}".format(k))
    bitKey = format(k, '064b')
    print("")

    # Compute and handle the key schedule
    # ini pembuatan subkey dimana subkeynya adalah k
    # Disini key mengalami perubahan besar
    # dari permutasikan dulu, shifting 16 kali, hingga akhirnya permutasikan lagi
    keyschedule, cdk, c, d, k = _expand_key_schedule(k)
    if direction == "decrypt":
        keyschedule = tuple(reversed(keyschedule))

    # Pack block bytes into uint64 in big endian
    # nah disini plaintext baru disentuh
    # plaintext diubah menjadi bentuk binary
    m = 0
    for b in block:
        assert 0 <= b <= 0xFF
        m = (m << 8) | b
    assert 0 <= m < (1 << 64)
    print("Disini plaintext baru disentuh")
    print("Yang dibawah ini adalah perubahan plaintext ke binarynya")
    print("(P) {0:064b}".format(m))
    p = format(m, '064b')

    # Do initial permutation on block and split into two uint32 words
    # disini plaintext baru mengalami permutasi awal menggunakan table Initial Permutation Table
    m = _extract_bits(m, 64, _INITIAL_PERMUTATION)
    # hasil permutasi
    print("Sehabis itu, plaintext di permutasikan terhadap table Initial Permutation")
    print("IP(P) = {0:064b}".format(m))
    ipp = format(m, '064b')
    left = (m >> 32) & cryptocommon.UINT32_MASK
    right = (m >> 0) & cryptocommon.UINT32_MASK
    # disini hasil permutasi di pecah menjadi dua
    l = []
    r = []
    print("Dipecah menjadi dua")
    print("L0 = {0:032b}".format(left))
    print("R0 = {0:032b}".format(right))
    print("")
    l.append(format(left, '032b'))
    r.append(format(right, '032b'))

    # Perform 16 rounds of encryption/decryption
    # nah disini baru kita masuk ke tahap akhir
    # Ekspansi kunci R, terus XOR kan dengan Subkey (k) untuk mendapat A
    # lalu di permutasikan dengan S-box dan mendapatkan B
    # terakhir di permutasikan terhadap P-Box
    # Cara diulangi kembali hingga 16 kali atau sampai subkey(keyschedule) habis

    er = []
    a = []
    b = []
    pb = []
    ld = []
    for (i, subkey) in enumerate(keyschedule):
        if printdebug: print("Round {:2d}: block = [{:032b} {:032b}]".format(i + 1, left, right))
        leftDummy, a1, b1, c1, d1 = _feistel_function(right, subkey, i + 1)
        er.append(format(a1, '032b'))
        a.append(format(b1, '032b'))
        b.append(format(c1, '032b'))
        pb.append(format(d1, '032b'))
        left2 = left ^ leftDummy
        print("R" + str(i + 1) + " = {0:032b}".format(left2))
        ld.append(format(left2, '032b'))
        left, right = right, left2  # disini right mendapat hasil dari left xor hasil perhitungan Right di fungsi tersebut
        l.append(format(left, '032b'))
        r.append(format(right, '032b'))
        assert 0 <= right <= cryptocommon.UINT32_MASK
        print("")

    # putaran ke 16 dilakukan di luar for
    # Merge the halves back into a uint64 and do final permutation on new block
    m = right << 32 | left
    print("R16L16 = {0:064b}".format(m))
    rl = format(m, '064b')
    m = _extract_bits(m, 64, _FINAL_PERMUTATION)
    print("Cipher = {0:064b}".format(m))
    cipher = format(m, '064b')
    assert 0 <= m < (1 << 64)
    print("Merge the halves back into a uint64 and do final permutation on new block")

    # Serialize the new block as bytes in big endian
    result = []
    for i in reversed(range(8)):
        result.append(int((m >> (i * 8)) & 0xFF))
    return result, bitKey, cdk, c, d, k, p, ipp, er, a, b, pb, ld, rl, cipher


# Given a uint64 key, this computes and returns a tuple containing 16 elements of uint48.
def _expand_key_schedule(key):
    result = []
    i = 1

    # disini key mengalami permutasi dan langsung di bagi menjadi dua
    left = _extract_bits(key, 64, _PERMUTED_CHOICE_1_LEFT)
    right = _extract_bits(key, 64, _PERMUTED_CHOICE_1_RIGHT)

    print("Setelah itu, key tersebut akan mengalami permutasi terhadap table PC-1")
    print("CD(K) = {0:032b} {0:032b}".format(left, right))
    Cdk = format(left, '032b') + format(right, '032b')
    print("")
    print("Setelah mengalami permutasi, maka key akan di shift ke kiri tergantung aturan")
    print("Setelah di shift C dan D akan digabungkan lagi dan di permutasikan terhadap table PC-2")
    # NAH baru disini key mengalami shifting sebanyak 16 kali
    c = []
    d = []
    k = []
    for shift in _ROUND_KEY_SHIFTS:
        left = _rotate_left_uint28(left, shift)
        right = _rotate_left_uint28(right, shift)
        print("C" + str(i) + " \t= {0:028b}".format(left))
        print("D" + str(i) + " \t= {0:028b}".format(right))
        c.append(format(left, '032b'))
        d.append(format(right, '032b'))
        # disini pergeseran selesai
        assert 0 <= left < (1 << 28)
        assert 0 <= right < (1 << 28)
        # ini dilakukan check untuk memastikan left dan right sama-sama memiliki value 28
        # disini dilakukan penggabungan
        packed = left << 28 | right
        print("C" + str(i) + "D" + str(i) + " = {0:056b}".format(packed))
        # terus dilaksanakanlah yang namanya permutasi PC-2
        subkey = _extract_bits(packed, 56, _PERMUTED_CHOICE_2)
        k.append(format(subkey, '048b'))
        # sehingga menghasilkan
        print("K" + str(i) + " \t= {0:048b}".format(subkey))
        assert 0 <= subkey < (1 << 48)
        i += 1
        print("")
        result.append(subkey)
    return tuple(result), Cdk, c, d, k


# 'data' is uint32, 'subkey' is uint48, and result is uint32.
def _feistel_function(data, subkey, a):
    i = a
    er = _extract_bits(data, 32, _FEISTEL_EXPANSION)  # uint48 #disini right mengalami ekspansi
    print("E(R(" + str(i) + ")-1) = {0:048b}".format(a))
    print("K" + str(i) + " = {0:048b}".format(subkey))
    b = a ^ subkey  # uint48 setelah itu right di xor-kan dengan subkey
    print("A" + str(i) + " = {0:048b}".format(b))
    c = _do_sboxes(
        b)  # uint32 setelah di xor dan mendapat A, maka langkah selanjutnya adalah men subtitusikannya dengan table S-Boxes
    print("B" + str(i) + " = {0:032b}".format(c))
    d = _extract_bits(c, 32, _FEISTEL_PERMUTATION)  # uint32 sehabis itu, B akan dipermutasukan terhadap P-Box
    print("P(B" + str(i) + ") = {0:032b}".format(d))
    assert 0 <= d < cryptocommon.UINT32_MASK
    return d, er, a, b, d


# 'data' is uint48, and result is uint32.
def _do_sboxes(data):
    assert 0 <= data < (1 << 48)
    mask = (1 << 6) - 1
    result = 0
    for i in range(
            8):  # Topmost 6 bits use _SBOXES[0], next lower 6 bits use _SBOXES[1], ..., lowest 6 bits use _SBOXES[7].
        result |= _SBOXES[7 - i][(data >> (i * 6)) & mask] << (i * 4)
    assert 0 <= result < cryptocommon.UINT32_MASK
    return result


# Extracts bits from 'value' according to 'indices'. 'value' is uint(bitwidth), and the result is a uint(len(indices)).
# Bit positions in 'value' are numbered from 1 at the most significant bit to 'bitwidth' at the least significant bit.
# indices[0] selects which bit of 'value' maps into the MSB of the result, and indices[-1] maps to the LSB of the result.
# For example: _extract_bits(0b10000, 5, [5, 1, 2]) = 0b010.
def _extract_bits(value, bitwidth, indices):
    assert 0 <= value < (1 << bitwidth)
    result = 0
    for i in indices:
        result <<= 1
        result |= (value >> (bitwidth - i)) & 1
    assert 0 <= result < (1 << len(indices))
    return result


# 'value' is uint28, 'amount' is in the range [0, 28), and result is uint28.
def _rotate_left_uint28(value, amount):
    mask = (1 << 28) - 1
    assert 0 <= value <= mask
    assert 0 <= amount < 28
    return ((value << amount) | (value >> (28 - amount))) & mask


# ---- Numerical constants/tables ----

# All tables below are copied from https://en.wikipedia.org/wiki/DES_supplementary_material .

# Defines 16 rounds
_ROUND_KEY_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# 64 bits -> 28 bits
_PERMUTED_CHOICE_1_LEFT = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3,
                           60, 52, 44, 36]
_PERMUTED_CHOICE_1_RIGHT = [63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5,
                            28, 20, 12, 4]

# 56 bits -> 48 bits
_PERMUTED_CHOICE_2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
                      31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

# 64 bits -> 64 bits
_INITIAL_PERMUTATION = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64,
                        56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53,
                        45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
_FINAL_PERMUTATION = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37,
                      5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2,
                      42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

# 32 bits -> 48 bits
_FEISTEL_EXPANSION = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19,
                      20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

# 32 bits -> 32 bits
_FEISTEL_PERMUTATION = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13,
                        30, 6, 22, 11, 4, 25]

# 8 different S-boxes, each mapping 6 input bits to 4 output bits
_SBOXES = [
    [0xE, 0x0, 0x4, 0xF, 0xD, 0x7, 0x1, 0x4, 0x2, 0xE, 0xF, 0x2, 0xB, 0xD, 0x8, 0x1, 0x3, 0xA, 0xA, 0x6, 0x6, 0xC, 0xC,
     0xB, 0x5, 0x9, 0x9, 0x5, 0x0, 0x3, 0x7, 0x8, 0x4, 0xF, 0x1, 0xC, 0xE, 0x8, 0x8, 0x2, 0xD, 0x4, 0x6, 0x9, 0x2, 0x1,
     0xB, 0x7, 0xF, 0x5, 0xC, 0xB, 0x9, 0x3, 0x7, 0xE, 0x3, 0xA, 0xA, 0x0, 0x5, 0x6, 0x0, 0xD],
    [0xF, 0x3, 0x1, 0xD, 0x8, 0x4, 0xE, 0x7, 0x6, 0xF, 0xB, 0x2, 0x3, 0x8, 0x4, 0xE, 0x9, 0xC, 0x7, 0x0, 0x2, 0x1, 0xD,
     0xA, 0xC, 0x6, 0x0, 0x9, 0x5, 0xB, 0xA, 0x5, 0x0, 0xD, 0xE, 0x8, 0x7, 0xA, 0xB, 0x1, 0xA, 0x3, 0x4, 0xF, 0xD, 0x4,
     0x1, 0x2, 0x5, 0xB, 0x8, 0x6, 0xC, 0x7, 0x6, 0xC, 0x9, 0x0, 0x3, 0x5, 0x2, 0xE, 0xF, 0x9],
    [0xA, 0xD, 0x0, 0x7, 0x9, 0x0, 0xE, 0x9, 0x6, 0x3, 0x3, 0x4, 0xF, 0x6, 0x5, 0xA, 0x1, 0x2, 0xD, 0x8, 0xC, 0x5, 0x7,
     0xE, 0xB, 0xC, 0x4, 0xB, 0x2, 0xF, 0x8, 0x1, 0xD, 0x1, 0x6, 0xA, 0x4, 0xD, 0x9, 0x0, 0x8, 0x6, 0xF, 0x9, 0x3, 0x8,
     0x0, 0x7, 0xB, 0x4, 0x1, 0xF, 0x2, 0xE, 0xC, 0x3, 0x5, 0xB, 0xA, 0x5, 0xE, 0x2, 0x7, 0xC],
    [0x7, 0xD, 0xD, 0x8, 0xE, 0xB, 0x3, 0x5, 0x0, 0x6, 0x6, 0xF, 0x9, 0x0, 0xA, 0x3, 0x1, 0x4, 0x2, 0x7, 0x8, 0x2, 0x5,
     0xC, 0xB, 0x1, 0xC, 0xA, 0x4, 0xE, 0xF, 0x9, 0xA, 0x3, 0x6, 0xF, 0x9, 0x0, 0x0, 0x6, 0xC, 0xA, 0xB, 0x1, 0x7, 0xD,
     0xD, 0x8, 0xF, 0x9, 0x1, 0x4, 0x3, 0x5, 0xE, 0xB, 0x5, 0xC, 0x2, 0x7, 0x8, 0x2, 0x4, 0xE],
    [0x2, 0xE, 0xC, 0xB, 0x4, 0x2, 0x1, 0xC, 0x7, 0x4, 0xA, 0x7, 0xB, 0xD, 0x6, 0x1, 0x8, 0x5, 0x5, 0x0, 0x3, 0xF, 0xF,
     0xA, 0xD, 0x3, 0x0, 0x9, 0xE, 0x8, 0x9, 0x6, 0x4, 0xB, 0x2, 0x8, 0x1, 0xC, 0xB, 0x7, 0xA, 0x1, 0xD, 0xE, 0x7, 0x2,
     0x8, 0xD, 0xF, 0x6, 0x9, 0xF, 0xC, 0x0, 0x5, 0x9, 0x6, 0xA, 0x3, 0x4, 0x0, 0x5, 0xE, 0x3],
    [0xC, 0xA, 0x1, 0xF, 0xA, 0x4, 0xF, 0x2, 0x9, 0x7, 0x2, 0xC, 0x6, 0x9, 0x8, 0x5, 0x0, 0x6, 0xD, 0x1, 0x3, 0xD, 0x4,
     0xE, 0xE, 0x0, 0x7, 0xB, 0x5, 0x3, 0xB, 0x8, 0x9, 0x4, 0xE, 0x3, 0xF, 0x2, 0x5, 0xC, 0x2, 0x9, 0x8, 0x5, 0xC, 0xF,
     0x3, 0xA, 0x7, 0xB, 0x0, 0xE, 0x4, 0x1, 0xA, 0x7, 0x1, 0x6, 0xD, 0x0, 0xB, 0x8, 0x6, 0xD],
    [0x4, 0xD, 0xB, 0x0, 0x2, 0xB, 0xE, 0x7, 0xF, 0x4, 0x0, 0x9, 0x8, 0x1, 0xD, 0xA, 0x3, 0xE, 0xC, 0x3, 0x9, 0x5, 0x7,
     0xC, 0x5, 0x2, 0xA, 0xF, 0x6, 0x8, 0x1, 0x6, 0x1, 0x6, 0x4, 0xB, 0xB, 0xD, 0xD, 0x8, 0xC, 0x1, 0x3, 0x4, 0x7, 0xA,
     0xE, 0x7, 0xA, 0x9, 0xF, 0x5, 0x6, 0x0, 0x8, 0xF, 0x0, 0xE, 0x5, 0x2, 0x9, 0x3, 0x2, 0xC],
    [0xD, 0x1, 0x2, 0xF, 0x8, 0xD, 0x4, 0x8, 0x6, 0xA, 0xF, 0x3, 0xB, 0x7, 0x1, 0x4, 0xA, 0xC, 0x9, 0x5, 0x3, 0x6, 0xE,
     0xB, 0x5, 0x0, 0x0, 0xE, 0xC, 0x9, 0x7, 0x2, 0x7, 0x2, 0xB, 0x1, 0x4, 0xE, 0x1, 0x7, 0x9, 0x4, 0xC, 0xA, 0xE, 0x8,
     0x2, 0xD, 0x0, 0xF, 0x6, 0xC, 0xA, 0x9, 0xD, 0x0, 0xF, 0x3, 0x3, 0x5, 0x5, 0x6, 0x8, 0xB],
]

def getHexAscii(text):
    x1=binascii.hexlify(text.encode())
    y1=str(x1,'ascii')

    return y1

if __name__ == "__main__":
    pesan = getHexAscii("yonathan")
    kunci = "133457799BBCDFF1"

    plaintextbytelist = cryptocommon.hexstr_to_bytelist(pesan)
    keybytelist = cryptocommon.hexstr_to_bytelist(kunci)

    print(plaintextbytelist)
    print(keybytelist)

    print(encrypt(plaintextbytelist, keybytelist))