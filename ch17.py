from functools import reduce
from random import choice
from typing import List

from ch01 import from_base64, Base64
from ch10 import encrypt_cbc, decrypt_cbc, WrongPaddingException, strip_padding
from ch11 import generate_bytes

fixkey: bytes = generate_bytes()


def encrypt_random_string(bs: int = 16, teststring: str = None) -> bytes:
    iv = generate_bytes()
    # noinspection PyTypeChecker
    strings: List[Base64] = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
                             "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
                             "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
                             "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
                             "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
                             "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
                             "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
                             "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
                             "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
                             "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]
    rand_string = from_base64(choice(strings))
    if teststring:
        rand_string = teststring
    return iv + encrypt_cbc(rand_string, fixkey, iv, bs)


def decrypt_check_padding(data, bs: int = 16) -> bool:
    iv = data[:bs]
    data = data[bs:]
    try:
        decrypt_cbc(data, fixkey, iv, bs)
    except WrongPaddingException:
        return False
    return True


def padding_oracle_attack(cipher: bytes, bs: int = 16) -> bytes:
    size = len(cipher)
    if size < bs * 2:
        raise Exception("Can only attack more than 2 block sizes")
    res = reduce(list.__add__,
                 [crack_block(cipher[index - (2 * bs):index])
                  for index in range(bs * 2, size + 1, bs)])
    return strip_padding(bytes(res), False)


def crack_block(cipher: bytes, bs: int = 16) -> List[int]:
    plain = []
    for index in range(1, bs + 1):
        inv_index = bs - index
        c1 = cipher[inv_index]
        if index < bs:
            # anti-false-positive byte
            # the correct way is probably backtracking,
            # see set3_tests, ch17
            afp = [c1 ^ 0x2]
            left = cipher[:inv_index - 1]
        else:
            afp = []
            left = b""
        right = cipher[bs:]
        zip_xor = zip(plain, cipher[inv_index + 1:bs])
        infix = afp + [0] + [index ^ p ^ c for (p, c) in zip_xor]

        probe = list(left) + infix + list(right)
        c1_ = crack_byte(probe, inv_index)
        p2 = index ^ c1_ ^ c1
        plain.insert(0, p2)
    return plain


def crack_byte(cipher: List[int], offset: int) -> int:
    for char in range(256):
        cipher[offset] = char
        if decrypt_check_padding(bytes(cipher)):
            return char
    raise Exception("Bug")

# def test(data, bs: int = 16) -> bytes:
#     iv = data[:bs]
#     data = data[bs:]
#     return decrypt_cbc(data, fixkey, iv, bs, False)
