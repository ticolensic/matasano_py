from functools import reduce
from random import choice
from typing import List

from ch01 import from_base64, Base64
from ch10 import encrypt_cbc, decrypt_cbc, WrongPaddingException
from ch11 import generate_bytes

# fixkey: bytes = generate_bytes()
fixkey: bytes = b'\0' * 16


def encrypt_random_string(bs: int = 16, teststring: str = None) -> bytes:
    global fixkey
    # iv = generate_bytes()
    iv: bytes = b'\6' * 16
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
    # rand_string = b"\8" * 16
    # rand_string = b"1098qwetykjhgfds4141425209853743URUVNTOSPOARMTGU" * 2
    rand_string = b"abcdefghijklmnopqrstuvwx"
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


def test(data, bs: int = 16) -> bytes:
    iv = data[:bs]
    data = data[bs:]
    return decrypt_cbc(data, fixkey, iv, bs, False)


def padding_oracle_attack(cipher: bytes, bs: int = 16) -> bytes:
    size = len(cipher)
    if size < bs * 2:
        raise Exception("Can only attack more than 2 block sizes")
    res = reduce(list.__add__,
                 [crack_block(cipher[index - (2 * bs):index])
                  for index in range(bs * 2, size + 1, bs)])
    return bytes(res)


def crack_block(cipher: bytes, bs: int = 16) -> List[int]:
    plain = []
    for index in range(1, bs + 1):
        inv_index = bs - index
        c1 = cipher[inv_index]
        temp = cipher[inv_index + 1:bs]
        infix = [0] + [index ^ p ^ c for (p, c) in zip(plain, temp)]
        # print(infix)
        mangled = list(cipher[:inv_index]) + infix + list(cipher[bs:])
        c1_ = crack_byte(mangled, inv_index)
        p2 = index ^ c1_ ^ c1
        plain.insert(0, p2)
    return plain


def crack_byte(cipher: List[int], offset: int) -> int:
    for char in range(256):
        cipher[offset] = char

        if decrypt_check_padding(bytes(cipher)):
            t = test(bytes(cipher))

            return char
    t = test(bytes(cipher))
    # print(t)
    return 0
    raise Exception("Bug")
