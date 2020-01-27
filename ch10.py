from tco import *

from ch02 import fixed_xor
from ch07 import encrypt_aes_128_ecb, decrypt_aes_128_ecb
from ch09 import pkcs7_pad
from ch15 import pkcs7_validate


@with_continuations()
def encrypt_cbc(block: bytes, key: bytes, vector: bytes = b'\0' * 16, block_size: int = 16, self=None) -> bytes:
    if not block:
        return b""
    left = pkcs7_pad(block[:block_size], block_size)
    right = block[block_size:]

    xored = fixed_xor(left, vector)
    left_res = encrypt_aes_128_ecb(xored, key)
    right_res = encrypt_cbc(right, key, left_res)
    return left_res + right_res


# @with_continuations()
def decrypt_cbc(block: bytes, key: bytes, vector: bytes = None, block_size: int = 16,
                padding: bool = True, self=None) -> bytes:
    if not block:
        return b""
    if not vector:
        vector = b'\0' * 16
    d = decrypt_aes_128_ecb(block[:block_size], key)
    left = fixed_xor(d, vector)
    right = decrypt_cbc(block[block_size:], key, block[:block_size], block_size, padding)
    if padding and (not right):
        left = strip_padding(left)
    return left + right


def strip_padding(data: bytes, bs: int = 16):
    if len(data) % bs > 0:
        raise WrongPaddingException("Uneven padding")
    if not pkcs7_validate(data, bs):
        raise WrongPaddingException("Wrong padding")
    x = b""  # WA for Code Analysis
    for x in range(bs, 0, -1):
        test = map(lambda z: z == x, data[-x:])
        if all(test):
            break
    return data.rstrip(bytes([x]))


class WrongPaddingException(Exception):
    pass
