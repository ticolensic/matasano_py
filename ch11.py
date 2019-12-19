from random import randint
from typing import Callable

from ch07 import encrypt_aes_128_ecb
from ch09 import pkcs7_pad
from ch10 import encrypt_cbc


def ecb_or_cbc(func: Callable[[bytes], bytes]):
    data = bytes(b'\0' * 128)
    test_data = func(data)
    return True if test_data[32:48] == test_data[48:64] else False


def encryption_oracle_ecb_cbc(data: bytes, is_ecb: bool) -> bytes:
    key = generate_bytes()
    before = generate_bytes(randint(5, 10))
    after = generate_bytes(randint(5, 10))
    data = before + data + after
    data = pkcs7_pad(data)
    if is_ecb:
        output = encrypt_aes_128_ecb(data, key)
    else:
        iv = generate_bytes()
        output = encrypt_cbc(data, key, iv)
    return output


def generate_bytes(size: int = 16) -> bytes:
    return bytes([randint(0, 255) for _ in range(size)])
