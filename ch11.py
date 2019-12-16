from random import randint

from ch07 import encrypt_aes_128_ecb
from ch09 import pkcs7_pad
from ch10 import encrypt_cbc


def encryption_oracle(data) -> bytes:
    key = generate_bytes()
    before = generate_bytes(randint(5, 10))
    after = generate_bytes(randint(5, 10))
    data1 = before + data + after
    data = pkcs7_pad(data1)
    if randint(1, 2) == 1:
        iv = generate_bytes()
        output = encrypt_cbc(data, key, vector=iv)
    else:
        output = encrypt_aes_128_ecb(data, key)
    return output


def generate_bytes(size: int = 16) -> bytes:
    return bytes([randint(0, 255) for _ in range(size)])
