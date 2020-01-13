from collections import defaultdict

from ch10 import decrypt_cbc, encrypt_cbc
from ch11 import generate_bytes

iv: bytes = generate_bytes()
key: bytes = generate_bytes()


# iv: bytes = b"\0" * 16
# key: bytes = b"\0" * 16


def encrypt_cbc_fix(data: bytes) -> bytes:
    global key
    global iv
    return encrypt_cbc(data, key, iv)


def decrypt_cbc_fix(data: bytes) -> bytes:
    global key
    global iv
    return decrypt_cbc(data, key, iv)


def encrypt_wrapper(data: bytes) -> bytes:
    left = b"comment1=cooking%20MCs;userdata="
    right = b";comment2=%20like%20a%20pound%20of%20bacon"
    data = data.replace(b';', b'%3B').replace(b'=', b'%3D')
    data = left + data + right
    return encrypt_cbc_fix(data)


def check_admin(data: bytes) -> bool:
    dec: bytes = decrypt_cbc_fix(data)
    d = dict(
        (x.split(b'=')[0], x.split(b'=')[1])
        for x in dec.split(b';')
    )
    breakdown = defaultdict(lambda: b"false", d)
    return breakdown[b"admin"] == b"true"


def flip_bits(enc_data: bytes, target: bytes, offset, block_size: int = 16) -> bytes:
    prev = offset - block_size
    size = len(target)
    if ((offset % block_size) + size) > block_size:
        raise Exception("Can attack only one block")
    if offset < 16:
        raise Exception("Can't attack the first block")

    enc_flipped = bytearray(enc_data)
    for i in range(size):
        enc_flipped[prev + i] ^= target[i]

    dec_flipped = decrypt_cbc_fix(bytes(enc_flipped))
    result = bytearray(enc_data)
    for i in range(size):
        result[prev + i] ^= dec_flipped[offset + i]

    return bytes(result)


def crack_admin() -> bytes:
    data = encrypt_wrapper(b"A" * 32)
    inject = b";admin=true"
    return flip_bits(data, inject, 53)
