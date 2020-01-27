from typing import Callable

from ch01 import from_base64, Base64
from ch07 import encrypt_aes_128_ecb
from ch09 import pkcs7_pad
from ch10 import strip_padding
from ch11 import generate_bytes, ecb_or_cbc

unknown_string = from_base64(Base64("""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""))
key = generate_bytes()


def encryption_oracle_ecb(data: bytes) -> bytes:
    global key
    data = pkcs7_pad(data + unknown_string)
    return encrypt_aes_128_ecb(data, key)


# needs a rewrite
def find_block_size(func: Callable[[bytes], bytes]):
    return len(func(b"A"))


def crack_ecb_simple(func: Callable[[bytes], bytes], left_base_size: int = 0) -> bytes:
    # block_size = find_block_size(func)  # wrong
    block_size = 16
    answer = []
    base_byte = b"A"
    base_offset = round_up(left_base_size, block_size)
    lefter = base_byte * (base_offset - left_base_size)

    if not ecb_or_cbc(func, base_offset):
        raise Exception("This is not a ECB oracle")

    guess_data_size = len(func(lefter))

    zip_vars = (
        (x // block_size,  # distance
         block_size - x % block_size - 1)  # padding_size
        for x in range(guess_data_size)
    )
    for distance, padding_size in zip_vars:
        # as left part is always 15 bytes, for the first round we need padding
        # and for all consecutive blocks we don't, so:
        # bool(distance) ^ 1 returns 0 if (distance > 0)
        left_padding_size = padding_size * (bool(distance) ^ 1)

        left_data_size = block_size - left_padding_size - 1
        left = (base_byte * left_padding_size) + bytes(answer[-left_data_size:])
        right = (base_byte * padding_size)
        blocks = [left + bytes([b]) + right for b in range(256)]
        block_pairs = [(block, func(lefter + block)) for block in blocks]
        for block, enc_block in block_pairs:
            enc_offset = base_offset + block_size * (distance + 1)

            left_start = base_offset
            right_start = enc_offset

            if enc_block[left_start:left_start + block_size] == enc_block[right_start:right_start + block_size]:
                x = block[block_size - 1]
                answer.append(x)
                break
    if len(answer) % block_size > 0:
        return bytes(answer)
    else:
        return strip_padding(bytes(answer))


def round_up(x: int, y: int) -> int:
    # rounds up to integer, e.g. 27 round up to 16 is 32
    if x == 0:
        return 0
    return y - (x % y) + x
