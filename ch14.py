from random import randint
from typing import Callable

from ch11 import generate_bytes
from ch12 import crack_ecb_simple, encryption_oracle_ecb

random_bytes = generate_bytes(randint(0, 64))


def encryption_oracle_ecb_hard(data: bytes) -> bytes:
    global random_bytes
    data = random_bytes + data
    return encryption_oracle_ecb(data)


def crack_ecb_hard(func: Callable[[bytes], bytes]) -> bytes:
    # the padding is called 'lefter', because it is even more to the left than
    # the actual attack
    bs = 16
    lefter_size = find_lefter_pad_size(func, bs)
    return crack_ecb_simple(func, lefter_size)


def find_lefter_pad_size(func: Callable[[bytes], bytes], bs: int = 16) -> int:
    reference = func(b"a" * bs)
    sample_pads = [b"a" * x + b"b" + b"a" * (bs - x) for x in range(bs)]
    sample_out = [find_diff(reference, func(sp)) for sp in sample_pads]
    offset = [sample_out[i] - i for i in range(1, len(sample_out)) if sample_out[i - 1] != sample_out[i]]
    if offset:
        return offset[0]
    else:  # all equal
        return sample_out[0]


def find_diff(alice, bob):
    # take a look at itertools.takewhile
    for offset in range(len(bob)):
        if alice[offset] != bob[offset]:
            return offset
    return None
