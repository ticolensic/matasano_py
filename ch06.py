from itertools import combinations
from random import randrange
from typing import List, Dict, Any

from bitarray import bitarray

from ch03 import crack_sb_xor_v3, english_scoring
from ch05 import repeating_xor


def hamming_distance(s1: bytes, s2: bytes) -> int:
    ba1 = bitarray()
    ba2 = bitarray()
    ba1.frombytes(s1)
    ba2.frombytes(s2)
    return sum(b1 != b2 for b1, b2 in zip(ba1, ba2))


def slice_in_blocks(data: bytes, block_size: int) -> List[bytes]:
    return [data[i::block_size] for i in range(block_size)]


def break_repeating_xor(data: bytes) -> bytes:
    keysizes: List[int] = find_keysizes_4avg(data)
    best_score = -255
    ret = ""
    for ks in sorted(keysizes):
        blocks = slice_in_blocks(data, ks)
        guessed_key = bytes([crack_sb_xor_v3(b) for b in blocks])
        guessed_strings = repeating_xor(data, guessed_key)
        guessed_strings = bytes(''.join([chr(c) for c in guessed_strings]), "ascii")
        score = english_scoring(guessed_strings)
        if best_score < score:
            best_score = score
            ret = guessed_key
    return ret


def find_keysizes(data: bytes, ret_size=3, keysize=2, keysize_max=40) -> List[int]:
    """
    Somehow this function doesn't work for the task
    """
    normalized_distances = {}
    while keysize <= keysize_max:
        sample1 = data[:keysize]
        sample2 = data[keysize:keysize * 2]
        hd = hamming_distance(sample1, sample2)
        normalized_distances[keysize] = hd / keysize
        keysize += 1
    sorted_nd: Any = sorted(normalized_distances.items(), key=lambda x: x[1])
    return [x[0] for x in sorted_nd[:ret_size]]


def find_keysizes_4avg(data: bytes, sample_size=6, keysize=2, keysize_max=40) -> List[int]:
    nd_avg: Dict[int, float] = {}
    while keysize <= keysize_max:
        rnd = randrange(len(data) - keysize * sample_size)
        samples = [data[rnd + keysize * i:rnd + keysize * (i + 1)] for i in range(sample_size)]
        comb_samples = list(combinations(samples, 2))
        normalized_distances = [hamming_distance(s1, s2) for (s1, s2) in comb_samples]
        nd_avg[keysize] = (sum(normalized_distances) / len(normalized_distances)) / keysize
        keysize += 1
    # WA for PyCharm - Any type
    sorted_nd_avg: Any = sorted(nd_avg.items(), key=lambda x: x[1])
    return [x[0] for x in sorted_nd_avg[:3]]
