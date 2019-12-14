from typing import List

from ch03 import crack_sb_xor_v2, english_scoring


def detect_xor(data: List[bytes]) -> bytes:
    """
    Probably needs a rewrite
    TODO
    """
    best_matches = [crack_sb_xor_v2(x) for x in data]
    best = None
    prev = 0
    for match in best_matches:
        rating = english_scoring(match)
        if rating > prev:
            best = match
            prev = rating
    return best
