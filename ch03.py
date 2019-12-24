from collections import Counter
from string import ascii_letters, digits

long_read_chars = '\n\r! "$\'&)(-,.;:?'
good_symbols = bytes(ascii_letters + digits + long_read_chars, "ascii")
etaoin = b'etaoin shldru'

"""
    * Side note
    Interesting observation: the correct "Cooking MC's like a pound of bacon" wins with sample 3 and 7, the in-between
    4..6 give a very positive score to a string with lots of h's, which could happen with single xor. As an example,
    if all etaion characters are equally weighted, on a small input string initial MOST_COMMON1-6 belongs to
    [etaoinshldru] the u's or the h's could easily outweigh the e's. To make it more proportional,  we might 
    need to break this string into two buckets, where:
    [etaoin] should cover most common 1 to 6 chars
    [shldru] should cover 1 to 12 (sic)
    Or more buckets (e.g. 3-4), where:
    eta-bucket will give one point to [eta], zero points to [oin], and minus one to the rest
    oin-bucket will give one point to [oin], zero points to [eta] and [shl] and minus one to the rest
    etc
 """


def rate_english_v1(data: bytes) -> int:
    """
    Numbers + alphabet + non-english characters (that could still be found in an English text)
    are stripped away. Depending on how many chars left out of that scope is the negative score.
    """
    bad_symbols = [x for x in data if x not in good_symbols]
    return len(bad_symbols)


def rate_english_v2(data: bytes, pick_sample=3) -> int:
    """
     find X most frequent characters in string and find_diff to etaoin. All spare are a minus.
    """

    mc = Counter(data).most_common(pick_sample)  # list of tuples
    mc = [z for (z, _) in mc]

    neg = [x for x in mc if x not in etaoin]
    pos = [x for x in mc if x in etaoin]
    return sum([len(pos), -len(neg)])


def english_scoring(data: bytes, pick_sample=3) -> float:
    """
    Next idea: break the text down into words and check against a dictionary, for big texts every matched word
    will be e.g. 0.1 (need some statistics on that).

    TO DO: Develop a scoring value system and test against many samples
    Maybe normalize against the text size
    """
    score = 0
    transform = data.lower()
    score += rate_english_v1(transform) * -2 / len(data)
    score += rate_english_v2(data.lower(), pick_sample)
    return score


def crack_sb_xor_v1(data: bytes) -> bytes:
    """
    'smart version'
    """
    most_common_byte = Counter(data).most_common(1)[0][0]
    results = {}
    for c in ' etaoin':
        key = ord(c) ^ most_common_byte
        answer = bytes([x ^ key for x in data])
        results[rate_english_v1(answer)] = answer
    return results[max(results.keys())]


def crack_sb_xor_v2(data: bytes) -> bytes:
    results = {}
    for c in range(0, 256):
        answer = bytes([x ^ c for x in data])
        score = english_scoring(answer, 7)
        results[score] = answer
    return results[max(results.keys())]


def crack_sb_xor_v3(data: bytes) -> int:
    """
    Dupe version that returns a key.
    TODO: v1/2 must be deprecated and all the code rewritten to use this func
    """
    results = {}
    for c in range(0, 256):
        answer = bytes([c ^ x for x in data])
        score = english_scoring(answer, 3)
        results[score] = c
    return results[max(results.keys())]
