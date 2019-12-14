def repeating_xor(line: bytes, key: bytes) -> bytes:
    linekey = list(zip(line, key * int(len(line) / len(key) + 1)))
    return bytes([x ^ y for x, y in linekey])
