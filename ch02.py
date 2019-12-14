def fixed_xor(data: bytes, key: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(data, key)])
