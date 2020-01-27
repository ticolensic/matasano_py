def pkcs7_validate(data: bytes, bs: int = 16) -> bool:
    byte = data[-1]
    if byte > bs or byte == 0:
        return False
    sample = data[-byte:]
    test = map(lambda x: x == byte, sample)
    return all(test)
