def pkcs7_validate(data: bytes) -> bool:
    byte = data[-1]
    sample = data[-byte:]
    test = map(lambda x: x == byte, sample)
    return all(test)
