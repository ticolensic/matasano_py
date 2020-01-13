def pkcs7_validate(data: bytes, bs: int = 16) -> bool:
    if len(data) % bs != 0:
        raise Exception("Not padded to a block")
    byte = data[-1]
    sample = data[-byte:]
    test = map(lambda x: x == byte, sample)
    return all(test)
