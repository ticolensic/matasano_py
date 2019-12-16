def pad(data: bytes, width: int, char: bytes) -> bytes:
    data += char * (width - len(data) % width)
    return data


def pkcs7_pad(data: bytes, pad_bytes: int = 16) -> bytes:
    length = pad_bytes - len(data) % pad_bytes
    padding = b'%c' % length
    return pad(data, pad_bytes, padding)
