def pad(data: bytes, width: int, char: bytes) -> bytes:
    # len_data_width = len(data) % width
    # if len_data_width == 0:
    #     return data
    data_width = width - len(data) % width
    data += char * data_width
    return data


def pkcs7_pad(data: bytes, pad_bytes: int = 16) -> bytes:
    length = pad_bytes - len(data) % pad_bytes
    padding = b'%c' % length
    return pad(data, pad_bytes, padding)
