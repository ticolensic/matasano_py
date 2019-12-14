from typing import NewType

Base64 = NewType("Base64", str)
Hex = NewType("Hex", str)


def from_hex(data: Hex) -> bytes:
    # generate 0-9 and a-f string
    d = list(range(ord('0'), ord('9') + 1)) + list(range(ord('a'), ord('f') + 1))
    i = 0
    res = []
    data = data.strip('\r\n ')
    if len(data) % 2 == 1:
        data = '0' + data
        print(data)
    while i < len(data):
        c = d.index(ord(data[i])) * 16 + d.index(ord(data[i + 1]))
        res.append(c)
        i += 2
    return bytes(res)


def to_hex(inbytes: bytes) -> Hex:
    d = list(range(ord('0'), ord('9') + 1)) + list(range(ord('a'), ord('f') + 1))
    first = [x >> 4 for x in inbytes]
    second = [x & 0xf for x in inbytes]
    ret = Hex(''.join([chr(d[item]) for sublist in zip(first, second) for item in sublist]))
    return ret


def to_base64(inbytes: bytes) -> Base64:
    d = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    i = 0
    res = Base64("")
    while i < len(inbytes):
        c1 = inbytes[i] >> 2
        c2 = ((inbytes[i] & 0x3) << 4) + (inbytes[i + 1] >> 4)
        c3 = ((inbytes[i + 1] & 0xf) << 2) + (inbytes[i + 2] >> 6)
        c4 = inbytes[i + 2] & 0x3f
        res += ''.join([chr(d[x]) for x in [c1, c2, c3, c4]])
        i += 3
    return res


def from_base64(string: Base64) -> bytes:
    d = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    res = []
    for line in string.split('\n'):
        i = 0
        chars = [d.index(x) for x in line]
        while i < len(chars):
            bs = [
                (chars[i + 0] << 2) + ((chars[i + 1] & 0b00110000) >> 4),
                ((chars[i + 1] & 0b00001111) << 4) + ((chars[i + 2] & 0b00111100) >> 2),
                ((chars[i + 2] & 0b00000011) << 6) + (chars[i + 3])
            ]
            i += 4
            res += bs
    return bytes(res)
