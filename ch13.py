import re

from ch07 import encrypt_aes_128_ecb, decrypt_aes_128_ecb
from ch09 import pkcs7_pad
from ch10 import strip_padding
from ch11 import generate_bytes

reEmail = re.compile("^[a-z0-9-]+@[a-z0-9-]+\.[a-z0-9-]+$")
key = None


def kv_parse(string: str) -> dict:
    ret = {}
    for substr in string.split('&'):
        k, v = substr.split('=')
        ret[str(k)] = str(v)
    return ret


def kv_return(d: dict) -> str:
    return '&'.join(['='.join([k, v]) for k, v in d.items()])


def check_email(email: str) -> bool:
    gx = reEmail.match(email)
    return bool(gx)


def profile_for(email: str) -> str:
    # This is not what is required in the excercise
    # and frankly I don't yet know how to perform this
    # if not check_email(email):
    #     raise Exception("Email incorrect")
    ret = {
        "email": email.replace("=", "").replace("&", ""),
        "uid":   "10",
        "role":  "user"
    }
    return kv_return(ret)


def encrypt_profile(email: str) -> bytes:
    global key
    if key is None:
        key = generate_bytes()
    data = profile_for(email)
    data = pkcs7_pad(bytes(data, "ascii"))
    return encrypt_aes_128_ecb(data, key)


def decrypt_profile(data: bytes) -> dict:
    global key
    ret = decrypt_aes_128_ecb(data, key)
    ret = strip_padding(ret)
    ret = kv_parse(ret.decode("ascii"))
    return dict(ret)


def attack_profile() -> bytes:
    email = "admin@foo.bar"
    admin = pkcs7_pad(b"admin").decode("ascii")
    padding = "x" * (16 - len("email="))

    enc_bytes = encrypt_profile(email)
    enc_admin = encrypt_profile(padding + admin + "@foo.bar")
    return enc_bytes[0:32] + enc_admin[16:32]
