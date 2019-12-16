from Crypto.Cipher import AES


def decrypt_aes_128_ecb(data: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).decrypt(data)


def encrypt_aes_128_ecb(data: bytes, key: bytes = 16) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(data)
