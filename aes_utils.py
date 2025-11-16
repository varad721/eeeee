# aes_utils.py
from Crypto.Cipher import AES

AES_KEY = b"Yg&tc%DEuh6%Zc^8"
AES_IV = b"6oyZDr22E3ychjM%"

def remove_pkcs7_padding(data: bytes, block_size: int) -> bytes:
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("Invalid data or block size.")

    padding_length = data[-1]
    if padding_length <= 0 or padding_length > block_size:
        raise ValueError("Bad padding.")

    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("Bad padding.")

    return data[:-padding_length]

class AESUtils:
    def __init__(self, key: bytes = AES_KEY, iv: bytes = AES_IV):
        self.key = key
        self.iv = iv

    def decrypt_aes_cbc(self, data: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        decrypted = cipher.decrypt(data)
        return remove_pkcs7_padding(decrypted, AES.block_size)

    def encrypt_aes_cbc(self, data: bytes) -> bytes:
        # Use standard PKCS7 padding
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        # Manually pad
        pad_len = AES.block_size - len(data) % AES.block_size
        padded = data + bytes([pad_len] * pad_len)
        return cipher.encrypt(padded)
