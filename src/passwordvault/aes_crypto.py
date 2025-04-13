from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64
import hashlib


# AES block size i bitar
BLOCK_SIZE = 128


# Hash the master password (SHA-256 hashing algoritm) ---
def hash_password(password: str) -> str:
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return hashed


def encrypt(plaintext: str, key: bytes) -> str:
    iv = os.urandom(16)  # 16 byte IV för AES
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Slå ihop IV och data, och returnera som base64-sträng
    return base64.b64encode(iv + encrypted_data).decode()


def decrypt(encoded_data: str, key: bytes) -> str:
    raw_data = base64.b64decode(encoded_data.encode())
    iv = raw_data[:16]
    encrypted_data = raw_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

    return decrypted_data.decode()





