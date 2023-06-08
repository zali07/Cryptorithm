from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from os import urandom
import base64


def AES128_CTR_EN(plaintext, password):
    data = plaintext.encode("utf-8")
    password_bytes = password.encode("utf-8")
    nonce = urandom(16)
    salt = urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key128 = kdf.derive(password_bytes)
    
    cipher = Cipher(algorithms.AES(key128), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode("utf-8"), salt, key128, nonce


def AES256_CTR_EN(plaintext, password):
    data = plaintext.encode("utf-8")
    password_bytes = password.encode("utf-8")
    nonce = urandom(16)
    salt = urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key256 = kdf.derive(password_bytes)

    cipher = Cipher(algorithms.AES(key256), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode("utf-8"), salt, key256, nonce