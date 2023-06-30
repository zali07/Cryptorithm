from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from os import urandom
import base64
from struct import pack
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad


def AES_CTR_EN(plaintext, password, AESType): #AESType 128 or 256
    data = plaintext.encode("utf-8")
    password_bytes = password.encode("utf-8")
    nonce = urandom(16)
    salt = urandom(16)
    if AESType == 128:
        keyLen = 16
    elif AESType == 256:
        keyLen = 32
    else:
        return
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=keyLen,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password_bytes)

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode("utf-8"), base64.b64encode(key).decode("utf-8"), base64.b64encode(nonce).decode("utf-8")

def AES_CTR_DE(ciphertext, key, nonce):
    try:
        ciphertext = base64.b64decode(ciphertext)
        nonce = base64.b64decode(nonce)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_text.decode("utf-8")
    except:
        return None
    
def blowfish_EN(plaintext):
    data = plaintext.encode("utf-8")
    key = urandom(16)
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    ciphertext = cipher.encrypt(pad(data, Blowfish.block_size))
    return ciphertext.hex(), key.hex()


def blowfish_DE(ciphertext, key):
    ciphertext = bytes.fromhex(ciphertext)
    key = bytes.fromhex(key)
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), Blowfish.block_size)
    return plaintext.decode("utf-8")