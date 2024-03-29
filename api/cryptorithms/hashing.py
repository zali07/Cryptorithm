import hashlib
import whirlpool
import bcrypt

def hash_SHA(plaintext, SHAType):
    data = plaintext.encode("utf-8")
    if SHAType == 1: #SHA-1
        hash = hashlib.sha1(data).hexdigest()
    elif SHAType == 256: #SHA-256
        hash = hashlib.sha256(data).hexdigest()
    elif SHAType == 384: #SHA-384
        hash = hashlib.sha384(data).hexdigest()
    elif SHAType == 512: #SHA-512
        hash = hashlib.sha512(data).hexdigest()
    else:
        hash = -1
    return hash

def whirlpool_hash(plaintext):
    plaintext = plaintext.encode("utf-8")
    hash = whirlpool.new(plaintext).hexdigest()
    return hash

def bcrypt_hash(plaintext):
    plaintext = plaintext.encode("utf-8")
    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(plaintext, salt)
    return hash.decode("utf-8")

def bcrypt_check(plaintext, hash):
    try:
        plaintext = plaintext.encode("utf-8")
        hash = hash.encode("utf-8")
        if bcrypt.checkpw(plaintext, hash):
            return "Correct!"
    except:
        return "False!"