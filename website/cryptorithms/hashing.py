import hashlib

data = b"Hello, World!"  # Data to be hashed

#HASH
def hash_SHA(plaintext, SHAType):
    data = plaintext.encode("utf-8")
    match SHAType:
        case 1: #SHA-1
            hash = hashlib.sha1(data).hexdigest()
        case 256: #SHA-256
            hash = hashlib.sha256(data).hexdigest()
        case 384: #SHA-384
            hash = hashlib.sha384(data).hexdigest()
        case 512: #SHA-512
            hash = hashlib.sha512(data).hexdigest()
        case other:
            hash = -1
    return hash
