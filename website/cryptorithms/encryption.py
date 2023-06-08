import random

#DATATRANSFORMATION
# caesar
def caesar_encrypt(plaintext, shift):
    """
    Encrypts the given plaintext using Caesar cipher with the given shift.
    """
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            shifted_char = chr((ord(char.lower()) - ord('a') + shift) % 26 + ord('a'))
            ciphertext += shifted_char.upper() if char.isupper() else shifted_char
        else:
            ciphertext += char
    return ciphertext


# affin
def affine_encrypt(plaintext, a, b):
    """
    Encrypts the given plaintext using Affine cipher with the given coefficients a and b.
    """
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            shifted_char = chr((a * (ord(char.lower()) - ord('a')) + b) % 26 + ord('a'))
            ciphertext += shifted_char.upper() if char.isupper() else shifted_char
        else:
            ciphertext += char
    return ciphertext

def generate_affine_key():
    """
    Generates a random Affine cipher key (a, b).
    """
    a = random.choice([1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25])
    b = random.randint(0, 25)
    return a, b
