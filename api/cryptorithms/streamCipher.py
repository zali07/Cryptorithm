import random
import string
from math import gcd
from base64 import b64encode
from os import urandom
import base64
from Crypto.Cipher import ChaCha20


def caesar_encrypt(plaintext, shift):
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            shifted_char = chr((ord(char.lower()) - ord('a') + shift) % 26 + ord('a'))
            ciphertext += shifted_char.upper() if char.isupper() else shifted_char
        else:
            ciphertext += char
    return ciphertext

def caesar_decrypt(ciphertext, shift=None):
    if shift is None:
        freq_table = ['e', 't', 'a', 'o', 'i', 'n', 's', 'r', 'h', 'l', 'd', 'c', 'u', 'm', 'f', 'p', 'g', 'w', 'y', 'b', 'v', 'k', 'x', 'j', 'q', 'z']
        for i in range(26):
            possible_plaintext = ""
            for char in ciphertext:
                if char.isalpha():
                    shifted_char = chr((ord(char.lower()) - ord('a') + i) % 26 + ord('a'))
                    possible_plaintext += shifted_char.upper() if char.isupper() else shifted_char
                else:
                    possible_plaintext += char
            letter_freq = {}
            for char in string.ascii_lowercase:
                letter_freq[char] = possible_plaintext.lower().count(char)
            sorted_freq_table = sorted(freq_table, key=lambda x: letter_freq[x], reverse=True)
            if sorted_freq_table == freq_table:
                return possible_plaintext
        return None
    else:
        plaintext = ""
        for char in ciphertext:
            if char.isalpha():
                shifted_char = chr((ord(char.lower()) - ord('a') - shift) % 26 + ord('a'))
                plaintext += shifted_char.upper() if char.isupper() else shifted_char
            else:
                plaintext += char
        return plaintext

def affine_encrypt(plaintext, a, b):
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            shifted_char = chr((a * (ord(char.lower()) - ord('a')) + b) % 26 + ord('a'))
            ciphertext += shifted_char.upper() if char.isupper() else shifted_char
        else:
            ciphertext += char
    return ciphertext

def generate_affine_key():
    a = random.choice([1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25])
    b = random.randint(0, 25)
    return a, b

def affine_decrypt(ciphertext, a, b):
    plaintext = ""
    a_inverse = mod_inverse(a, 26)
    for char in ciphertext:
        if char.isalpha():
            shifted_char = chr((a_inverse * (ord(char.lower()) - ord('a') - b)) % 26 + ord('a'))
            plaintext += shifted_char.upper() if char.isupper() else shifted_char
        else:
            plaintext += char
    return plaintext

def mod_inverse(a, m):
    if gcd(a, m) != 1:
        return None
    t, new_t = 0, 1
    r, new_r = m, a
    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
    if r > 1:
        return None
    if t < 0:
        t = t + m
    return t

def chacha20_EN(plaintext):
    plaintext = plaintext.encode('utf-8')
    key = urandom(32)
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.encrypt(plaintext)
    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ciphertext).decode('utf-8')
    key = b64encode(key).decode('utf-8')
    return ct, key, nonce

def chacha20_DE(ciphertext, key, nonce):
    try:
        ciphertext = base64.b64decode(ciphertext)
        nonce = base64.b64decode(nonce)
        key = base64.b64decode(key)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode('utf-8')
    except:
        return None