import string
from math import gcd

# caesar
def caesar_decrypt(ciphertext, shift=None):
    """
    Decrypts the given ciphertext using Caesar cipher with the given shift, or
    tries to decrypt using the 26 letter alphabets frequency table if shift is None.
    """
    if shift is None:
        # Frequency table of 26 letter alphabets in English language
        freq_table = ['e', 't', 'a', 'o', 'i', 'n', 's', 'r', 'h', 'l', 'd', 'c', 'u', 'm', 'f', 'p', 'g', 'w', 'y', 'b', 'v', 'k', 'x', 'j', 'q', 'z']
        for i in range(26):
            possible_plaintext = ""
            for char in ciphertext:
                if char.isalpha():
                    shifted_char = chr((ord(char.lower()) - ord('a') + i) % 26 + ord('a'))
                    possible_plaintext += shifted_char.upper() if char.isupper() else shifted_char
                else:
                    possible_plaintext += char
            # Calculate the frequency of each letter in the possible plaintext
            letter_freq = {}
            for char in string.ascii_lowercase:
                letter_freq[char] = possible_plaintext.lower().count(char)
            # Check if the letter frequency matches the expected frequency table
            sorted_freq_table = sorted(freq_table, key=lambda x: letter_freq[x], reverse=True)
            if sorted_freq_table == freq_table:
                return possible_plaintext
        # If none of the shifts matched the frequency table, return None
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
    

# affin
def affine_decrypt(ciphertext, a, b):
    """
    Decrypts the given ciphertext using Affine cipher with the given coefficients a and b.
    """
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
    """
    Computes the modular inverse of a modulo m using the extended Euclidean algorithm.
    """
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


# hill



# rc4, lfsr, a51



# cbc, ctr, des, aes



# rsa



# rabin, saep
