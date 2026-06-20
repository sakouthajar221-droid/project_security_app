"""
Module de Confidentialité - Chiffrement Symétrique (AES)
"""

import base64
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def generate_aes_key(key_size=256):
    """Génère une clé AES aléatoire."""
    key_bytes = key_size // 8
    key = get_random_bytes(key_bytes)
    return {
        "algorithm": "AES",
        "key_size": key_size,
        "key": base64.b64encode(key).decode('utf-8'),
        "key_hex": key.hex()
    }


def encrypt_aes(plaintext, key_b64):
    """Chiffre un message avec AES-CBC."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    key = base64.b64decode(key_b64)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded)

    combined = iv + ciphertext
    return base64.b64encode(combined).decode('utf-8')


def decrypt_aes(ciphertext_b64, key_b64):
    """Déchiffre un message chiffré avec AES-CBC."""
    key = base64.b64decode(key_b64)
    raw = base64.b64decode(ciphertext_b64)

    iv = raw[:16]
    ciphertext = raw[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)

    return plaintext.decode('utf-8')