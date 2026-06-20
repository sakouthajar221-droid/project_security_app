"""
Module de Confidentialité - Chiffrement Asymétrique (RSA) et Hybride (AES+RSA)
"""

import base64
import time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from core.symmetric import generate_aes_key, encrypt_aes, decrypt_aes


# ========================== RSA ==========================

def generate_rsa_keys(key_size=2048):
    """Génère une paire de clés RSA (publique et privée)."""
    key = RSA.generate(key_size)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')

    return {
        "algorithm": "RSA",
        "key_size": key_size,
        "public_key": public_key,
        "private_key": private_key
    }


def encrypt_rsa(plaintext, public_key_pem):
    """Chiffre un message avec RSA (OAEP)."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key)

    max_chunk_size = (public_key.size_in_bytes()) - 42
    chunks = []

    for i in range(0, len(plaintext), max_chunk_size):
        chunk = plaintext[i:i + max_chunk_size]
        encrypted_chunk = cipher.encrypt(chunk)
        chunks.append(encrypted_chunk)

    combined = b''.join(chunks)
    return base64.b64encode(combined).decode('utf-8')


def decrypt_rsa(ciphertext_b64, private_key_pem):
    """Déchiffre un message chiffré avec RSA (OAEP)."""
    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key)

    raw = base64.b64decode(ciphertext_b64)
    chunk_size = private_key.size_in_bytes()

    chunks = []
    for i in range(0, len(raw), chunk_size):
        chunk = raw[i:i + chunk_size]
        decrypted_chunk = cipher.decrypt(chunk)
        chunks.append(decrypted_chunk)

    plaintext = b''.join(chunks)
    return plaintext.decode('utf-8')


# ========================== HYBRIDE ==========================

def generate_hybrid_keys(rsa_key_size=2048, aes_key_size=256):
    """Génère les clés pour le chiffrement hybride (AES + RSA)."""
    rsa_keys = generate_rsa_keys(rsa_key_size)
    aes_key_data = generate_aes_key(aes_key_size)

    return {
        "algorithm": "Hybride",
        "rsa_key_size": rsa_key_size,
        "aes_key_size": aes_key_size,
        "public_key": rsa_keys["public_key"],
        "private_key": rsa_keys["private_key"],
        "aes_key": aes_key_data["key"],
        "aes_key_hex": aes_key_data["key_hex"]
    }


def encrypt_hybrid(plaintext, aes_key_b64, public_key_pem):
    """Chiffrement hybride : AES pour le message, RSA pour la clé AES."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    aes_key = base64.b64decode(aes_key_b64)
    iv = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext, AES.block_size)
    encrypted_message = cipher_aes.encrypt(padded_data)

    public_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    key_len = len(encrypted_aes_key).to_bytes(4, 'big')
    combined = key_len + encrypted_aes_key + iv + encrypted_message

    return base64.b64encode(combined).decode('utf-8')


def decrypt_hybrid(ciphertext_b64, private_key_pem):
    """Déchiffrement hybride."""
    raw = base64.b64decode(ciphertext_b64)

    key_len = int.from_bytes(raw[:4], 'big')
    encrypted_aes_key = raw[4:4 + key_len]
    iv = raw[4 + key_len:4 + key_len + 16]
    encrypted_message = raw[4 + key_len + 16:]

    private_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_plaintext = cipher_aes.decrypt(encrypted_message)
    plaintext = unpad(padded_plaintext, AES.block_size)

    return plaintext.decode('utf-8')


# ========================== BENCHMARKING ==========================

def benchmark_encryption(message, iterations=50):
    """Benchmark les trois méthodes de chiffrement."""
    results = {}

    # --- AES Benchmark ---
    aes_key_data = generate_aes_key(256)
    aes_key = aes_key_data["key"]

    start = time.perf_counter()
    for _ in range(iterations):
        ct = encrypt_aes(message, aes_key)
    aes_enc_time = (time.perf_counter() - start) / iterations

    start = time.perf_counter()
    for _ in range(iterations):
        decrypt_aes(ct, aes_key)
    aes_dec_time = (time.perf_counter() - start) / iterations

    results["AES"] = {
        "encrypt_time_ms": round(aes_enc_time * 1000, 4),
        "decrypt_time_ms": round(aes_dec_time * 1000, 4),
        "ciphertext_size": len(ct)
    }

    # --- RSA Benchmark ---
    rsa_keys = generate_rsa_keys(2048)

    start = time.perf_counter()
    for _ in range(iterations):
        ct = encrypt_rsa(message, rsa_keys["public_key"])
    rsa_enc_time = (time.perf_counter() - start) / iterations

    start = time.perf_counter()
    for _ in range(iterations):
        decrypt_rsa(ct, rsa_keys["private_key"])
    rsa_dec_time = (time.perf_counter() - start) / iterations

    results["RSA"] = {
        "encrypt_time_ms": round(rsa_enc_time * 1000, 4),
        "decrypt_time_ms": round(rsa_dec_time * 1000, 4),
        "ciphertext_size": len(ct)
    }

    # --- Hybrid Benchmark ---
    hybrid_keys = generate_hybrid_keys()

    start = time.perf_counter()
    for _ in range(iterations):
        ct = encrypt_hybrid(message, hybrid_keys["aes_key"], hybrid_keys["public_key"])
    hybrid_enc_time = (time.perf_counter() - start) / iterations

    start = time.perf_counter()
    for _ in range(iterations):
        decrypt_hybrid(ct, hybrid_keys["private_key"])
    hybrid_dec_time = (time.perf_counter() - start) / iterations

    results["Hybride"] = {
        "encrypt_time_ms": round(hybrid_enc_time * 1000, 4),
        "decrypt_time_ms": round(hybrid_dec_time * 1000, 4),
        "ciphertext_size": len(ct)
    }

    return results


# ========================== AsymmetricCipher (pour signature_page) ==========================

class AsymmetricCipher:
    """
    Classe wrapper RSA pour signature_page.py.
    Utilise la bibliothèque cryptography (hazmat).
    """

    def __init__(self):
        self._private_key = None
        self._public_key = None

    def generate_keypair(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self._public_key = self._private_key.public_key()
        return self._private_key, self._public_key

    def export_public_key(self) -> str:
        from cryptography.hazmat.primitives import serialization
        if self._public_key is None:
            raise ValueError("Aucune clé publique disponible.")
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def export_private_key(self) -> str:
        from cryptography.hazmat.primitives import serialization
        if self._private_key is None:
            raise ValueError("Aucune clé privée disponible.")
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')