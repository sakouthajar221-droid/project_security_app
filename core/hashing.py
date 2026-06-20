"""
Module de hachage - HashManager
"""

import hashlib


class HashManager:

    @staticmethod
    def sha256_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> bool:
        return hash1 == hash2

    def hash_text(self, text: str, algorithm: str = "sha256") -> str:
        """Méthode d'instance pour signature_page."""
        if algorithm == "sha256":
            return hashlib.sha256(text.encode("utf-8")).hexdigest()
        elif algorithm == "sha512":
            return hashlib.sha512(text.encode("utf-8")).hexdigest()
        elif algorithm == "md5":
            return hashlib.md5(text.encode("utf-8")).hexdigest()
        else:
            raise ValueError(f"Algorithme non supporté : {algorithm}")

    def hash_file(self, filepath: str, algorithm: str = "sha256") -> str:
        """Hash d'un fichier."""
        h = hashlib.new(algorithm)
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()