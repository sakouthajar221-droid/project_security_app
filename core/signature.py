"""
Module de Signature Numérique - RSA-PSS
"""

import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


class DigitalSignature:

    def sign(self, private_key_or_message, data_or_key=None):
        """
        Supporte deux ordres d'arguments :
          • sign(private_key, data)      — ancienne convention
          • sign(message, private_key)   — nouvelle convention (signature_page)
        Retourne bytes si ancien appel, str base64 si nouvel appel.
        """
        if hasattr(private_key_or_message, 'sign'):
            # Ancien appel : sign(private_key, data)
            private_key = private_key_or_message
            data = data_or_key
            return self._sign_raw(private_key, data)
        else:
            # Nouvel appel : sign(message, private_key)
            data = private_key_or_message
            private_key = data_or_key
            raw = self._sign_raw(private_key, data)
            return base64.b64encode(raw).decode()

    def _sign_raw(self, private_key, data) -> bytes:
        if isinstance(data, str):
            data = data.encode()
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify(self, public_key_or_message, data_or_sig=None, sig_or_pubkey=None):
        """
        Supporte deux ordres d'arguments :
          • verify(public_key, data, signature_bytes)  — ancienne convention
          • verify(message, signature_b64, public_key) — nouvelle convention
        Retourne toujours bool.
        """
        if hasattr(public_key_or_message, 'verify'):
            # Ancien appel : verify(public_key, data, signature)
            public_key = public_key_or_message
            data       = data_or_sig
            signature  = sig_or_pubkey
            return self._verify_raw(public_key, data, signature)
        else:
            # Nouvel appel : verify(message, signature_b64, public_key)
            data       = public_key_or_message
            sig_b64    = data_or_sig
            public_key = sig_or_pubkey
            try:
                signature = base64.b64decode(sig_b64)
            except Exception:
                return False
            return self._verify_raw(public_key, data, signature)

    def _verify_raw(self, public_key, data, signature) -> bool:
        if isinstance(data, str):
            data = data.encode()
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except (InvalidSignature, Exception):
            return False

    def sign_file(self, filepath: str, private_key) -> str:
        """Signe un fichier et retourne la signature en base64."""
        with open(filepath, "rb") as f:
            data = f.read()
        raw = self._sign_raw(private_key, data)
        return base64.b64encode(raw).decode()

    def verify_file(self, filepath: str, signature_b64: str, public_key) -> bool:
        """Vérifie la signature d'un fichier."""
        with open(filepath, "rb") as f:
            data = f.read()
        try:
            signature = base64.b64decode(signature_b64)
        except Exception:
            return False
        return self._verify_raw(public_key, data, signature)