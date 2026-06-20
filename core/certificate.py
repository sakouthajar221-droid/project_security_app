"""
Module : certificate.py
Description : Gestion des certificats numériques X.509 auto-signés
"""

import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class CertificateManager:
    """Gestionnaire de certificats numériques X.509."""

    def __init__(self):
        self.private_key = None
        self.certificate = None

    def generate_key_pair(self, key_size: int = 2048) -> rsa.RSAPrivateKey:
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        return self.private_key

    def generate_self_signed_cert(
        self,
        common_name: str,
        organization: str,
        country: str,
        state: str = "",
        locality: str = "",
        validity_days: int = 365,
        key_size: int = 2048
    ) -> x509.Certificate:
        self.generate_key_pair(key_size)

        name_attributes = [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        ]
        if state:
            name_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
        if locality:
            name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))

        subject = issuer = x509.Name(name_attributes)

        now = datetime.datetime.utcnow()
        self.certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self.private_key, hashes.SHA256(), default_backend())
        )

        return self.certificate

    def get_certificate_info(self) -> dict:
        if self.certificate is None:
            raise ValueError("Aucun certificat disponible. Générez-en un d'abord.")

        cert = self.certificate

        def get_attr(name_obj, oid):
            try:
                return name_obj.get_attributes_for_oid(oid)[0].value
            except IndexError:
                return "N/A"

        subject_cn  = get_attr(cert.subject, NameOID.COMMON_NAME)
        subject_org = get_attr(cert.subject, NameOID.ORGANIZATION_NAME)
        subject_c   = get_attr(cert.subject, NameOID.COUNTRY_NAME)
        subject_st  = get_attr(cert.subject, NameOID.STATE_OR_PROVINCE_NAME)
        subject_loc = get_attr(cert.subject, NameOID.LOCALITY_NAME)
        issuer_cn   = get_attr(cert.issuer, NameOID.COMMON_NAME)

        is_self_signed = cert.subject == cert.issuer
        pub_key_size   = cert.public_key().key_size

        return {
            "common_name"         : subject_cn,
            "organization"        : subject_org,
            "country"             : subject_c,
            "state"               : subject_st,
            "locality"            : subject_loc,
            "issuer"              : issuer_cn,
            "serial_number"       : str(cert.serial_number),
            "valid_from"          : cert.not_valid_before.strftime("%d/%m/%Y %H:%M:%S"),
            "valid_to"            : cert.not_valid_after.strftime("%d/%m/%Y %H:%M:%S"),
            "is_self_signed"      : "Oui ✅" if is_self_signed else "Non ❌",
            "public_key_size"     : f"{pub_key_size} bits",
            "signature_algorithm" : cert.signature_hash_algorithm.name.upper(),
            "version"             : str(cert.version.name),
        }

    def export_certificate_pem(self) -> str:
        if self.certificate is None:
            raise ValueError("Aucun certificat à exporter.")
        return self.certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def export_private_key_pem(self, password: bytes = None) -> str:
        if self.private_key is None:
            raise ValueError("Aucune clé privée disponible.")
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password else serialization.NoEncryption()
        )
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption
        ).decode("utf-8")

    def save_to_files(self, cert_path: str, key_path: str, password: bytes = None):
        if self.certificate is None or self.private_key is None:
            raise ValueError("Certificat ou clé privée manquant.")
        with open(cert_path, "wb") as f:
            f.write(self.certificate.public_bytes(serialization.Encoding.PEM))
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password else serialization.NoEncryption()
        )
        with open(key_path, "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption
            ))

    def load_certificate_from_pem(self, pem_data: str):
        self.certificate = x509.load_pem_x509_certificate(
            pem_data.encode("utf-8"), default_backend()
        )
        return self.certificate

    def load_from_file(self, cert_path: str):
        if not os.path.exists(cert_path):
            raise FileNotFoundError(f"Fichier introuvable : {cert_path}")
        with open(cert_path, "rb") as f:
            self.certificate = x509.load_pem_x509_certificate(f.read(), default_backend())
        return self.certificate