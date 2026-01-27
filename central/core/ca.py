from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@dataclass(frozen=True)
class CASettings:
    key_path: str
    cert_path: str
    ca_valid_days: int
    cert_valid_days: int
    subject_common_name: str = "InfraCensus Internal CA"


class CertificateAuthority:
    def __init__(self, settings: CASettings) -> None:
        self._settings = settings
        self._key_path = Path(settings.key_path)
        self._cert_path = Path(settings.cert_path)
        self._key_path.parent.mkdir(parents=True, exist_ok=True)
        self._cert_path.parent.mkdir(parents=True, exist_ok=True)
        self._private_key, self._ca_cert = self._load_or_create_ca()

    def issue_certificate(self, csr_pem: str) -> tuple[str, str, str, datetime, datetime, str]:
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
        if not csr.is_signature_valid:
            raise ValueError("CSR signature is invalid")
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=self._settings.cert_valid_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self._private_key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        ca_pem = self._ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        serial = format(cert.serial_number, "x")
        return cert_pem, serial, fingerprint, cert.not_valid_before, cert.not_valid_after, ca_pem

    def _load_or_create_ca(self) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        if self._key_path.exists() and self._cert_path.exists():
            key = serialization.load_pem_private_key(self._key_path.read_bytes(), password=None)
            cert = x509.load_pem_x509_certificate(self._cert_path.read_bytes())
            return key, cert
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "InfraCensus"),
                x509.NameAttribute(NameOID.COMMON_NAME, self._settings.subject_common_name),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=self._settings.ca_valid_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256())
        )
        self._key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self._cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return key, cert
