from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

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
    CA_BASE_DIR = Path("/var/lib/infracensus/ca").resolve()

    def __init__(self, settings: CASettings) -> None:
        self._settings = settings
        # Validate and sanitize paths to prevent path traversal
        self._key_path = self._validate_path(settings.key_path, "CA key")
        self._cert_path = self._validate_path(settings.cert_path, "CA cert")
        self._key_path.parent.mkdir(parents=True, exist_ok=True)
        self._cert_path.parent.mkdir(parents=True, exist_ok=True)
        self._private_key, self._ca_cert = self._load_or_create_ca()

    def _validate_path(self, path_str: str, name: str = "path") -> Path:
        """Validate path is within CA base directory and avoid traversal."""
        if not path_str:
            raise ValueError(f"Missing {name} path")
        if ".." in path_str or path_str.startswith(("/", "\\\\")):
            raise ValueError(f"Path traversal detected in {name}: {path_str}")
        path = (self.CA_BASE_DIR / path_str).resolve()
        try:
            path.relative_to(self.CA_BASE_DIR)
        except ValueError as exc:
            raise ValueError(f"Path {name} escapes CA directory: {path_str}") from exc
        if path.is_symlink():
            real_path = path.resolve()
            try:
                real_path.relative_to(self.CA_BASE_DIR)
            except ValueError as exc:
                raise ValueError(
                    f"Symlink {name} points outside CA directory: {path_str}"
                ) from exc
        return path

    def issue_certificate(
        self, csr_pem: str
    ) -> tuple[str, str, str, datetime, datetime, str]:
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
        if not csr.is_signature_valid:
            raise ValueError("CSR signature is invalid")
        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=self._settings.cert_valid_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .sign(self._private_key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        ca_pem = self._ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        serial = format(cert.serial_number, "x")
        return (
            cert_pem,
            serial,
            fingerprint,
            cert.not_valid_before,
            cert.not_valid_after,
            ca_pem,
        )

    def _load_or_create_ca(self) -> tuple[Any, x509.Certificate]:
        if self._key_path.exists() and self._cert_path.exists():
            key = serialization.load_pem_private_key(
                self._key_path.read_bytes(), password=None
            )
            cert = x509.load_pem_x509_certificate(self._cert_path.read_bytes())
            return key, cert
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(UTC)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "InfraCensus"),
                x509.NameAttribute(
                    NameOID.COMMON_NAME, self._settings.subject_common_name
                ),
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
