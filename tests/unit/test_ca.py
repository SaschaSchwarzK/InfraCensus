from __future__ import annotations

from datetime import UTC, datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from central.core.ca import CASettings, CertificateAuthority


def _create_csr(common_name: str) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def test_ca_creates_and_persists(tmp_path):
    key_path = tmp_path / "ca.key"
    cert_path = tmp_path / "ca.crt"
    settings = CASettings(
        key_path=str(key_path),
        cert_path=str(cert_path),
        ca_valid_days=3650,
        cert_valid_days=365,
    )

    ca1 = CertificateAuthority(settings)
    assert key_path.exists()
    assert cert_path.exists()

    ca2 = CertificateAuthority(settings)
    cert1 = ca1._ca_cert  # pylint: disable=protected-access
    cert2 = ca2._ca_cert  # pylint: disable=protected-access
    assert cert1.subject == cert2.subject
    assert cert1.serial_number == cert2.serial_number


def test_issue_certificate_valid(tmp_path):
    settings = CASettings(
        key_path=str(tmp_path / "ca.key"),
        cert_path=str(tmp_path / "ca.crt"),
        ca_valid_days=3650,
        cert_valid_days=365,
    )
    ca = CertificateAuthority(settings)
    csr_pem = _create_csr("collector-1")

    cert_pem, serial, fingerprint, valid_from, valid_to, ca_pem = ca.issue_certificate(
        csr_pem
    )

    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    ca_cert = x509.load_pem_x509_certificate(ca_pem.encode("utf-8"))
    assert cert.issuer == ca_cert.subject
    assert (
        cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        == "collector-1"
    )
    assert serial == format(cert.serial_number, "x")
    assert fingerprint == cert.fingerprint(hashes.SHA256()).hex()
    assert isinstance(valid_from, datetime)
    assert isinstance(valid_to, datetime)
    assert valid_from.tzinfo == UTC
    assert valid_to.tzinfo == UTC


def test_issue_certificate_invalid_csr(tmp_path):
    settings = CASettings(
        key_path=str(tmp_path / "ca.key"),
        cert_path=str(tmp_path / "ca.crt"),
        ca_valid_days=3650,
        cert_valid_days=365,
    )
    ca = CertificateAuthority(settings)
    csr_pem = _create_csr("collector-2")
    # Corrupt the CSR to force a failure
    broken = csr_pem.replace("A", "B", 1)
    with pytest.raises(ValueError):
        ca.issue_certificate(broken)
