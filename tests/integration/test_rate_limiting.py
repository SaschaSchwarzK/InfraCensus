import importlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from central.core.auth import hash_token


def _generate_csr() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "InfraCensus"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "collector-test"),
                ]
            )
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


@pytest.fixture()
def client(tmp_path: Path):
    db_path = tmp_path / "test.db"
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir(parents=True, exist_ok=True)
    os.environ["ENVIRONMENT"] = "dev"
    os.environ["SESSION_SECRET"] = "test-session-secret-0123456789abcdef"
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["CA_KEY_PATH"] = str(ca_dir / "ca.key")
    os.environ["CA_CERT_PATH"] = str(ca_dir / "ca.crt")
    os.environ["COLLECTOR_RATE_LIMIT_PER_HOUR"] = "1"

    import central.api.app as app_module
    import central.api.collector as collector_module
    import central.core.config as config_module
    import central.db.engine as engine_module

    importlib.reload(config_module)
    importlib.reload(engine_module)
    importlib.reload(collector_module)
    importlib.reload(app_module)

    from central.db.base import Base
    from central.db.engine import engine
    from central.db.models import CollectorEnrollmentToken, Tenant
    from central.db.session import get_session

    Base.metadata.create_all(engine)
    token = "test-token"
    token_hash = hash_token(token)
    now = datetime.now(UTC)
    with get_session() as session:
        tenant = Tenant(name="test-tenant")
        session.add(tenant)
        session.flush()
        session.add(
            CollectorEnrollmentToken(
                tenant_id=tenant.id,
                token_hash=token_hash,
                expires_at=now + timedelta(minutes=10),
            )
        )
    return TestClient(app_module.app)


def test_collector_rate_limit_enforcement(client: TestClient):
    csr = _generate_csr()
    first = client.post(
        "/api/v1/collectors/enroll",
        json={
            "token": "test-token",
            "csr": csr,
            "name": "test-collector",
        },
    )
    assert first.status_code in {200, 201}
    second = client.post(
        "/api/v1/collectors/enroll",
        json={
            "token": "test-token",
            "csr": csr,
            "name": "test-collector-2",
        },
    )
    assert second.status_code == 429
