import hashlib
import importlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _generate_csr() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "InfraCensus"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "collector-e2e"),
                ]
            )
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _timestamp_header() -> dict[str, str]:
    return {
        "x-timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }


@pytest.mark.asyncio
async def test_full_scan_flow(tmp_path: Path):
    db_path = tmp_path / "test.db"
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir(parents=True, exist_ok=True)
    os.environ["ENVIRONMENT"] = "dev"
    os.environ["SESSION_SECRET"] = "test-session-secret-1234567890"
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["CA_KEY_PATH"] = str(ca_dir / "ca.key")
    os.environ["CA_CERT_PATH"] = str(ca_dir / "ca.crt")

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
    from central.db.models import (
        Collector,
        CollectorEnrollmentToken,
        Network,
        ScanSchedule,
        ScanScheduleType,
        Tenant,
    )
    from central.db.session import get_session

    Base.metadata.create_all(engine)
    token = "test-token"
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
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
        network = Network(
            tenant_id=tenant.id,
            name="corp",
            cidr="10.0.0.0/24",
        )
        session.add(network)
        session.flush()
        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="daily",
            scheduled_at_utc=now - timedelta(minutes=1),
            network_ids=str(network.id),
        )
        session.add(schedule)
        session.flush()
        session_type = ScanScheduleType(
            schedule_id=schedule.id,
            scan_type="discovery",
            scheduled_at_utc=now - timedelta(minutes=1),
        )
        session.add(session_type)

    async with httpx.AsyncClient(app=app_module.app, base_url="http://test") as client:
        csr = _generate_csr()
        enroll_response = await client.post(
            "/collectors/enroll",
            json={
                "token": token,
                "csr": csr,
                "name": "test-collector",
            },
        )
        assert enroll_response.status_code in {200, 201}

        with get_session() as session:
            collector = (
                session.query(Collector)
                .filter(Collector.name == "test-collector")
                .one()
            )
            cert_serial = collector.cert_serial
            cert_fingerprint = collector.cert_fingerprint

        poll_response = await client.get(
            "/collectors/jobs/poll",
            headers={
                **_timestamp_header(),
                "x-client-cert-serial": cert_serial or "",
                "x-client-cert-fingerprint": cert_fingerprint or "",
            },
        )
        assert poll_response.status_code == 200
        jobs = poll_response.json().get("jobs", [])
        assert jobs
        job_id = jobs[0]["job_id"]

        ack_response = await client.post(
            "/collectors/jobs/ack",
            headers={
                **_timestamp_header(),
                "x-client-cert-serial": cert_serial or "",
                "x-client-cert-fingerprint": cert_fingerprint or "",
            },
            json={
                "job_id": job_id,
                "collector_time_utc": datetime.now(UTC)
                .isoformat()
                .replace("+00:00", "Z"),
            },
        )
        assert ack_response.status_code == 200

        result_response = await client.post(
            "/collectors/jobs/result",
            headers={
                **_timestamp_header(),
                "x-client-cert-serial": cert_serial or "",
                "x-client-cert-fingerprint": cert_fingerprint or "",
            },
            json={
                "job_id": job_id,
                "collector_time_utc": datetime.now(UTC)
                .isoformat()
                .replace("+00:00", "Z"),
                "results": [
                    {"duration_ms": 25, "success": True},
                ],
            },
        )
        assert result_response.status_code == 200

    with get_session() as session:
        updated = (
            session.query(ScanScheduleType)
            .filter(ScanScheduleType.id == session_type.id)
            .one()
        )
        assert updated.finished_at_utc is not None
