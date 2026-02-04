from __future__ import annotations

import os
import shutil
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from central.core.auth import hash_token
from central.db.base import Base
from central.db.models import (
    Collector,
    CollectorEnrollmentToken,
    Network,
    ScanSchedule,
    ScanScheduleType,
    Site,
    Tenant,
)


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        result = subprocess.run(
            ["docker", "info"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return False
    return result.returncode == 0


def _wait_for_ready(url: str, timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    last_status = None
    while time.time() < deadline:
        try:
            response = httpx.get(url, timeout=3.0)
            last_status = response.status_code
            if response.status_code == 200:
                return
        except httpx.RequestError:
            pass
        time.sleep(1.0)
    raise AssertionError(f"Service not ready: {url} (last status: {last_status})")


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@pytest.mark.e2e
def test_container_collector_flow(tmp_path: Path) -> None:
    if os.getenv("E2E_DOCKER") != "1":
        pytest.skip("Set E2E_DOCKER=1 to run container e2e tests.")
    if not _docker_available():
        pytest.skip("Docker not available for e2e test.")

    e2e_root = tmp_path / "e2e"
    e2e_root.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "E2E_ROOT": str(e2e_root)}

    compose_file = Path(__file__).resolve().parents[2] / "docker-compose.e2e.yml"
    log_env = env

    def _compose_logs(service: str) -> str:
        result = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(compose_file),
                "logs",
                "--no-color",
                service,
            ],
            check=False,
            env=log_env,
            capture_output=True,
            text=True,
        )
        if result.stdout:
            return result.stdout
        return result.stderr or ""

    subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(compose_file),
            "up",
            "-d",
            "--build",
            "postgres",
            "central",
        ],
        check=True,
        env=env,
    )
    try:
        try:
            _wait_for_ready("http://127.0.0.1:18000/health", timeout=90.0)
            _wait_for_ready("http://127.0.0.1:18000/ready", timeout=90.0)
        except AssertionError as exc:
            logs = _compose_logs("central")
            raise AssertionError(f"{exc}\ncentral logs:\n{logs}") from exc

        db_url = (
            "postgresql+psycopg://infracensus:infracensus@localhost:15432/infracensus"
        )
        engine = create_engine(db_url, future=True)
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(
            bind=engine, autoflush=False, expire_on_commit=False, future=True
        )

        token = "e2e-token"
        token_hash = hash_token(token)
        now = datetime.now(UTC)

        with SessionLocal() as session:
            tenant = Tenant(name="e2e-tenant")
            session.add(tenant)
            session.flush()
            site = Site(tenant_id=tenant.id, name="e2e-site", timezone="UTC")
            session.add(site)
            session.flush()
            session.add(
                CollectorEnrollmentToken(
                    tenant_id=tenant.id,
                    site_id=site.id,
                    token_hash=token_hash,
                    expires_at=now + timedelta(minutes=30),
                )
            )
            session.commit()

        env_with_token = {**env, "ENROLLMENT_TOKEN": token}
        subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(compose_file),
                "up",
                "-d",
                "--build",
                "collector",
            ],
            check=True,
            env=env_with_token,
        )

        collector: Collector | None = None
        deadline = time.time() + 60
        while time.time() < deadline:
            with SessionLocal() as session:
                collector = (
                    session.query(Collector)
                    .filter(Collector.name == "e2e-collector")
                    .one_or_none()
                )
            if collector and collector.cert_serial:
                break
            time.sleep(2)
        assert collector is not None
        assert collector.cert_serial

        with SessionLocal() as session:
            network = Network(
                tenant_id=collector.tenant_id,
                site_id=collector.site_id,
                name="e2e-net",
                cidr="10.0.0.0/24",
            )
            session.add(network)
            session.flush()
            schedule = ScanSchedule(
                tenant_id=collector.tenant_id,
                site_id=collector.site_id,
                name="e2e-schedule",
                scheduled_at_utc=now - timedelta(minutes=1),
                network_ids=str(network.id),
            )
            session.add(schedule)
            session.flush()
            schedule_type = ScanScheduleType(
                schedule_id=schedule.id,
                scan_type="ping",
                scheduled_at_utc=now - timedelta(minutes=1),
                priority=1,
            )
            session.add(schedule_type)
            session.commit()

        deadline = time.time() + 120
        finished = False
        while time.time() < deadline:
            with SessionLocal() as session:
                updated = (
                    session.query(ScanScheduleType)
                    .filter(ScanScheduleType.id == schedule_type.id)
                    .one()
                )
                if updated.finished_at_utc is not None:
                    finished = True
                    break
            time.sleep(2)
        if not finished:
            logs = _compose_logs("collector")
            raise AssertionError(
                f"Collector did not complete job.\ncollector logs:\n{logs}"
            )
    finally:
        subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "down", "-v"],
            check=False,
            env=env,
        )
