from __future__ import annotations

import logging
from uuid import uuid4

from central.core.celery_config import celery_app
from central.core.logging import log_info, log_warning
from central.db.models import (
    DeviceIdentity,
    IdentityType,
    InventoryDevice,
    Observation,
)
from central.db.session import get_session
from central.workers.base import ResilientTask


class ReconcileDeviceTask(ResilientTask):
    name = "workers.reconcile_device"

    def run(self, observation_id: int, parsed_data: dict) -> dict:
        """
        Match observation to existing device or create new one

        Strategy:
        1. Try matching by serial number (highest confidence)
        2. Try matching by MAC address
        3. Try matching by hostname + mgmt IP
        4. Create new device if no match
        """
        with get_session() as session:
            obs = session.get(Observation, observation_id)
            if not obs or not obs.scan_run:
                log_warning(
                    logging.getLogger(__name__),
                    "reconcile.missing_observation",
                    observation_id=observation_id,
                )
                return {"observation_id": observation_id, "status": "missing"}
            identities = parsed_data.get("identities", {})

            # Device matching logic
            device = self._find_or_create_device(
                session=session,
                tenant_id=obs.scan_run.tenant_id,
                site_id=obs.scan_run.site_id,
                scan_run_id=obs.scan_run_id,
                identities=identities,
                device_info=parsed_data.get("device_info", {}),
            )

            self._ensure_identities(session, device, identities, obs.scan_run_id)

            # Link observation to device
            obs.device_id = device.id
            session.commit()

            # Chain to snapshot creation
            from central.workers.snapshots import create_snapshot_task

            create_snapshot_task.delay(
                observation_id=observation_id, device_id=device.id
            )

            action = "matched" if device.created_at < obs.created_at else "created"
            log_info(
                logging.getLogger(__name__),
                "reconcile.complete",
                observation_id=observation_id,
                device_id=device.id,
                action=action,
            )
            return {
                "observation_id": observation_id,
                "device_id": device.id,
                "action": action,
            }

    def _find_or_create_device(
        self,
        session,
        tenant_id: int,
        site_id: int | None,
        scan_run_id: int,
        identities: dict,
        device_info: dict,
    ) -> InventoryDevice:
        """Multi-stage device matching"""
        # Try serial number
        if serial := identities.get("serial"):
            if device := self._find_by_identity(
                session, tenant_id, IdentityType.serial, serial
            ):
                return device

        # Try MAC address
        if mac := identities.get("mac"):
            if device := self._find_by_identity(
                session, tenant_id, IdentityType.mac, mac
            ):
                return device

        # Try hostname + mgmt_ip combo
        if hostname := identities.get("hostname"):
            if mgmt_ip := identities.get("mgmt_ip"):
                if device := self._find_by_hostname_ip(
                    session, tenant_id, hostname, mgmt_ip
                ):
                    return device

        # Create new device
        return self._create_device(
            session, tenant_id, site_id, scan_run_id, identities, device_info
        )

    def _find_by_identity(
        self,
        session,
        tenant_id: int,
        identity_type: IdentityType,
        value: str,
    ) -> InventoryDevice | None:
        return (
            session.query(InventoryDevice)
            .join(DeviceIdentity, DeviceIdentity.device_id == InventoryDevice.id)
            .filter(
                InventoryDevice.tenant_id == tenant_id,
                DeviceIdentity.identity_type == identity_type,
                DeviceIdentity.value == value,
            )
            .first()
        )

    def _find_by_hostname_ip(
        self,
        session,
        tenant_id: int,
        hostname: str,
        mgmt_ip: str,
    ) -> InventoryDevice | None:
        hostname_ids = (
            session.query(DeviceIdentity.device_id)
            .join(InventoryDevice, InventoryDevice.id == DeviceIdentity.device_id)
            .filter(
                InventoryDevice.tenant_id == tenant_id,
                DeviceIdentity.identity_type == IdentityType.hostname,
                DeviceIdentity.value == hostname,
            )
            .all()
        )
        hostname_set = {row[0] for row in hostname_ids}
        if not hostname_set:
            return None
        ip_ids = (
            session.query(DeviceIdentity.device_id)
            .join(InventoryDevice, InventoryDevice.id == DeviceIdentity.device_id)
            .filter(
                InventoryDevice.tenant_id == tenant_id,
                DeviceIdentity.identity_type == IdentityType.mgmt_ip,
                DeviceIdentity.value == mgmt_ip,
            )
            .all()
        )
        ip_set = {row[0] for row in ip_ids}
        match_ids = hostname_set & ip_set
        if not match_ids:
            return None
        return (
            session.query(InventoryDevice)
            .filter(InventoryDevice.id.in_(match_ids))
            .first()
        )

    def _create_device(
        self,
        session,
        tenant_id: int,
        site_id: int | None,
        scan_run_id: int,
        identities: dict,
        device_info: dict,
    ) -> InventoryDevice:
        device = InventoryDevice(
            tenant_id=tenant_id,
            site_id=site_id,
            device_uuid=str(uuid4()),
            vendor=device_info.get("vendor"),
            model=device_info.get("model"),
            device_family=device_info.get("device_family"),
            serial_number=identities.get("serial"),
            asset_tag=device_info.get("asset_tag"),
            hostname=device_info.get("hostname") or identities.get("hostname"),
            fqdn=device_info.get("fqdn"),
            device_role=device_info.get("device_role"),
        )
        session.add(device)
        session.flush()
        self._ensure_identities(session, device, identities, scan_run_id)
        session.flush()
        log_info(
            logging.getLogger(__name__),
            "reconcile.device_created",
            device_id=device.id,
            tenant_id=tenant_id,
            site_id=site_id,
        )
        return device

    def _ensure_identities(
        self,
        session,
        device: InventoryDevice,
        identities: dict,
        scan_run_id: int,
    ) -> None:
        mapping = {
            "serial": (IdentityType.serial, 100),
            "mac": (IdentityType.mac, 80),
            "hostname": (IdentityType.hostname, 60),
            "sysname": (IdentityType.sysname, 60),
            "mgmt_ip": (IdentityType.mgmt_ip, 50),
        }
        for key, (identity_type, confidence) in mapping.items():
            value = identities.get(key)
            if not value:
                continue
            existing = (
                session.query(DeviceIdentity)
                .filter(
                    DeviceIdentity.device_id == device.id,
                    DeviceIdentity.identity_type == identity_type,
                    DeviceIdentity.value == value,
                )
                .one_or_none()
            )
            if existing:
                existing.last_seen_scan_run_id = scan_run_id
            else:
                session.add(
                    DeviceIdentity(
                        device_id=device.id,
                        identity_type=identity_type,
                        value=value,
                        first_seen_scan_run_id=scan_run_id,
                        last_seen_scan_run_id=scan_run_id,
                        confidence=confidence,
                    )
                )


reconcile_device_task = celery_app.register_task(ReconcileDeviceTask())
