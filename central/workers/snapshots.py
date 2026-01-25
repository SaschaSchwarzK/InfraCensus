from __future__ import annotations

from celery import Task
import hashlib
import json
import logging

from central.core.celery_config import celery_app
from central.core.logging import log_info, log_warning
from central.db.models import (
    DeviceSnapshot,
    InterfaceSnapshot,
    IpSnapshot,
    NeighborSnapshot,
    Observation,
)
from central.db.session import get_session
from central.workers.base import ResilientTask


class CreateSnapshotTask(ResilientTask):
    name = 'workers.create_snapshot'
    
    def run(self, observation_id: int, device_id: int) -> dict:
        """
        Create DeviceSnapshot, InterfaceSnapshot, IpSnapshot, etc.
        """
        with get_session() as session:
            obs = session.get(Observation, observation_id)
            if not obs:
                log_warning(
                    logging.getLogger(__name__),
                    "snapshot.missing_observation",
                    observation_id=observation_id,
                )
                return {'snapshot_created': False, 'reason': 'missing_observation'}
            parsed = {}
            if obs.parsed_payload_json:
                parsed = json.loads(obs.parsed_payload_json)
            device_info = parsed.get("device_info", {})

            existing_snapshot = session.query(DeviceSnapshot).filter(
                DeviceSnapshot.scan_run_id == obs.scan_run_id,
                DeviceSnapshot.device_id == device_id,
            ).one_or_none()
            if existing_snapshot:
                log_info(
                    logging.getLogger(__name__),
                    "snapshot.exists",
                    observation_id=observation_id,
                    device_id=device_id,
                    scan_run_id=obs.scan_run_id,
                )
                return {'snapshot_created': False, 'reason': 'already_exists'}
            
            # Create device snapshot
            snapshot = DeviceSnapshot(
                scan_run_id=obs.scan_run_id,
                device_id=device_id,
                vendor=device_info.get('vendor'),
                model=device_info.get('model'),
                hostname=device_info.get('hostname'),
                os_version=device_info.get('os_version'),
                snapshot_hash=self._compute_hash(parsed)
            )
            session.add(snapshot)
            
            # Create interface snapshots
            existing_ifaces = {
                row[0]
                for row in session.query(InterfaceSnapshot.name).filter(
                    InterfaceSnapshot.scan_run_id == obs.scan_run_id,
                    InterfaceSnapshot.device_id == device_id,
                )
            }
            for iface in parsed.get('interfaces', []):
                if iface.get("name") in existing_ifaces:
                    continue
                iface_snapshot = InterfaceSnapshot(
                    scan_run_id=obs.scan_run_id,
                    device_id=device_id,
                    name=iface['name'],
                    interface_type=iface.get('type'),
                    mac_address=iface.get('mac'),
                    admin_status=iface.get('admin_status'),
                    oper_status=iface.get('oper_status'),
                    snapshot_hash=self._compute_hash(iface)
                )
                session.add(iface_snapshot)
                
                # Create IP snapshots
                for ip_data in iface.get('ip_addresses', []):
                    ip_snapshot = IpSnapshot(
                        scan_run_id=obs.scan_run_id,
                        device_id=device_id,
                        interface_name=iface['name'],
                        ip_address=ip_data['address'],
                        prefix_length=ip_data['prefix_length'],
                        ip_version=ip_data.get('version', 'ipv4'),
                        snapshot_hash=self._compute_hash(ip_data),
                    )
                    session.add(ip_snapshot)
            
            # Create neighbor snapshots
            for neighbor in parsed.get('neighbors', []):
                neighbor_snapshot = NeighborSnapshot(
                    scan_run_id=obs.scan_run_id,
                    device_id=device_id,
                    local_interface=neighbor['local_interface'],
                    remote_chassis_id=neighbor.get('remote_chassis_id'),
                    remote_interface=neighbor.get('remote_interface'),
                    snapshot_hash=self._compute_hash(neighbor),
                )
                session.add(neighbor_snapshot)
            
            session.commit()
            
            # Chain to change detection
            from central.workers.change_detection import detect_changes_task

            detect_changes_task.delay(device_id, obs.scan_run_id)
            log_info(
                logging.getLogger(__name__),
                "snapshot.created",
                observation_id=observation_id,
                device_id=device_id,
                scan_run_id=obs.scan_run_id,
            )
            return {'snapshot_created': True}

    def _compute_hash(self, payload: dict) -> str:
        raw = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


create_snapshot_task = celery_app.register_task(CreateSnapshotTask())
