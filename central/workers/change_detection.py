from __future__ import annotations

import logging

from central.core.celery_config import celery_app
from central.core.logging import log_info, log_warning
from central.db.models import DeviceSnapshot, InterfaceSnapshot, IpSnapshot
from central.db.session import get_session
from central.workers.base import ResilientTask


class DetectChangesTask(ResilientTask):
    name = "workers.detect_changes"

    def run(self, device_id: int, current_scan_run_id: int) -> dict:
        """
        Compare current snapshot with previous to detect changes
        """
        with get_session() as session:
            current = (
                session.query(DeviceSnapshot)
                .filter(
                    DeviceSnapshot.device_id == device_id,
                    DeviceSnapshot.scan_run_id == current_scan_run_id,
                )
                .first()
            )
            if not current:
                log_warning(
                    logging.getLogger(__name__),
                    "changes.missing_snapshot",
                    device_id=device_id,
                    scan_run_id=current_scan_run_id,
                )
                return {"changes": None, "reason": "missing_snapshot"}
            previous = (
                session.query(DeviceSnapshot)
                .filter(
                    DeviceSnapshot.device_id == device_id,
                    DeviceSnapshot.scan_run_id < current_scan_run_id,
                )
                .order_by(DeviceSnapshot.scan_run_id.desc())
                .first()
            )
            if not previous:
                log_info(
                    logging.getLogger(__name__),
                    "changes.first_snapshot",
                    device_id=device_id,
                    scan_run_id=current_scan_run_id,
                )
                return {"changes": None, "reason": "first_snapshot"}

            changes = {
                "device": self._compare_device_snapshots(current, previous),
                "interfaces": self._compare_interfaces(
                    device_id, current_scan_run_id, previous.scan_run_id, session
                ),
                "ips": self._compare_ips(
                    device_id, current_scan_run_id, previous.scan_run_id, session
                ),
            }

            if self._has_significant_changes(changes):
                notify_change_task.delay(device_id, changes)
                log_info(
                    logging.getLogger(__name__),
                    "changes.significant",
                    device_id=device_id,
                    scan_run_id=current_scan_run_id,
                )

            return changes

    def _compare_device_snapshots(
        self, current: DeviceSnapshot, previous: DeviceSnapshot
    ) -> dict:
        fields = [
            "vendor",
            "model",
            "device_family",
            "serial_number",
            "hostname",
            "fqdn",
            "os_name",
            "os_version",
            "firmware_version",
            "mgmt_ips",
            "reachable_protocols",
            "auth_method",
        ]
        diffs = []
        for field in fields:
            if getattr(current, field) != getattr(previous, field):
                diffs.append(
                    {
                        "field": field,
                        "before": getattr(previous, field),
                        "after": getattr(current, field),
                    }
                )
        return {"changed": bool(diffs), "diffs": diffs}

    def _compare_interfaces(
        self,
        device_id: int,
        current_scan_run_id: int,
        previous_scan_run_id: int,
        session,
    ) -> dict:
        current = (
            session.query(InterfaceSnapshot)
            .filter(
                InterfaceSnapshot.device_id == device_id,
                InterfaceSnapshot.scan_run_id == current_scan_run_id,
            )
            .all()
        )
        previous = (
            session.query(InterfaceSnapshot)
            .filter(
                InterfaceSnapshot.device_id == device_id,
                InterfaceSnapshot.scan_run_id == previous_scan_run_id,
            )
            .all()
        )
        current_map = {row.name: row.snapshot_hash for row in current}
        previous_map = {row.name: row.snapshot_hash for row in previous}
        added = [name for name in current_map.keys() if name not in previous_map]
        removed = [name for name in previous_map.keys() if name not in current_map]
        changed = [
            name
            for name in current_map.keys()
            if name in previous_map and current_map[name] != previous_map[name]
        ]
        return {"added": added, "removed": removed, "changed": changed}

    def _compare_ips(
        self,
        device_id: int,
        current_scan_run_id: int,
        previous_scan_run_id: int,
        session,
    ) -> dict:
        current = (
            session.query(IpSnapshot)
            .filter(
                IpSnapshot.device_id == device_id,
                IpSnapshot.scan_run_id == current_scan_run_id,
            )
            .all()
        )
        previous = (
            session.query(IpSnapshot)
            .filter(
                IpSnapshot.device_id == device_id,
                IpSnapshot.scan_run_id == previous_scan_run_id,
            )
            .all()
        )

        def key(row: IpSnapshot) -> tuple[str, str, int]:
            return (row.interface_name, row.ip_address, row.prefix_length)

        current_set = {key(row) for row in current}
        previous_set = {key(row) for row in previous}
        return {
            "added": sorted(current_set - previous_set),
            "removed": sorted(previous_set - current_set),
        }

    def _has_significant_changes(self, changes: dict) -> bool:
        if changes.get("device", {}).get("changed"):
            return True
        if (
            changes.get("interfaces", {}).get("added")
            or changes.get("interfaces", {}).get("removed")
            or changes.get("interfaces", {}).get("changed")
        ):
            return True
        if changes.get("ips", {}).get("added") or changes.get("ips", {}).get("removed"):
            return True
        return False


@celery_app.task(name="workers.notify_change")
def notify_change_task(device_id: int, changes: dict) -> dict:
    log_info(
        logging.getLogger(__name__),
        "changes.notify",
        device_id=device_id,
    )
    return {"device_id": device_id, "changes": changes}


detect_changes_task = celery_app.register_task(DetectChangesTask())
