from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from central.core.celery_config import celery_app
from central.core.logging import log_info, log_warning
from central.db.models import Observation, ObservationProtocol
from central.db.session import get_session
from central.workers.base import DeduplicatedTask


class IngestScanResultTask(DeduplicatedTask):
    name = "workers.ingest_scan_result"
    rate_limit = "100/m"

    def run(
        self,
        collector_id: int,
        scan_run_id: int,
        protocol: str,
        results: list[dict[str, Any]],
        metadata: dict[str, Any],
    ) -> dict:
        """
        Store raw observations in the database

        Args:
            collector_id: ID of the reporting collector
            scan_run_id: Associated scan run
            protocol: discovery, snmp, ssh, http, netconf
            results: List of raw scan results
            metadata: Collector timestamp, duration, etc.

        Returns:
            Summary of ingestion (count, observation_ids)
        """
        log_info(
            self.logger,
            "ingestion.start",
            collector_id=collector_id,
            scan_run_id=scan_run_id,
            protocol=protocol,
            result_count=len(results),
        )
        protocol_value = self._normalize_protocol(protocol)
        collected_at = self._coerce_datetime(metadata.get("collected_at_utc"))
        with get_session() as session:
            observations = []
            for result in results:
                obs = Observation(
                    scan_run_id=scan_run_id,
                    protocol=protocol_value,
                    ip_address=result.get("ip"),
                    collected_at_utc=collected_at,
                    success=result.get("success", True),
                    error=result.get("error"),
                    duration_ms=result.get("duration_ms"),
                    raw_payload_ref=self._store_raw_payload(result),
                    parsed_payload_json=json.dumps(result),
                    evidence_hash=self._compute_hash(result),
                    parser_version="1.0.0",
                )
                observations.append(obs)

            session.add_all(observations)
            session.flush()
            observation_ids = [obs.id for obs in observations]

            session.commit()

            # Chain to parsing workers
            for obs_id in observation_ids:
                from central.workers.parsers import parse_observation_task

                parse_observation_task.delay(obs_id)

            log_info(
                self.logger,
                "ingestion.complete",
                collector_id=collector_id,
                scan_run_id=scan_run_id,
                protocol=protocol,
                ingested=len(observation_ids),
            )
            return {
                "ingested": len(observation_ids),
                "observation_ids": observation_ids,
            }

    def _normalize_protocol(self, protocol: str) -> ObservationProtocol:
        value = (protocol or "").strip().lower()
        try:
            return ObservationProtocol(value)
        except ValueError as exc:
            log_warning(self.logger, "ingestion.invalid_protocol", protocol=protocol)
            raise ValueError(f"Unknown protocol: {protocol}") from exc

    def _coerce_datetime(self, value: Any) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=UTC)
        if isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
            except ValueError:
                return None
        return None

    def _compute_hash(self, payload: Any) -> str:
        raw = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def _store_raw_payload(self, payload: Any) -> str | None:
        return None


ingest_scan_result_task = celery_app.register_task(IngestScanResultTask())
