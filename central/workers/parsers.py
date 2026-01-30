from __future__ import annotations

import json
import logging

from central.core.celery_config import celery_app
from central.core.logging import log_info, log_warning
from central.db.models import Observation, ObservationProtocol
from central.db.session import get_session
from central.workers.base import ResilientTask


class BaseParser:
    def parse(self, raw_data: dict) -> dict:
        return raw_data


class SnmpParser(BaseParser):
    def parse(self, raw_data: dict) -> dict:
        return {
            "identities": {
                "serial": raw_data.get("serial"),
                "sysname": raw_data.get("sysName"),
                "mac": raw_data.get("mac"),
                "hostname": raw_data.get("sysName"),
                "mgmt_ip": raw_data.get("ip"),
            },
            "device_info": {
                "vendor": raw_data.get("vendor"),
                "model": raw_data.get("model") or raw_data.get("sysDescr"),
                "hostname": raw_data.get("sysName"),
                "os_version": raw_data.get("osVersion"),
            },
            "interfaces": raw_data.get("interfaces", []),
            "neighbors": raw_data.get("neighbors", []),
        }


class ParserFactory:
    _parsers = {
        ObservationProtocol.snmp: SnmpParser(),
    }

    @classmethod
    def get_parser(cls, protocol: ObservationProtocol) -> BaseParser:
        return cls._parsers.get(protocol, BaseParser())


class ParseObservationTask(ResilientTask):
    name = "workers.parse_observation"

    def run(self, observation_id: int) -> dict:
        """
        Parse raw observation into structured device data
        """
        with get_session() as session:
            obs = session.get(Observation, observation_id)
            if not obs:
                log_warning(
                    logging.getLogger(__name__),
                    "parser.missing_observation",
                    observation_id=observation_id,
                )
                return {"observation_id": observation_id, "status": "missing"}
            parser = ParserFactory.get_parser(obs.protocol)
            raw_payload = {}
            if obs.parsed_payload_json:
                raw_payload = json.loads(obs.parsed_payload_json)
            log_info(
                logging.getLogger(__name__),
                "parser.start",
                observation_id=observation_id,
                protocol=str(obs.protocol.value),
            )
            parsed_data = parser.parse(raw_payload)

            # Update observation with parsed data
            obs.parsed_payload_json = json.dumps(parsed_data)
            session.commit()

            # Chain to reconciliation
            from central.workers.reconciliation import reconcile_device_task

            reconcile_device_task.delay(
                observation_id=observation_id, parsed_data=parsed_data
            )
            log_info(
                logging.getLogger(__name__),
                "parser.complete",
                observation_id=observation_id,
                protocol=str(obs.protocol.value),
            )
            return {"observation_id": observation_id, "status": "parsed"}


parse_observation_task = celery_app.register_task(ParseObservationTask())
