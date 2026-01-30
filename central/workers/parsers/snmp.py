class SnmpParser:
    def parse(self, raw_data: dict) -> dict:
        """Extract device info from SNMP data"""
        return {
            "identities": {
                "serial": self._extract_serial(raw_data),
                "sysname": raw_data.get("sysName"),
                "mac": self._extract_base_mac(raw_data),
            },
            "device_info": {
                "vendor": self._map_vendor(raw_data.get("sysObjectID")),
                "model": raw_data.get("sysDescr"),
                "hostname": raw_data.get("sysName"),
            },
            "interfaces": self._parse_interfaces(raw_data),
            "neighbors": self._parse_lldp_cdp(raw_data),
        }

    def _extract_serial(self, raw_data: dict) -> str | None:
        value = raw_data.get("serial") or raw_data.get("serialNumber")
        if value is None:
            return None
        return str(value).strip() or None

    def _extract_base_mac(self, raw_data: dict) -> str | None:
        value = raw_data.get("mac") or raw_data.get("baseMac")
        if value is None:
            return None
        return str(value).strip() or None

    def _map_vendor(self, sys_object_id: object) -> str | None:
        if sys_object_id is None:
            return None
        return str(sys_object_id).strip() or None

    def _parse_interfaces(self, raw_data: dict) -> list[dict]:
        interfaces = raw_data.get("interfaces")
        if isinstance(interfaces, list):
            return interfaces
        return []

    def _parse_lldp_cdp(self, raw_data: dict) -> list[dict]:
        neighbors = raw_data.get("neighbors")
        if isinstance(neighbors, list):
            return neighbors
        return []
