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
