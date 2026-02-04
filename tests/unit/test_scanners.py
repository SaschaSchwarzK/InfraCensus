"""Unit tests for improved scanners."""

import pytest

from collector.scanners.discovery.nmap import NmapScanner
from collector.scanners.http.scanner import HttpScanner
from collector.scanners.netconf.scanner import NetconfScanner
from collector.scanners.snmp.scanner import SnmpScanner
from collector.scanners.ssh.scanner import SshScanner


class TestHttpScannerImproved:
    """Tests for improved HTTP scanner."""

    @pytest.mark.asyncio
    async def test_scan_returns_structured_data(self):
        """Test that HTTP scanner returns structured data."""
        scanner = HttpScanner()
        results = await scanner.scan(
            ["httpbin.org"],
            {
                "port": 80,
                "timeout": 10,
                "use_https": False,
                "follow_redirects": True,
            },
        )

        assert len(results) == 1
        result = results[0]

        # Check basic fields
        assert result.ip == "httpbin.org"
        assert isinstance(result.duration_ms, int)
        assert isinstance(result.data, dict)

        # Check extracted metadata (if scan succeeded)
        if result.success:
            assert "status_code" in result.data
            assert "server" in result.data
            assert "content_type" in result.data

    @pytest.mark.asyncio
    async def test_https_scan_with_ssl_verification_disabled(self):
        """Test HTTPS scanning with SSL verification disabled."""
        scanner = HttpScanner()
        results = await scanner.scan(
            ["httpbin.org"],
            {
                "port": 443,
                "timeout": 10,
                "use_https": True,
                "verify_ssl": False,
            },
        )

        assert len(results) == 1
        result = results[0]
        assert "protocol" in result.data
        assert result.data["protocol"] == "https"

    @pytest.mark.asyncio
    async def test_invalid_target_rejected(self):
        """Test that invalid targets are rejected."""
        scanner = HttpScanner()
        results = await scanner.scan(
            ["127.0.0.1"],  # Loopback should be rejected
            {"port": 80, "timeout": 5},
        )

        assert len(results) == 1
        result = results[0]
        assert not result.success
        assert "invalid_target" in result.data.get("status", "")


class TestSshScannerImproved:
    """Tests for improved SSH scanner."""

    @pytest.mark.asyncio
    async def test_ssh_banner_extraction(self):
        """Test SSH banner grabbing."""
        scanner = SshScanner()
        # Note: This test requires a publicly accessible SSH server
        # In real tests, use a mock SSH server
        results = await scanner.scan(
            ["test.rebex.net"],  # Public test SSH server
            {"port": 22, "timeout": 10, "grab_banner": True},
        )

        assert len(results) == 1
        result = results[0]

        # If scan succeeded, check for banner data
        if result.success:
            assert "banner" in result.data
            assert "ssh_version" in result.data
            assert result.data["banner"] != "unknown"

    @pytest.mark.asyncio
    async def test_ssh_connection_timeout(self):
        """Test SSH scanner handles timeouts properly."""
        scanner = SshScanner()
        results = await scanner.scan(
            ["192.0.2.1"],  # TEST-NET-1, should timeout
            {"port": 22, "timeout": 1},
        )

        assert len(results) == 1
        result = results[0]
        assert not result.success
        assert "timeout" in (
            result.error or ""
        ).lower() or "unreachable" in result.data.get("status", "")


class TestSnmpScannerImproved:
    """Tests for improved SNMP scanner."""

    @pytest.mark.asyncio
    async def test_snmp_query_structure(self):
        """Test SNMP scanner builds queries correctly."""
        scanner = SnmpScanner()

        # Test with non-existent host (won't respond but tests structure)
        results = await scanner.scan(
            ["192.0.2.1"],  # TEST-NET-1
            {"port": 161, "timeout": 2, "retries": 1, "community": "public"},
        )

        assert len(results) == 1
        result = results[0]

        # Should have attempted scan
        assert result.ip == "192.0.2.1"
        assert "community" in result.data

    @pytest.mark.asyncio
    async def test_snmp_uses_credentials(self):
        """Test SNMP scanner uses provided credentials."""
        scanner = SnmpScanner()

        credentials = {
            "192.0.2.1": [{"community": "test_community"}],
        }

        results = await scanner.scan(
            ["192.0.2.1"],
            {
                "port": 161,
                "timeout": 2,
                "retries": 0,
                "credentials_by_target": credentials,
            },
        )

        assert len(results) == 1
        result = results[0]
        assert result.data.get("credential_source") == "central"

    @pytest.mark.asyncio
    async def test_snmp_uses_v3_credentials(self, monkeypatch):
        """Test SNMP scanner uses v3 credentials when provided."""
        scanner = SnmpScanner()

        credentials = {
            "192.0.2.1": [
                {
                    "username": "snmpuser",
                    "auth_key": "authpass",
                    "priv_key": "privpass",
                    "auth_protocol": "sha",
                    "priv_protocol": "aes",
                }
            ],
        }

        async def fake_snmp_get(_target, _port, _community, _timeout, v3_params):
            assert v3_params is not None
            assert v3_params.get("username") == "snmpuser"
            return None

        monkeypatch.setattr(scanner, "_snmp_get", fake_snmp_get)

        results = await scanner.scan(
            ["192.0.2.1"],
            {
                "port": 161,
                "timeout": 1,
                "retries": 0,
                "credentials_by_target": credentials,
            },
        )

        assert len(results) == 1
        result = results[0]
        assert result.data.get("credential_source") == "central"


class TestNmapScannerImproved:
    """Tests for improved Nmap scanner."""

    @pytest.mark.asyncio
    async def test_nmap_xml_parsing(self):
        """Test Nmap XML parsing functionality."""
        scanner = NmapScanner()

        # Sample XML output for testing
        sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up" reason="echo-reply" />
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="router.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.2p1" />
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18.0" />
      </port>
    </ports>
  </host>
</nmaprun>"""

        # Test parsing directly
        parsed = scanner._parse_nmap_xml(sample_xml, "192.168.1.1")

        assert parsed["host_up"] is True
        assert len(parsed["ports"]) == 2
        assert parsed["hostnames"] == ["router.local"]
        assert parsed["open_ports"] == 2

        # Check port details
        ssh_port = next(p for p in parsed["ports"] if p["port"] == 22)
        assert ssh_port["state"] == "open"
        assert ssh_port["service"] == "ssh"
        assert "OpenSSH" in ssh_port["version"]

    @pytest.mark.asyncio
    async def test_nmap_argument_validation(self):
        """Test that dangerous nmap arguments are rejected."""
        scanner = NmapScanner()

        # Test dangerous arguments
        with pytest.raises(ValueError):
            scanner._build_nmap_args("port_scan", "80", "; rm -rf /")

        with pytest.raises(ValueError):
            scanner._build_nmap_args("port_scan", "80", "&& cat /etc/passwd")

        # Test valid arguments
        args = scanner._build_nmap_args("service_detection", "1-1000", "-sV")
        assert "-sV" in args
        assert "-p" in args

    @pytest.mark.asyncio
    async def test_nmap_target_validation_blocks_local_ranges(self):
        scanner = NmapScanner()
        ok, _, err = await scanner._run_nmap("127.0.0.1", 1, [])
        assert ok is False
        assert err == "invalid_target"
        ok, _, err = await scanner._run_nmap("224.0.0.1", 1, [])
        assert ok is False
        assert err == "invalid_target"
        ok, _, err = await scanner._run_nmap("169.254.10.1", 1, [])
        assert ok is False
        assert err == "invalid_target"


class TestNetconfScannerImproved:
    """Tests for improved NETCONF scanner."""

    @pytest.mark.asyncio
    async def test_netconf_hello_message_format(self):
        """Test NETCONF hello message is properly formatted."""
        scanner = NetconfScanner()
        hello = scanner._build_hello_message()

        assert "<?xml version=" in hello
        assert "<hello xmlns=" in hello
        assert "<capabilities>" in hello
        assert "urn:ietf:params:netconf:base:1.0" in hello
        assert "]]>]]>" in hello

    @pytest.mark.asyncio
    async def test_netconf_capability_parsing(self):
        """Test NETCONF capability parsing."""
        scanner = NetconfScanner()

        sample_hello = """<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:base:1.1</capability>
    <capability>urn:ietf:params:netconf:capability:startup:1.0</capability>
  </capabilities>
  <session-id>12345</session-id>
</hello>]]>]]>"""

        capabilities, session_id = scanner._parse_hello_response(sample_hello)

        assert len(capabilities) == 3
        assert "urn:ietf:params:netconf:base:1.0" in capabilities
        assert "urn:ietf:params:netconf:base:1.1" in capabilities
        assert session_id == "12345"

    @pytest.mark.asyncio
    async def test_netconf_parses_namespaced_xml(self):
        """Test NETCONF parser handles namespaces and attributes."""
        scanner = NetconfScanner()

        sample = """<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:ex="urn:example">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:base:1.1</capability>
  </capabilities>
  <session-id ex:attr="value">6789</session-id>
</hello>]]>]]>"""

        capabilities, session_id = scanner._parse_hello_response(sample)
        assert session_id == "6789"
        assert "urn:ietf:params:netconf:base:1.0" in capabilities
        assert "urn:ietf:params:netconf:base:1.1" in capabilities


class TestConcurrentScanning:
    """Tests for concurrent scanning capabilities."""

    @pytest.mark.asyncio
    async def test_multiple_targets_scanned_concurrently(self):
        """Test that multiple targets are scanned concurrently."""
        import time

        scanner = HttpScanner()

        targets = ["httpbin.org", "example.com", "python.org"]

        start = time.perf_counter()
        results = await scanner.scan(
            targets,
            {"port": 80, "timeout": 10, "use_https": False},
        )
        duration = time.perf_counter() - start

        # Should complete in less time than sequential would take
        assert len(results) == len(targets)

        # Concurrent execution should be faster than 3x single timeout
        # (allowing for overhead)
        assert duration < 25  # Much less than 3 * 10 seconds


class TestErrorHandling:
    """Tests for error handling in scanners."""

    @pytest.mark.asyncio
    async def test_invalid_port_rejected(self):
        """Test that invalid ports are rejected."""
        scanner = HttpScanner()

        with pytest.raises(ValueError, match="Invalid port"):
            await scanner.scan(["example.com"], {"port": 70000})

        with pytest.raises(ValueError, match="Invalid port"):
            await scanner.scan(["example.com"], {"port": -1})

    @pytest.mark.asyncio
    async def test_scanner_handles_exceptions_gracefully(self):
        """Test that scanners handle unexpected exceptions."""
        scanner = SshScanner()

        # Scan invalid target
        results = await scanner.scan(
            ["256.256.256.256"],  # Invalid IP
            {"port": 22, "timeout": 5},
        )

        assert len(results) == 1
        result = results[0]
        assert not result.success
        assert result.error is not None
