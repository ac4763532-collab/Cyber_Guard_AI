"""
CyberGuard AI - Network Intelligence Service Tests

Covers the free DNS/geoip/RDAP lookups and the service façade's threat-intel
honesty gate. All external calls (socket, httpx, ThreatIntelService) are
mocked - no real network traffic.
"""

import socket
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.services.network_intel.dns_lookup import resolve_dns
from app.services.network_intel.geoip import lookup_geoip
from app.services.network_intel.rdap import lookup_rdap
from app.services.network_intel.service import lookup_network_intel
from app.utils.network import is_ip_address


# =============================================================================
# is_ip_address
# =============================================================================

class TestIsIpAddress:
    def test_valid_ip(self):
        assert is_ip_address("8.8.8.8") is True

    def test_domain_is_not_ip(self):
        assert is_ip_address("example.com") is False

    def test_octet_out_of_range_is_not_ip(self):
        assert is_ip_address("999.1.1.1") is False

    def test_cidr_is_not_ip(self):
        # CIDR notation isn't a plain IP for this helper's purposes.
        assert is_ip_address("192.168.1.0/24") is False


# =============================================================================
# DNS lookup
# =============================================================================

class TestResolveDns:
    @pytest.mark.asyncio
    async def test_forward_lookup_success(self):
        with patch("socket.gethostbyname_ex", return_value=("dns.google", [], ["8.8.8.8"])):
            result = await resolve_dns("dns.google")
        assert result["query_type"] == "forward"
        assert result["hostname"] == "dns.google"
        assert result["resolved_ips"] == ["8.8.8.8"]
        assert result["error"] is None

    @pytest.mark.asyncio
    async def test_forward_lookup_no_record(self):
        with patch("socket.gethostbyname_ex", side_effect=socket.gaierror("not found")):
            result = await resolve_dns("this-domain-does-not-exist-xyz.invalid")
        assert result["hostname"] is None
        assert result["resolved_ips"] == []
        assert "No DNS record found" in result["error"]

    @pytest.mark.asyncio
    async def test_reverse_lookup_success(self):
        with patch("socket.gethostbyaddr", return_value=("dns.google", [], ["8.8.8.8"])):
            result = await resolve_dns("8.8.8.8")
        assert result["query_type"] == "reverse"
        assert result["hostname"] == "dns.google"
        assert result["error"] is None

    @pytest.mark.asyncio
    async def test_reverse_lookup_no_ptr_record(self):
        with patch("socket.gethostbyaddr", side_effect=socket.herror("no ptr")):
            result = await resolve_dns("203.0.113.5")
        assert result["hostname"] is None
        assert "No reverse DNS record" in result["error"]


# =============================================================================
# GeoIP lookup
# =============================================================================

def _mock_circuit_allowing():
    circuit = MagicMock()
    circuit.allow_request = AsyncMock(return_value=True)
    circuit.record_success = AsyncMock()
    circuit.record_failure = AsyncMock()
    return circuit


class TestLookupGeoip:
    @pytest.mark.asyncio
    async def test_success(self):
        payload = {
            "status": "success",
            "country": "United States",
            "countryCode": "US",
            "regionName": "California",
            "city": "Mountain View",
            "lat": 37.4,
            "lon": -122.0,
            "isp": "Google LLC",
            "org": "Google LLC",
            "as": "AS15169 Google LLC",
        }
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = MagicMock(return_value=payload)

        with patch(
            "app.services.network_intel.geoip.get_circuit_breaker",
            return_value=_mock_circuit_allowing(),
        ), patch.object(httpx.AsyncClient, "get", AsyncMock(return_value=mock_response)):
            result = await lookup_geoip("8.8.8.8")

        assert result["configured"] is True
        assert result["available"] is True
        assert result["country"] == "United States"
        assert result["error"] is None

    @pytest.mark.asyncio
    async def test_private_range_is_not_fabricated_as_clean(self):
        payload = {"status": "fail", "message": "private range"}
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = MagicMock(return_value=payload)

        with patch(
            "app.services.network_intel.geoip.get_circuit_breaker",
            return_value=_mock_circuit_allowing(),
        ), patch.object(httpx.AsyncClient, "get", AsyncMock(return_value=mock_response)):
            result = await lookup_geoip("192.168.1.1")

        assert result["configured"] is True
        assert result["available"] is False
        assert "private" in result["error"].lower()
        assert result["country"] is None

    @pytest.mark.asyncio
    async def test_transport_error_does_not_fabricate_data(self):
        with patch(
            "app.services.network_intel.geoip.get_circuit_breaker",
            return_value=_mock_circuit_allowing(),
        ), patch.object(
            httpx.AsyncClient, "get", AsyncMock(side_effect=httpx.ConnectError("boom"))
        ):
            result = await lookup_geoip("8.8.8.8")

        assert result["available"] is False
        assert result["error"] is not None
        assert result["country"] is None


# =============================================================================
# RDAP lookup
# =============================================================================

class TestLookupRdap:
    @pytest.mark.asyncio
    async def test_success(self):
        payload = {
            "handle": "EXAMPLE-COM",
            "status": ["active"],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar Inc."]]],
                }
            ],
            "events": [
                {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2024-08-14T04:00:00Z"},
            ],
            "nameservers": [{"ldhName": "ns1.example.com"}],
        }
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json = MagicMock(return_value=payload)

        with patch(
            "app.services.network_intel.rdap.get_circuit_breaker",
            return_value=_mock_circuit_allowing(),
        ), patch.object(httpx.AsyncClient, "get", AsyncMock(return_value=mock_response)):
            result = await lookup_rdap("example.com")

        assert result["available"] is True
        assert result["registrar"] == "Example Registrar Inc."
        assert result["nameservers"] == ["ns1.example.com"]
        assert result["error"] is None

    @pytest.mark.asyncio
    async def test_not_found_is_explicit_not_blank(self):
        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch(
            "app.services.network_intel.rdap.get_circuit_breaker",
            return_value=_mock_circuit_allowing(),
        ), patch.object(httpx.AsyncClient, "get", AsyncMock(return_value=mock_response)):
            result = await lookup_rdap("this-will-not-resolve.invalid")

        assert result["available"] is False
        assert result["error"] == "No RDAP record found"

    @pytest.mark.asyncio
    async def test_timeout_does_not_fabricate_data(self):
        with patch(
            "app.services.network_intel.rdap.get_circuit_breaker",
            return_value=_mock_circuit_allowing(),
        ), patch.object(
            httpx.AsyncClient, "get", AsyncMock(side_effect=httpx.TimeoutException("slow"))
        ):
            result = await lookup_rdap("example.com")

        assert result["available"] is False
        assert "timed out" in result["error"]


# =============================================================================
# Service façade - the critical honesty gate
# =============================================================================

class TestLookupNetworkIntel:
    @pytest.mark.asyncio
    async def test_not_configured_sentinel_never_reads_as_clean(self):
        """
        When no VirusTotal/AbuseIPDB key is configured, threat_intel must be
        an explicit {"configured": False, "is_malicious": None, ...}
        sentinel - never a default "is_malicious: False" that would look
        like a verified-clean verdict.
        """
        mock_dns = {"query_type": "reverse", "hostname": "dns.google", "resolved_ips": ["8.8.8.8"], "aliases": [], "error": None}
        mock_geo = {"configured": True, "available": True, "country": "US", "country_code": "US", "region": "CA", "city": "Mountain View", "lat": 37.4, "lon": -122.0, "isp": "Google", "org": "Google", "asn": "AS15169", "error": None}
        mock_rdap = {"configured": True, "available": True, "registrar": None, "created_date": None, "updated_date": None, "status": [], "nameservers": [], "raw_handle": None, "error": None}

        mock_service = MagicMock()
        mock_service.is_configured = False

        with patch("app.services.network_intel.service.resolve_dns", AsyncMock(return_value=mock_dns)), \
             patch("app.services.network_intel.service.lookup_rdap", AsyncMock(return_value=mock_rdap)), \
             patch("app.services.network_intel.service.lookup_geoip", AsyncMock(return_value=mock_geo)), \
             patch("app.services.network_intel.service.get_threat_intel_service", return_value=mock_service):
            result = await lookup_network_intel("8.8.8.8")

        assert result.threat_intel["configured"] is False
        assert result.threat_intel["is_malicious"] is None
        assert result.threat_intel["risk_score"] is None
        assert result.threat_intel["sources"] == []

    @pytest.mark.asyncio
    async def test_configured_and_clean_reports_real_verdict(self):
        mock_dns = {"query_type": "reverse", "hostname": "dns.google", "resolved_ips": ["8.8.8.8"], "aliases": [], "error": None}
        mock_geo = {"configured": True, "available": True, "country": "US", "country_code": "US", "region": "CA", "city": "Mountain View", "lat": 37.4, "lon": -122.0, "isp": "Google", "org": "Google", "asn": "AS15169", "error": None}
        mock_rdap = {"configured": True, "available": True, "registrar": None, "created_date": None, "updated_date": None, "status": [], "nameservers": [], "raw_handle": None, "error": None}

        from app.services.threat_intel.service import ThreatIntelResult, IOCType as RealIOCType

        mock_ti_result = ThreatIntelResult(
            ioc_type=RealIOCType.IP,
            ioc_value="8.8.8.8",
            is_malicious=False,
            risk_score=0,
            sources=["VirusTotal", "AbuseIPDB"],
            error=None,
        )
        mock_service = MagicMock()
        mock_service.is_configured = True
        mock_service.lookup = AsyncMock(return_value=mock_ti_result)

        with patch("app.services.network_intel.service.resolve_dns", AsyncMock(return_value=mock_dns)), \
             patch("app.services.network_intel.service.lookup_rdap", AsyncMock(return_value=mock_rdap)), \
             patch("app.services.network_intel.service.lookup_geoip", AsyncMock(return_value=mock_geo)), \
             patch("app.services.network_intel.service.get_threat_intel_service", return_value=mock_service):
            result = await lookup_network_intel("8.8.8.8")

        assert result.threat_intel["configured"] is True
        assert result.threat_intel["is_malicious"] is False
        assert result.threat_intel["sources"] == ["VirusTotal", "AbuseIPDB"]

    @pytest.mark.asyncio
    async def test_domain_target_chains_dns_to_geoip(self):
        """A domain target should resolve to an IP via DNS before geoip is called."""
        mock_dns = {"query_type": "forward", "hostname": "example.com", "resolved_ips": ["93.184.216.34"], "aliases": [], "error": None}
        mock_rdap = {"configured": True, "available": True, "registrar": "Example Registrar", "created_date": None, "updated_date": None, "status": [], "nameservers": [], "raw_handle": None, "error": None}

        mock_service = MagicMock()
        mock_service.is_configured = False

        geoip_mock = AsyncMock(return_value={"configured": True, "available": True, "country": "US", "country_code": "US", "region": None, "city": None, "lat": None, "lon": None, "isp": None, "org": None, "asn": None, "error": None})

        with patch("app.services.network_intel.service.resolve_dns", AsyncMock(return_value=mock_dns)), \
             patch("app.services.network_intel.service.lookup_rdap", AsyncMock(return_value=mock_rdap)), \
             patch("app.services.network_intel.service.lookup_geoip", geoip_mock), \
             patch("app.services.network_intel.service.get_threat_intel_service", return_value=mock_service):
            result = await lookup_network_intel("example.com")

        geoip_mock.assert_awaited_once_with("93.184.216.34")
        assert result.geoip["available"] is True

    @pytest.mark.asyncio
    async def test_domain_with_no_dns_resolution_does_not_fabricate_geoip(self):
        mock_dns = {"query_type": "forward", "hostname": None, "resolved_ips": [], "aliases": [], "error": "No DNS record found for this domain"}
        mock_rdap = {"configured": True, "available": False, "registrar": None, "created_date": None, "updated_date": None, "status": [], "nameservers": [], "raw_handle": None, "error": "No RDAP record found"}

        mock_service = MagicMock()
        mock_service.is_configured = False

        geoip_mock = AsyncMock()

        with patch("app.services.network_intel.service.resolve_dns", AsyncMock(return_value=mock_dns)), \
             patch("app.services.network_intel.service.lookup_rdap", AsyncMock(return_value=mock_rdap)), \
             patch("app.services.network_intel.service.lookup_geoip", geoip_mock), \
             patch("app.services.network_intel.service.get_threat_intel_service", return_value=mock_service):
            result = await lookup_network_intel("this-domain-does-not-exist-xyz.invalid")

        geoip_mock.assert_not_awaited()
        assert result.geoip["available"] is False
        assert result.geoip["error"] == "Could not resolve target to an IP for geolocation"
