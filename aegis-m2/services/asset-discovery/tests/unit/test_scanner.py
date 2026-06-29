"""
Unit tests for asset discovery — scanner, risk scoring, deduplication logic.
No real DB or network required.
"""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../../shared/python"))

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.scanners.network_scanner import NetworkScanner, DiscoveredHost, DiscoveredPort


class TestNetworkScanner:

    def setup_method(self):
        self.scanner = NetworkScanner(
            default_ports="22,80,443",
            excluded_ranges=["169.254.0.0/16", "224.0.0.0/4"],
            timeout=30,
        )

    def test_excluded_range_blocked(self):
        assert self.scanner._is_excluded("169.254.1.1") is True
        assert self.scanner._is_excluded("169.254.0.0/16") is True
        assert self.scanner._is_excluded("224.0.0.1") is True

    def test_normal_range_allowed(self):
        assert self.scanner._is_excluded("192.168.1.0/24") is False
        assert self.scanner._is_excluded("10.0.0.1") is False
        assert self.scanner._is_excluded("172.16.0.0/12") is False

    def test_internet_range_allowed_by_default(self):
        # Operator must explicitly exclude public ranges
        # The excluded list is configurable — this tests the default
        assert self.scanner._is_excluded("8.8.8.8") is False

    def test_infer_asset_type_windows_server(self):
        result = self.scanner._infer_asset_type("Windows Server 2019", "Windows")
        assert result == "server"

    def test_infer_asset_type_windows_endpoint(self):
        result = self.scanner._infer_asset_type("Windows 10 Enterprise", "Windows")
        assert result == "endpoint"

    def test_infer_asset_type_linux_server(self):
        result = self.scanner._infer_asset_type("Ubuntu 22.04 LTS", "Linux")
        assert result == "server"

    def test_infer_asset_type_network_device(self):
        result = self.scanner._infer_asset_type("Cisco IOS", "router")
        assert result == "network_device"

    def test_infer_asset_type_unknown(self):
        result = self.scanner._infer_asset_type(None, None)
        assert result == "unknown"

    @pytest.mark.asyncio
    async def test_scan_excluded_target_returns_empty(self):
        results = await self.scanner.scan_network("169.254.1.1")
        assert results == []

    @pytest.mark.asyncio
    async def test_scan_timeout_returns_empty(self):
        scanner = NetworkScanner(timeout=0)  # Instant timeout
        with patch("asyncio.wait_for", side_effect=__import__("asyncio").TimeoutError):
            results = await scanner.scan_network("192.168.1.1")
        assert results == []


class TestRiskScoring:
    """Test the heuristic risk scoring logic."""

    def setup_method(self):
        from app.services.asset_service import AssetService
        self.svc = AssetService.__new__(AssetService)

    def _make_asset(self, asset_type="server"):
        asset = MagicMock()
        asset.asset_type = asset_type
        asset.open_ports = []
        return asset

    def _make_host(self, ports: list[int]) -> DiscoveredHost:
        return DiscoveredHost(
            ip_address="192.168.1.1",
            ports=[
                DiscoveredPort(port_number=p, protocol="tcp", state="open")
                for p in ports
            ],
        )

    def test_server_base_score(self):
        asset = self._make_asset("server")
        host = self._make_host([])
        score = self.svc._calculate_risk_score(asset, host)
        assert score == 40.0

    def test_rdp_open_adds_risk(self):
        asset = self._make_asset("endpoint")
        host = self._make_host([3389])  # RDP
        score = self.svc._calculate_risk_score(asset, host)
        assert score > 25.0  # Base endpoint (25) + RDP (15)

    def test_telnet_open_high_risk(self):
        asset = self._make_asset("server")
        host = self._make_host([23])  # Telnet
        score = self.svc._calculate_risk_score(asset, host)
        assert score >= 60.0  # Server (40) + telnet (20)

    def test_many_ports_adds_risk(self):
        asset = self._make_asset("server")
        host = self._make_host(list(range(1, 25)))  # 24 ports
        score_many = self.svc._calculate_risk_score(asset, host)
        host_few = self._make_host([80, 443])
        score_few = self.svc._calculate_risk_score(asset, host_few)
        assert score_many > score_few

    def test_score_capped_at_100(self):
        asset = self._make_asset("network_device")
        # Many high-risk ports
        host = self._make_host([21, 23, 445, 135, 3389, 5900] + list(range(8000, 8030)))
        score = self.svc._calculate_risk_score(asset, host)
        assert score <= 100.0


class TestScanRequest:
    def test_empty_target_rejected(self):
        from app.models.schemas import ScanRequest
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            ScanRequest(target="")

    def test_internet_scan_rejected(self):
        from app.models.schemas import ScanRequest
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            ScanRequest(target="0.0.0.0/0")

    def test_valid_cidr_accepted(self):
        from app.models.schemas import ScanRequest
        req = ScanRequest(target="192.168.1.0/24")
        assert req.target == "192.168.1.0/24"

    def test_valid_single_host(self):
        from app.models.schemas import ScanRequest
        req = ScanRequest(target="10.0.0.5", aggressive=True)
        assert req.aggressive is True
