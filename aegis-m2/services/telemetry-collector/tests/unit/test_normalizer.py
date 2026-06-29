"""
Unit tests for the EventNormalizer.
Tests every source type to ensure the common schema is always populated.
"""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../../shared/python"))

import pytest
from app.normalizer import EventNormalizer


@pytest.fixture
def normalizer():
    return EventNormalizer()


class TestWindowsEventNormalization:
    def test_basic_windows_event(self, normalizer):
        raw = {
            "@timestamp": "2024-01-15T10:30:00Z",
            "host": {"ip": "192.168.1.10", "name": "DESKTOP-ABC123"},
            "event": {"code": 4624, "action": "logged-in"},
            "user": {"name": "john.doe", "domain": "CORP"},
            "process": {"name": "lsass.exe", "pid": 1234},
        }
        result = normalizer.normalize(raw, "windows_event")
        assert result["event_type"] == "windows_event"
        assert result["asset_ip"] == "192.168.1.10"
        assert result["asset_hostname"] == "DESKTOP-ABC123"
        assert result["user"]["name"] == "john.doe"
        assert result["event_code"] == 4624
        assert "event_id" in result
        assert "ingested_at" in result
        assert result["source_type"] == "windows_event"

    def test_windows_event_missing_fields_dont_crash(self, normalizer):
        result = normalizer.normalize({}, "windows_event")
        assert result["event_type"] == "windows_event"
        assert result["event_id"] is not None


class TestSyslogNormalization:
    def test_syslog_event(self, normalizer):
        raw = {
            "timestamp": "2024-01-15T10:30:00Z",
            "hostname": "web-server-01",
            "host_ip": "10.0.0.5",
            "severity": "error",
            "message": "Failed password for root from 203.0.113.1 port 22 ssh2",
            "program": "sshd",
        }
        result = normalizer.normalize(raw, "syslog")
        assert result["event_type"] == "syslog"
        assert result["asset_ip"] == "10.0.0.5"
        assert result["asset_hostname"] == "web-server-01"
        assert "Failed password" in result["raw_log"]


class TestNetflowNormalization:
    def test_netflow_event(self, normalizer):
        raw = {
            "@timestamp": "2024-01-15T10:30:00Z",
            "source": {"ip": "192.168.1.10", "port": 54321, "bytes": 1024},
            "destination": {"ip": "8.8.8.8", "port": 443, "bytes": 2048},
            "network": {"transport": "tcp"},
        }
        result = normalizer.normalize(raw, "netflow")
        assert result["event_type"] == "netflow"
        assert result["network"]["src_ip"] == "192.168.1.10"
        assert result["network"]["dst_ip"] == "8.8.8.8"
        assert result["network"]["dst_port"] == 443
        assert result["network"]["protocol"] == "tcp"
        assert result["network"]["bytes_sent"] == 1024


class TestDNSNormalization:
    def test_dns_query(self, normalizer):
        raw = {
            "@timestamp": "2024-01-15T10:30:00Z",
            "client_ip": "192.168.1.50",
            "query": "malicious-domain.ru",
            "type": "A",
            "rcode": "NOERROR",
            "resolved_ip": "185.220.101.1",
        }
        result = normalizer.normalize(raw, "dns")
        assert result["event_type"] == "dns"
        assert result["dns"]["question_name"] == "malicious-domain.ru"
        assert result["dns"]["resolved_ip"] == "185.220.101.1"


class TestProcessNormalization:
    def test_process_creation(self, normalizer):
        raw = {
            "@timestamp": "2024-01-15T10:30:00Z",
            "host_ip": "192.168.1.20",
            "hostname": "WORKSTATION-01",
            "pid": 4567,
            "process_name": "powershell.exe",
            "command_line": "powershell -enc JABjAG0AZAA=",
            "ppid": 1234,
            "sha256": "abc123def456",
            "user": "SYSTEM",
        }
        result = normalizer.normalize(raw, "process")
        assert result["event_type"] == "process"
        assert result["process"]["name"] == "powershell.exe"
        assert result["process"]["pid"] == 4567
        assert result["process"]["hash_sha256"] == "abc123def456"
        assert "enc" in result["process"]["command_line"]


class TestEventIDDeduplication:
    def test_same_event_produces_same_id(self, normalizer):
        raw = {
            "@timestamp": "2024-01-15T10:30:00Z",
            "host_ip": "192.168.1.1",
            "message": "test event",
        }
        r1 = normalizer.normalize(raw, "generic")
        r2 = normalizer.normalize(raw, "generic")
        assert r1["event_id"] == r2["event_id"]

    def test_different_events_produce_different_ids(self, normalizer):
        r1 = normalizer.normalize({"message": "event A", "host_ip": "1.1.1.1"}, "generic")
        r2 = normalizer.normalize({"message": "event B", "host_ip": "1.1.1.1"}, "generic")
        assert r1["event_id"] != r2["event_id"]


class TestGenericFallback:
    def test_unknown_source_type_uses_generic(self, normalizer):
        raw = {"message": "some unknown log", "ip": "10.0.0.1"}
        result = normalizer.normalize(raw, "unknown_format_xyz")
        assert result["event_type"] == "generic"
        assert result["event_id"] is not None
