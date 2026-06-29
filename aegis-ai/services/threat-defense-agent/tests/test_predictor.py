"""Unit tests for PredictiveThreatMonitor — no live services required."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.agents.predictor import PredictiveThreatMonitor, _shannon_entropy


def _now():
    return datetime.now(tz=timezone.utc)


def _ts(offset_seconds: int = 0) -> str:
    return (_now() - timedelta(seconds=abs(offset_seconds))).isoformat()


class TestShannonEntropy:
    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_uniform_string(self):
        # All same chars → 0 entropy
        assert _shannon_entropy("aaaa") == 0.0

    def test_high_entropy_random(self):
        # Random-looking string should have high entropy
        s = "xK9mP2qR7nL4wB8vT1"
        assert _shannon_entropy(s) > 3.0

    def test_low_entropy_word(self):
        assert _shannon_entropy("google") < 3.0

    def test_high_entropy_b64(self):
        s = "aGVsbG8ud29ybGQ"  # base64-like
        assert _shannon_entropy(s) > 3.0


class TestBruteForce:
    def setup_method(self):
        self.monitor = PredictiveThreatMonitor()

    def _auth_failure(self, src_ip: str, asset: str = "host-01") -> dict:
        return {
            "category": "auth",
            "auth_result": "failure",
            "src_ip": src_ip,
            "asset_id": asset,
            "timestamp": _ts(10),
        }

    def test_detects_brute_force_3_failures(self):
        events = [self._auth_failure("10.0.0.1") for _ in range(3)]
        preds = self.monitor.analyze(events)
        types = [p["threat_type"] for p in preds]
        assert "brute_force_imminent" in types

    def test_no_brute_force_below_threshold(self):
        events = [self._auth_failure("10.0.0.1") for _ in range(2)]
        preds = self.monitor.analyze(events)
        types = [p["threat_type"] for p in preds]
        assert "brute_force_imminent" not in types

    def test_brute_force_confidence_is_085(self):
        events = [self._auth_failure("10.0.0.2") for _ in range(5)]
        preds = self.monitor.analyze(events)
        bf = [p for p in preds if p["threat_type"] == "brute_force_imminent"]
        assert bf[0]["confidence"] == 0.85

    def test_brute_force_different_ips_independent(self):
        events = (
            [self._auth_failure("192.168.1.1") for _ in range(3)] +
            [self._auth_failure("192.168.1.2") for _ in range(3)]
        )
        preds = self.monitor.analyze(events)
        bf = [p for p in preds if p["threat_type"] == "brute_force_imminent"]
        assert len(bf) == 2

    def test_old_events_excluded(self):
        # Events older than 5 minutes should not trigger
        old_ts = (_now() - timedelta(minutes=6)).isoformat()
        events = [
            {"category": "auth", "auth_result": "failure", "src_ip": "1.2.3.4", "asset_id": "h", "timestamp": old_ts}
            for _ in range(5)
        ]
        preds = self.monitor.analyze(events)
        types = [p["threat_type"] for p in preds]
        assert "brute_force_imminent" not in types

    def test_prediction_has_required_fields(self):
        events = [self._auth_failure("10.0.1.1") for _ in range(3)]
        preds = self.monitor.analyze(events)
        bf = next(p for p in preds if p["threat_type"] == "brute_force_imminent")
        for field in ("prediction_id", "threat_type", "confidence", "affected_assets",
                      "evidence_summary", "predicted_attack_vector", "recommended_actions", "expires_at"):
            assert field in bf, f"Missing field: {field}"


class TestDnsTunnel:
    def setup_method(self):
        self.monitor = PredictiveThreatMonitor()

    def _dns_event(self, query: str) -> dict:
        return {"category": "dns", "query": query, "asset_id": "host-02", "timestamp": _ts(10)}

    def test_detects_high_entropy_dns(self):
        events = [self._dns_event("xK9mP2qR7nL4wB8vT1jF3.exfil.attacker.com")]
        preds = self.monitor.analyze(events)
        types = [p["threat_type"] for p in preds]
        assert "dns_tunnel_imminent" in types

    def test_no_detection_for_normal_dns(self):
        events = [self._dns_event("www.google.com")]
        preds = self.monitor.analyze(events)
        types = [p["threat_type"] for p in preds]
        assert "dns_tunnel_imminent" not in types

    def test_confidence_is_080(self):
        events = [self._dns_event("xK9mP2qR7nL4wB8vT1.evil.com")]
        preds = self.monitor.analyze(events)
        dns = [p for p in preds if p["threat_type"] == "dns_tunnel_imminent"]
        if dns:
            assert dns[0]["confidence"] == 0.80

    def test_old_dns_events_excluded(self):
        old_ts = (_now() - timedelta(minutes=3)).isoformat()
        events = [{"category": "dns", "query": "aGVsbG8ud29ybGQ.evil.com", "asset_id": "h", "timestamp": old_ts}]
        preds = self.monitor.analyze(events)
        types = [p["threat_type"] for p in preds]
        assert "dns_tunnel_imminent" not in types


class TestC2Beacon:
    def setup_method(self):
        self.monitor = PredictiveThreatMonitor()

    def test_detects_process_plus_network(self):
        events = [
            {"category": "process", "process_name": "powershell.exe", "asset_id": "host-03", "timestamp": _ts(10)},
            {"category": "network", "dest_ip": "1.2.3.4", "asset_id": "host-03", "timestamp": _ts(5)},
        ]
        preds = self.monitor.analyze(events)
        types = [p["threat_type"] for p in preds]
        assert "c2_beacon_imminent" in types

    def test_no_detection_process_only(self):
        events = [{"category": "process", "process_name": "calc.exe", "asset_id": "host-04", "timestamp": _ts(10)}]
        preds = self.monitor.analyze(events)
        types = [p["threat_type"] for p in preds]
        assert "c2_beacon_imminent" not in types

    def test_no_detection_different_assets(self):
        events = [
            {"category": "process", "process_name": "cmd.exe", "asset_id": "host-A", "timestamp": _ts(10)},
            {"category": "network", "dest_ip": "5.6.7.8", "asset_id": "host-B", "timestamp": _ts(5)},
        ]
        preds = self.monitor.analyze(events)
        types = [p["threat_type"] for p in preds]
        assert "c2_beacon_imminent" not in types

    def test_confidence_is_075(self):
        events = [
            {"category": "process", "process_name": "wscript.exe", "asset_id": "host-05", "timestamp": _ts(10)},
            {"category": "network", "dest_ip": "9.9.9.9", "asset_id": "host-05", "timestamp": _ts(5)},
        ]
        preds = self.monitor.analyze(events)
        c2 = [p for p in preds if p["threat_type"] == "c2_beacon_imminent"]
        assert c2[0]["confidence"] == 0.75


class TestAccountCompromise:
    def setup_method(self):
        self.monitor = PredictiveThreatMonitor()

    def _event(self, result: str, src: str = "10.0.0.5") -> dict:
        return {
            "category": "auth",
            "auth_result": result,
            "src_ip": src,
            "username": "admin",
            "asset_id": "dc-01",
            "timestamp": _ts(30),
        }

    def test_detects_success_after_failures(self):
        events = [self._event("failure"), self._event("failure"), self._event("success")]
        preds = self.monitor.analyze(events)
        types = [p["threat_type"] for p in preds]
        assert "account_compromise" in types

    def test_confidence_is_090(self):
        events = [self._event("failure"), self._event("failure"), self._event("success")]
        preds = self.monitor.analyze(events)
        ac = [p for p in preds if p["threat_type"] == "account_compromise"]
        assert ac[0]["confidence"] == 0.90

    def test_no_detection_success_only(self):
        events = [self._event("success")]
        preds = self.monitor.analyze(events)
        types = [p["threat_type"] for p in preds]
        assert "account_compromise" not in types

    def test_no_detection_failures_only(self):
        events = [self._event("failure") for _ in range(5)]
        preds = self.monitor.analyze(events)
        # Brute force yes, but NOT account_compromise (no success)
        types = [p["threat_type"] for p in preds]
        assert "account_compromise" not in types


class TestLateralSpread:
    def setup_method(self):
        self.monitor = PredictiveThreatMonitor()

    def _event(self, asset: str) -> dict:
        return {
            "category": "network",
            "mitre_technique": "T1021",
            "asset_id": asset,
            "timestamp": _ts(60),
        }

    def test_detects_same_technique_3_assets(self):
        events = [self._event(f"host-{i}") for i in range(3)]
        preds = self.monitor.analyze(events)
        types = [p["threat_type"] for p in preds]
        assert "lateral_spread_imminent" in types

    def test_no_detection_below_3_assets(self):
        events = [self._event(f"host-{i}") for i in range(2)]
        preds = self.monitor.analyze(events)
        types = [p["threat_type"] for p in preds]
        assert "lateral_spread_imminent" not in types

    def test_confidence_is_088(self):
        events = [self._event(f"host-{i}") for i in range(4)]
        preds = self.monitor.analyze(events)
        ls = [p for p in preds if p["threat_type"] == "lateral_spread_imminent"]
        assert ls[0]["confidence"] == 0.88

    def test_different_techniques_independent(self):
        events = [
            {"category": "network", "mitre_technique": "T1021", "asset_id": f"h{i}", "timestamp": _ts(60)}
            for i in range(3)
        ] + [
            {"category": "network", "mitre_technique": "T1059", "asset_id": f"x{i}", "timestamp": _ts(60)}
            for i in range(3)
        ]
        preds = self.monitor.analyze(events)
        ls = [p for p in preds if p["threat_type"] == "lateral_spread_imminent"]
        assert len(ls) == 2

    def test_no_technique_no_detection(self):
        events = [{"category": "network", "asset_id": f"h{i}", "timestamp": _ts(60)} for i in range(3)]
        preds = self.monitor.analyze(events)
        types = [p["threat_type"] for p in preds]
        assert "lateral_spread_imminent" not in types


class TestParseTimestamp:
    def test_iso_string(self):
        ts = "2024-01-01T12:00:00+00:00"
        result = PredictiveThreatMonitor._parse_ts(ts)
        assert result is not None
        assert result.tzinfo is not None

    def test_datetime_object(self):
        dt = datetime.now(tz=timezone.utc)
        result = PredictiveThreatMonitor._parse_ts(dt)
        assert result == dt

    def test_none_returns_none(self):
        assert PredictiveThreatMonitor._parse_ts(None) is None

    def test_invalid_string_returns_none(self):
        assert PredictiveThreatMonitor._parse_ts("not-a-date") is None

    def test_naive_datetime_gets_utc(self):
        dt = datetime(2024, 1, 1, 12, 0, 0)
        result = PredictiveThreatMonitor._parse_ts(dt)
        assert result is not None
        assert result.tzinfo is not None
