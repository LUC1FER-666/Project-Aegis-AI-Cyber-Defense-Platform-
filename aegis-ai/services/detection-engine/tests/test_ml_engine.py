"""
Tests — ML Anomaly Detection Engine

Covers:
- Feature extraction per log type
- Model training lifecycle
- Anomaly scoring
- Pre-training behavior (no false positives before min_samples)
"""
import pytest
import numpy as np
from app.engines.ml_engine import (
    FeatureExtractor, MLAnomalyDetector
)


class TestFeatureExtractor:
    def setup_method(self):
        self.fx = FeatureExtractor()

    def test_process_event_returns_correct_key(self):
        key, vec = self.fx.extract({"log_type": "process", "command_line": "cmd.exe"})
        assert key == "process"
        assert vec is not None

    def test_process_features_shape(self):
        key, vec = self.fx.extract({
            "log_type": "process",
            "command_line": "powershell -enc abc",
            "user": "SYSTEM",
        })
        assert vec.shape == (7,)

    def test_process_features_encoded_flag(self):
        _, vec_enc = self.fx.extract({
            "log_type": "process",
            "command_line": "powershell -EncodedCommand abc123",
        })
        _, vec_plain = self.fx.extract({
            "log_type": "process",
            "command_line": "notepad.exe file.txt",
        })
        # has_encoded should differ (index 5)
        assert vec_enc[5] == 1.0
        assert vec_plain[5] == 0.0

    def test_network_event_returns_correct_key(self):
        key, vec = self.fx.extract({"log_type": "netflow", "dst_port": 443})
        assert key == "network"
        assert vec is not None
        assert vec.shape == (7,)

    def test_network_port_risk_high_risk_port(self):
        _, vec = self.fx.extract({"log_type": "netflow", "dst_port": 4444})
        # port_risk index is 4; 4444 is high-risk → 2
        assert vec[4] == 2.0

    def test_network_port_risk_safe_port(self):
        _, vec = self.fx.extract({"log_type": "netflow", "dst_port": 443})
        assert vec[4] == 0.0

    def test_auth_event(self):
        key, vec = self.fx.extract({
            "log_type": "auth",
            "status": "failure",
            "user": "administrator",
            "source_ip": "192.168.1.1",
        })
        assert key == "auth"
        assert vec.shape == (5,)
        # success=0, is_admin_target=1
        assert vec[0] == 0.0
        assert vec[2] == 1.0

    def test_auth_success_flag(self):
        _, vec = self.fx.extract({"log_type": "auth", "status": "success"})
        assert vec[0] == 1.0

    def test_dns_event(self):
        key, vec = self.fx.extract({
            "log_type": "dns",
            "query": "normal.example.com",
            "record_type": "A",
        })
        assert key == "dns"
        assert vec.shape == (7,)

    def test_dns_long_query_flag(self):
        long_query = "a" * 60 + ".example.com"
        _, vec = self.fx.extract({"log_type": "dns", "query": long_query})
        # is_long at index 4
        assert vec[4] == 1.0

    def test_dns_entropy_increases_with_random_string(self):
        _, vec_rand = self.fx.extract({"log_type": "dns", "query": "xkqvzajmplrty.example.com"})
        _, vec_word = self.fx.extract({"log_type": "dns", "query": "normal.example.com"})
        # entropy at index 2 should be higher for random string
        assert vec_rand[2] > vec_word[2]

    def test_generic_fallback(self):
        key, vec = self.fx.extract({"log_type": "syslog", "message": "some message"})
        assert key == "syslog"
        assert vec is not None

    def test_generic_no_message_returns_none(self):
        key, vec = self.fx.extract({"log_type": "syslog"})
        assert vec is None

    def test_windows_event(self):
        key, vec = self.fx.extract({"log_type": "windows_event", "event_id": 4688})
        assert key == "windows"
        assert vec.shape == (3,)
        # event_id=4688 → category=2 (process)
        assert vec[1] == 2.0

    def test_hour_extraction_from_iso_timestamp(self):
        from app.engines.ml_engine import FeatureExtractor
        fx = FeatureExtractor()
        hour = fx._hour_from_ts("2024-06-15T14:30:00Z")
        assert hour == 14

    def test_hour_extraction_missing_returns_zero(self):
        from app.engines.ml_engine import FeatureExtractor
        fx = FeatureExtractor()
        assert fx._hour_from_ts(None) == 0


class TestMLAnomalyDetector:
    def _make_process_events(self, n: int, high_entropy=False):
        events = []
        for i in range(n):
            cmd = f"{'z'*300}" if high_entropy else f"svchost.exe -k netsvcs {i}"
            events.append({
                "log_type": "process",
                "command_line": cmd,
                "user": "NT AUTHORITY\\NETWORK SERVICE",
                "timestamp": "2024-01-01T10:00:00Z",
            })
        return events

    def test_returns_no_anomaly_before_training(self):
        detector = MLAnomalyDetector(min_samples=50, contamination=0.1)
        score, is_anom = detector.score_event({
            "log_type": "process",
            "command_line": "cmd.exe /c whoami",
        })
        assert score == 0.0
        assert is_anom is False

    def test_model_trains_after_min_samples(self):
        detector = MLAnomalyDetector(min_samples=20, contamination=0.1)
        events = self._make_process_events(25)
        for ev in events:
            detector.score_event(ev)

        info = detector.get_model_info()
        assert "process" in info
        assert info["process"]["is_trained"]

    def test_anomaly_score_in_range_after_training(self):
        detector = MLAnomalyDetector(min_samples=20, contamination=0.1)
        events = self._make_process_events(25)
        for ev in events:
            detector.score_event(ev)

        score, _ = detector.score_event({
            "log_type": "process",
            "command_line": "svchost.exe -k normal 26",
        })
        assert 0.0 <= score <= 1.0

    def test_is_any_model_trained_false_before_training(self):
        detector = MLAnomalyDetector(min_samples=100)
        assert not detector.is_any_model_trained()

    def test_is_any_model_trained_true_after_training(self):
        detector = MLAnomalyDetector(min_samples=10, contamination=0.1)
        for ev in self._make_process_events(15):
            detector.score_event(ev)
        assert detector.is_any_model_trained()

    def test_multiple_categories_independent_models(self):
        detector = MLAnomalyDetector(min_samples=10, contamination=0.1)

        # Train process model
        for ev in self._make_process_events(15):
            detector.score_event(ev)

        # Add some auth events (not enough to train)
        for i in range(5):
            detector.score_event({"log_type": "auth", "status": "success", "user": "user1"})

        info = detector.get_model_info()
        assert info["process"]["is_trained"]
        assert not info["auth"]["is_trained"]

    def test_network_features_do_not_crash(self):
        detector = MLAnomalyDetector(min_samples=5, contamination=0.2)
        events = [
            {"log_type": "netflow", "dst_port": 443, "bytes_in": 1500, "protocol": "tcp"}
            for _ in range(10)
        ]
        for ev in events:
            score, _ = detector.score_event(ev)
            assert 0.0 <= score <= 1.0

    def test_sample_count_tracked(self):
        detector = MLAnomalyDetector(min_samples=50)
        for i in range(10):
            detector.score_event({"log_type": "process", "command_line": f"cmd {i}"})
        info = detector.get_model_info()
        assert info["process"]["sample_count"] == 10

    def test_model_version_increments_on_retrain(self):
        """Force a retrain by manipulating last_trained_at."""
        detector = MLAnomalyDetector(min_samples=10, contamination=0.1, retrain_interval=0)
        events = self._make_process_events(15)
        for ev in events:
            detector.score_event(ev)

        initial_version = detector._models["process"].model_version

        # Trigger retrain (interval=0 so always retrain)
        import time
        detector._models["process"].last_trained_at = 0  # force stale
        detector.score_event({"log_type": "process", "command_line": "new event"})

        assert detector._models["process"].model_version > initial_version
