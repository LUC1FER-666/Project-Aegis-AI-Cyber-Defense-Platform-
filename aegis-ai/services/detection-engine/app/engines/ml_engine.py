"""
Detection Engine — Layer 2: ML Anomaly Detection

Uses Isolation Forest (unsupervised) to detect anomalous events.
Model is trained incrementally as telemetry flows in and reused across
the service lifetime.  We maintain separate models per event category
(process, network, auth, dns) because their feature spaces differ.
"""
from __future__ import annotations

import logging
import pickle
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


# ── Feature extraction ──────────────────────────────────────────────────────────

class FeatureExtractor:
    """
    Extracts numerical feature vectors from normalised telemetry events.
    Each category has its own feature schema.
    Unknown/missing fields default to 0.
    """

    def extract(self, event: dict[str, Any]) -> tuple[str, Optional[np.ndarray]]:
        """
        Returns (model_key, feature_vector | None).
        model_key determines which Isolation Forest to use.
        Returns (key, None) if the event can't be featurised.
        """
        log_type = event.get("log_type", "")

        if log_type == "process":
            return "process", self._process_features(event)
        elif log_type in ("netflow", "network"):
            return "network", self._network_features(event)
        elif log_type == "auth":
            return "auth", self._auth_features(event)
        elif log_type == "dns":
            return "dns", self._dns_features(event)
        elif log_type == "windows_event":
            return "windows", self._windows_features(event)
        else:
            return log_type or "generic", self._generic_features(event)

    # ── Per-category feature schemas ───────────────────────────────────────────

    def _process_features(self, ev: dict) -> np.ndarray:
        """
        Features: command length, arg count, hour-of-day, privilege indicators,
        script interpreter presence, parent/child relationship encoded.
        """
        cmd = str(ev.get("command_line") or ev.get("CommandLine") or "")
        parent = str(ev.get("parent_process") or ev.get("ParentProcessName") or "")
        user = str(ev.get("user") or ev.get("User") or "")
        ts = ev.get("timestamp")

        hour = self._hour_from_ts(ts)
        is_privileged = int("system" in user.lower() or "root" in user.lower() or "admin" in user.lower())
        has_script = int(any(x in cmd.lower() for x in ("powershell", "cmd", "bash", "sh ", "/bin/", "wscript", "cscript")))
        has_encoded = int("encodedcommand" in cmd.lower() or "-enc" in cmd.lower() or "base64" in cmd.lower())
        cmd_len = min(len(cmd), 1000)
        arg_count = cmd.count(" ") + 1 if cmd else 0
        is_network_parent = int(any(x in parent.lower() for x in ("browser", "chrome", "firefox", "edge", "iexplore", "outlook")))

        return np.array([cmd_len, arg_count, hour, is_privileged, has_script, has_encoded, is_network_parent], dtype=float)

    def _network_features(self, ev: dict) -> np.ndarray:
        """
        Features: byte count, packet count, duration, port risk category,
        protocol encoded, hour-of-day.
        """
        bytes_in = float(ev.get("bytes_in") or ev.get("bytes") or 0)
        bytes_out = float(ev.get("bytes_out") or 0)
        packets = float(ev.get("packets") or 0)
        duration = float(ev.get("duration") or 0)
        dst_port = int(ev.get("dst_port") or ev.get("destination_port") or 0)
        proto = str(ev.get("protocol") or "").lower()
        ts = ev.get("timestamp")

        hour = self._hour_from_ts(ts)
        # Port risk categories: 0=standard, 1=common, 2=high-risk
        port_risk = self._port_risk(dst_port)
        proto_enc = {"tcp": 0, "udp": 1, "icmp": 2}.get(proto, 3)

        return np.array([
            min(bytes_in, 1e9), min(bytes_out, 1e9), packets,
            min(duration, 86400), port_risk, proto_enc, hour
        ], dtype=float)

    def _auth_features(self, ev: dict) -> np.ndarray:
        """
        Features: success/failure, hour, admin target, remote vs local,
        auth type encoded.
        """
        status = str(ev.get("status") or "").lower()
        success = int(status in ("success", "accepted", "ok", "granted"))
        user = str(ev.get("user") or ev.get("username") or "")
        src = str(ev.get("source_ip") or ev.get("src_ip") or "")
        auth_type = str(ev.get("auth_type") or "").lower()
        ts = ev.get("timestamp")

        hour = self._hour_from_ts(ts)
        is_admin_target = int(any(x in user.lower() for x in ("admin", "root", "system", "administrator")))
        is_remote = int(bool(src) and src not in ("127.0.0.1", "::1", "localhost"))
        auth_enc = {"password": 0, "kerberos": 1, "ntlm": 2, "certificate": 3}.get(auth_type, 4)

        return np.array([success, hour, is_admin_target, is_remote, auth_enc], dtype=float)

    def _dns_features(self, ev: dict) -> np.ndarray:
        """
        Features: query length, subdomain depth, entropy of query,
        query type encoded, has numbers in domain.
        """
        query = str(ev.get("query") or ev.get("dns_query") or "")
        qtype = str(ev.get("record_type") or ev.get("query_type") or "A").upper()
        ts = ev.get("timestamp")

        hour = self._hour_from_ts(ts)
        depth = query.count(".")
        entropy = self._string_entropy(query)
        has_digits = int(any(c.isdigit() for c in query))
        is_long = int(len(query) > 50)
        qtype_enc = {"A": 0, "AAAA": 1, "MX": 2, "TXT": 3, "CNAME": 4, "NS": 5}.get(qtype, 6)

        return np.array([len(query), depth, entropy, has_digits, is_long, qtype_enc, hour], dtype=float)

    def _windows_features(self, ev: dict) -> np.ndarray:
        """Windows Event Log features based on event ID ranges."""
        event_id = int(ev.get("event_id") or ev.get("EventID") or 0)
        # Category buckets: auth=1, process=2, network=3, object=4, other=0
        category = 0
        if event_id in range(4624, 4650):
            category = 1  # auth
        elif event_id in (4688, 4689):
            category = 2  # process
        elif event_id in (5156, 5157, 5158):
            category = 3  # network
        elif event_id in range(4656, 4663):
            category = 4  # object access

        ts = ev.get("timestamp")
        hour = self._hour_from_ts(ts)
        return np.array([event_id, category, hour], dtype=float)

    def _generic_features(self, ev: dict) -> Optional[np.ndarray]:
        """Fallback: feature vector from message length and hour only."""
        msg = str(ev.get("message") or ev.get("raw") or "")
        ts = ev.get("timestamp")
        if not msg:
            return None
        return np.array([len(msg), self._hour_from_ts(ts)], dtype=float)

    # ── Utilities ──────────────────────────────────────────────────────────────

    @staticmethod
    def _hour_from_ts(ts: Any) -> int:
        """Extract hour-of-day (0-23) from a timestamp string or int epoch."""
        if ts is None:
            return 0
        try:
            if isinstance(ts, (int, float)):
                from datetime import datetime, timezone
                return datetime.fromtimestamp(ts, tz=timezone.utc).hour
            from datetime import datetime
            parsed = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            return parsed.hour
        except Exception:
            return 0

    @staticmethod
    def _port_risk(port: int) -> int:
        safe = {80, 443, 53, 22, 25, 110, 143, 993, 995, 21, 23}
        high_risk = {4444, 1337, 31337, 6666, 6667, 9999, 8888, 8080, 3128}
        if port in safe:
            return 0
        if port in high_risk or port > 49151:
            return 2
        return 1

    @staticmethod
    def _string_entropy(s: str) -> float:
        """Shannon entropy of a string — high entropy suggests DGA/encoded data."""
        if not s:
            return 0.0
        from collections import Counter
        import math
        counts = Counter(s)
        total = len(s)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())


# ── Per-category model state ───────────────────────────────────────────────────

@dataclass
class ModelState:
    model_key: str
    clf: Optional[IsolationForest] = None
    scaler: Optional[StandardScaler] = None
    buffer: list[np.ndarray] = field(default_factory=list)
    is_trained: bool = False
    sample_count: int = 0
    last_trained_at: float = 0.0
    model_version: int = 0
    feature_dim: int = 0


# ── Anomaly Detector ──────────────────────────────────────────────────────────

class MLAnomalyDetector:
    """
    Isolation Forest–based anomaly detector.

    Lifecycle:
    1. Events arrive → features extracted → buffered
    2. Once buffer ≥ min_samples, train/retrain the model
    3. Subsequent events scored immediately; buffer still accumulates
    4. Retrain every retrain_interval seconds to adapt to drift
    """

    def __init__(
        self,
        min_samples: int = 100,
        contamination: float = 0.05,
        retrain_interval: int = 3600,
    ):
        self.min_samples = min_samples
        self.contamination = contamination
        self.retrain_interval = retrain_interval

        self._extractor = FeatureExtractor()
        self._models: dict[str, ModelState] = {}

    # ── Public API ─────────────────────────────────────────────────────────────

    def score_event(self, event: dict[str, Any]) -> tuple[float, bool]:
        """
        Score an event for anomalousness.

        Returns:
            (anomaly_score, is_anomaly)
            anomaly_score: 0.0 (very normal) → 1.0 (very anomalous)
            is_anomaly: True if model flags it as anomalous

        Before the model is trained, returns (0.0, False) — no false positives
        before enough data is collected.
        """
        model_key, features = self._extractor.extract(event)

        if features is None:
            return 0.0, False

        state = self._get_or_create_state(model_key, features.shape[0])

        # Buffer the sample
        state.buffer.append(features)
        state.sample_count += 1

        # Train / retrain if threshold met
        self._maybe_train(state)

        if not state.is_trained:
            return 0.0, False

        # Score: IsolationForest.decision_function returns negative for anomalies
        # We invert and normalise to [0, 1]
        try:
            X = state.scaler.transform(features.reshape(1, -1))
            raw_score = state.clf.decision_function(X)[0]
            # Typical range: -0.5 to 0.5; we map to [0,1]
            anomaly_score = float(np.clip(0.5 - raw_score, 0.0, 1.0))
            # IsolationForest labels: -1 = anomaly, 1 = normal
            label = state.clf.predict(X)[0]
            is_anomaly = label == -1
            return anomaly_score, is_anomaly
        except Exception as exc:
            logger.debug("Scoring error for key %s: %s", model_key, exc)
            return 0.0, False

    def get_model_info(self) -> dict[str, dict]:
        """Return training status for all model keys."""
        return {
            key: {
                "is_trained": s.is_trained,
                "sample_count": s.sample_count,
                "version": s.model_version,
                "buffer_size": len(s.buffer),
            }
            for key, s in self._models.items()
        }

    def is_any_model_trained(self) -> bool:
        return any(s.is_trained for s in self._models.values())

    # ── Internal ──────────────────────────────────────────────────────────────

    def _get_or_create_state(self, model_key: str, feature_dim: int) -> ModelState:
        if model_key not in self._models:
            self._models[model_key] = ModelState(
                model_key=model_key,
                feature_dim=feature_dim,
            )
        return self._models[model_key]

    def _maybe_train(self, state: ModelState) -> None:
        """Train or retrain if conditions are met."""
        now = time.time()

        should_initial_train = (
            not state.is_trained and len(state.buffer) >= self.min_samples
        )
        should_retrain = (
            state.is_trained
            and (now - state.last_trained_at) > self.retrain_interval
            and len(state.buffer) >= self.min_samples
        )

        if not (should_initial_train or should_retrain):
            return

        try:
            self._train(state)
        except Exception as exc:
            logger.warning("Training failed for %s: %s", state.model_key, exc)

    def _train(self, state: ModelState) -> None:
        """Fit Isolation Forest on the current buffer."""
        X = np.array(state.buffer)

        # Trim buffer to last 10k samples to avoid unbounded memory growth
        if len(state.buffer) > 10_000:
            state.buffer = state.buffer[-10_000:]

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        clf = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42,
            n_jobs=1,
        )
        clf.fit(X_scaled)

        state.scaler = scaler
        state.clf = clf
        state.is_trained = True
        state.last_trained_at = time.time()
        state.model_version += 1

        logger.info(
            "ML model '%s' trained: %d samples, v%d",
            state.model_key, X.shape[0], state.model_version
        )
