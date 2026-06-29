"""
Detection Engine — Pipeline

Orchestrates the four-layer detection pipeline:
  Event → Sigma → ML → LLM → Correlator → Alert/Incident

Called by the Kafka consumer for each normalised telemetry event.
Also callable directly for API-triggered test detections.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.engines.sigma_engine import SigmaRuleEngine
from app.engines.ml_engine import MLAnomalyDetector
from app.engines.llm_engine import LLMReasoningEngine
from app.engines.correlator import AlertCorrelator, AlertRecord
from app.models import Alert, Incident, DetectionRule, Severity, AlertStatus, IncidentStatus

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}


class DetectionPipeline:
    """
    Stateful pipeline that holds engine instances and runs them in sequence.
    Instantiated once at startup; shared across all Kafka consumer coroutines.
    """

    def __init__(
        self,
        sigma_engine: SigmaRuleEngine,
        ml_detector: MLAnomalyDetector,
        llm_engine: LLMReasoningEngine,
        correlator: AlertCorrelator,
        kafka_publisher=None,   # injected to avoid circular import
    ):
        self.sigma = sigma_engine
        self.ml = ml_detector
        self.llm = llm_engine
        self.correlator = correlator
        self.kafka_publisher = kafka_publisher

        # Counters (in-memory metrics)
        self.events_processed = 0
        self.sigma_hits = 0
        self.ml_anomalies = 0
        self.alerts_created = 0
        self.alerts_suppressed = 0
        self.incidents_created = 0

    async def process_event(
        self,
        event: dict[str, Any],
        db: AsyncSession,
    ) -> list[dict[str, Any]]:
        """
        Run a single normalised telemetry event through the full pipeline.
        Returns list of created alert dicts (for downstream publishing).
        """
        self.events_processed += 1
        created_alerts = []

        # ── Layer 1: Sigma ─────────────────────────────────────────────────────
        sigma_matches = self.sigma.match_event(event)

        for rule in sigma_matches:
            self.sigma_hits += 1
            alert = await self._create_alert_from_sigma(rule, event, db)
            if alert:
                created_alerts.append(alert)

        # ── Layer 2: ML Anomaly ────────────────────────────────────────────────
        anomaly_score, is_anomaly = self.ml.score_event(event)

        if is_anomaly and anomaly_score > 0.7:
            self.ml_anomalies += 1
            alert = await self._create_alert_from_ml(event, anomaly_score, db)
            if alert:
                created_alerts.append(alert)

        return created_alerts

    # ── Sigma alert creation ───────────────────────────────────────────────────

    async def _create_alert_from_sigma(
        self,
        rule,  # SigmaRule
        event: dict[str, Any],
        db: AsyncSession,
    ) -> Optional[dict[str, Any]]:
        """
        Create an Alert row from a Sigma rule match.
        Runs LLM validation and correlator.
        """
        severity_str = rule.severity
        severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        # Base confidence from severity
        base_confidence = {
            "critical": 0.90,
            "high": 0.80,
            "medium": 0.65,
            "low": 0.50,
            "info": 0.40,
        }.get(severity_str, 0.60)

        # Extract evidence (key fields that matched)
        evidence = self._extract_evidence(event)

        # ── Layer 3: LLM validation ────────────────────────────────────────────
        llm_result = await self.llm.validate_alert(
            rule_title=rule.title,
            rule_id=rule.rule_id,
            severity=severity_str,
            mitre_technique=rule.mitre_technique,
            evidence=evidence,
            asset_context={"asset_id": event.get("asset_id"), "hostname": event.get("hostname")},
        )

        # Adjust confidence based on LLM assessment
        if llm_result.confidence > 0:
            final_confidence = (base_confidence + llm_result.confidence) / 2
        else:
            final_confidence = base_confidence

        # Ensure the rule exists in DB (upsert)
        await self._ensure_rule_exists(rule, db)

        # Create alert
        alert = Alert(
            id=uuid.uuid4(),
            rule_id=rule.rule_id,
            asset_id=event.get("asset_id") or event.get("hostname"),
            severity=severity,
            mitre_technique=rule.mitre_technique,
            confidence_score=round(final_confidence, 3),
            evidence=evidence,
            source_event_id=event.get("event_id") or event.get("id"),
            source_log_type=event.get("log_type"),
            source_timestamp=self._parse_ts(event.get("timestamp")),
            llm_validated=llm_result.is_true_positive,
            llm_reasoning=llm_result.reasoning,
            suppressed_by_llm=llm_result.suppressed,
            status=AlertStatus.SUPPRESSED if llm_result.suppressed else AlertStatus.OPEN,
        )

        db.add(alert)
        await db.flush()   # get the auto-generated id

        if llm_result.suppressed:
            self.alerts_suppressed += 1
            logger.debug("Alert suppressed by LLM: rule=%s", rule.rule_id)
            return None

        self.alerts_created += 1

        # Update rule hit count
        await db.execute(
            DetectionRule.__table__.update()
            .where(DetectionRule.rule_id == rule.rule_id)
            .values(hit_count=DetectionRule.hit_count + 1)
        )

        # ── Layer 4: Correlation ───────────────────────────────────────────────
        await self._run_correlator(alert, event, db)

        return {
            "alert_id": str(alert.id),
            "rule_id": alert.rule_id,
            "asset_id": alert.asset_id,
            "severity": severity_str,
            "mitre_technique": alert.mitre_technique,
            "confidence_score": alert.confidence_score,
            "evidence": alert.evidence,
            "source_event_id": alert.source_event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ── ML alert creation ──────────────────────────────────────────────────────

    async def _create_alert_from_ml(
        self,
        event: dict[str, Any],
        anomaly_score: float,
        db: AsyncSession,
    ) -> Optional[dict[str, Any]]:
        """Create an alert from an ML anomaly detection hit."""
        ml_rule_id = "aegis-ml-isolation-forest"

        # Ensure the synthetic ML rule exists
        existing = await db.execute(
            select(DetectionRule).where(DetectionRule.rule_id == ml_rule_id)
        )
        if not existing.scalar_one_or_none():
            ml_rule = DetectionRule(
                rule_id=ml_rule_id,
                title="ML Anomaly: Isolation Forest",
                description="Unsupervised anomaly detected by Isolation Forest model",
                severity=Severity.MEDIUM,
                rule_type="ml",
                enabled=True,
            )
            db.add(ml_rule)
            await db.flush()

        severity = Severity.HIGH if anomaly_score > 0.85 else Severity.MEDIUM
        severity_str = "high" if anomaly_score > 0.85 else "medium"

        evidence = self._extract_evidence(event)
        evidence["anomaly_score"] = round(anomaly_score, 4)
        evidence["log_type"] = event.get("log_type", "unknown")

        alert = Alert(
            id=uuid.uuid4(),
            rule_id=ml_rule_id,
            asset_id=event.get("asset_id") or event.get("hostname"),
            severity=severity,
            confidence_score=round(anomaly_score, 3),
            anomaly_score=round(anomaly_score, 4),
            evidence=evidence,
            source_event_id=event.get("event_id") or event.get("id"),
            source_log_type=event.get("log_type"),
            source_timestamp=self._parse_ts(event.get("timestamp")),
            llm_validated=None,
            status=AlertStatus.OPEN,
        )

        db.add(alert)
        await db.flush()
        self.alerts_created += 1

        await self._run_correlator(alert, event, db)

        return {
            "alert_id": str(alert.id),
            "rule_id": ml_rule_id,
            "asset_id": alert.asset_id,
            "severity": severity_str,
            "mitre_technique": None,
            "confidence_score": alert.confidence_score,
            "evidence": alert.evidence,
            "source_event_id": alert.source_event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ── Correlator integration ─────────────────────────────────────────────────

    async def _run_correlator(
        self,
        alert: Alert,
        event: dict[str, Any],
        db: AsyncSession,
    ) -> None:
        """Feed alert to correlator; persist any emitted incidents."""
        record = AlertRecord(
            alert_id=str(alert.id),
            rule_id=alert.rule_id,
            asset_id=alert.asset_id,
            severity=alert.severity.value,
            mitre_technique=alert.mitre_technique,
            confidence_score=alert.confidence_score,
            evidence=alert.evidence,
            source_event_id=alert.source_event_id,
            source_log_type=alert.source_log_type,
            created_at=datetime.now(timezone.utc),
        )

        incidents = await self.correlator.ingest_alert(record)
        for corr_incident in incidents:
            await self._persist_incident(corr_incident, alert.id, db)

    async def _persist_incident(self, corr_incident, triggering_alert_id, db: AsyncSession) -> None:
        """Save a correlated incident to DB and link alerts."""
        severity = SEVERITY_MAP.get(corr_incident.severity, Severity.MEDIUM)

        incident = Incident(
            id=uuid.UUID(corr_incident.incident_id),
            title=corr_incident.title,
            description=corr_incident.description,
            severity=severity,
            status=IncidentStatus.OPEN,
            mitre_techniques=corr_incident.mitre_techniques,
            affected_assets=corr_incident.affected_assets,
            alert_count=corr_incident.alert_count,
            correlation_key=corr_incident.correlation_key,
            first_seen=corr_incident.first_seen,
            last_seen=corr_incident.last_seen,
        )
        db.add(incident)
        await db.flush()

        # Link alerts to the incident
        for alert_id_str in corr_incident.alert_ids:
            try:
                alert_id = uuid.UUID(alert_id_str)
                await db.execute(
                    Alert.__table__.update()
                    .where(Alert.id == alert_id)
                    .values(incident_id=incident.id)
                )
            except Exception as exc:
                logger.debug("Could not link alert %s to incident: %s", alert_id_str, exc)

        self.incidents_created += 1
        logger.info(
            "Incident created: %s [%s] (%d alerts)",
            incident.title, corr_incident.severity, corr_incident.alert_count
        )

        # Publish to Kafka if publisher available
        if self.kafka_publisher:
            await self.kafka_publisher.publish_incident(incident)

    # ── Helpers ────────────────────────────────────────────────────────────────

    async def _ensure_rule_exists(self, rule, db: AsyncSession) -> None:
        """Upsert detection rule metadata from a Sigma rule."""
        existing = await db.execute(
            select(DetectionRule).where(DetectionRule.rule_id == rule.rule_id)
        )
        if existing.scalar_one_or_none():
            return

        severity = SEVERITY_MAP.get(rule.severity, Severity.MEDIUM)
        db_rule = DetectionRule(
            rule_id=rule.rule_id,
            title=rule.title,
            description=rule.description,
            severity=severity,
            mitre_technique=rule.mitre_technique,
            mitre_tactic=rule.mitre_tactic,
            rule_type="sigma",
            enabled=True,
            extra_data={"tags": rule.tags, "logsource": rule.logsource},
        )
        db.add(db_rule)
        await db.flush()

    @staticmethod
    def _extract_evidence(event: dict[str, Any]) -> dict[str, Any]:
        """Extract a curated evidence dict from the raw event."""
        EVIDENCE_FIELDS = [
            "hostname", "asset_id", "user", "username", "User",
            "command_line", "CommandLine", "process_name", "ProcessName",
            "parent_process", "ParentProcessName",
            "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "bytes_in", "bytes_out",
            "event_id", "EventID", "log_type",
            "message", "action", "status",
            "query", "dns_query",
            "file_path", "registry_key",
        ]
        evidence = {}
        for f in EVIDENCE_FIELDS:
            if f in event and event[f] is not None:
                val = event[f]
                # Truncate very long strings
                if isinstance(val, str) and len(val) > 512:
                    val = val[:512] + "...[truncated]"
                evidence[f] = val
        return evidence

    @staticmethod
    def _parse_ts(ts: Any) -> Optional[datetime]:
        if ts is None:
            return None
        try:
            if isinstance(ts, datetime):
                return ts
            if isinstance(ts, (int, float)):
                return datetime.fromtimestamp(ts, tz=timezone.utc)
            return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except Exception:
            return None
