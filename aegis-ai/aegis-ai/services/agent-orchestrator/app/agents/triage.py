"""
Incident Triage Agent
Calls Ollama llama3.2 to produce structured triage.
Falls back to deterministic heuristics on ANY error.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

import httpx

from app.config import get_settings
from app.schemas import TriageResult

logger = logging.getLogger(__name__)

# ── Attack stage inference from MITRE technique IDs ─────────────────────────
_TECHNIQUE_STAGE_MAP: list[tuple[list[str], str]] = [
    (["T1059", "T1053", "T1204"], "execution"),
    (["T1110", "T1078", "T1566"], "initial_access"),
    (["T1071", "T1041", "T1048"], "exfiltration"),
    (["T1021", "T1076", "T1563"], "lateral_movement"),
    (["T1547", "T1053", "T1543"], "persistence"),
    (["T1046", "T1595", "T1590"], "reconnaissance"),
    (["T1486", "T1490", "T1498"], "impact"),
]


def _infer_attack_stage(mitre_techniques: list[str]) -> str:
    """Return best-guess attack stage from MITRE technique IDs."""
    for techniques, stage in _TECHNIQUE_STAGE_MAP:
        for t in mitre_techniques:
            t_prefix = t.split(".")[0]  # handle sub-techniques e.g. T1059.001
            if t_prefix in techniques:
                return stage
    return "execution"  # safe default


def _heuristic_triage(incident: dict[str, Any]) -> TriageResult:
    """Rule-based fallback triage when LLM is unavailable."""
    severity = (incident.get("severity") or "medium").lower()
    mitre_techniques: list[str] = incident.get("mitre_techniques") or []
    title = incident.get("title") or incident.get("incident_title") or "Unknown"
    alert_count = len(incident.get("alert_ids") or incident.get("alerts") or [])

    urgency_map = {
        "critical": 0.95,
        "high": 0.80,
        "medium": 0.55,
        "low": 0.30,
    }
    tier_map = {
        "critical": "automated",
        "high": "supervised",
        "medium": "supervised",
        "low": "manual",
    }

    urgency_score = urgency_map.get(severity, 0.55)
    tier = tier_map.get(severity, "supervised")
    attack_stage = _infer_attack_stage(mitre_techniques)

    key_indicators: list[str] = []
    if mitre_techniques:
        key_indicators.append(f"MITRE techniques: {', '.join(mitre_techniques)}")
    if alert_count:
        key_indicators.append(f"{alert_count} correlated alert(s)")
    if severity in ("critical", "high"):
        key_indicators.append(f"Elevated severity: {severity}")
    if not key_indicators:
        key_indicators = ["Heuristic triage — LLM unavailable"]

    summary = (
        f"Heuristic triage for incident '{title}'. "
        f"Severity is {severity}, inferred attack stage is {attack_stage}. "
        f"Response tier set to {tier} based on severity rules."
    )

    return TriageResult(
        urgency_score=urgency_score,
        attack_stage=attack_stage,
        recommended_response_tier=tier,
        summary=summary,
        key_indicators=key_indicators,
    )


def _parse_llm_response(raw: str, incident: dict[str, Any]) -> TriageResult:
    """Extract JSON from LLM output and validate against TriageResult schema."""
    # Strip markdown fences if present
    cleaned = re.sub(r"```(?:json)?", "", raw).strip()
    # Find first { ... } block
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not match:
        raise ValueError("No JSON object found in LLM response")
    data = json.loads(match.group())

    valid_stages = {
        "reconnaissance", "initial_access", "execution", "persistence",
        "lateral_movement", "exfiltration", "impact"
    }
    valid_tiers = {"automated", "supervised", "manual"}

    attack_stage = str(data.get("attack_stage", "execution")).lower()
    if attack_stage not in valid_stages:
        attack_stage = _infer_attack_stage(
            incident.get("mitre_techniques") or []
        )

    tier = str(data.get("recommended_response_tier", "supervised")).lower()
    if tier not in valid_tiers:
        tier = "supervised"

    urgency = float(data.get("urgency_score", 0.55))
    urgency = max(0.0, min(1.0, urgency))

    key_indicators = data.get("key_indicators") or []
    if not isinstance(key_indicators, list):
        key_indicators = [str(key_indicators)]

    return TriageResult(
        urgency_score=urgency,
        attack_stage=attack_stage,
        recommended_response_tier=tier,
        summary=str(data.get("summary", "LLM triage completed.")),
        key_indicators=[str(k) for k in key_indicators],
    )


class IncidentTriageAgent:
    """
    Triage an incident using Ollama llama3.2.
    Falls back to heuristics on ANY exception (network, timeout, parse error, etc.).
    """

    def __init__(self) -> None:
        self.settings = get_settings()

    def _build_prompt(self, incident: dict[str, Any]) -> str:
        title = incident.get("title") or incident.get("incident_title") or "Unknown"
        severity = incident.get("severity", "unknown")
        techniques = incident.get("mitre_techniques") or []
        alerts = incident.get("alert_ids") or incident.get("alerts") or []
        asset_ids = incident.get("asset_ids") or []

        return f"""You are a senior SOC analyst. Analyse the following security incident and produce a structured triage.

Incident details:
- Title: {title}
- Severity: {severity}
- MITRE ATT&CK Techniques: {', '.join(techniques) if techniques else 'Unknown'}
- Correlated alerts: {len(alerts)}
- Affected assets: {', '.join(str(a) for a in asset_ids) if asset_ids else 'Unknown'}

Respond ONLY with a single JSON object (no markdown fences, no preamble) with exactly these fields:
{{
  "urgency_score": <float 0.0-1.0>,
  "attack_stage": "<one of: reconnaissance|initial_access|execution|persistence|lateral_movement|exfiltration|impact>",
  "recommended_response_tier": "<one of: automated|supervised|manual>",
  "summary": "<one paragraph explanation>",
  "key_indicators": ["<indicator1>", "<indicator2>"]
}}"""

    async def triage(self, incident: dict[str, Any]) -> TriageResult:
        """
        Run LLM triage. Always returns a TriageResult — never raises.
        Falls back to heuristics if LLM is disabled, unreachable, or returns bad data.
        """
        if not self.settings.llm_enabled:
            logger.info("LLM_ENABLED=false — using heuristic triage")
            return _heuristic_triage(incident)

        try:
            return await self._llm_triage(incident)
        except Exception as exc:
            logger.warning("LLM triage failed (%s: %s) — falling back to heuristics", type(exc).__name__, exc)
            return _heuristic_triage(incident)

    async def _llm_triage(self, incident: dict[str, Any]) -> TriageResult:
        prompt = self._build_prompt(incident)
        payload = {
            "model": self.settings.ollama_model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1},
        }

        async with httpx.AsyncClient(timeout=self.settings.ollama_timeout) as client:
            resp = await client.post(
                f"{self.settings.ollama_base_url}/api/generate",
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            raw_text = data.get("response", "")

        return _parse_llm_response(raw_text, incident)
