"""
Attack Narrative Engine
Generates human-readable attack narratives using Ollama llama3.2.
Falls back to template-based narratives on any error.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)

SEVERITY_WORDS = {
    "critical": "Critical — immediate response required",
    "high": "High — urgent investigation needed",
    "medium": "Medium — monitor and investigate",
    "low": "Low — routine review recommended",
}


def _heuristic_narrative(context: dict[str, Any]) -> dict[str, Any]:
    """Generate narrative from templates when LLM is unavailable."""
    title = context.get("title") or context.get("threat_type") or "Security Threat Detected"
    severity = str(context.get("severity") or "medium").lower()
    techniques = context.get("mitre_techniques") or context.get("recommended_actions") or []
    assets = context.get("affected_assets") or context.get("asset_ids") or []
    confidence = float(context.get("confidence") or 0.7)

    headline = f"Security threat detected: {title}"
    severity_assessment = SEVERITY_WORDS.get(severity, f"{severity.capitalize()} severity threat identified")

    timeline = [
        "Initial indicators observed in telemetry data",
        f"Pattern matched on {len(assets)} asset(s): {', '.join(str(a) for a in assets[:3])}",
        "Automated analysis triggered",
        "SOC notification dispatched",
    ]
    if techniques:
        timeline.insert(2, f"Attack techniques identified: {', '.join(str(t) for t in techniques[:3])}")

    return {
        "headline": headline,
        "severity_assessment": severity_assessment,
        "attack_timeline": timeline,
        "likely_objective": "Unauthorised access, credential theft, or lateral movement based on observed indicators",
        "immediate_actions": [
            "Isolate affected assets from the network",
            "Review authentication logs for affected users",
            "Enable enhanced monitoring on related assets",
            "Notify incident response team",
        ],
        "technical_indicators": [
            f"Affected assets: {', '.join(str(a) for a in assets[:5])}" if assets else "No specific assets identified",
            f"Confidence score: {confidence:.0%}",
            f"Techniques: {', '.join(str(t) for t in techniques[:3])}" if techniques else "Unknown techniques",
        ],
        "confidence": confidence,
    }


def _parse_llm_narrative(raw: str, context: dict[str, Any]) -> dict[str, Any]:
    """Parse and validate Ollama's JSON response."""
    cleaned = re.sub(r"```(?:json)?", "", raw).strip()
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not match:
        raise ValueError("No JSON found in LLM response")

    data = json.loads(match.group())

    # Validate and coerce fields
    timeline = data.get("attack_timeline") or []
    if not isinstance(timeline, list):
        timeline = [str(timeline)]

    immediate_actions = data.get("immediate_actions") or []
    if not isinstance(immediate_actions, list):
        immediate_actions = [str(immediate_actions)]

    indicators = data.get("technical_indicators") or []
    if not isinstance(indicators, list):
        indicators = [str(indicators)]

    confidence = float(data.get("confidence") or context.get("confidence") or 0.7)
    confidence = max(0.0, min(1.0, confidence))

    return {
        "headline": str(data.get("headline") or "Threat detected"),
        "severity_assessment": str(data.get("severity_assessment") or "Unknown severity"),
        "attack_timeline": [str(t) for t in timeline],
        "likely_objective": str(data.get("likely_objective") or "Unknown objective"),
        "immediate_actions": [str(a) for a in immediate_actions],
        "technical_indicators": [str(i) for i in indicators],
        "confidence": confidence,
    }


def _build_prompt(context: dict[str, Any]) -> str:
    title = context.get("title") or context.get("threat_type") or "Unknown Threat"
    severity = context.get("severity", "medium")
    techniques = context.get("mitre_techniques") or []
    assets = context.get("affected_assets") or []
    evidence = context.get("evidence_summary") or context.get("evidence") or ""
    confidence = context.get("confidence", 0.7)

    return f"""You are a senior SOC analyst writing an attack briefing. Generate a clear, actionable narrative for this threat.

Threat details:
- Title: {title}
- Severity: {severity}
- Confidence: {confidence:.0%}
- Affected assets: {', '.join(str(a) for a in assets) if assets else 'Unknown'}
- MITRE techniques: {', '.join(str(t) for t in techniques) if techniques else 'Unknown'}
- Evidence: {evidence}

Respond ONLY with a single JSON object (no markdown, no preamble):
{{
  "headline": "<one sentence summary>",
  "severity_assessment": "<Critical/High/Medium/Low with one sentence justification>",
  "attack_timeline": ["<Step 1>", "<Step 2>", "<Step 3>"],
  "likely_objective": "<what the attacker is trying to achieve>",
  "immediate_actions": ["<Action 1>", "<Action 2>", "<Action 3>"],
  "technical_indicators": ["<IOC 1>", "<IOC 2>"],
  "confidence": <float 0.0-1.0>
}}"""


class AttackNarrativeEngine:

    def __init__(self) -> None:
        self.settings = get_settings()

    async def generate(self, context: dict[str, Any]) -> dict[str, Any]:
        """Generate narrative — always returns a result, never raises."""
        if not self.settings.llm_enabled:
            logger.info("LLM disabled — using heuristic narrative")
            return _heuristic_narrative(context)
        try:
            return await self._llm_narrative(context)
        except Exception as exc:
            logger.warning("LLM narrative failed (%s) — using heuristic fallback", exc)
            return _heuristic_narrative(context)

    async def _llm_narrative(self, context: dict[str, Any]) -> dict[str, Any]:
        prompt = _build_prompt(context)
        payload = {
            "model": self.settings.ollama_model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2},
        }
        async with httpx.AsyncClient(timeout=self.settings.ollama_timeout) as client:
            resp = await client.post(f"{self.settings.ollama_base_url}/api/generate", json=payload)
            resp.raise_for_status()
            raw = resp.json().get("response", "")
        return _parse_llm_narrative(raw, context)
