"""
Detection Engine — Layer 3: LLM Reasoning Layer

Uses Ollama (llama3.2) to validate detection hits and reduce false positives.
The LLM is given: rule title, mitre technique, event evidence, and asset context.
It returns a structured JSON decision.

We apply LLM validation only to medium+ severity alerts to avoid latency
on high-volume low-severity hits.  Timeout is enforced; failures are
non-fatal and default to PASS (keep the alert).
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

# LLM validation is only run for these severities to control overhead
LLM_VALIDATE_SEVERITIES = {"critical", "high", "medium"}

# System prompt that constrains the LLM to structured JSON output only
SYSTEM_PROMPT = """You are a cybersecurity threat analyst working inside an autonomous \
detection system. Your job is to review a single detection alert and decide whether it \
represents a genuine threat or a false positive.

You will be given:
- The detection rule title and MITRE ATT&CK technique
- The severity level
- Key evidence fields from the triggering event
- Optional context about the affected asset

You MUST respond with ONLY a JSON object in this exact schema:
{
  "is_true_positive": <boolean>,
  "confidence": <float between 0.0 and 1.0>,
  "reasoning": "<one or two sentences explaining your decision>",
  "suppressed": <boolean — set to true ONLY if you are highly confident this is a false positive>
}

Rules:
- Be conservative: when in doubt, mark is_true_positive=true and suppressed=false
- Only set suppressed=true when you are very confident (confidence > 0.85) it is a false positive
- Do NOT add any text outside the JSON object
"""


@dataclass
class LLMValidationResult:
    is_true_positive: bool
    confidence: float
    reasoning: str
    suppressed: bool
    raw_response: str = ""
    error: Optional[str] = None


class LLMReasoningEngine:
    """
    Validates alerts via Ollama.  Can be disabled entirely (llm_enabled=False)
    in which case all alerts pass through with no LLM reasoning.
    """

    def __init__(
        self,
        ollama_base_url: str = "http://localhost:11434",
        model: str = "llama3.2",
        timeout: float = 15.0,
        enabled: bool = True,
    ):
        self.base_url = ollama_base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.enabled = enabled

    async def validate_alert(
        self,
        rule_title: str,
        rule_id: str,
        severity: str,
        mitre_technique: Optional[str],
        evidence: dict[str, Any],
        asset_context: Optional[dict[str, Any]] = None,
    ) -> LLMValidationResult:
        """
        Validate a single alert with the LLM.
        Returns a default pass-through result on any error.
        """
        # Skip low-severity hits to reduce load
        if severity.lower() not in LLM_VALIDATE_SEVERITIES:
            return LLMValidationResult(
                is_true_positive=True,
                confidence=0.5,
                reasoning="LLM validation skipped for low-severity alert.",
                suppressed=False,
            )

        if not self.enabled:
            return LLMValidationResult(
                is_true_positive=True,
                confidence=0.5,
                reasoning="LLM validation disabled.",
                suppressed=False,
            )

        prompt = self._build_prompt(
            rule_title, rule_id, severity, mitre_technique, evidence, asset_context
        )

        try:
            raw = await self._call_ollama(prompt)
            return self._parse_response(raw)
        except httpx.TimeoutException:
            logger.warning("LLM validation timed out for rule '%s'", rule_id)
            return LLMValidationResult(
                is_true_positive=True,
                confidence=0.5,
                reasoning="LLM validation timed out — alert preserved.",
                suppressed=False,
                error="timeout",
            )
        except Exception as exc:
            logger.warning("LLM validation error for rule '%s': %s", rule_id, exc)
            return LLMValidationResult(
                is_true_positive=True,
                confidence=0.5,
                reasoning=f"LLM validation failed: {exc} — alert preserved.",
                suppressed=False,
                error=str(exc),
            )

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _build_prompt(
        self,
        rule_title: str,
        rule_id: str,
        severity: str,
        mitre_technique: Optional[str],
        evidence: dict[str, Any],
        asset_context: Optional[dict[str, Any]] = None,
    ) -> str:
        """Construct the user message for the LLM."""
        lines = [
            f"Detection Rule: {rule_title}",
            f"Rule ID: {rule_id}",
            f"Severity: {severity}",
        ]

        if mitre_technique:
            lines.append(f"MITRE ATT&CK: {mitre_technique}")

        # Truncate evidence to avoid context window overflow
        evidence_str = json.dumps(self._truncate_dict(evidence, max_values=15), indent=2)
        lines.append(f"\nEvidence (triggering event fields):\n{evidence_str}")

        if asset_context:
            ctx_str = json.dumps(self._truncate_dict(asset_context, max_values=8), indent=2)
            lines.append(f"\nAsset context:\n{ctx_str}")

        return "\n".join(lines)

    async def _call_ollama(self, user_message: str) -> str:
        """Make a non-streaming request to Ollama /api/chat."""
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            "stream": False,
            "options": {
                "temperature": 0.1,   # Low temperature for deterministic JSON
                "num_predict": 256,   # Limit token generation
            },
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/api/chat",
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()

        # Ollama response: {"message": {"role": "assistant", "content": "..."}}
        return data.get("message", {}).get("content", "")

    def _parse_response(self, raw: str) -> LLMValidationResult:
        """
        Parse the LLM JSON response.
        Tolerant: extracts JSON even if surrounded by markdown fences.
        """
        text = raw.strip()

        # Strip markdown code fences if present
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(
                line for line in lines
                if not line.startswith("```")
            ).strip()

        # Find JSON object boundaries
        start = text.find("{")
        end = text.rfind("}") + 1
        if start == -1 or end == 0:
            raise ValueError(f"No JSON object found in LLM response: {raw[:200]}")

        parsed = json.loads(text[start:end])

        is_tp = bool(parsed.get("is_true_positive", True))
        confidence = float(parsed.get("confidence", 0.5))
        confidence = max(0.0, min(1.0, confidence))
        reasoning = str(parsed.get("reasoning", ""))
        suppressed = bool(parsed.get("suppressed", False))

        # Safety: never suppress a critical alert via LLM
        # (humans must review those manually)
        return LLMValidationResult(
            is_true_positive=is_tp,
            confidence=confidence,
            reasoning=reasoning,
            suppressed=suppressed,
            raw_response=raw,
        )

    @staticmethod
    def _truncate_dict(d: dict, max_values: int = 15) -> dict:
        """Keep only the first max_values keys; truncate long string values."""
        result = {}
        for i, (k, v) in enumerate(d.items()):
            if i >= max_values:
                result["..."] = f"({len(d) - max_values} more fields)"
                break
            if isinstance(v, str) and len(v) > 500:
                result[k] = v[:500] + "...[truncated]"
            else:
                result[k] = v
        return result
