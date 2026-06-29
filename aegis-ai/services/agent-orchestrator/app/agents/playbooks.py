"""
Playbook Engine
Maps incidents to response playbooks based on MITRE technique + severity + attack_stage.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ActionStep:
    action_type: str
    target: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "target": self.target,
            "parameters": self.parameters,
        }


@dataclass
class Playbook:
    name: str
    trigger_techniques: list[str]       # MITRE technique prefixes (e.g. "T1110")
    trigger_attack_stages: list[str]    # fallback stage match
    step_templates: list[str]           # ordered list of action types

    def to_info(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "trigger_techniques": self.trigger_techniques,
            "trigger_attack_stages": self.trigger_attack_stages,
            "steps": self.step_templates,
        }


# ── Built-in playbooks ───────────────────────────────────────────────────────

PLAYBOOKS: list[Playbook] = [
    Playbook(
        name="brute_force_response",
        trigger_techniques=["T1110"],
        trigger_attack_stages=["initial_access"],
        step_templates=["block_ip", "force_password_reset", "notify_soc"],
    ),
    Playbook(
        name="malware_execution_response",
        trigger_techniques=["T1059", "T1053"],
        trigger_attack_stages=["execution"],
        step_templates=["kill_process", "isolate_host", "collect_logs", "notify_soc"],
    ),
    Playbook(
        name="lateral_movement_response",
        trigger_techniques=["T1021", "T1076"],
        trigger_attack_stages=["lateral_movement"],
        step_templates=["isolate_host", "collect_logs", "escalate_to_analyst"],
    ),
    Playbook(
        name="data_exfiltration_response",
        trigger_techniques=["T1071", "T1041"],
        trigger_attack_stages=["exfiltration"],
        step_templates=["block_ip", "collect_logs", "notify_soc", "escalate_to_analyst"],
    ),
    Playbook(
        name="generic_investigation",
        trigger_techniques=[],
        trigger_attack_stages=[],
        step_templates=["collect_logs", "enrich_asset", "escalate_to_analyst"],
    ),
]


def _technique_prefix(tech: str) -> str:
    """Return base technique (strip sub-technique suffix)."""
    return tech.split(".")[0].upper()


class PlaybookEngine:
    """
    Selects the most appropriate playbook for an incident.

    Priority:
    1. Exact MITRE technique match
    2. Attack stage match
    3. generic_investigation fallback
    """

    def __init__(self) -> None:
        self._playbooks = PLAYBOOKS

    def select_playbook(
        self,
        mitre_techniques: list[str],
        attack_stage: str,
        severity: str,  # kept for future priority logic
    ) -> Playbook:
        prefixes = {_technique_prefix(t) for t in mitre_techniques}

        # 1. Exact technique match
        for pb in self._playbooks:
            if pb.trigger_techniques and prefixes.intersection(
                set(pb.trigger_techniques)
            ):
                logger.info(
                    "Playbook selected by technique match: %s (techniques=%s)",
                    pb.name,
                    prefixes,
                )
                return pb

        # 2. Attack stage match
        for pb in self._playbooks:
            if attack_stage in pb.trigger_attack_stages:
                logger.info(
                    "Playbook selected by attack stage: %s (stage=%s)",
                    pb.name,
                    attack_stage,
                )
                return pb

        # 3. Fallback
        generic = next(pb for pb in self._playbooks if pb.name == "generic_investigation")
        logger.info("No specific playbook matched — using generic_investigation")
        return generic

    def instantiate_steps(
        self, playbook: Playbook, incident: dict[str, Any]
    ) -> list[ActionStep]:
        """
        Create concrete ActionStep objects from a playbook template,
        injecting incident context into each step.
        """
        asset_ids: list[str] = incident.get("asset_ids") or []
        primary_asset = asset_ids[0] if asset_ids else ""
        incident_id = incident.get("id") or incident.get("incident_id") or ""

        steps: list[ActionStep] = []
        for action_type in playbook.step_templates:
            step = ActionStep(
                action_type=action_type,
                target=primary_asset or incident_id,
                parameters={
                    "incident_id": incident_id,
                    "asset_ids": asset_ids,
                    "severity": incident.get("severity", "medium"),
                    "mitre_techniques": incident.get("mitre_techniques") or [],
                },
            )
            steps.append(step)

        return steps

    def list_playbooks(self) -> list[dict[str, Any]]:
        return [pb.to_info() for pb in self._playbooks]
