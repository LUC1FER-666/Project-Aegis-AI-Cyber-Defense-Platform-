"""Unit tests for PlaybookEngine."""
from __future__ import annotations

import pytest

from app.agents.playbooks import ActionStep, Playbook, PlaybookEngine


INCIDENT = {
    "id": "inc-001",
    "title": "Test",
    "severity": "high",
    "mitre_techniques": [],
    "asset_ids": ["asset-abc"],
}


class TestPlaybookEngine:
    def setup_method(self):
        self.engine = PlaybookEngine()

    # ── Playbook selection ────────────────────────────────────────────────────

    def test_brute_force_selected_for_T1110(self):
        pb = self.engine.select_playbook(["T1110"], "initial_access", "high")
        assert pb.name == "brute_force_response"

    def test_malware_selected_for_T1059(self):
        pb = self.engine.select_playbook(["T1059.001"], "execution", "critical")
        assert pb.name == "malware_execution_response"

    def test_malware_selected_for_T1053(self):
        pb = self.engine.select_playbook(["T1053.005"], "execution", "high")
        assert pb.name == "malware_execution_response"

    def test_lateral_movement_by_technique(self):
        pb = self.engine.select_playbook(["T1021"], "lateral_movement", "high")
        assert pb.name == "lateral_movement_response"

    def test_exfiltration_by_technique_T1071(self):
        pb = self.engine.select_playbook(["T1071.004"], "exfiltration", "high")
        assert pb.name == "data_exfiltration_response"

    def test_exfiltration_by_technique_T1041(self):
        pb = self.engine.select_playbook(["T1041"], "exfiltration", "high")
        assert pb.name == "data_exfiltration_response"

    def test_stage_fallback_lateral_movement(self):
        pb = self.engine.select_playbook([], "lateral_movement", "medium")
        assert pb.name == "lateral_movement_response"

    def test_stage_fallback_exfiltration(self):
        pb = self.engine.select_playbook([], "exfiltration", "medium")
        assert pb.name == "data_exfiltration_response"

    def test_generic_fallback_when_no_match(self):
        pb = self.engine.select_playbook([], "impact", "low")
        assert pb.name == "generic_investigation"

    def test_technique_priority_over_stage(self):
        # T1110 → brute_force even if stage says exfiltration
        pb = self.engine.select_playbook(["T1110"], "exfiltration", "high")
        assert pb.name == "brute_force_response"

    def test_unknown_technique_falls_back(self):
        pb = self.engine.select_playbook(["T9999"], "execution", "low")
        # No technique match, execution stage matches malware_execution_response
        assert pb.name in (
            "malware_execution_response",
            "generic_investigation",
        )

    # ── Step instantiation ────────────────────────────────────────────────────

    def test_brute_force_steps(self):
        pb = self.engine.select_playbook(["T1110"], "initial_access", "high")
        steps = self.engine.instantiate_steps(pb, INCIDENT)
        types = [s.action_type for s in steps]
        assert types == ["block_ip", "force_password_reset", "notify_soc"]

    def test_malware_steps(self):
        pb = self.engine.select_playbook(["T1059"], "execution", "high")
        steps = self.engine.instantiate_steps(pb, INCIDENT)
        types = [s.action_type for s in steps]
        assert types == ["kill_process", "isolate_host", "collect_logs", "notify_soc"]

    def test_lateral_movement_steps(self):
        pb = self.engine.select_playbook(["T1021"], "lateral_movement", "high")
        steps = self.engine.instantiate_steps(pb, INCIDENT)
        types = [s.action_type for s in steps]
        assert types == ["isolate_host", "collect_logs", "escalate_to_analyst"]

    def test_exfiltration_steps(self):
        pb = self.engine.select_playbook(["T1071"], "exfiltration", "high")
        steps = self.engine.instantiate_steps(pb, INCIDENT)
        types = [s.action_type for s in steps]
        assert types == ["block_ip", "collect_logs", "notify_soc", "escalate_to_analyst"]

    def test_generic_steps(self):
        pb = self.engine.select_playbook([], "reconnaissance", "low")
        steps = self.engine.instantiate_steps(pb, INCIDENT)
        types = [s.action_type for s in steps]
        assert types == ["collect_logs", "enrich_asset", "escalate_to_analyst"]

    def test_steps_are_action_step_instances(self):
        pb = self.engine.select_playbook(["T1059"], "execution", "high")
        steps = self.engine.instantiate_steps(pb, INCIDENT)
        for s in steps:
            assert isinstance(s, ActionStep)

    def test_step_parameters_contain_incident_id(self):
        pb = self.engine.select_playbook(["T1059"], "execution", "high")
        steps = self.engine.instantiate_steps(pb, INCIDENT)
        for s in steps:
            assert s.parameters.get("incident_id") == "inc-001"

    def test_step_target_uses_asset(self):
        pb = self.engine.select_playbook(["T1059"], "execution", "high")
        steps = self.engine.instantiate_steps(pb, INCIDENT)
        assert steps[0].target == "asset-abc"

    def test_step_target_fallback_when_no_assets(self):
        incident_no_asset = {**INCIDENT, "asset_ids": []}
        pb = self.engine.select_playbook([], "impact", "low")
        steps = self.engine.instantiate_steps(pb, incident_no_asset)
        # Target falls back to incident_id
        assert steps[0].target == "inc-001"

    # ── to_dict / to_info ─────────────────────────────────────────────────────

    def test_action_step_to_dict(self):
        step = ActionStep("block_ip", "192.168.1.1", {"k": "v"})
        d = step.to_dict()
        assert d["action_type"] == "block_ip"
        assert d["target"] == "192.168.1.1"
        assert d["parameters"] == {"k": "v"}

    def test_list_playbooks_returns_all_five(self):
        playbooks = self.engine.list_playbooks()
        names = [p["name"] for p in playbooks]
        assert "brute_force_response" in names
        assert "malware_execution_response" in names
        assert "lateral_movement_response" in names
        assert "data_exfiltration_response" in names
        assert "generic_investigation" in names
        assert len(playbooks) == 5

    def test_playbook_info_has_required_fields(self):
        for pb in self.engine.list_playbooks():
            assert "name" in pb
            assert "trigger_techniques" in pb
            assert "trigger_attack_stages" in pb
            assert "steps" in pb
