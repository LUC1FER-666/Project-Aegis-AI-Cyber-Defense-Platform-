"""
Tests — Sigma Rule Engine

Covers:
- Parser: basic fields, MITRE tag extraction, condition parsing variants
- Evaluator: field matching, modifiers, logsource, condition logic
- Engine: load from dict, match_event
"""
import pytest
from app.engines.sigma_engine import (
    SigmaParser, SigmaEvaluator, SigmaRuleEngine, SigmaRule
)


# ── Parser tests ───────────────────────────────────────────────────────────────

class TestSigmaParser:
    def setup_method(self):
        self.parser = SigmaParser()

    def _minimal_rule(self, **overrides):
        base = {
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": ["attack.t1059.001", "attack.execution"],
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|contains": "powershell"},
                "condition": "selection",
            },
        }
        base.update(overrides)
        return base

    def test_basic_parse(self):
        rule = self.parser.parse_dict(self._minimal_rule())
        assert rule.rule_id == "test-001"
        assert rule.title == "Test Rule"
        assert rule.severity == "high"

    def test_severity_mapping_informational(self):
        rule = self.parser.parse_dict(self._minimal_rule(level="informational"))
        assert rule.severity == "info"

    def test_severity_mapping_critical(self):
        rule = self.parser.parse_dict(self._minimal_rule(level="critical"))
        assert rule.severity == "critical"

    def test_mitre_technique_extracted(self):
        rule = self.parser.parse_dict(self._minimal_rule())
        assert rule.mitre_technique == "T1059.001"

    def test_mitre_tactic_extracted(self):
        rule = self.parser.parse_dict(self._minimal_rule())
        assert rule.mitre_tactic == "execution"

    def test_no_tags(self):
        rule = self.parser.parse_dict(self._minimal_rule(tags=[]))
        assert rule.mitre_technique is None
        assert rule.mitre_tactic is None

    def test_missing_id_generates_uuid(self):
        data = self._minimal_rule()
        del data["id"]
        rule = self.parser.parse_dict(data)
        assert len(rule.rule_id) > 8  # UUID generated

    def test_missing_detection_raises(self):
        with pytest.raises(ValueError, match="no detection block"):
            self.parser.parse_dict({
                "title": "Bad Rule",
                "logsource": {},
                "detection": {},
            })

    def test_missing_condition_raises(self):
        with pytest.raises(ValueError, match="no condition"):
            self.parser.parse_dict({
                "title": "No Condition",
                "logsource": {},
                "detection": {"selection": {"foo": "bar"}},
            })

    def test_condition_simple_selection(self):
        rule = self.parser.parse_dict(self._minimal_rule())
        assert "selection" in rule.condition.selections
        assert rule.condition.filters == []

    def test_condition_selection_and_not_filter(self):
        data = self._minimal_rule()
        data["detection"]["filter"] = {"CommandLine|contains": "legit"}
        data["detection"]["condition"] = "selection and not filter"
        rule = self.parser.parse_dict(data)
        assert "selection" in rule.condition.selections
        assert "filter" in rule.condition.filters

    def test_condition_1_of_them(self):
        data = {
            "title": "1 of them",
            "id": "test-002",
            "level": "medium",
            "logsource": {},
            "detection": {
                "selection1": {"foo": "bar"},
                "selection2": {"baz": "qux"},
                "condition": "1 of them",
            },
        }
        rule = self.parser.parse_dict(data)
        assert "selection1" in rule.condition.selections
        assert "selection2" in rule.condition.selections
        assert not rule.condition.require_all

    def test_condition_all_of_them(self):
        data = {
            "title": "all of them",
            "id": "test-003",
            "level": "medium",
            "logsource": {},
            "detection": {
                "sel_a": {"foo": "bar"},
                "sel_b": {"baz": "qux"},
                "condition": "all of them",
            },
        }
        rule = self.parser.parse_dict(data)
        assert rule.condition.require_all

    def test_condition_wildcard_prefix(self):
        data = {
            "title": "wildcard",
            "id": "test-004",
            "level": "high",
            "logsource": {},
            "detection": {
                "selection_a": {"cmd": "x"},
                "selection_b": {"cmd": "y"},
                "filter_legit": {"user": "admin"},
                "condition": "1 of selection*",
            },
        }
        rule = self.parser.parse_dict(data)
        assert "selection_a" in rule.condition.selections
        assert "selection_b" in rule.condition.selections
        assert "filter_legit" not in rule.condition.selections


# ── Evaluator tests ────────────────────────────────────────────────────────────

class TestSigmaEvaluator:
    def setup_method(self):
        self.ev = SigmaEvaluator()
        self.parser = SigmaParser()

    def _make_rule(self, detection, logsource=None, tags=None):
        return self.parser.parse_dict({
            "title": "Test",
            "id": "eval-test",
            "level": "high",
            "tags": tags or [],
            "logsource": logsource or {},
            "detection": detection,
        })

    # -- Field modifiers -------------------------------------------------------

    def test_contains_match(self):
        rule = self._make_rule({
            "selection": {"CommandLine|contains": "powershell"},
            "condition": "selection",
        })
        assert self.ev.match(rule, {"CommandLine": "C:\\powershell.exe -enc", "log_type": "process"})

    def test_contains_no_match(self):
        rule = self._make_rule({
            "selection": {"CommandLine|contains": "powershell"},
            "condition": "selection",
        })
        assert not self.ev.match(rule, {"CommandLine": "notepad.exe", "log_type": "process"})

    def test_contains_case_insensitive(self):
        rule = self._make_rule({
            "selection": {"CommandLine|contains": "POWERSHELL"},
            "condition": "selection",
        })
        assert self.ev.match(rule, {"CommandLine": "powershell.exe -enc", "log_type": "process"})

    def test_startswith(self):
        rule = self._make_rule({
            "selection": {"CommandLine|startswith": "C:\\Windows"},
            "condition": "selection",
        })
        assert self.ev.match(rule, {"CommandLine": "C:\\Windows\\System32\\cmd.exe", "log_type": "process"})
        assert not self.ev.match(rule, {"CommandLine": "D:\\tools\\cmd.exe", "log_type": "process"})

    def test_endswith(self):
        rule = self._make_rule({
            "selection": {"ProcessName|endswith": ".exe"},
            "condition": "selection",
        })
        assert self.ev.match(rule, {"ProcessName": "svchost.exe", "log_type": "process"})
        assert not self.ev.match(rule, {"ProcessName": "script.ps1", "log_type": "process"})

    def test_exact_match(self):
        rule = self._make_rule({
            "selection": {"status": "failure"},
            "condition": "selection",
        })
        assert self.ev.match(rule, {"status": "failure", "log_type": "auth"})
        assert not self.ev.match(rule, {"status": "success", "log_type": "auth"})

    def test_list_of_values_any_match(self):
        rule = self._make_rule({
            "selection": {"dst_port": [4444, 1337, 31337]},
            "condition": "selection",
        })
        assert self.ev.match(rule, {"dst_port": "4444", "log_type": "netflow"})
        assert not self.ev.match(rule, {"dst_port": "80", "log_type": "netflow"})

    def test_regex_modifier(self):
        rule = self._make_rule({
            "selection": {"src_ip|re": r"^10\.0\."},
            "condition": "selection",
        })
        assert self.ev.match(rule, {"src_ip": "10.0.1.5", "log_type": "auth"})
        assert not self.ev.match(rule, {"src_ip": "192.168.1.1", "log_type": "auth"})

    def test_missing_field_no_match(self):
        rule = self._make_rule({
            "selection": {"CommandLine|contains": "powershell"},
            "condition": "selection",
        })
        assert not self.ev.match(rule, {"ProcessName": "cmd.exe", "log_type": "process"})

    # -- Condition logic -------------------------------------------------------

    def test_selection_and_not_filter(self):
        rule = self._make_rule({
            "selection": {"CommandLine|contains": "powershell"},
            "filter": {"CommandLine|contains": "WindowsPowerShell\\v1.0"},
            "condition": "selection and not filter",
        })
        # Matches selection but NOT filter → alert
        assert self.ev.match(rule, {"CommandLine": "powershell -enc abc", "log_type": "process"})
        # Matches both → filtered out
        assert not self.ev.match(rule, {"CommandLine": "WindowsPowerShell\\v1.0\\powershell.exe", "log_type": "process"})

    def test_1_of_them(self):
        rule = self._make_rule({
            "sel_a": {"CommandLine|contains": "mimikatz"},
            "sel_b": {"CommandLine|contains": "sekurlsa"},
            "condition": "1 of them",
        })
        assert self.ev.match(rule, {"CommandLine": "mimikatz.exe", "log_type": "process"})
        assert self.ev.match(rule, {"CommandLine": "sekurlsa::logonpasswords", "log_type": "process"})
        assert not self.ev.match(rule, {"CommandLine": "notepad.exe", "log_type": "process"})

    def test_all_of_them(self):
        rule = self._make_rule({
            "sel_ps": {"CommandLine|contains": "powershell"},
            "sel_enc": {"CommandLine|contains": "-enc"},
            "condition": "all of them",
        })
        # Both present
        assert self.ev.match(rule, {"CommandLine": "powershell -enc abc", "log_type": "process"})
        # Only one
        assert not self.ev.match(rule, {"CommandLine": "powershell -help", "log_type": "process"})

    # -- Logsource filtering ---------------------------------------------------

    def test_logsource_process_matches_process_log(self):
        rule = self._make_rule(
            detection={"selection": {"CommandLine|contains": "cmd"}, "condition": "selection"},
            logsource={"category": "process_creation"},
        )
        assert self.ev.match(rule, {"CommandLine": "cmd.exe", "log_type": "process"})

    def test_logsource_process_does_not_match_auth_log(self):
        rule = self._make_rule(
            detection={"selection": {"CommandLine|contains": "cmd"}, "condition": "selection"},
            logsource={"category": "process_creation"},
        )
        # log_type is auth → logsource filter rejects
        assert not self.ev.match(rule, {"CommandLine": "cmd.exe", "log_type": "auth"})

    def test_logsource_auth_matches_auth_log(self):
        rule = self._make_rule(
            detection={"selection": {"status": "failure"}, "condition": "selection"},
            logsource={"category": "authentication"},
        )
        assert self.ev.match(rule, {"status": "failure", "log_type": "auth"})

    def test_empty_logsource_matches_all(self):
        rule = self._make_rule(
            detection={"selection": {"message|contains": "error"}, "condition": "selection"},
            logsource={},
        )
        assert self.ev.match(rule, {"message": "critical error occurred", "log_type": "syslog"})
        assert self.ev.match(rule, {"message": "critical error occurred", "log_type": "auth"})

    # -- Keyword blocks --------------------------------------------------------

    def test_keyword_list_search(self):
        rule = self._make_rule({
            "keywords": ["mimikatz", "sekurlsa", "wdigest"],
            "condition": "keywords",
        })
        assert self.ev.match(rule, {"message": "executing mimikatz.exe", "log_type": "syslog"})
        assert not self.ev.match(rule, {"message": "notepad opened", "log_type": "syslog"})

    # -- Dot notation ----------------------------------------------------------

    def test_dot_notation_field_access(self):
        rule = self._make_rule({
            "selection": {"process.name|contains": "cmd"},
            "condition": "selection",
        })
        assert self.ev.match(rule, {"process": {"name": "cmd.exe"}, "log_type": "process"})


# ── Engine integration tests ──────────────────────────────────────────────────

class TestSigmaRuleEngine:
    def setup_method(self):
        self.engine = SigmaRuleEngine(rules_path="/nonexistent")

    def test_load_rule_dict(self):
        self.engine.load_rule_dict({
            "title": "Test",
            "id": "eng-001",
            "level": "high",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|contains": "mimikatz"},
                "condition": "selection",
            },
        })
        assert self.engine.rule_count == 1

    def test_match_event_returns_matching_rules(self):
        self.engine.load_rule_dict({
            "title": "Mimikatz Detection",
            "id": "eng-002",
            "level": "critical",
            "tags": ["attack.t1003"],
            "logsource": {},
            "detection": {
                "selection": {"CommandLine|contains": "mimikatz"},
                "condition": "selection",
            },
        })
        matches = self.engine.match_event({"CommandLine": "mimikatz.exe", "log_type": "process"})
        assert len(matches) == 1
        assert matches[0].rule_id == "eng-002"

    def test_no_match_returns_empty(self):
        self.engine.load_rule_dict({
            "title": "Test",
            "id": "eng-003",
            "level": "low",
            "logsource": {},
            "detection": {
                "selection": {"CommandLine|contains": "mimikatz"},
                "condition": "selection",
            },
        })
        matches = self.engine.match_event({"CommandLine": "notepad.exe", "log_type": "process"})
        assert len(matches) == 0

    def test_multiple_rules_multiple_matches(self):
        for i, keyword in enumerate(["mimikatz", "sekurlsa"]):
            self.engine.load_rule_dict({
                "title": f"Rule {i}",
                "id": f"eng-multi-{i}",
                "level": "high",
                "logsource": {},
                "detection": {
                    "selection": {"CommandLine|contains": keyword},
                    "condition": "selection",
                },
            })
        # Event matching both
        matches = self.engine.match_event({"CommandLine": "mimikatz sekurlsa::logonpasswords", "log_type": "process"})
        assert len(matches) == 2

    def test_get_rule(self):
        self.engine.load_rule_dict({
            "title": "Get Test",
            "id": "eng-get",
            "level": "medium",
            "logsource": {},
            "detection": {"selection": {"foo": "bar"}, "condition": "selection"},
        })
        rule = self.engine.get_rule("eng-get")
        assert rule is not None
        assert rule.title == "Get Test"

    def test_get_nonexistent_rule_returns_none(self):
        assert self.engine.get_rule("nonexistent") is None

    def test_rule_error_does_not_crash_engine(self):
        """A bad rule should not cause match_event to crash."""
        self.engine.load_rule_dict({
            "title": "Good Rule",
            "id": "eng-good",
            "level": "high",
            "logsource": {},
            "detection": {"selection": {"cmd|contains": "x"}, "condition": "selection"},
        })
        # Manually insert a bad rule
        from app.engines.sigma_engine import SigmaRule, SigmaCondition
        bad_rule = SigmaRule(
            rule_id="eng-bad",
            title="Bad",
            description="",
            severity="high",
            mitre_technique=None,
            mitre_tactic=None,
            logsource={},
            detection={},
            condition=SigmaCondition(raw="selection", selections=["selection"], filters=[]),
            tags=[],
            raw={},
        )
        self.engine._rules["eng-bad"] = bad_rule
        # Should not raise
        matches = self.engine.match_event({"cmd": "x", "log_type": "process"})
        assert any(m.rule_id == "eng-good" for m in matches)

    def test_load_sigma_rule_files(self, tmp_path):
        """Integration: load actual YAML files from disk."""
        rule_file = tmp_path / "test_rule.yml"
        rule_file.write_text("""
title: Disk Load Test
id: disk-001
level: medium
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'notepad'
  condition: selection
""")
        engine = SigmaRuleEngine(rules_path=str(tmp_path))
        count = engine.load_rules()
        assert count == 1
        assert engine.rule_count == 1
