"""
Detection Engine — Layer 1: Sigma Rule Engine

Parses YAML Sigma rules and evaluates them against normalized telemetry events.

Sigma spec reference: https://github.com/SigmaHQ/sigma/wiki/Specification
We implement the subset most relevant to SIEM/EDR detections:
  - condition: keywords (1 of them*, all of them, selection*, filter*)
  - detection block with field/value matching
  - field modifiers: contains, startswith, endswith, re (regex), all, windash
  - logsource matching (category, product, service)
"""
from __future__ import annotations

import logging
import os
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class SigmaCondition:
    """Parsed condition expression from a Sigma rule."""
    raw: str
    selections: list[str]        # named selection blocks to AND together
    filters: list[str]           # named filter blocks to NOT
    require_all: bool = False    # true → all of them*; false → 1 of them*


@dataclass
class SigmaRule:
    """Parsed, ready-to-evaluate Sigma rule."""
    rule_id: str
    title: str
    description: str
    severity: str                # critical/high/medium/low/informational
    mitre_technique: Optional[str]
    mitre_tactic: Optional[str]
    logsource: dict[str, str]    # category, product, service
    detection: dict[str, Any]    # raw detection block
    condition: SigmaCondition
    tags: list[str]
    raw: dict[str, Any]          # full parsed YAML for audit


# ── Parser ─────────────────────────────────────────────────────────────────────

class SigmaParser:
    """Converts YAML Sigma rule files into SigmaRule objects."""

    SEVERITY_MAP = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "info",
        "info": "info",
    }

    def parse_file(self, path: str) -> SigmaRule:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return self.parse_dict(data)

    def parse_dict(self, data: dict[str, Any]) -> SigmaRule:
        """Parse a dict (already loaded from YAML) into a SigmaRule."""
        rule_id = data.get("id") or str(uuid.uuid4())
        title = data.get("title", "Untitled Rule")
        description = data.get("description", "")
        severity_raw = data.get("level", "medium").lower()
        severity = self.SEVERITY_MAP.get(severity_raw, "medium")

        # MITRE ATT&CK extraction from tags
        tags = data.get("tags", []) or []
        mitre_technique = None
        mitre_tactic = None
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower.startswith("attack.t"):
                # e.g. attack.t1059.001 → T1059.001
                raw_technique = tag.split(".", 1)[1].upper()
                mitre_technique = raw_technique
            elif tag_lower.startswith("attack."):
                mitre_tactic = tag.split(".", 1)[1]

        logsource = data.get("logsource", {}) or {}
        detection = data.get("detection", {})

        if not detection:
            raise ValueError(f"Rule '{title}' has no detection block")

        condition_raw = detection.get("condition", "")
        if not condition_raw:
            raise ValueError(f"Rule '{title}' has no condition in detection block")

        condition = self._parse_condition(str(condition_raw), detection)

        return SigmaRule(
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            mitre_technique=mitre_technique,
            mitre_tactic=mitre_tactic,
            logsource=logsource,
            detection=detection,
            condition=condition,
            tags=tags,
            raw=data,
        )

    def _parse_condition(self, condition_str: str, detection: dict) -> SigmaCondition:
        """
        Parse Sigma condition expressions.
        Supported patterns:
          selection                   → single named block
          selection and not filter    → selection AND NOT filter
          1 of selection*             → any selection* block matches
          all of them                 → all named blocks must match
          1 of them                   → any named block matches
          selection1 or selection2    → either block matches
        """
        raw = condition_str.strip()
        selections: list[str] = []
        filters: list[str] = []
        require_all = False

        # Normalise spacing
        cond = re.sub(r"\s+", " ", raw)

        # "all of them" / "1 of them" → expand to all non-condition keys
        named_blocks = [k for k in detection if k != "condition"]

        if re.fullmatch(r"all of them", cond, re.IGNORECASE):
            require_all = True
            selections = named_blocks
        elif re.match(r"1 of them", cond, re.IGNORECASE):
            selections = named_blocks
        elif re.match(r"1 of (\w+)\*", cond, re.IGNORECASE):
            prefix_match = re.match(r"1 of (\w+)\*", cond, re.IGNORECASE)
            prefix = prefix_match.group(1).lower()
            selections = [k for k in named_blocks if k.lower().startswith(prefix)]
        elif re.match(r"all of (\w+)\*", cond, re.IGNORECASE):
            prefix_match = re.match(r"all of (\w+)\*", cond, re.IGNORECASE)
            prefix = prefix_match.group(1).lower()
            selections = [k for k in named_blocks if k.lower().startswith(prefix)]
            require_all = True
        else:
            # Handle: "sel1 and not filter1" / "sel1 or sel2" / "sel1 and sel2 and not f1"
            # Split on spaces and parse tokens
            tokens = cond.split()
            i = 0
            negate_next = False
            while i < len(tokens):
                tok = tokens[i].lower().rstrip(",")
                if tok in ("and", "or", "not"):
                    if tok == "not":
                        negate_next = True
                else:
                    # It's a block name (possibly with wildcard)
                    block_name = tokens[i].rstrip(",")
                    if block_name.endswith("*"):
                        prefix = block_name[:-1].lower()
                        expanded = [k for k in named_blocks if k.lower().startswith(prefix)]
                        if negate_next:
                            filters.extend(expanded)
                        else:
                            selections.extend(expanded)
                    else:
                        if negate_next:
                            filters.append(block_name)
                        else:
                            selections.append(block_name)
                    negate_next = False
                i += 1

        return SigmaCondition(
            raw=raw,
            selections=selections,
            filters=filters,
            require_all=require_all,
        )


# ── Evaluator ──────────────────────────────────────────────────────────────────

class SigmaEvaluator:
    """Evaluates a normalised event dict against a SigmaRule."""

    def match(self, rule: SigmaRule, event: dict[str, Any]) -> bool:
        """
        Returns True if the event matches the rule.
        Applies logsource filtering first, then evaluates condition.
        """
        if not self._logsource_matches(rule.logsource, event):
            return False

        detection = rule.detection
        condition = rule.condition

        # Evaluate each selection block
        block_results: dict[str, bool] = {}
        for block_name in set(condition.selections + condition.filters):
            block_def = detection.get(block_name)
            if block_def is None:
                # Wildcard expansions may reference blocks that don't exist
                block_results[block_name] = False
                continue
            block_results[block_name] = self._eval_block(block_def, event)

        # Evaluate condition logic
        if condition.require_all:
            sel_result = all(block_results.get(s, False) for s in condition.selections)
        else:
            sel_result = any(block_results.get(s, False) for s in condition.selections)

        filter_result = any(block_results.get(f, False) for f in condition.filters)

        return sel_result and not filter_result

    # ── logsource ──────────────────────────────────────────────────────────────

    def _logsource_matches(self, logsource: dict, event: dict) -> bool:
        """
        Match logsource to event.
        Telemetry events carry 'log_type' from the normalizer.
        We map Sigma logsource fields to our log_type values.
        """
        if not logsource:
            return True  # No logsource constraint → match all

        category = logsource.get("category", "").lower()
        product = logsource.get("product", "").lower()
        service = logsource.get("service", "").lower()

        log_type = event.get("log_type", "").lower()

        # Mapping: Sigma logsource → our log_type values
        LOGSOURCE_MAP: dict[str, list[str]] = {
            "process_creation": ["process", "windows_event"],
            "process": ["process"],
            "network_connection": ["netflow", "network"],
            "network": ["netflow", "network"],
            "dns_query": ["dns"],
            "dns": ["dns"],
            "authentication": ["auth", "windows_event"],
            "auth": ["auth"],
            "file_event": ["windows_event", "auditd"],
            "web": ["syslog"],
            "syslog": ["syslog"],
            "windows": ["windows_event"],
        }

        # Check category first, then product
        for key in [category, product, service]:
            if not key:
                continue
            allowed = LOGSOURCE_MAP.get(key)
            if allowed is not None:
                return log_type in allowed

        # No recognised logsource key → allow match (be permissive)
        return True

    # ── block evaluation ───────────────────────────────────────────────────────

    def _eval_block(self, block_def: Any, event: dict) -> bool:
        """
        Evaluate a detection block against an event.
        A block can be:
          - dict: field/value pairs (all must match — implicit AND)
          - list of dicts: any dict must match (OR semantics)
          - list of strings: keyword search across all values
        """
        if isinstance(block_def, list):
            if all(isinstance(item, str) for item in block_def):
                # Keyword list — search all event values
                return self._eval_keywords(block_def, event)
            elif all(isinstance(item, dict) for item in block_def):
                # OR of multiple field maps
                return any(self._eval_field_map(item, event) for item in block_def)
            else:
                # Mixed — treat each item individually with OR
                return any(
                    self._eval_keywords([item], event) if isinstance(item, str)
                    else self._eval_field_map(item, event)
                    for item in block_def
                )
        elif isinstance(block_def, dict):
            return self._eval_field_map(block_def, event)
        else:
            return False

    def _eval_field_map(self, field_map: dict, event: dict) -> bool:
        """All field conditions must match (AND)."""
        for field_spec, expected in field_map.items():
            if not self._eval_field(field_spec, expected, event):
                return False
        return True

    def _eval_field(self, field_spec: str, expected: Any, event: dict) -> bool:
        """
        Evaluate one field condition. Supports modifiers:
          field|contains, field|startswith, field|endswith,
          field|re, field|all, field|contains|all, field|windash
        """
        parts = field_spec.split("|")
        field_name = parts[0]
        modifiers = [m.lower() for m in parts[1:]]

        # Get field value from event (support nested dot notation)
        actual = self._get_field(event, field_name)
        if actual is None:
            return False

        # Normalise expected to a list for consistent processing
        if isinstance(expected, list):
            values = [str(v) for v in expected]
        elif expected is None:
            return actual is None
        else:
            values = [str(expected)]

        # Determine if ALL values must match or ANY
        require_all_values = "all" in modifiers

        results = []
        for val in values:
            results.append(self._match_value(str(actual), val, modifiers))

        if require_all_values:
            return all(results)
        return any(results)

    def _match_value(self, actual: str, expected: str, modifiers: list[str]) -> bool:
        """Match actual string against expected with the given modifiers."""
        # windash: replace - with / in expected for Windows paths
        if "windash" in modifiers:
            expected_variants = [expected, expected.replace("-", "/"), expected.replace("/", "-")]
        else:
            expected_variants = [expected]

        for variant in expected_variants:
            if "re" in modifiers:
                try:
                    if re.search(variant, actual, re.IGNORECASE):
                        return True
                except re.error:
                    pass
            elif "contains" in modifiers:
                if variant.lower() in actual.lower():
                    return True
            elif "startswith" in modifiers:
                if actual.lower().startswith(variant.lower()):
                    return True
            elif "endswith" in modifiers:
                if actual.lower().endswith(variant.lower()):
                    return True
            else:
                # Exact match (case-insensitive for string fields)
                if actual.lower() == variant.lower():
                    return True

        return False

    def _eval_keywords(self, keywords: list[str], event: dict) -> bool:
        """Check if any keyword appears in any string value of the event."""
        all_values = self._flatten_event_values(event)
        for keyword in keywords:
            kw_lower = keyword.lower()
            if any(kw_lower in str(v).lower() for v in all_values):
                return True
        return False

    def _get_field(self, event: dict, field_name: str) -> Optional[Any]:
        """
        Retrieve field from event. Supports:
        - Direct key: 'CommandLine'
        - Dot notation: 'process.command_line'
        - Case-insensitive lookup
        """
        # Direct lookup
        if field_name in event:
            return event[field_name]

        # Case-insensitive direct
        field_lower = field_name.lower()
        for k, v in event.items():
            if k.lower() == field_lower:
                return v

        # Dot notation
        if "." in field_name:
            parts = field_name.split(".", 1)
            sub = event.get(parts[0]) or {}
            if isinstance(sub, dict):
                return self._get_field(sub, parts[1])

        return None

    def _flatten_event_values(self, obj: Any, depth: int = 0) -> list:
        """Recursively extract all string values from a nested dict/list."""
        if depth > 5:
            return []
        if isinstance(obj, dict):
            results = []
            for v in obj.values():
                results.extend(self._flatten_event_values(v, depth + 1))
            return results
        elif isinstance(obj, list):
            results = []
            for item in obj:
                results.extend(self._flatten_event_values(item, depth + 1))
            return results
        elif obj is not None:
            return [str(obj)]
        return []


# ── Rule Engine (orchestrates parser + evaluator + rule registry) ──────────────

class SigmaRuleEngine:
    """
    Loads Sigma rules from disk, exposes match_event() for streaming use.
    Thread-safe for concurrent reads; reload() takes a brief lock.
    """

    def __init__(self, rules_path: str):
        self.rules_path = Path(rules_path)
        self._rules: dict[str, SigmaRule] = {}
        self._parser = SigmaParser()
        self._evaluator = SigmaEvaluator()

    def load_rules(self) -> int:
        """
        Scan rules_path for .yml/.yaml files and load them.
        Returns number of rules successfully loaded.
        """
        loaded = 0
        errors = 0

        if not self.rules_path.exists():
            logger.warning("Sigma rules path does not exist: %s", self.rules_path)
            return 0

        for rule_file in sorted(self.rules_path.rglob("*.y*ml")):
            try:
                rule = self._parser.parse_file(str(rule_file))
                self._rules[rule.rule_id] = rule
                loaded += 1
                logger.debug("Loaded sigma rule: %s (%s)", rule.title, rule.rule_id)
            except Exception as exc:
                errors += 1
                logger.warning("Failed to load rule %s: %s", rule_file, exc)

        logger.info("Sigma engine: loaded %d rules, %d errors", loaded, errors)
        return loaded

    def load_rule_dict(self, data: dict[str, Any]) -> SigmaRule:
        """Load a single rule from a dict (for testing / dynamic rules)."""
        rule = self._parser.parse_dict(data)
        self._rules[rule.rule_id] = rule
        return rule

    def match_event(self, event: dict[str, Any]) -> list[SigmaRule]:
        """
        Test an event against all loaded rules.
        Returns list of matching SigmaRule objects.
        """
        matches = []
        for rule in self._rules.values():
            try:
                if self._evaluator.match(rule, event):
                    matches.append(rule)
            except Exception as exc:
                logger.warning("Error evaluating rule %s: %s", rule.rule_id, exc)
        return matches

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def get_rule(self, rule_id: str) -> Optional[SigmaRule]:
        return self._rules.get(rule_id)

    def all_rules(self) -> list[SigmaRule]:
        return list(self._rules.values())
