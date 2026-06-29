"""
EventNormalizer — extracted to its own module so it can be tested
without importing FastAPI, Prometheus, or any other heavy dependencies.
"""
from __future__ import annotations
import hashlib
from datetime import datetime, timezone
from typing import Any


class EventNormalizer:
    def normalize(self, raw: dict[str, Any], source_type: str) -> dict[str, Any]:
        normalizers = {
            "windows_event": self._normalize_windows,
            "syslog": self._normalize_syslog,
            "auditd": self._normalize_auditd,
            "netflow": self._normalize_netflow,
            "dns": self._normalize_dns,
            "auth": self._normalize_auth,
            "process": self._normalize_process,
            "generic": self._normalize_generic,
        }
        fn = normalizers.get(source_type, self._normalize_generic)
        normalized = fn(raw)
        normalized["event_id"] = self._generate_event_id(normalized)
        normalized["source_type"] = source_type
        normalized["ingested_at"] = datetime.now(timezone.utc).isoformat()
        normalized.setdefault("@timestamp", normalized["ingested_at"])
        normalized.setdefault("tags", [])
        return normalized

    def _generate_event_id(self, event: dict) -> str:
        content = f"{event.get('@timestamp','')}{event.get('asset_ip','')}{event.get('raw_log','')}"
        return hashlib.sha256(content.encode()).hexdigest()[:32]

    def _normalize_windows(self, raw: dict) -> dict:
        return {
            "@timestamp": raw.get("@timestamp") or raw.get("TimeCreated"),
            "asset_ip": raw.get("host", {}).get("ip", raw.get("asset_ip")),
            "asset_hostname": raw.get("host", {}).get("name", raw.get("computer_name")),
            "event_type": "windows_event",
            "event_code": raw.get("event", {}).get("code", raw.get("EventID")),
            "event_action": raw.get("event", {}).get("action"),
            "user": {
                "name": raw.get("user", {}).get("name", raw.get("SubjectUserName")),
                "domain": raw.get("user", {}).get("domain", raw.get("SubjectDomainName")),
                "privilege_level": "unknown",
            },
            "process": {
                "name": raw.get("process", {}).get("name"),
                "pid": raw.get("process", {}).get("pid"),
                "command_line": raw.get("process", {}).get("command_line"),
            },
            "raw_log": str(raw),
        }

    def _normalize_syslog(self, raw: dict) -> dict:
        return {
            "@timestamp": raw.get("timestamp"),
            "asset_ip": raw.get("host_ip", raw.get("source_ip")),
            "asset_hostname": raw.get("hostname"),
            "event_type": "syslog",
            "severity_label": raw.get("severity", "unknown"),
            "facility": raw.get("facility"),
            "message": raw.get("message", ""),
            "program": raw.get("program"),
            "raw_log": raw.get("message", str(raw)),
        }

    def _normalize_auditd(self, raw: dict) -> dict:
        return {
            "@timestamp": raw.get("@timestamp"),
            "asset_ip": raw.get("host", {}).get("ip"),
            "asset_hostname": raw.get("host", {}).get("name"),
            "event_type": "auditd",
            "audit_type": raw.get("auditd", {}).get("message_type"),
            "user": {"name": raw.get("user", {}).get("name"), "id": raw.get("user", {}).get("id")},
            "process": {
                "name": raw.get("process", {}).get("name"),
                "pid": raw.get("process", {}).get("pid"),
                "command_line": raw.get("process", {}).get("args"),
            },
            "file": {"path": raw.get("file", {}).get("path")},
            "raw_log": str(raw),
        }

    def _normalize_netflow(self, raw: dict) -> dict:
        return {
            "@timestamp": raw.get("@timestamp"),
            "asset_ip": raw.get("source", {}).get("ip", raw.get("src_ip")),
            "event_type": "netflow",
            "network": {
                "src_ip": raw.get("source", {}).get("ip", raw.get("src_ip")),
                "dst_ip": raw.get("destination", {}).get("ip", raw.get("dst_ip")),
                "src_port": raw.get("source", {}).get("port", raw.get("src_port")),
                "dst_port": raw.get("destination", {}).get("port", raw.get("dst_port")),
                "protocol": raw.get("network", {}).get("transport", raw.get("protocol")),
                "bytes_sent": raw.get("source", {}).get("bytes", 0),
                "bytes_received": raw.get("destination", {}).get("bytes", 0),
            },
            "raw_log": str(raw),
        }

    def _normalize_dns(self, raw: dict) -> dict:
        return {
            "@timestamp": raw.get("@timestamp"),
            "asset_ip": raw.get("source_ip", raw.get("client_ip")),
            "asset_hostname": raw.get("source_hostname"),
            "event_type": "dns",
            "dns": {
                "question_name": raw.get("query", raw.get("question", {}).get("name")),
                "question_type": raw.get("type", raw.get("question", {}).get("type")),
                "response_code": raw.get("rcode"),
                "answers": raw.get("answers", []),
                "resolved_ip": raw.get("resolved_ip"),
            },
            "raw_log": str(raw),
        }

    def _normalize_auth(self, raw: dict) -> dict:
        return {
            "@timestamp": raw.get("@timestamp") or raw.get("timestamp"),
            "asset_ip": raw.get("host_ip", raw.get("server_ip")),
            "asset_hostname": raw.get("hostname"),
            "event_type": "auth",
            "auth": {
                "outcome": raw.get("outcome", raw.get("result", "unknown")),
                "method": raw.get("method", raw.get("auth_type")),
                "source_ip": raw.get("source_ip", raw.get("client_ip")),
            },
            "user": {"name": raw.get("username", raw.get("user")), "domain": raw.get("domain")},
            "raw_log": str(raw),
        }

    def _normalize_process(self, raw: dict) -> dict:
        return {
            "@timestamp": raw.get("@timestamp") or raw.get("timestamp"),
            "asset_ip": raw.get("host_ip"),
            "asset_hostname": raw.get("hostname"),
            "event_type": "process",
            "process": {
                "pid": raw.get("pid"),
                "name": raw.get("process_name", raw.get("name")),
                "command_line": raw.get("command_line", raw.get("cmdline")),
                "parent_pid": raw.get("parent_pid", raw.get("ppid")),
                "hash_md5": raw.get("md5"),
                "hash_sha256": raw.get("sha256"),
                "path": raw.get("path", raw.get("executable")),
            },
            "user": {"name": raw.get("user", raw.get("username"))},
            "action": raw.get("action", "created"),
            "raw_log": str(raw),
        }

    def _normalize_generic(self, raw: dict) -> dict:
        return {
            "@timestamp": raw.get("@timestamp") or raw.get("timestamp"),
            "asset_ip": raw.get("host_ip", raw.get("source_ip", raw.get("ip"))),
            "asset_hostname": raw.get("hostname"),
            "event_type": "generic",
            "message": raw.get("message", str(raw)),
            "raw_log": str(raw),
        }
