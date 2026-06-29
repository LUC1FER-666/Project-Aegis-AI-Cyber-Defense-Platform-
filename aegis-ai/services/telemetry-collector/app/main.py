"""
Aegis AI — Telemetry Collector Service
Accepts logs from agents, syslog forwarders, and cloud sources.
Normalizes them into a common schema and indexes to Elasticsearch.
Also publishes to Kafka for real-time detection.
"""
from __future__ import annotations

import hashlib
import uuid
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator

import sys
sys.path.insert(0, "/shared/python")
from aegis_common.logging import configure_logging, get_logger
from aegis_common.models import HealthResponse

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Normalizer — converts any log format into the common Aegis event schema
# ---------------------------------------------------------------------------

class EventNormalizer:
    """
    Converts raw log payloads into the normalised Aegis event format.
    Each source type has its own normalisation path.

    The normalized schema maps to the Elasticsearch index aegis-events-*.
    """

    def normalize(self, raw: dict[str, Any], source_type: str) -> dict[str, Any]:
        """
        Dispatch to the correct normalizer based on source_type.
        Returns a normalized event dict ready for Elasticsearch.
        """
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

        # Enrich with common fields
        normalized["event_id"] = self._generate_event_id(normalized)
        normalized["source_type"] = source_type
        normalized["ingested_at"] = datetime.now(timezone.utc).isoformat()
        normalized.setdefault("@timestamp", normalized["ingested_at"])
        normalized.setdefault("tags", [])

        return normalized

    def _generate_event_id(self, event: dict) -> str:
        """Deterministic ID based on content — prevents duplicate indexing."""
        content = f"{event.get('@timestamp','')}{event.get('asset_ip','')}{event.get('raw_log','')}"
        return hashlib.sha256(content.encode()).hexdigest()[:32]

    def _normalize_windows(self, raw: dict) -> dict:
        """Windows Event Log format (via Winlogbeat or agent)."""
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
        """RFC 5424 syslog format."""
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
        """Linux auditd format."""
        return {
            "@timestamp": raw.get("@timestamp"),
            "asset_ip": raw.get("host", {}).get("ip"),
            "asset_hostname": raw.get("host", {}).get("name"),
            "event_type": "auditd",
            "audit_type": raw.get("auditd", {}).get("message_type"),
            "user": {
                "name": raw.get("user", {}).get("name"),
                "id": raw.get("user", {}).get("id"),
            },
            "process": {
                "name": raw.get("process", {}).get("name"),
                "pid": raw.get("process", {}).get("pid"),
                "command_line": raw.get("process", {}).get("args"),
            },
            "file": {
                "path": raw.get("file", {}).get("path"),
            },
            "raw_log": str(raw),
        }

    def _normalize_netflow(self, raw: dict) -> dict:
        """NetFlow v9 / IPFIX format."""
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
        """DNS query/response logs."""
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
        """Authentication events (SSH, LDAP, Kerberos, local)."""
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
            "user": {
                "name": raw.get("username", raw.get("user")),
                "domain": raw.get("domain"),
            },
            "raw_log": str(raw),
        }

    def _normalize_process(self, raw: dict) -> dict:
        """Process creation/termination events."""
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
        """Catch-all for unknown log formats."""
        return {
            "@timestamp": raw.get("@timestamp") or raw.get("timestamp"),
            "asset_ip": raw.get("host_ip", raw.get("source_ip", raw.get("ip"))),
            "asset_hostname": raw.get("hostname"),
            "event_type": "generic",
            "message": raw.get("message", str(raw)),
            "raw_log": str(raw),
        }


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

normalizer = EventNormalizer()


def create_app() -> FastAPI:
    from app.config import get_settings
    settings = get_settings()
    configure_logging(settings.service_name, settings.log_level, settings.environment)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        logger.info("telemetry_collector_starting")
        # Initialize Elasticsearch index templates on startup
        await _setup_elasticsearch(settings)
        yield
        logger.info("telemetry_collector_stopped")

    app = FastAPI(
        title="Aegis AI — Telemetry Collector",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    Instrumentator().instrument(app).expose(app, endpoint="/metrics")

    from app.routers.telemetry import router as telemetry_router
    app.include_router(telemetry_router, prefix="/api/v1")

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(
            status="healthy",
            service=settings.service_name,
            version="0.1.0",
            environment=settings.environment,
        )

    return app


async def _setup_elasticsearch(settings) -> None:
    """Create Elasticsearch index template for aegis-events-* on startup."""
    try:
        import httpx
        template = {
            "index_patterns": ["aegis-events-*"],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "index.lifecycle.name": "aegis-events-policy",
                },
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "event_id": {"type": "keyword"},
                        "asset_id": {"type": "keyword"},
                        "asset_ip": {"type": "ip"},
                        "asset_hostname": {"type": "keyword"},
                        "event_type": {"type": "keyword"},
                        "source_type": {"type": "keyword"},
                        "tags": {"type": "keyword"},
                        "raw_log": {"type": "text"},
                        "network": {
                            "properties": {
                                "src_ip": {"type": "ip"},
                                "dst_ip": {"type": "ip"},
                                "src_port": {"type": "integer"},
                                "dst_port": {"type": "integer"},
                                "protocol": {"type": "keyword"},
                            }
                        },
                        "process": {
                            "properties": {
                                "pid": {"type": "integer"},
                                "name": {"type": "keyword"},
                                "command_line": {"type": "text"},
                                "hash_sha256": {"type": "keyword"},
                            }
                        },
                        "user": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "domain": {"type": "keyword"},
                            }
                        },
                    }
                },
            },
        }
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{settings.elasticsearch_url}/_index_template/aegis-events",
                json=template,
                timeout=10,
            )
            if resp.status_code in (200, 201):
                logger.info("elasticsearch_template_created")
            else:
                logger.warning("elasticsearch_template_warning", status=resp.status_code)
    except Exception as e:
        logger.warning("elasticsearch_setup_skipped", error=str(e))


app = create_app()
