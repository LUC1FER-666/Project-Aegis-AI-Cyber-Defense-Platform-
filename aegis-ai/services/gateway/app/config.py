"""Gateway-specific configuration."""
from functools import lru_cache

import sys
import os
sys.path.insert(0, "/shared/python")

from aegis_common.config import BaseServiceSettings


class GatewaySettings(BaseServiceSettings):
    service_name: str = "gateway"
    service_port: int = 8000

    # Internal service URLs (used for proxying/health checks)
    asset_discovery_url: str = "http://asset-discovery:8001"
    telemetry_url: str = "http://telemetry-collector:8002"
    threat_intel_url: str = "http://threat-intel:8003"
    detection_engine_url: str = "http://detection-engine:8004"
    agent_orchestrator_url: str = "http://agent-orchestrator:8005"
    knowledge_graph_url: str = "http://knowledge-graph:8006"
    investigation_url: str = "http://investigation:8007"
    response_engine_url: str = "http://response-engine:8008"
    approval_workflow_url: str = "http://approval-workflow:8009"

    # Rate limiting (requests per minute per user)
    rate_limit_per_minute: int = 300
    rate_limit_burst: int = 50

    # Initial admin account (created on first startup)
    initial_admin_email: str = "admin@aegis.local"
    initial_admin_password: str = "AegisAdmin@2024!"  # Must change on first login


@lru_cache
def get_settings() -> GatewaySettings:
    return GatewaySettings()
