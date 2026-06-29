"""Asset Discovery Service configuration."""
from functools import lru_cache
from pydantic import Field
import sys
sys.path.insert(0, "/shared/python")
from aegis_common.config import BaseServiceSettings


class AssetDiscoverySettings(BaseServiceSettings):
    service_name: str = "asset-discovery"
    service_port: int = 8001

    # Scanning configuration
    scan_timeout: int = 300          # Max seconds for a single scan job
    max_concurrent_scans: int = 3    # Don't hammer the network
    default_scan_ports: str = "22,80,443,3389,8080,8443,3306,5432,6379,27017"
    ping_timeout: int = 2            # Seconds for ICMP ping

    # Network ranges to NEVER scan (safety guardrail)
    excluded_ranges: str = "169.254.0.0/16,224.0.0.0/4"

    # Auto-discovery schedule (cron expression)
    auto_scan_enabled: bool = False   # Off by default — operator must enable
    auto_scan_cron: str = "0 2 * * *" # 2 AM daily if enabled

    # Gateway URL for internal service auth validation
    gateway_url: str = "http://gateway:8000"


@lru_cache
def get_settings() -> AssetDiscoverySettings:
    return AssetDiscoverySettings()
