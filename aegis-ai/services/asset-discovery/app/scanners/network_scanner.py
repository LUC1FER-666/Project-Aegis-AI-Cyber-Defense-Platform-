"""
Network scanner using python-nmap.
Wraps nmap in async-friendly way using asyncio.to_thread (nmap is synchronous).

Security note: This scanner is designed to only scan networks you own or
have explicit permission to scan. The ScanRequest validator and the
excluded_ranges config provide guardrails, but the operator is responsible
for ensuring scans are authorised.
"""
from __future__ import annotations

import asyncio
import ipaddress
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import sys
sys.path.insert(0, "/shared/python")
from aegis_common.logging import get_logger

logger = get_logger(__name__)


@dataclass
class DiscoveredPort:
    port_number: int
    protocol: str
    state: str
    service_name: str | None = None
    service_version: str | None = None
    service_product: str | None = None
    banner: str | None = None


@dataclass
class DiscoveredHost:
    """Normalised result of scanning a single host."""
    ip_address: str
    hostname: str | None = None
    mac_address: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    os_family: str | None = None
    asset_type: str = "unknown"
    ports: list[DiscoveredPort] = field(default_factory=list)
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scanned_at: datetime = field(default_factory=datetime.utcnow)
    raw_data: dict[str, Any] = field(default_factory=dict)


class NetworkScanner:
    """
    Async wrapper around python-nmap.
    All nmap calls run in a thread pool to avoid blocking the event loop.
    """

    def __init__(
        self,
        default_ports: str = "22,80,443,3389,8080,8443,3306,5432,6379,27017",
        excluded_ranges: list[str] | None = None,
        timeout: int = 300,
    ) -> None:
        self.default_ports = default_ports
        self.excluded_ranges = excluded_ranges or ["169.254.0.0/16", "224.0.0.0/4"]
        self.timeout = timeout

    def _is_excluded(self, target: str) -> bool:
        """Check if a target falls within an excluded range."""
        try:
            target_net = ipaddress.ip_network(target, strict=False)
            for excluded in self.excluded_ranges:
                excl_net = ipaddress.ip_network(excluded, strict=False)
                if target_net.overlaps(excl_net):
                    return True
        except ValueError:
            pass  # Not a network — could be a hostname, let nmap handle it
        return False

    async def scan_network(
        self,
        target: str,
        ports: str | None = None,
        aggressive: bool = False,
    ) -> list[DiscoveredHost]:
        """
        Scan a network range and return discovered hosts.
        Runs nmap in a thread to avoid blocking the event loop.
        """
        if self._is_excluded(target):
            logger.warning("scan_target_excluded", target=target)
            return []

        ports_arg = ports or self.default_ports
        logger.info("scan_starting", target=target, ports=ports_arg, aggressive=aggressive)

        try:
            hosts = await asyncio.wait_for(
                asyncio.to_thread(self._run_nmap, target, ports_arg, aggressive),
                timeout=self.timeout,
            )
            logger.info("scan_completed", target=target, hosts_found=len(hosts))
            return hosts
        except asyncio.TimeoutError:
            logger.error("scan_timeout", target=target, timeout=self.timeout)
            return []
        except Exception as e:
            logger.error("scan_failed", target=target, error=str(e))
            return []

    def _run_nmap(
        self, target: str, ports: str, aggressive: bool
    ) -> list[DiscoveredHost]:
        """
        Synchronous nmap execution — runs in thread pool.
        Falls back to a ping sweep if nmap is not installed.
        """
        try:
            import nmap  # type: ignore
            return self._nmap_scan(target, ports, aggressive)
        except ImportError:
            logger.warning("nmap_not_installed_using_fallback")
            return self._ping_sweep_fallback(target)

    def _nmap_scan(
        self, target: str, ports: str, aggressive: bool
    ) -> list[DiscoveredHost]:
        """Full nmap scan with service and OS detection."""
        import nmap  # type: ignore

        nm = nmap.PortScanner()

        # Build nmap arguments
        args = f"-p {ports} --open -T4"
        if aggressive:
            args += " -A"      # OS detection, version detection, script scanning
        else:
            args += " -sV"     # Service version detection only

        nm.scan(hosts=target, arguments=args)

        discovered: list[DiscoveredHost] = []

        for host_ip in nm.all_hosts():
            host_data = nm[host_ip]

            if host_data.state() != "up":
                continue

            # Hostname
            hostnames = host_data.hostnames()
            hostname = hostnames[0]["name"] if hostnames else None
            if hostname == host_ip:
                hostname = None

            # OS detection
            os_name = os_version = os_family = None
            if "osmatch" in host_data and host_data["osmatch"]:
                best_match = host_data["osmatch"][0]
                os_name = best_match.get("name")
                if host_data.get("osclass"):
                    osclass = host_data["osclass"][0]
                    os_family = osclass.get("osfamily")
                    os_version = osclass.get("osgen")

            # Asset type inference from OS
            asset_type = self._infer_asset_type(os_name, os_family)

            # Ports
            ports_list: list[DiscoveredPort] = []
            for proto in host_data.all_protocols():
                for port_num in host_data[proto].keys():
                    port_data = host_data[proto][port_num]
                    if port_data["state"] == "open":
                        ports_list.append(DiscoveredPort(
                            port_number=port_num,
                            protocol=proto,
                            state=port_data["state"],
                            service_name=port_data.get("name"),
                            service_version=port_data.get("version"),
                            service_product=port_data.get("product"),
                        ))

            discovered.append(DiscoveredHost(
                ip_address=host_ip,
                hostname=hostname,
                mac_address=host_data.get("addresses", {}).get("mac"),
                os_name=os_name,
                os_version=os_version,
                os_family=os_family,
                asset_type=asset_type,
                ports=ports_list,
                raw_data=dict(host_data),
            ))

        return discovered

    def _ping_sweep_fallback(self, target: str) -> list[DiscoveredHost]:
        """
        Fallback when nmap isn't installed.
        Uses Python's socket to check if hosts respond — much less info.
        """
        import socket

        discovered: list[DiscoveredHost] = []

        try:
            network = ipaddress.ip_network(target, strict=False)
            hosts_to_check = list(network.hosts())[:254]  # Cap at /24 equivalent
        except ValueError:
            # Single host
            hosts_to_check = [ipaddress.ip_address(target)]

        for host_ip in hosts_to_check:
            ip_str = str(host_ip)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip_str, 80))
            sock.close()

            if result == 0:
                try:
                    hostname = socket.gethostbyaddr(ip_str)[0]
                except socket.herror:
                    hostname = None

                discovered.append(DiscoveredHost(
                    ip_address=ip_str,
                    hostname=hostname,
                    ports=[DiscoveredPort(port_number=80, protocol="tcp", state="open")],
                ))

        return discovered

    def _infer_asset_type(
        self, os_name: str | None, os_family: str | None
    ) -> str:
        """
        Best-effort asset type inference from OS information.
        This is refined later by the AI asset classifier in Milestone 6.
        """
        if not os_name and not os_family:
            return "unknown"

        combined = f"{os_name or ''} {os_family or ''}".lower()

        if any(k in combined for k in ["windows server", "ubuntu server", "centos", "rhel", "debian"]):
            return "server"
        if any(k in combined for k in ["windows 10", "windows 11", "macos", "mac os x"]):
            return "endpoint"
        if any(k in combined for k in ["cisco", "juniper", "router", "switch", "firewall"]):
            return "network_device"
        if any(k in combined for k in ["android"]) or ("ios" in combined and "cisco" not in combined):
            return "mobile"
        if "linux" in combined:
            return "server"
        if "windows" in combined:
            return "endpoint"

        return "unknown"
