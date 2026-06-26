from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from orbit.models import Evidence, Finding, ScanOptions, Severity, Target


COMMON_PORTS: dict[int, tuple[str, Severity, str]] = {
    21: ("FTP", Severity.MEDIUM, "Prefer SFTP or another encrypted transfer path."),
    22: ("SSH", Severity.INFO, "Restrict administration to trusted networks and enforce key-based access."),
    23: ("Telnet", Severity.HIGH, "Disable Telnet and replace it with SSH."),
    25: ("SMTP", Severity.INFO, "Confirm mail relay controls and anti-abuse configuration."),
    80: ("HTTP", Severity.INFO, "Redirect HTTP traffic to HTTPS where possible."),
    110: ("POP3", Severity.MEDIUM, "Prefer encrypted mail retrieval protocols."),
    143: ("IMAP", Severity.MEDIUM, "Prefer encrypted mail retrieval protocols."),
    389: ("LDAP", Severity.MEDIUM, "Require LDAPS or StartTLS and restrict access."),
    445: ("SMB", Severity.HIGH, "Do not expose SMB to the public internet."),
    1433: ("MSSQL", Severity.HIGH, "Restrict database services to private networks."),
    1521: ("Oracle DB", Severity.HIGH, "Restrict database services to private networks."),
    2049: ("NFS", Severity.HIGH, "Do not expose NFS to untrusted networks."),
    3306: ("MySQL", Severity.HIGH, "Restrict database services to private networks."),
    3389: ("RDP", Severity.HIGH, "Place RDP behind VPN/ZTNA and enforce MFA."),
    5432: ("PostgreSQL", Severity.HIGH, "Restrict database services to private networks."),
    5900: ("VNC", Severity.HIGH, "Disable public VNC or protect it with VPN/ZTNA."),
    6379: ("Redis", Severity.HIGH, "Do not expose Redis directly to the internet."),
    8080: ("Alternate HTTP", Severity.LOW, "Confirm the service is intended to be public."),
    8443: ("Alternate HTTPS", Severity.LOW, "Confirm the service is intended to be public."),
    9200: ("Elasticsearch", Severity.HIGH, "Do not expose Elasticsearch directly to the internet."),
    11211: ("Memcached", Severity.HIGH, "Do not expose Memcached directly to the internet."),
    27017: ("MongoDB", Severity.HIGH, "Restrict database services to private networks."),
}

AGGRESSIVE_EXTRA_PORTS = {
    53: ("DNS", Severity.INFO, "Confirm recursion is disabled for untrusted clients."),
    587: ("SMTP submission", Severity.INFO, "Confirm authentication and anti-abuse controls."),
    993: ("IMAPS", Severity.INFO, "Confirm service ownership and hardening."),
    995: ("POP3S", Severity.INFO, "Confirm service ownership and hardening."),
    9300: ("Elasticsearch transport", Severity.HIGH, "Do not expose cluster transport ports publicly."),
}


def run(target: Target, options: ScanOptions) -> tuple[dict[str, Any], list[Finding]]:
    port_map = dict(COMMON_PORTS)
    if options.depth == "aggressive":
        port_map.update(AGGRESSIVE_EXTRA_PORTS)

    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=min(options.max_workers, len(port_map))) as pool:
        futures = {
            pool.submit(_is_open, target.host, port, options.timeout): port
            for port in port_map
        }
        for future in as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except OSError:
                continue

    open_ports.sort()
    findings: list[Finding] = []
    for port in open_ports:
        service, severity, recommendation = port_map[port]
        if port in {80, 443}:
            continue
        context = _reachability_context(target)
        findings.append(
            Finding(
                id=f"ORBIT-PORT-{port}",
                title=f"{context['title_prefix']} {service} service accepted a connection",
                severity=severity,
                category="network",
                description=f"TCP port {port} accepted a connection from ORBIT's scan vantage point.",
                impact=context["impact"],
                recommendation=recommendation,
                evidence=[Evidence("port", str(port)), Evidence("service", service), Evidence("reachability", context["evidence"])],
                confidence="medium",
            )
        )

    return {"open_tcp_ports": open_ports, "checked_ports": sorted(port_map)}, findings


def _is_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=min(timeout, 2.5)):
            return True
    except OSError:
        return False


def _reachability_context(target: Target) -> dict[str, str]:
    try:
        address = ipaddress.ip_address(target.host)
    except ValueError:
        return {
            "title_prefix": "Reachable",
            "impact": "The service is reachable from the scanner. If this scan ran from an external network, the service may increase attack surface; if it ran from inside a trusted network, validate that the exposure is intentional.",
            "evidence": "scanner vantage point",
        }

    if address.is_loopback:
        return {
            "title_prefix": "Local",
            "impact": "The service is reachable on loopback from this machine. This does not prove public exposure, but local services should still be intentional, patched, and bound only where needed.",
            "evidence": "loopback target",
        }
    if address.is_private or address.is_link_local:
        return {
            "title_prefix": "Private-network",
            "impact": "The service is reachable from this scan vantage point on non-public address space. This does not prove internet exposure, but it may matter for internal segmentation and lateral-movement risk.",
            "evidence": "non-public target",
        }
    return {
        "title_prefix": "Internet-address",
        "impact": "The service accepted a TCP connection on a public-address target. Confirm it is intentionally exposed and hardened, because reachable services can expand breach entry points if misconfigured or vulnerable.",
        "evidence": "public-address target",
    }
