from __future__ import annotations

import ipaddress
import socket
from typing import Any

from orbit.models import Evidence, Finding, ScanOptions, Severity, Target


def run(target: Target, options: ScanOptions) -> tuple[dict[str, Any], list[Finding]]:
    observations: dict[str, Any] = {"addresses": [], "errors": []}
    findings: list[Finding] = []

    try:
        records = socket.getaddrinfo(target.host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        findings.append(
            Finding(
                id="ORBIT-DNS-001",
                title="Target does not resolve",
                severity=Severity.HIGH,
                category="dns",
                description="The target hostname could not be resolved by the local resolver.",
                impact="Users, scanners, and monitoring systems may be unable to reach the service.",
                recommendation="Confirm the hostname, DNS zone, registrar status, and authoritative nameserver health.",
                evidence=[Evidence("resolver_error", str(exc))],
                confidence="high",
            )
        )
        observations["errors"].append(str(exc))
        return observations, findings

    addresses = sorted({record[4][0] for record in records})
    observations["addresses"] = addresses

    private_addresses = []
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            private_addresses.append(address)

    if private_addresses:
        findings.append(
            Finding(
                id="ORBIT-DNS-002",
                title="Hostname resolves to non-public address space",
                severity=Severity.MEDIUM,
                category="dns",
                description="The target resolves to private, loopback, or link-local address space.",
                impact="External users may fail to reach the asset, or internal-only infrastructure may be exposed through public DNS.",
                recommendation="Verify that the DNS record is intentional and does not disclose internal network design.",
                evidence=[Evidence("addresses", ", ".join(private_addresses))],
                confidence="medium",
            )
        )

    if len(addresses) == 1:
        findings.append(
            Finding(
                id="ORBIT-DNS-003",
                title="Single resolved address",
                severity=Severity.INFO,
                category="resilience",
                description="The target resolves to a single address from this resolver.",
                impact="A single-address deployment can increase outage impact if no upstream load balancing or failover exists.",
                recommendation="Confirm that availability, failover, and DDoS absorption are handled elsewhere.",
                evidence=[Evidence("address", addresses[0])],
                confidence="low",
            )
        )

    return observations, findings
