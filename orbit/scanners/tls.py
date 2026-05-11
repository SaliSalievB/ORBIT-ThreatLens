from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from orbit.models import Evidence, Finding, ScanOptions, Severity, Target


def run(target: Target, options: ScanOptions) -> tuple[dict[str, Any], list[Finding]]:
    observations: dict[str, Any] = {"enabled": target.scheme == "https", "errors": []}
    findings: list[Finding] = []

    if target.scheme != "https":
        findings.append(
            Finding(
                id="ORBIT-TLS-001",
                title="Target URL is not HTTPS",
                severity=Severity.MEDIUM,
                category="tls",
                description="The supplied target uses cleartext HTTP.",
                impact="Credentials, session cookies, and sensitive pages can be exposed or modified in transit.",
                recommendation="Serve the application over HTTPS and redirect HTTP traffic to HTTPS.",
                evidence=[Evidence("scheme", target.scheme)],
                confidence="high",
            )
        )
        return observations, findings

    port = target.port or 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((target.host, port), timeout=options.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target.host) as tls:
                cert = tls.getpeercert()
                observations.update(
                    {
                        "version": tls.version(),
                        "cipher": tls.cipher(),
                        "subject": cert.get("subject"),
                        "issuer": cert.get("issuer"),
                        "not_after": cert.get("notAfter"),
                        "subject_alt_names": cert.get("subjectAltName", []),
                    }
                )
    except ssl.SSLCertVerificationError as exc:
        findings.append(
            Finding(
                id="ORBIT-TLS-002",
                title="TLS certificate verification failed",
                severity=Severity.HIGH,
                category="tls",
                description="The TLS certificate failed standard client verification.",
                impact="Users may see browser warnings, and attackers may be able to impersonate the service if trust is broken.",
                recommendation="Install a valid certificate for the target hostname from a trusted CA and include the correct SAN entries.",
                evidence=[Evidence("verification_error", str(exc))],
                confidence="high",
            )
        )
        observations["errors"].append(str(exc))
        return observations, findings
    except (OSError, ssl.SSLError) as exc:
        findings.append(
            Finding(
                id="ORBIT-TLS-003",
                title="TLS handshake failed",
                severity=Severity.MEDIUM,
                category="tls",
                description="ORBIT could not complete a TLS handshake with the target.",
                impact="Some users or monitoring systems may fail to connect, depending on client and network conditions.",
                recommendation="Confirm the service is listening on HTTPS and supports modern TLS clients.",
                evidence=[Evidence("error", str(exc))],
                confidence="medium",
            )
        )
        observations["errors"].append(str(exc))
        return observations, findings

    not_after = observations.get("not_after")
    if isinstance(not_after, str):
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expires - datetime.now(timezone.utc)).days
            observations["days_until_expiry"] = days_left
            if days_left < 0:
                severity = Severity.CRITICAL
                title = "TLS certificate is expired"
                recommendation = "Renew and deploy the certificate immediately."
            elif days_left <= 14:
                severity = Severity.HIGH
                title = "TLS certificate expires soon"
                recommendation = "Renew and deploy the certificate before expiry."
            elif days_left <= 30:
                severity = Severity.MEDIUM
                title = "TLS certificate expires within 30 days"
                recommendation = "Schedule certificate renewal and verify automation."
            else:
                severity = Severity.INFO
                title = ""
                recommendation = ""

            if title:
                findings.append(
                    Finding(
                        id="ORBIT-TLS-004",
                        title=title,
                        severity=severity,
                        category="tls",
                        description="The target certificate is at or near the end of its validity period.",
                        impact="Expired certificates break user access and can disable automated integrations.",
                        recommendation=recommendation,
                        evidence=[Evidence("days_until_expiry", str(days_left)), Evidence("not_after", not_after)],
                        confidence="high",
                    )
                )
        except ValueError:
            observations["errors"].append(f"Could not parse certificate expiry: {not_after}")

    version = observations.get("version")
    if version in {"TLSv1", "TLSv1.1"}:
        findings.append(
            Finding(
                id="ORBIT-TLS-005",
                title="Legacy TLS protocol accepted",
                severity=Severity.HIGH,
                category="tls",
                description=f"The negotiated TLS protocol was {version}.",
                impact="Legacy protocols increase exposure to downgrade and cryptographic weaknesses.",
                recommendation="Disable TLS 1.0 and TLS 1.1; prefer TLS 1.2 and TLS 1.3.",
                evidence=[Evidence("tls_version", str(version))],
                confidence="medium",
            )
        )

    return observations, findings
