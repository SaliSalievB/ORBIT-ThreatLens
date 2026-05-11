from __future__ import annotations

import gzip
import ssl
from dataclasses import dataclass
from http.client import HTTPResponse
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import HTTPRedirectHandler, Request, build_opener

from orbit.models import Evidence, Finding, ScanOptions, Severity, Target


SECURITY_HEADERS: dict[str, tuple[Severity, str, str, str]] = {
    "strict-transport-security": (
        Severity.MEDIUM,
        "HTTP Strict Transport Security is missing",
        "Without HSTS, browsers may allow protocol downgrade or insecure first-hop access.",
        "Add Strict-Transport-Security with an appropriate max-age after confirming HTTPS is stable.",
    ),
    "content-security-policy": (
        Severity.MEDIUM,
        "Content Security Policy is missing",
        "A missing CSP can increase the impact of cross-site scripting or content injection.",
        "Deploy a Content-Security-Policy tuned to the application.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "X-Content-Type-Options is missing",
        "Browsers may perform MIME sniffing that turns benign uploads or responses into executable content.",
        "Add X-Content-Type-Options: nosniff.",
    ),
    "referrer-policy": (
        Severity.LOW,
        "Referrer-Policy is missing",
        "Sensitive URLs may leak to third-party destinations through the Referer header.",
        "Add a Referrer-Policy such as strict-origin-when-cross-origin or no-referrer.",
    ),
    "permissions-policy": (
        Severity.LOW,
        "Permissions-Policy is missing",
        "Browser features may be available more broadly than intended.",
        "Add a Permissions-Policy that disables unused high-risk browser capabilities.",
    ),
}

EXPOSURE_CHECKS = [
    {
        "path": "/.env",
        "id": "ORBIT-WEB-ENV",
        "title": "Environment file appears publicly accessible",
        "signatures": ("APP_KEY=", "DB_PASSWORD=", "SECRET_KEY=", "AWS_ACCESS_KEY_ID=", "OPENAI_API_KEY="),
        "severity": Severity.CRITICAL,
        "recommendation": "Remove the file from the web root, rotate any exposed secrets, and add deployment checks that prevent secret files from being served.",
    },
    {
        "path": "/.git/config",
        "id": "ORBIT-WEB-GIT",
        "title": "Git metadata appears publicly accessible",
        "signatures": ("[core]", "[remote ", "repositoryformatversion"),
        "severity": Severity.HIGH,
        "recommendation": "Block access to .git paths and redeploy from a clean artifact that excludes repository metadata.",
    },
    {
        "path": "/server-status",
        "id": "ORBIT-WEB-SERVER-STATUS",
        "title": "Server status endpoint appears exposed",
        "signatures": ("Apache Server Status", "Server Version:", "Current Time:"),
        "severity": Severity.MEDIUM,
        "recommendation": "Restrict server status endpoints to trusted administrators or disable them.",
    },
    {
        "path": "/.DS_Store",
        "id": "ORBIT-WEB-DS-STORE",
        "title": "Finder metadata appears publicly accessible",
        "signatures": ("Bud1",),
        "severity": Severity.MEDIUM,
        "recommendation": "Remove .DS_Store files from deployed artifacts and block dotfile access at the web server.",
    },
]


@dataclass(slots=True)
class FetchResult:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    final_url: str


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def run(target: Target, options: ScanOptions) -> tuple[dict[str, Any], list[Finding]]:
    observations: dict[str, Any] = {"requests": {}, "errors": []}
    findings: list[Finding] = []
    base_url = target.origin

    primary = _fetch(base_url, timeout=options.timeout)
    if isinstance(primary, FetchResult):
        observations["requests"]["primary"] = _summarize_fetch(primary)
        findings.extend(_header_findings(primary, target))
        findings.extend(_cookie_findings(primary))
        findings.extend(_cors_findings(primary))
        findings.extend(_server_banner_findings(primary))
    else:
        observations["errors"].append(f"{base_url}: {primary}")
        findings.append(
            Finding(
                id="ORBIT-HTTP-001",
                title="HTTP request failed",
                severity=Severity.MEDIUM,
                category="http",
                description="ORBIT could not complete a basic HTTP request to the target.",
                impact="Availability, TLS, WAF, or routing issues may prevent users and monitors from reaching the service.",
                recommendation="Confirm that the target URL, firewall, TLS configuration, and upstream routing are healthy.",
                evidence=[Evidence("error", str(primary))],
                confidence="medium",
            )
        )

    if target.scheme == "https":
        http_url = f"http://{target.host}{f':{target.port}' if target.port and target.port != 443 else ''}/"
        redirect_probe = _fetch(http_url, timeout=options.timeout, max_bytes=0)
        if isinstance(redirect_probe, FetchResult):
            observations["requests"]["http_redirect_probe"] = _summarize_fetch(redirect_probe)
            if not redirect_probe.final_url.lower().startswith("https://"):
                findings.append(
                    Finding(
                        id="ORBIT-HTTP-002",
                        title="HTTP does not redirect to HTTPS",
                        severity=Severity.MEDIUM,
                        category="http",
                        description="The cleartext HTTP endpoint did not land on an HTTPS URL.",
                        impact="Users may remain on cleartext transport if they enter or follow an HTTP URL.",
                        recommendation="Redirect HTTP to HTTPS before serving application content.",
                        evidence=[Evidence("final_url", redirect_probe.final_url), Evidence("status", str(redirect_probe.status))],
                        confidence="medium",
                    )
                )

    if isinstance(primary, FetchResult):
        findings.extend(_exposure_findings(base_url, options, observations))

    return observations, findings


def _fetch(url: str, timeout: float, max_bytes: int = 65536, follow_redirects: bool = True) -> FetchResult | str:
    opener = build_opener() if follow_redirects else build_opener(NoRedirectHandler)
    request = Request(
        url,
        headers={
            "User-Agent": "ORBIT/0.1 authorized-security-assessment",
            "Accept": "text/html,application/xhtml+xml,application/json,text/plain,*/*",
            "Accept-Encoding": "gzip",
            "Range": f"bytes=0-{max_bytes}" if max_bytes else "bytes=0-0",
        },
        method="GET",
    )
    try:
        response = opener.open(request, timeout=timeout)
        return _read_response(url, response, max_bytes)
    except HTTPError as exc:
        body = exc.read(max_bytes) if max_bytes else b""
        return FetchResult(
            url=url,
            status=exc.code,
            headers={key.lower(): value for key, value in exc.headers.items()},
            body=_maybe_decompress(body, exc.headers.get("Content-Encoding")),
            final_url=exc.geturl(),
        )
    except (URLError, TimeoutError, ssl.SSLError, OSError) as exc:
        return str(exc)


def _read_response(url: str, response: HTTPResponse, max_bytes: int) -> FetchResult:
    body = response.read(max_bytes) if max_bytes else b""
    headers = {key.lower(): value for key, value in response.headers.items()}
    return FetchResult(
        url=url,
        status=response.status,
        headers=headers,
        body=_maybe_decompress(body, response.headers.get("Content-Encoding")),
        final_url=response.geturl(),
    )


def _maybe_decompress(body: bytes, encoding: str | None) -> bytes:
    if encoding and "gzip" in encoding.lower():
        try:
            return gzip.decompress(body)
        except OSError:
            return body
    return body


def _summarize_fetch(result: FetchResult) -> dict[str, Any]:
    return {
        "url": result.url,
        "final_url": result.final_url,
        "status": result.status,
        "headers": {key: _safe_header_value(key, value) for key, value in result.headers.items()},
        "body_bytes_sampled": len(result.body),
    }


def _safe_header_value(key: str, value: str) -> str:
    if key.lower() in {"set-cookie", "authorization"}:
        return "[redacted]"
    if len(value) > 180:
        return f"{value[:180]}..."
    return value


def _header_findings(result: FetchResult, target: Target) -> list[Finding]:
    findings: list[Finding] = []
    for header, (severity, title, impact, recommendation) in SECURITY_HEADERS.items():
        if header == "strict-transport-security" and target.scheme != "https":
            continue
        if header not in result.headers:
            findings.append(
                Finding(
                    id=f"ORBIT-HEADER-{header.upper().replace('-', '_')}",
                    title=title,
                    severity=severity,
                    category="http",
                    description=f"The {header} response header was not present on the primary response.",
                    impact=impact,
                    recommendation=recommendation,
                    evidence=[Evidence("url", result.final_url), Evidence("status", str(result.status))],
                    confidence="high",
                )
            )

    if "x-frame-options" not in result.headers and "content-security-policy" not in result.headers:
        findings.append(
            Finding(
                id="ORBIT-HEADER-FRAME",
                title="Clickjacking protections are missing",
                severity=Severity.LOW,
                category="http",
                description="Neither X-Frame-Options nor Content-Security-Policy was available to constrain framing.",
                impact="Attackers may be able to embed sensitive pages in a hostile frame for clickjacking attacks.",
                recommendation="Use CSP frame-ancestors or X-Frame-Options to restrict framing.",
                evidence=[Evidence("url", result.final_url)],
                confidence="medium",
            )
        )

    return findings


def _cookie_findings(result: FetchResult) -> list[Finding]:
    findings: list[Finding] = []
    cookies = [value for key, value in result.headers.items() if key.lower() == "set-cookie"]
    for index, cookie in enumerate(cookies, start=1):
        lowered = cookie.lower()
        missing = []
        if "secure" not in lowered:
            missing.append("Secure")
        if "httponly" not in lowered:
            missing.append("HttpOnly")
        if "samesite" not in lowered:
            missing.append("SameSite")
        if missing:
            findings.append(
                Finding(
                    id=f"ORBIT-COOKIE-{index}",
                    title="Session cookie hardening attributes are missing",
                    severity=Severity.MEDIUM if {"Secure", "HttpOnly"} & set(missing) else Severity.LOW,
                    category="http",
                    description="A Set-Cookie header is missing one or more browser-enforced hardening attributes.",
                    impact="Cookie theft, cross-site request forgery, or cleartext leakage can have greater impact.",
                    recommendation="Set Secure, HttpOnly, and an appropriate SameSite value on sensitive cookies.",
                    evidence=[Evidence("missing_attributes", ", ".join(missing))],
                    confidence="medium",
                )
            )
    return findings


def _cors_findings(result: FetchResult) -> list[Finding]:
    allow_origin = result.headers.get("access-control-allow-origin", "")
    allow_credentials = result.headers.get("access-control-allow-credentials", "")
    if allow_origin.strip() == "*" and allow_credentials.lower().strip() == "true":
        return [
            Finding(
                id="ORBIT-CORS-001",
                title="Permissive CORS with credentials",
                severity=Severity.HIGH,
                category="http",
                description="The response allows any origin while also allowing credentials.",
                impact="Browsers may expose authenticated responses to untrusted origins if application logic depends on these headers.",
                recommendation="Restrict Access-Control-Allow-Origin to trusted origins and avoid credentialed wildcard CORS.",
                evidence=[Evidence("access-control-allow-origin", allow_origin), Evidence("access-control-allow-credentials", allow_credentials)],
                confidence="high",
            )
        ]
    if allow_origin.strip() == "*":
        return [
            Finding(
                id="ORBIT-CORS-002",
                title="Wildcard CORS is enabled",
                severity=Severity.LOW,
                category="http",
                description="The response allows cross-origin reads from any origin.",
                impact="Public cross-origin reads may be intentional for APIs, but are risky on authenticated or sensitive endpoints.",
                recommendation="Confirm wildcard CORS is required; otherwise restrict it to trusted origins.",
                evidence=[Evidence("access-control-allow-origin", allow_origin)],
                confidence="medium",
            )
        ]
    return []


def _server_banner_findings(result: FetchResult) -> list[Finding]:
    banner = result.headers.get("server")
    if not banner:
        return []
    if any(ch.isdigit() for ch in banner):
        return [
            Finding(
                id="ORBIT-HTTP-003",
                title="Server banner exposes version detail",
                severity=Severity.LOW,
                category="http",
                description="The Server header appears to expose product or version detail.",
                impact="Version detail can help attackers quickly map likely vulnerabilities.",
                recommendation="Reduce banner detail where practical and rely on asset inventory for operational visibility.",
                evidence=[Evidence("server", banner[:120])],
                confidence="medium",
            )
        ]
    return []


def _exposure_findings(base_url: str, options: ScanOptions, observations: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    exposure_observations: list[dict[str, Any]] = []
    for check in EXPOSURE_CHECKS:
        url = urljoin(base_url, check["path"])
        result = _fetch(url, timeout=options.timeout, max_bytes=4096, follow_redirects=False)
        if not isinstance(result, FetchResult):
            exposure_observations.append({"path": check["path"], "error": result})
            continue
        body_text = result.body.decode("utf-8", errors="ignore")
        exposure_observations.append({"path": check["path"], "status": result.status, "bytes": len(result.body)})
        if result.status == 200 and any(signature in body_text for signature in check["signatures"]):
            findings.append(
                Finding(
                    id=str(check["id"]),
                    title=str(check["title"]),
                    severity=check["severity"],
                    category="exposure",
                    description=f"The path {check['path']} returned content matching ORBIT's exposure signature.",
                    impact="Publicly exposed operational files can disclose credentials, source paths, software versions, or administrative data.",
                    recommendation=str(check["recommendation"]),
                    evidence=[Evidence("path", str(check["path"])), Evidence("status", str(result.status))],
                    confidence="high",
                )
            )
    observations["exposure_probes"] = exposure_observations
    return findings
