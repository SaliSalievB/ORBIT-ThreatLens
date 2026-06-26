from __future__ import annotations

import os
from typing import Any, Protocol

from .ai_client import AIGatewayClient, AIGatewayError, DEFAULT_AI_TIMEOUT
from .models import Evidence, Finding, ScanOptions, ScanReport, Severity, SEVERITY_WEIGHTS, Target, utc_now
from .risk import calculate_risk_score, summarize_findings
from .scanners import dns, http, ports, tls
from .target import normalize_target


class ScannerModule(Protocol):
    def run(self, target: Target, options: ScanOptions) -> tuple[dict[str, Any], list[Finding]]:
        ...


class AuthorizationRequired(PermissionError):
    pass


SCANNERS: list[tuple[str, ScannerModule]] = [
    ("dns", dns),
    ("tls", tls),
    ("http", http),
    ("ports", ports),
]


def scan_target(target_value: str, options: ScanOptions) -> ScanReport:
    if not options.authorized and os.getenv("ORBIT_ASSUME_AUTHORIZED") != "1":
        raise AuthorizationRequired(
            "ORBIT only runs against assets you are authorized to assess. "
            "Pass --authorized or set ORBIT_ASSUME_AUTHORIZED=1 for controlled internal use."
        )

    target = normalize_target(target_value)
    started_at = utc_now()
    observations: dict[str, Any] = {}
    findings: list[Finding] = []

    for name, scanner in SCANNERS:
        try:
            module_observations, module_findings = scanner.run(target, options)
            observations[name] = module_observations
            findings.extend(module_findings)
        except Exception as exc:  # pragma: no cover - defensive isolation
            observations[name] = {"error": str(exc)}
            findings.append(
                Finding(
                    id=f"ORBIT-SCANNER-{name.upper()}",
                    title=f"{name.upper()} scanner failed",
                    severity=Severity.INFO,
                    category="scanner",
                    description=f"The {name} scanner raised an unexpected error.",
                    impact="The report may be incomplete for this assessment area.",
                    recommendation="Re-run with a longer timeout or file a bug with the target type and traceback.",
                    evidence=[Evidence("error", str(exc))],
                    confidence="high",
                )
            )

    risk_score = calculate_risk_score(findings)
    report = ScanReport(
        target=target,
        started_at=started_at,
        completed_at=utc_now(),
        options={
            "depth": options.depth,
            "timeout": options.timeout,
            "include_ai": options.include_ai,
        },
        findings=sorted(findings, key=lambda item: (-SEVERITY_WEIGHTS[item.severity], item.id)),
        observations=observations,
        risk_score=risk_score,
        summary=summarize_findings(findings),
    )

    if options.include_ai:
        try:
            analysis = AIGatewayClient(
                gateway_url=options.ai_gateway_url,
                api_token=options.api_token,
                timeout=max(options.timeout, DEFAULT_AI_TIMEOUT),
            ).analyze(report)
            report.ai_summary = analysis.get("summary")
            report.ai_usage = analysis.get("usage")
        except AIGatewayError as exc:
            report.ai_summary = f"AI analysis unavailable: {exc}"

    return report
