from __future__ import annotations

from collections import Counter

from .models import Finding, Severity, SEVERITY_WEIGHTS


def calculate_risk_score(findings: list[Finding]) -> int:
    raw = sum(SEVERITY_WEIGHTS[finding.severity] for finding in findings)
    return min(100, raw * 3)


def summarize_findings(findings: list[Finding]) -> str:
    if not findings:
        return "No material exposure findings were detected by the enabled checks."

    counts = Counter(finding.severity for finding in findings)
    notable = [
        finding.title
        for finding in sorted(
            findings,
            key=lambda item: SEVERITY_WEIGHTS[item.severity],
            reverse=True,
        )[:3]
    ]
    parts = [
        f"{counts.get(Severity.CRITICAL, 0)} critical",
        f"{counts.get(Severity.HIGH, 0)} high",
        f"{counts.get(Severity.MEDIUM, 0)} medium",
        f"{counts.get(Severity.LOW, 0)} low",
    ]
    return f"Detected {', '.join(parts)} findings. Top concerns: {', '.join(notable)}."
