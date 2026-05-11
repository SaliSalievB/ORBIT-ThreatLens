from orbit.models import Finding, Severity
from orbit.risk import calculate_risk_score, summarize_findings


def _finding(severity: Severity, title: str) -> Finding:
    return Finding(
        id=title,
        title=title,
        severity=severity,
        category="test",
        description="description",
        impact="impact",
        recommendation="recommendation",
    )


def test_calculate_risk_score_caps_at_100() -> None:
    findings = [_finding(Severity.CRITICAL, f"c{i}") for i in range(20)]

    assert calculate_risk_score(findings) == 100


def test_summarize_findings_prioritizes_severity() -> None:
    findings = [
        _finding(Severity.LOW, "low"),
        _finding(Severity.HIGH, "high"),
        _finding(Severity.MEDIUM, "medium"),
    ]

    summary = summarize_findings(findings)

    assert "1 high" in summary
    assert "Top concerns: high, medium, low" in summary
