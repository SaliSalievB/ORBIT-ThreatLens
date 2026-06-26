from pathlib import Path

from orbit.models import Evidence, Finding, ScanReport, Severity, Target
from orbit.report import render_markdown, write_report_files


def _report() -> ScanReport:
    return ScanReport(
        target=Target(original="https://example.com", host="example.com", scheme="https"),
        started_at="2026-06-25T10:00:00+00:00",
        completed_at="2026-06-25T10:00:01+00:00",
        options={"depth": "standard", "timeout": 4.0, "include_ai": False},
        findings=[
            Finding(
                id="ORBIT-TEST-001",
                title="Example finding",
                severity=Severity.MEDIUM,
                category="test",
                description="description",
                impact="impact",
                recommendation="recommendation",
            )
        ],
        observations={"headers": {"Authorization": "Bearer secret"}},
        risk_score=20,
        summary="Detected one example finding.",
    )


def test_render_markdown_includes_findings_without_raw_observations() -> None:
    markdown = render_markdown(_report())

    assert "# ORBIT Report: example.com" in markdown
    assert "Example finding" in markdown
    assert "Bearer secret" not in markdown


def test_write_report_files_creates_json_and_markdown(tmp_path: Path) -> None:
    json_path, md_path = write_report_files(_report(), tmp_path)

    assert json_path.exists()
    assert md_path.exists()
    assert json_path.suffix == ".json"
    assert md_path.suffix == ".md"


def test_render_markdown_escapes_evidence_values() -> None:
    report = _report()
    report.findings[0].evidence.append(Evidence("header\nname", "value`\n- injected"))

    markdown = render_markdown(report)

    assert "`header\\nname`" in markdown
    assert "`value&#96;\\n- injected`" in markdown
    assert "\n- injected" not in markdown
