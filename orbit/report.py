from __future__ import annotations

import json
import re
from pathlib import Path

from .models import ScanReport, Severity


def write_report_files(report: ScanReport, output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    base = f"{_slug(report.target.host)}-{report.completed_at.replace(':', '').replace('+', 'Z')}"
    json_path = output_dir / f"{base}.json"
    md_path = output_dir / f"{base}.md"
    json_path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, md_path


def render_markdown(report: ScanReport) -> str:
    counts = {severity: 0 for severity in Severity}
    for finding in report.findings:
        counts[finding.severity] += 1

    lines = [
        f"# ORBIT Report: {report.target.host}",
        "",
        f"- Target: `{report.target.origin}`",
        f"- Started: `{report.started_at}`",
        f"- Completed: `{report.completed_at}`",
        f"- Risk score: **{report.risk_score}/100**",
        f"- Findings: {counts[Severity.CRITICAL]} critical, {counts[Severity.HIGH]} high, {counts[Severity.MEDIUM]} medium, {counts[Severity.LOW]} low, {counts[Severity.INFO]} info",
        "",
        "## Summary",
        "",
        report.summary,
        "",
    ]

    if report.ai_summary:
        lines.extend(["## AI Breach-Impact Summary", "", report.ai_summary, ""])

    lines.extend(["## Findings", ""])
    if not report.findings:
        lines.extend(["No findings were produced by the enabled scanners.", ""])
    for finding in report.findings:
        lines.extend(
            [
                f"### {finding.title}",
                "",
                f"- ID: `{finding.id}`",
                f"- Severity: **{finding.severity.value.upper()}**",
                f"- Category: `{finding.category}`",
                f"- Confidence: `{finding.confidence}`",
                "",
                finding.description,
                "",
                f"Impact: {finding.impact}",
                "",
                f"Recommendation: {finding.recommendation}",
                "",
            ]
        )
        if finding.evidence:
            lines.append("Evidence:")
            for evidence in finding.evidence:
                lines.append(f"- {_markdown_code(evidence.label)}: {_markdown_code(evidence.value)}")
            lines.append("")
        if finding.references:
            lines.append("References:")
            for reference in finding.references:
                lines.append(f"- {reference}")
            lines.append("")

    lines.extend(
        [
            "## Notes",
            "",
            "ORBIT performs authorized exposure assessment and does not exploit findings. Validate all findings before making risk decisions.",
            "",
        ]
    )
    return "\n".join(lines)


def _slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", value).strip("-") or "target"


def _markdown_code(value: str) -> str:
    safe = str(value).replace("\r", "\\r").replace("\n", "\\n").replace("`", "&#96;")
    return f"`{safe}`"
