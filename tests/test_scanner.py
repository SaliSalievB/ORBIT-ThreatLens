import json

import pytest

from orbit.models import Finding, ScanOptions, Severity
from orbit import scanner
from orbit.scanner import AuthorizationRequired, scan_target
from orbit.ai_client import DEFAULT_AI_TIMEOUT


def test_scan_requires_authorization() -> None:
    with pytest.raises(AuthorizationRequired):
        scan_target("example.com", ScanOptions(authorized=False))


def test_scan_isolates_scanner_failures_and_sorts_findings(monkeypatch) -> None:
    class BrokenScanner:
        def run(self, target, options):
            raise RuntimeError("boom")

    class LowScanner:
        def run(self, target, options):
            return {}, [
                Finding(
                    id="LOW",
                    title="Low finding",
                    severity=Severity.LOW,
                    category="test",
                    description="description",
                    impact="impact",
                    recommendation="recommendation",
                )
            ]

    class HighScanner:
        def run(self, target, options):
            return {}, [
                Finding(
                    id="HIGH",
                    title="High finding",
                    severity=Severity.HIGH,
                    category="test",
                    description="description",
                    impact="impact",
                    recommendation="recommendation",
                )
            ]

    monkeypatch.setattr(
        scanner,
        "SCANNERS",
        [("low", LowScanner()), ("broken", BrokenScanner()), ("high", HighScanner())],
    )

    report = scan_target("https://example.com", ScanOptions(authorized=True))

    assert [finding.id for finding in report.findings] == ["HIGH", "LOW", "ORBIT-SCANNER-BROKEN"]
    assert report.observations["broken"]["error"] == "boom"


def test_scan_sanitizes_target_before_ai_payload(monkeypatch) -> None:
    captured = {}

    class CaptureAIClient:
        def __init__(self, gateway_url=None, api_token=None, timeout=15.0):
            captured["timeout"] = timeout

        def analyze(self, report):
            captured["report"] = report.to_dict()
            return {"summary": "ok"}

    monkeypatch.setattr(scanner, "SCANNERS", [])
    monkeypatch.setattr(scanner, "AIGatewayClient", CaptureAIClient)

    report = scan_target(
        "https://example.com/login?token=secret#fragment",
        ScanOptions(authorized=True, include_ai=True),
    )

    payload = json.dumps(captured["report"])
    assert report.target.original == "https://example.com/login"
    assert captured["timeout"] == DEFAULT_AI_TIMEOUT
    assert "token=secret" not in payload
    assert "fragment" not in payload
