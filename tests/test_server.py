from fastapi.testclient import TestClient

from orbit import server
from orbit.models import ScanReport, Target


def _report() -> ScanReport:
    return ScanReport(
        target=Target(original="https://example.com", host="example.com", scheme="https"),
        started_at="2026-06-25T10:00:00+00:00",
        completed_at="2026-06-25T10:00:01+00:00",
        options={"depth": "standard", "timeout": 4.0, "include_ai": False},
        findings=[],
        observations={},
        risk_score=0,
        summary="No findings were produced by the enabled scanners.",
    )


def test_index_returns_dashboard_html() -> None:
    client = TestClient(server.app)

    response = client.get("/")

    assert response.status_code == 200
    assert "Threat Lens ORBIT" in response.text
    assert "Configure authorized scan" in response.text


def test_dashboard_responses_include_security_headers() -> None:
    client = TestClient(server.app)

    response = client.get("/")

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_api_error_responses_include_security_headers() -> None:
    client = TestClient(server.app)

    response = client.post(
        "/api/scan",
        json={"target": "https://example.com", "authorized": False},
    )

    assert response.status_code == 400
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'self'" in response.headers["content-security-policy"]


def test_static_responses_include_security_headers() -> None:
    client = TestClient(server.app)

    response = client.get("/static/logo.png")

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


def test_api_scan_rejects_unauthorized_target() -> None:
    client = TestClient(server.app)

    response = client.post(
        "/api/scan",
        json={"target": "https://example.com", "authorized": False},
    )

    assert response.status_code == 400
    assert "authorized" in response.json()["detail"]


def test_api_scan_rejects_non_loopback_clients_by_default() -> None:
    client = TestClient(server.app, client=("203.0.113.10", 5000))

    response = client.post(
        "/api/scan",
        json={"target": "https://example.com", "authorized": True},
    )

    assert response.status_code == 403
    assert "loopback" in response.json()["detail"]


def test_api_scan_allows_remote_clients_with_explicit_override(monkeypatch) -> None:
    def fake_scan_target(target, options):
        return _report()

    monkeypatch.setenv(server.REMOTE_DASHBOARD_ENV, "1")
    monkeypatch.setattr(server, "scan_target", fake_scan_target)
    client = TestClient(server.app, client=("203.0.113.10", 5000))

    response = client.post(
        "/api/scan",
        json={"target": "https://example.com", "authorized": True},
    )

    assert response.status_code == 200


def test_api_scan_rejects_mismatched_origin() -> None:
    client = TestClient(server.app)

    response = client.post(
        "/api/scan",
        headers={"origin": "http://evil.example"},
        json={"target": "https://example.com", "authorized": True},
    )

    assert response.status_code == 403
    assert "cross-origin" in response.json()["detail"]


def test_api_scan_allows_same_origin(monkeypatch) -> None:
    def fake_scan_target(target, options):
        return _report()

    monkeypatch.setattr(server, "scan_target", fake_scan_target)
    client = TestClient(server.app)

    response = client.post(
        "/api/scan",
        headers={"origin": "http://testserver"},
        json={"target": "https://example.com", "authorized": True},
    )

    assert response.status_code == 200


def test_api_scan_returns_report_and_markdown(monkeypatch) -> None:
    captured = {}

    def fake_scan_target(target, options):
        captured["target"] = target
        captured["options"] = options
        return _report()

    monkeypatch.setattr(server, "scan_target", fake_scan_target)
    client = TestClient(server.app)

    response = client.post(
        "/api/scan",
        json={
            "target": "https://example.com",
            "authorized": True,
            "depth": "standard",
            "timeout": 4.0,
            "include_ai": False,
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["report"]["target"]["host"] == "example.com"
    assert "# ORBIT Report: example.com" in data["markdown"]
    assert captured["target"] == "https://example.com"
    assert captured["options"].timeout == 4.0
