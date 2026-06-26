import io
import json
from urllib.error import HTTPError

import pytest

from orbit import __version__
from orbit import ai_client
from orbit.ai_client import AIGatewayClient, AIGatewayError
from orbit.models import ScanReport, Target


def _report() -> ScanReport:
    return ScanReport(
        target=Target(original="https://example.com", host="example.com", scheme="https"),
        started_at="2026-06-25T10:00:00+00:00",
        completed_at="2026-06-25T10:00:01+00:00",
        options={"depth": "standard", "timeout": 4.0, "include_ai": True},
        findings=[],
        observations={"headers": {"Authorization": "Bearer secret", "X-Request-ID": "abc"}},
        risk_score=0,
        summary="No findings were produced by the enabled scanners.",
    )


class _Response:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def read(self) -> bytes:
        return self.body


def test_gateway_client_redacts_payload_and_sends_bearer(monkeypatch) -> None:
    captured = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        captured["authorization"] = request.get_header("Authorization")
        captured["user_agent"] = request.get_header("User-agent")
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        return _Response(b'{"summary": "ok", "usage": {"remaining": 4}}')

    monkeypatch.setattr(ai_client, "urlopen", fake_urlopen)

    data = AIGatewayClient(
        gateway_url="https://gateway.example/v1/analyze",
        api_token="orbit-token",
        timeout=12.0,
    ).analyze(_report())

    assert data["summary"] == "ok"
    assert captured["url"] == "https://gateway.example/v1/analyze"
    assert captured["timeout"] == 12.0
    assert captured["authorization"] == "Bearer orbit-token"
    assert captured["user_agent"] == f"ORBIT/{__version__}"
    assert captured["payload"]["report"]["observations"]["headers"]["Authorization"] == "[redacted]"
    assert captured["payload"]["report"]["observations"]["headers"]["X-Request-ID"] == "abc"


def test_gateway_client_raises_on_http_error(monkeypatch) -> None:
    def fake_urlopen(request, timeout):
        raise HTTPError(
            url=request.full_url,
            code=429,
            msg="Too Many Requests",
            hdrs={},
            fp=io.BytesIO(b'{"detail":"limit reached"}'),
        )

    monkeypatch.setattr(ai_client, "urlopen", fake_urlopen)

    with pytest.raises(AIGatewayError, match="HTTP 429"):
        AIGatewayClient(gateway_url="https://gateway.example/v1/analyze").analyze(_report())


def test_gateway_client_raises_on_invalid_json(monkeypatch) -> None:
    def fake_urlopen(request, timeout):
        return _Response(b"not json")

    monkeypatch.setattr(ai_client, "urlopen", fake_urlopen)

    with pytest.raises(AIGatewayError, match="invalid JSON"):
        AIGatewayClient(gateway_url="https://gateway.example/v1/analyze").analyze(_report())


def test_gateway_client_rejects_public_http_before_network(monkeypatch) -> None:
    def fake_urlopen(request, timeout):
        raise AssertionError("network should not be reached")

    monkeypatch.setattr(ai_client, "urlopen", fake_urlopen)

    with pytest.raises(AIGatewayError, match="https"):
        AIGatewayClient(gateway_url="http://gateway.example/v1/analyze").analyze(_report())


def test_gateway_client_rejects_loopback_http_without_dev_override() -> None:
    with pytest.raises(AIGatewayError, match="ORBIT_ALLOW_INSECURE_AI_GATEWAY"):
        AIGatewayClient(gateway_url="http://127.0.0.1:9000/v1/analyze")


def test_gateway_client_allows_loopback_http_with_dev_override(monkeypatch) -> None:
    captured = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        return _Response(b'{"summary": "ok"}')

    monkeypatch.setattr(ai_client, "urlopen", fake_urlopen)
    monkeypatch.setenv("ORBIT_ALLOW_INSECURE_AI_GATEWAY", "1")

    data = AIGatewayClient(gateway_url="http://127.0.0.1:9000/v1/analyze").analyze(_report())

    assert data["summary"] == "ok"
    assert captured["url"] == "http://127.0.0.1:9000/v1/analyze"


def test_gateway_client_rejects_embedded_credentials() -> None:
    with pytest.raises(AIGatewayError, match="username or password"):
        AIGatewayClient(gateway_url="https://user:secret@gateway.example/v1/analyze")
