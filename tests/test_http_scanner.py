from orbit.models import ScanOptions
from orbit.scanners import http
from orbit.target import normalize_target


def test_security_header_findings_detect_missing_headers(monkeypatch) -> None:
    target = normalize_target("https://example.com")

    def fake_fetch(url, timeout, max_bytes=65536, follow_redirects=True):
        if url.endswith("/.env") or url.endswith("/.git/config") or url.endswith("/server-status") or url.endswith("/.DS_Store"):
            return http.FetchResult(url, 404, {}, b"", url)
        return http.FetchResult(url, 200, {"server": "nginx/1.25"}, b"ok", url)

    monkeypatch.setattr(http, "_fetch", fake_fetch)

    observations, findings = http.run(target, ScanOptions(authorized=True))

    titles = {finding.title for finding in findings}
    assert "HTTP Strict Transport Security is missing" in titles
    assert "Content Security Policy is missing" in titles
    assert "Server banner exposes version detail" in titles
    csp = next(finding for finding in findings if finding.id == "ORBIT-HEADER-CONTENT_SECURITY_POLICY")
    assert csp.evidence[0].label == "url"
    assert observations["exposure_probes"]


def test_cookie_findings_detect_missing_hardening_attributes() -> None:
    result = http.FetchResult(
        url="https://example.com",
        status=200,
        headers={"set-cookie": "sid=abc; Path=/"},
        body=b"",
        final_url="https://example.com",
    )

    findings = http._cookie_findings(result)

    assert len(findings) == 1
    assert findings[0].title == "Session cookie hardening attributes are missing"
    assert findings[0].evidence[0].value == "Secure, HttpOnly, SameSite"


def test_cors_findings_detect_wildcard_with_credentials() -> None:
    result = http.FetchResult(
        url="https://example.com",
        status=200,
        headers={
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        },
        body=b"",
        final_url="https://example.com",
    )

    findings = http._cors_findings(result)

    assert len(findings) == 1
    assert findings[0].id == "ORBIT-CORS-001"


def test_exposure_probe_detects_public_env_file(monkeypatch) -> None:
    target = normalize_target("https://example.com")

    def fake_fetch(url, timeout, max_bytes=65536, follow_redirects=True):
        if url.endswith("/.env"):
            return http.FetchResult(url, 200, {}, b"APP_KEY=redacted", url)
        if url.endswith("/.git/config") or url.endswith("/server-status") or url.endswith("/.DS_Store"):
            return http.FetchResult(url, 404, {}, b"", url)
        return http.FetchResult(url, 200, {}, b"ok", url)

    monkeypatch.setattr(http, "_fetch", fake_fetch)

    observations, findings = http.run(target, ScanOptions(authorized=True))

    assert any(finding.id == "ORBIT-WEB-ENV" for finding in findings)
    assert observations["exposure_probes"][0]["path"] == "/.env"


def test_summarize_fetch_redacts_sensitive_headers_and_url_metadata() -> None:
    result = http.FetchResult(
        url="https://example.com/path?token=secret#frag",
        status=200,
        headers={
            "x-api-key": "secret-key",
            "set-cookie": "sid=secret",
            "x-request-id": "abc",
        },
        body=b"",
        final_url="https://example.com/final?session=secret",
    )

    summary = http._summarize_fetch(result)

    assert summary["url"] == "https://example.com/path"
    assert summary["final_url"] == "https://example.com/final"
    assert summary["headers"]["x-api-key"] == "[redacted]"
    assert summary["headers"]["set-cookie"] == "[redacted]"
    assert summary["headers"]["x-request-id"] == "abc"


def test_http_redirect_evidence_sanitizes_final_url(monkeypatch) -> None:
    target = normalize_target("https://example.com")
    secure_headers = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
    }

    def fake_fetch(url, timeout, max_bytes=65536, follow_redirects=True):
        if url.startswith("http://"):
            return http.FetchResult(url, 200, {}, b"", "http://example.com/login?token=secret#frag")
        if url.endswith("/.env") or url.endswith("/.git/config") or url.endswith("/server-status") or url.endswith("/.DS_Store"):
            return http.FetchResult(url, 404, {}, b"", url)
        return http.FetchResult(url, 200, secure_headers, b"ok", url)

    monkeypatch.setattr(http, "_fetch", fake_fetch)

    observations, findings = http.run(target, ScanOptions(authorized=True))

    redirect_finding = next(finding for finding in findings if finding.id == "ORBIT-HTTP-002")
    assert redirect_finding.evidence[0].value == "http://example.com/login"
    assert "token=secret" not in str(observations)
