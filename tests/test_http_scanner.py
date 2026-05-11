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
    assert observations["exposure_probes"]
