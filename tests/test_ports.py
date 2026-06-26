from orbit.models import ScanOptions, Target
from orbit.scanners import ports


def test_loopback_port_finding_does_not_claim_public_exposure(monkeypatch) -> None:
    def fake_is_open(host, port, timeout):
        return port == 5432

    monkeypatch.setattr(ports, "_is_open", fake_is_open)

    observations, findings = ports.run(
        Target(original="http://127.0.0.1:8766/", host="127.0.0.1", scheme="http", port=8766),
        ScanOptions(authorized=True),
    )

    assert observations["open_tcp_ports"] == [5432]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.title == "Local PostgreSQL service accepted a connection"
    assert "does not prove public exposure" in finding.impact
    assert finding.evidence[2].label == "reachability"
    assert finding.evidence[2].value == "loopback target"


def test_public_address_port_finding_keeps_external_risk_context(monkeypatch) -> None:
    def fake_is_open(host, port, timeout):
        return port == 5432

    monkeypatch.setattr(ports, "_is_open", fake_is_open)

    _, findings = ports.run(
        Target(original="https://93.184.216.34/", host="93.184.216.34", scheme="https"),
        ScanOptions(authorized=True),
    )

    assert findings[0].title == "Internet-address PostgreSQL service accepted a connection"
    assert "public-address target" in findings[0].impact
