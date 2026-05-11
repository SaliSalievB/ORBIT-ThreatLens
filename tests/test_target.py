import pytest

from orbit.target import TargetError, normalize_target


def test_normalize_target_defaults_to_https() -> None:
    target = normalize_target("Example.COM")

    assert target.scheme == "https"
    assert target.host == "example.com"
    assert target.origin == "https://example.com"


def test_normalize_target_preserves_port_and_path() -> None:
    target = normalize_target("http://127.0.0.1:8080/login")

    assert target.scheme == "http"
    assert target.host == "127.0.0.1"
    assert target.port == 8080
    assert target.path == "/login"


def test_normalize_target_rejects_invalid_scheme() -> None:
    with pytest.raises(TargetError):
        normalize_target("ftp://example.com")
