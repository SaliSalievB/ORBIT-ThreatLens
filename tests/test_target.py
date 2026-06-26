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


def test_normalize_target_removes_query_and_fragment_from_stored_value() -> None:
    target = normalize_target("https://Example.COM/login?token=secret#section")

    assert target.original == "https://example.com/login"
    assert target.path == "/login"
    assert "token=secret" not in target.to_dict()["original"]


def test_normalize_target_rejects_invalid_scheme() -> None:
    with pytest.raises(TargetError):
        normalize_target("ftp://example.com")


def test_normalize_target_rejects_userinfo_credentials() -> None:
    with pytest.raises(TargetError, match="username or password"):
        normalize_target("https://user:secret@example.com")
