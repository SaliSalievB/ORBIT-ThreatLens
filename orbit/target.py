from __future__ import annotations

import ipaddress
from urllib.parse import urlparse, urlunparse

from .models import Target


class TargetError(ValueError):
    pass


def normalize_target(raw: str) -> Target:
    value = raw.strip()
    if not value:
        raise TargetError("Target cannot be empty.")

    parsed = urlparse(value if "://" in value else f"https://{value}")
    if parsed.scheme not in {"http", "https"}:
        raise TargetError("Only http and https targets are supported.")
    if not parsed.hostname:
        raise TargetError("Target must include a hostname or IP address.")
    if parsed.username or parsed.password:
        raise TargetError("Target URL must not include username or password.")

    host = parsed.hostname.lower().rstrip(".")
    if not _is_valid_host_or_ip(host):
        raise TargetError(f"Invalid target host: {host}")

    try:
        port = parsed.port
    except ValueError as exc:
        raise TargetError(str(exc)) from exc

    path = parsed.path or "/"
    canonical = urlunparse((parsed.scheme, _format_netloc(host, port), path, "", "", ""))
    return Target(
        original=canonical,
        host=host,
        scheme=parsed.scheme,
        port=port,
        path=path,
    )


def _is_valid_host_or_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass

    if len(value) > 253 or "_" in value:
        return False
    labels = value.split(".")
    return all(
        label
        and len(label) <= 63
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(ch.isalnum() or ch == "-" for ch in label)
        for label in labels
    )


def _format_netloc(host: str, port: int | None) -> str:
    display_host = f"[{host}]" if ":" in host else host
    return f"{display_host}:{port}" if port else display_host
