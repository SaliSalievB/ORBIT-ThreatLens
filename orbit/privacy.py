from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


SENSITIVE_KEYWORDS = (
    "authorization",
    "cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private",
    "session",
)


def redact_for_ai(value: Any) -> Any:
    """Return a copy safe enough for the ORBIT AI gateway.

    ORBIT never needs raw response bodies or credentials to summarize exposure.
    This function preserves finding titles, severity, evidence labels, and short
    non-sensitive values while dropping likely secrets from arbitrary payloads.
    """
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(word in lowered for word in SENSITIVE_KEYWORDS):
                redacted[str(key)] = "[redacted]"
            else:
                redacted[str(key)] = redact_for_ai(item)
        return redacted

    if isinstance(value, str):
        if len(value) > 500:
            return f"{value[:500]}... [truncated]"
        return value

    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        return [redact_for_ai(item) for item in value]

    return value
