from __future__ import annotations

import ipaddress
import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from . import __version__
from .models import ScanReport
from .privacy import redact_for_ai


DEFAULT_GATEWAY_URL = "https://165.245.244.247.sslip.io/v1/analyze"
INSECURE_GATEWAY_ENV = "ORBIT_ALLOW_INSECURE_AI_GATEWAY"
DEFAULT_AI_TIMEOUT = 45.0


class AIGatewayError(RuntimeError):
    pass


class AIGatewayClient:
    def __init__(
        self,
        gateway_url: str | None = None,
        api_token: str | None = None,
        timeout: float = DEFAULT_AI_TIMEOUT,
    ) -> None:
        self.gateway_url = _validate_gateway_url(gateway_url or os.getenv("ORBIT_AI_GATEWAY_URL") or DEFAULT_GATEWAY_URL)
        self.api_token = api_token or os.getenv("ORBIT_API_TOKEN")
        self.timeout = timeout

    def analyze(self, report: ScanReport) -> dict[str, Any]:
        payload = json.dumps({"report": redact_for_ai(report.to_dict())}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"ORBIT/{__version__}",
        }
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"

        request = Request(self.gateway_url, data=payload, headers=headers, method="POST")
        try:
            with urlopen(request, timeout=self.timeout) as response:
                body = response.read()
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise AIGatewayError(f"gateway returned HTTP {exc.code}: {detail}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise AIGatewayError(str(exc)) from exc

        try:
            data = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise AIGatewayError("gateway returned invalid JSON") from exc

        if not isinstance(data, dict):
            raise AIGatewayError("gateway returned an unexpected payload")
        return data


def _validate_gateway_url(value: str) -> str:
    url = value.strip().rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise AIGatewayError("AI gateway URL must use https.")
    if not parsed.hostname:
        raise AIGatewayError("AI gateway URL must include a host.")
    if parsed.username or parsed.password:
        raise AIGatewayError("AI gateway URL must not include username or password.")
    try:
        parsed.port
    except ValueError as exc:
        raise AIGatewayError(str(exc)) from exc

    if parsed.scheme == "http":
        if os.getenv(INSECURE_GATEWAY_ENV) == "1" and _is_loopback_host(parsed.hostname):
            return url
        raise AIGatewayError(f"AI gateway URL must use https unless {INSECURE_GATEWAY_ENV}=1 is set for loopback development.")
    return url


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower().strip("[]")
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False
