from __future__ import annotations

import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .models import ScanReport
from .privacy import redact_for_ai


DEFAULT_GATEWAY_URL = "https://orbit.threatlens.ai/v1/analyze"


class AIGatewayError(RuntimeError):
    pass


class AIGatewayClient:
    def __init__(
        self,
        gateway_url: str | None = None,
        api_token: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        self.gateway_url = (gateway_url or os.getenv("ORBIT_AI_GATEWAY_URL") or DEFAULT_GATEWAY_URL).rstrip("/")
        self.api_token = api_token or os.getenv("ORBIT_API_TOKEN")
        self.timeout = timeout

    def analyze(self, report: ScanReport) -> dict[str, Any]:
        payload = json.dumps({"report": redact_for_ai(report.to_dict())}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "ORBIT/0.1",
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
