from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Any

try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import HTMLResponse
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel
except ImportError as exc:  # pragma: no cover - import guard
    raise RuntimeError("Install ORBIT with the server extra: pip install '.[server]'") from exc

from .models import ScanOptions
from .report import render_markdown
from .scanner import AuthorizationRequired, scan_target
from .target import TargetError
from . import __version__


STATIC_DIR = Path(__file__).with_name("static")
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}
REMOTE_DASHBOARD_ENV = "ORBIT_DASHBOARD_ALLOW_REMOTE"

app = FastAPI(
    title="ORBIT Local Dashboard",
    description="Local dashboard for authorized ORBIT scans.",
    version=__version__,
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class ScanRequest(BaseModel):
    target: str
    authorized: bool
    depth: str = "standard"
    timeout: float = 4.0
    include_ai: bool = False
    ai_gateway_url: str | None = None
    api_token: str | None = None


@app.middleware("http")
async def add_security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        if name not in response.headers:
            response.headers[name] = value
    return response


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


@app.post("/api/scan")
def scan(payload: ScanRequest, request: Request) -> dict[str, Any]:
    _enforce_dashboard_request_policy(request)
    try:
        report = scan_target(
            payload.target,
            ScanOptions(
                authorized=payload.authorized,
                depth=payload.depth,
                timeout=payload.timeout,
                include_ai=payload.include_ai,
                ai_gateway_url=payload.ai_gateway_url,
                api_token=payload.api_token,
            ),
        )
    except (AuthorizationRequired, TargetError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"report": report.to_dict(), "markdown": render_markdown(report)}


def run(host: str = "127.0.0.1", port: int = 8765) -> None:
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - import guard
        raise RuntimeError("Install ORBIT with the server extra: pip install '.[server]'") from exc
    if not _is_loopback_host(host):
        print(
            f"Warning: ORBIT dashboard is listening on {host}. Scan API requests from non-loopback clients are blocked unless {REMOTE_DASHBOARD_ENV}=1.",
        )
    uvicorn.run("orbit.server:app", host=host, port=port, reload=False)


def _enforce_dashboard_request_policy(request: Request) -> None:
    client_host = request.client.host if request.client else ""
    if os.getenv(REMOTE_DASHBOARD_ENV) != "1" and not _is_loopback_host(client_host):
        raise HTTPException(status_code=403, detail="Dashboard scan API accepts loopback clients only by default.")

    origin = request.headers.get("origin")
    if origin and origin.rstrip("/") != _expected_origin(request):
        raise HTTPException(status_code=403, detail="Dashboard scan API rejected a cross-origin request.")


def _expected_origin(request: Request) -> str:
    host = request.headers.get("host", "")
    return f"{request.url.scheme}://{host}".rstrip("/")


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower().strip("[]")
    if normalized in {"localhost", "testclient"}:
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False
