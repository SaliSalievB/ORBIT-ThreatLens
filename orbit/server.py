from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel
except ImportError as exc:  # pragma: no cover - import guard
    raise RuntimeError("Install ORBIT with the server extra: pip install '.[server]'") from exc

from .models import ScanOptions
from .report import render_markdown
from .scanner import AuthorizationRequired, scan_target
from .target import TargetError


STATIC_DIR = Path(__file__).with_name("static")

app = FastAPI(
    title="ORBIT Local Dashboard",
    description="Local dashboard for authorized ORBIT scans.",
    version="0.1.0",
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


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


@app.post("/api/scan")
def scan(payload: ScanRequest) -> dict[str, Any]:
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
    uvicorn.run("orbit.server:app", host=host, port=port, reload=False)
