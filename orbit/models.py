from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


@dataclass(slots=True)
class Evidence:
    label: str
    value: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    impact: str
    recommendation: str
    evidence: list[Evidence] = field(default_factory=list)
    confidence: str = "medium"
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass(slots=True)
class Target:
    original: str
    host: str
    scheme: str
    port: int | None = None
    path: str = "/"

    @property
    def origin(self) -> str:
        port = f":{self.port}" if self.port else ""
        return f"{self.scheme}://{self.host}{port}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanOptions:
    authorized: bool = False
    depth: str = "standard"
    timeout: float = 4.0
    max_workers: int = 64
    include_ai: bool = False
    ai_gateway_url: str | None = None
    api_token: str | None = None


@dataclass(slots=True)
class ScanReport:
    target: Target
    started_at: str
    completed_at: str
    options: dict[str, Any]
    findings: list[Finding]
    observations: dict[str, Any]
    risk_score: int
    summary: str
    ai_summary: str | None = None
    ai_usage: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.to_dict(),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "options": self.options,
            "findings": [finding.to_dict() for finding in self.findings],
            "observations": self.observations,
            "risk_score": self.risk_score,
            "summary": self.summary,
            "ai_summary": self.ai_summary,
            "ai_usage": self.ai_usage,
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
