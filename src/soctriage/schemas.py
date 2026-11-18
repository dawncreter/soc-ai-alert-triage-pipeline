"""OCSF-aligned data models (a focused subset of OCSF v1.1 Detection Finding fields)."""
from __future__ import annotations

from datetime import datetime
from enum import IntEnum

from pydantic import BaseModel, Field


class Severity(IntEnum):
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class Technique(BaseModel):
    technique_id: str = Field(examples=["T1059.001"])
    name: str = Field(examples=["PowerShell"])
    tactic: str = Field(examples=["Execution"])


class Endpoint(BaseModel):
    hostname: str
    ip: str
    os: str = "windows"


class SecurityAlert(BaseModel):
    """A normalized EDR alert, independent of the vendor that produced it."""

    alert_id: str
    time: datetime
    severity: Severity
    title: str
    endpoint: Endpoint
    user: str = "unknown"
    process_name: str
    command_line: str = ""
    parent_process: str = ""
    sha256: str | None = None
    source: str = "unknown"
    techniques: list[Technique] = Field(default_factory=list)


class Incident(BaseModel):
    """A group of related alerts plus the triage decision."""

    incident_id: str
    hostname: str
    alerts: list[SecurityAlert]
    first_seen: datetime
    last_seen: datetime
    techniques: list[Technique] = Field(default_factory=list)
    risk_score: float = Field(default=0.0, ge=0, le=100)
    verdict: str = "pending"  # true_positive | benign | needs_review
    action: str = "monitor"  # contain | escalate | monitor | suppress
    summary: str = ""

    @property
    def size(self) -> int:
        return len(self.alerts)

    @property
    def tactics(self) -> list[str]:
        return sorted({t.tactic for t in self.techniques})
