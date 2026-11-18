"""REST API: POST raw vendor alerts, get back a prioritized incident queue.

    uvicorn soctriage.api:app --reload
"""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException

from .pipeline import run

app = FastAPI(title="SOC AI Alert Triage", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/triage")
def triage_alerts(payloads: list[dict[str, Any]]) -> dict[str, Any]:
    if not payloads:
        raise HTTPException(status_code=400, detail="send at least one alert")
    report = run(payloads)
    return {
        "metrics": report.metrics(),
        "rejected": report.rejected,
        "queue": [
            {"incident_id": i.incident_id, "host": i.hostname, "risk": i.risk_score, "verdict": i.verdict,
             "action": i.action, "tactics": i.tactics, "alerts": i.size, "summary": i.summary}
            for i in report.queue
        ],
    }
