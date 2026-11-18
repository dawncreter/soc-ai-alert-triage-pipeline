"""End-to-end pipeline: normalize -> enrich -> cluster -> triage -> metrics."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from .clustering import cluster
from .mitre import enrich
from .normalizer import normalize
from .schemas import Incident
from .triage import Summarizer, triage


@dataclass
class TriageReport:
    incidents: list[Incident]
    alerts_in: int
    rejected: list[str] = field(default_factory=list)

    @property
    def queue(self) -> list[Incident]:
        """What an analyst actually has to look at."""
        return [i for i in self.incidents if i.action in ("contain", "escalate")]

    def metrics(self, truth: set[str] | None = None) -> dict[str, float]:
        m: dict[str, float] = {
            "alerts_in": self.alerts_in,
            "incidents": len(self.incidents),
            "analyst_queue": len(self.queue),
            "suppressed": sum(i.action == "suppress" for i in self.incidents),
            "queue_reduction_pct": round(100 * (1 - len(self.queue) / self.alerts_in), 1) if self.alerts_in else 0.0,
        }
        if truth is not None:
            flagged = {i.hostname for i in self.queue}
            tp = len(flagged & truth)
            m["precision"] = round(tp / len(flagged), 3) if flagged else 0.0
            m["recall"] = round(tp / len(truth), 3) if truth else 1.0
        return m


def run(payloads: list[dict[str, Any]], window: timedelta = timedelta(minutes=30),
        summarizer: Summarizer | None = None) -> TriageReport:
    alerts, rejected = [], []
    for p in payloads:
        try:
            alerts.append(enrich(normalize(p)))
        except ValueError as exc:  # keep going; bad payloads are reported, not fatal
            rejected.append(str(exc))
    return TriageReport(triage(cluster(alerts, window), summarizer), len(payloads), rejected)
