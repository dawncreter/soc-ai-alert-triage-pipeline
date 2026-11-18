"""Group related alerts into incidents with DBSCAN over a custom alert distance.

distance(a, b) = 1.0                                   if the alerts are on different hosts
               = min(1, |t_a - t_b| / window) * w      otherwise
where w = 0.5 when the alerts share process lineage (same process, or one is the other's parent)
and w = 1.0 otherwise. Alerts within ``eps`` of each other (directly or through a chain of
neighbours) form one incident; DBSCAN noise points become single-alert incidents.
"""
from __future__ import annotations

from datetime import timedelta

import numpy as np
from sklearn.cluster import DBSCAN

from .schemas import Incident, SecurityAlert


def _related(a: SecurityAlert, b: SecurityAlert) -> bool:
    names_a = {a.process_name, a.parent_process} - {""}
    names_b = {b.process_name, b.parent_process} - {""}
    return bool(names_a & names_b)


def distance_matrix(alerts: list[SecurityAlert], window: timedelta) -> np.ndarray:
    n = len(alerts)
    d = np.ones((n, n))
    w = window.total_seconds()
    for i in range(n):
        d[i, i] = 0.0
        for j in range(i + 1, n):
            a, b = alerts[i], alerts[j]
            if a.endpoint.hostname != b.endpoint.hostname:
                continue
            dt = min(1.0, abs((a.time - b.time).total_seconds()) / w)
            d[i, j] = d[j, i] = dt * (0.5 if _related(a, b) else 1.0)
    return d


def cluster(
    alerts: list[SecurityAlert], window: timedelta = timedelta(minutes=30), eps: float = 0.25
) -> list[Incident]:
    """Return incidents ordered by first-seen time."""
    if not alerts:
        return []
    labels = DBSCAN(eps=eps, min_samples=1, metric="precomputed").fit(distance_matrix(alerts, window)).labels_
    groups: dict[int, list[SecurityAlert]] = {}
    for alert, label in zip(alerts, labels, strict=True):
        groups.setdefault(int(label), []).append(alert)
    incidents = []
    for members in groups.values():
        members.sort(key=lambda a: a.time)
        techniques = {t.technique_id: t for a in members for t in a.techniques}
        incidents.append(Incident(
            incident_id="",
            hostname=members[0].endpoint.hostname,
            alerts=members,
            first_seen=members[0].time,
            last_seen=members[-1].time,
            techniques=list(techniques.values()),
        ))
    incidents.sort(key=lambda i: (i.first_seen, i.hostname))
    for n, inc in enumerate(incidents, 1):
        inc.incident_id = f"INC-{n:04d}"
    return incidents
