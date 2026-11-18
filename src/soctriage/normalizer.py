"""Map vendor-specific EDR payloads into the common ``SecurityAlert`` model.

Two illustrative vendor formats are supported (``edr_a`` and ``edr_b``). Adding a vendor
means adding one mapping function and registering it in ``MAPPERS``.
"""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from .schemas import Endpoint, SecurityAlert, Severity

_SEV_WORDS = {"info": 1, "informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def _ts(value: Any) -> datetime:
    if isinstance(value, (int, float)):  # epoch milliseconds
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _edr_a(p: dict[str, Any]) -> SecurityAlert:
    """Format A: flat payload, numeric severity 0-100, ISO timestamps."""
    return SecurityAlert(
        alert_id=p["detection_id"],
        time=_ts(p["timestamp"]),
        severity=Severity(min(5, max(1, int(p["severity"]) // 20 + 1))),
        title=p["name"],
        endpoint=Endpoint(hostname=p["device"]["hostname"].lower(), ip=p["device"]["local_ip"],
                          os=p["device"].get("platform", "windows").lower()),
        user=p.get("user_name", "unknown"),
        process_name=p["filename"].lower(),
        command_line=p.get("cmdline", ""),
        parent_process=p.get("parent_filename", "").lower(),
        sha256=p.get("sha256"),
        source="edr_a",
    )


def _edr_b(p: dict[str, Any]) -> SecurityAlert:
    """Format B: nested evidence, word severity, epoch-millisecond timestamps."""
    proc = p["evidence"]["process"]
    return SecurityAlert(
        alert_id=p["id"],
        time=_ts(p["createdTime"]),
        severity=Severity(_SEV_WORDS[p["severity"].lower()]),
        title=p["title"],
        endpoint=Endpoint(hostname=p["machine"]["name"].lower(), ip=p["machine"]["ip"]),
        user=proc.get("account", "unknown"),
        process_name=proc["image"].lower(),
        command_line=proc.get("commandLine", ""),
        parent_process=proc.get("parentImage", "").lower(),
        sha256=proc.get("sha256"),
        source="edr_b",
    )


MAPPERS: dict[str, Callable[[dict[str, Any]], SecurityAlert]] = {"edr_a": _edr_a, "edr_b": _edr_b}


def normalize(payload: dict[str, Any]) -> SecurityAlert:
    """Normalize one raw payload. ``payload['vendor']`` selects the mapper."""
    vendor = payload.get("vendor")
    if vendor not in MAPPERS:
        raise ValueError(f"unsupported vendor: {vendor!r}")
    try:
        return MAPPERS[vendor](payload)
    except (KeyError, TypeError) as exc:
        raise ValueError(f"malformed {vendor} payload: missing {exc}") from exc
