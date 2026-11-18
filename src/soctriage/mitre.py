"""Map process activity to MITRE ATT&CK techniques with transparent, testable rules.

The rule table is intentionally small and readable. In production it would be loaded
from the ATT&CK STIX bundle and detection-engineering content.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .schemas import SecurityAlert, Technique


@dataclass(frozen=True)
class Rule:
    pattern: re.Pattern[str]
    technique: Technique


def _r(pattern: str, tid: str, name: str, tactic: str) -> Rule:
    return Rule(re.compile(pattern, re.IGNORECASE), Technique(technique_id=tid, name=name, tactic=tactic))


RULES: tuple[Rule, ...] = (
    _r(r"powershell(\.exe)?\b.*\s-(e|enc|encodedcommand)\s", "T1059.001", "PowerShell", "Execution"),
    _r(r"winword\.exe|excel\.exe", "T1566.001", "Spearphishing Attachment", "Initial Access"),
    _r(r"certutil(\.exe)?\b.*-urlcache", "T1105", "Ingress Tool Transfer", "Command and Control"),
    _r(r"sekurlsa|mimikatz|lsass.*(dump|minidump)|comsvcs.*minidump", "T1003.001", "LSASS Memory",
       "Credential Access"),
    _r(r"schtasks(\.exe)?\b.*/create", "T1053.005", "Scheduled Task", "Persistence"),
    _r(r"\bwhoami\b|net(\.exe)? (user|group)", "T1087", "Account Discovery", "Discovery"),
    _r(r"psexec|wmic(\.exe)?\b.*/node:", "T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
    _r(r"rundll32(\.exe)?\b", "T1218.011", "Rundll32", "Defense Evasion"),
    _r(r"vssadmin(\.exe)?\b.*delete shadows", "T1490", "Inhibit System Recovery", "Impact"),
)


def map_techniques(alert: SecurityAlert) -> list[Technique]:
    """Return every technique whose rule matches the alert's process context (deduplicated, ordered)."""
    haystack = " ".join([alert.parent_process, alert.process_name, alert.command_line, alert.title])
    seen: dict[str, Technique] = {}
    for rule in RULES:
        if rule.pattern.search(haystack):
            seen.setdefault(rule.technique.technique_id, rule.technique)
    return list(seen.values())


def enrich(alert: SecurityAlert) -> SecurityAlert:
    return alert.model_copy(update={"techniques": map_techniques(alert)})
