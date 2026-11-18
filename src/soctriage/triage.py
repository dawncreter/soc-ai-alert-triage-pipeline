"""Score incidents, decide an action, and write an analyst-ready summary.

Risk model (0-100):
    raw  = 2 * max_severity
         + sum(tactic_weight[t] for each distinct ATT&CK tactic)
         + 2 * (distinct_tactics - 1)          # kill-chain breadth bonus
         + log2(distinct_processes)             # breadth of tooling, not raw alert volume
    risk = 100 * (1 - exp(-raw / 12))

Decision:
    risk >= 70                                  -> true_positive, contain
    risk >= 40                                  -> needs_review, escalate
    no techniques and max severity <= LOW       -> benign, suppress
    otherwise                                   -> needs_review, monitor
"""
from __future__ import annotations

import math
import os
from typing import Protocol

from .schemas import Incident, Severity

TACTIC_WEIGHT = {
    "Initial Access": 3, "Execution": 3, "Persistence": 4, "Defense Evasion": 3, "Discovery": 1,
    "Credential Access": 6, "Lateral Movement": 6, "Command and Control": 4, "Impact": 8,
}
KILL_CHAIN = list(TACTIC_WEIGHT)  # display order


def risk_score(inc: Incident) -> float:
    max_sev = max(a.severity for a in inc.alerts)
    tactics = inc.tactics
    raw: float = 2 * int(max_sev) + sum(TACTIC_WEIGHT.get(t, 2) for t in tactics)
    raw += 2 * max(0, len(tactics) - 1) + math.log2(len({a.process_name for a in inc.alerts}))
    return round(100 * (1 - math.exp(-raw / 12)), 1)


def decide(inc: Incident) -> tuple[str, str]:
    if inc.risk_score >= 70:
        return "true_positive", "contain"
    if inc.risk_score >= 40:
        return "needs_review", "escalate"
    if not inc.techniques and max(a.severity for a in inc.alerts) <= Severity.LOW:
        return "benign", "suppress"
    return "needs_review", "monitor"


class Summarizer(Protocol):
    def summarize(self, inc: Incident) -> str: ...


class TemplateSummarizer:
    """Deterministic summary used offline and in tests."""

    def summarize(self, inc: Incident) -> str:
        mins = (inc.last_seen - inc.first_seen).total_seconds() / 60
        chain = " → ".join(t for t in KILL_CHAIN if t in inc.tactics) or "no ATT&CK techniques"
        techs = ", ".join(f"{t.technique_id} {t.name}" for t in inc.techniques) or "none"
        users = ", ".join(sorted({a.user for a in inc.alerts}))
        return (f"{inc.hostname}: {inc.size} alert(s) over {mins:.0f} min (user: {users}). "
                f"Kill chain: {chain}. Techniques: {techs}. "
                f"Risk {inc.risk_score:.0f}/100 → {inc.action.upper()}.")


class ClaudeSummarizer:  # pragma: no cover - needs network and an API key
    """Optional: richer investigation notes from Claude. ``pip install anthropic`` + ``ANTHROPIC_API_KEY``."""

    def __init__(self, model: str = "claude-sonnet-4-5"):
        import anthropic

        self.client, self.model = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"]), model

    def summarize(self, inc: Incident) -> str:
        facts = TemplateSummarizer().summarize(inc)
        lines = "\n".join(f"- {a.time:%H:%M:%S} {a.process_name} {a.command_line}" for a in inc.alerts)
        msg = self.client.messages.create(model=self.model, max_tokens=400, messages=[{"role": "user", "content": (
            "You are a tier-2 SOC analyst. Using only these facts, write a 4-sentence investigation note "
            f"and next steps.\nFacts: {facts}\nTimeline:\n{lines}")}])
        return msg.content[0].text


def triage(incidents: list[Incident], summarizer: Summarizer | None = None) -> list[Incident]:
    summarizer = summarizer or TemplateSummarizer()
    for inc in incidents:
        inc.risk_score = risk_score(inc)
        inc.verdict, inc.action = decide(inc)
        inc.summary = summarizer.summarize(inc)
    return sorted(incidents, key=lambda i: i.risk_score, reverse=True)
