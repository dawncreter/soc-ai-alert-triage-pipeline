"""Run the pipeline on synthetic traffic and print the analyst queue.

    soc-triage demo [--hosts 200]
"""
from __future__ import annotations

import argparse

from .pipeline import run
from .synthetic import generate


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="soc-triage")
    sub = ap.add_subparsers(dest="cmd", required=True)
    demo = sub.add_parser("demo")
    demo.add_argument("--hosts", type=int, default=200)
    args = ap.parse_args(argv)

    payloads, truth = generate(hosts=args.hosts)
    report = run(payloads)
    print("Analyst queue")
    print("-------------")
    for inc in report.queue:
        print(f"[{inc.incident_id}] risk {inc.risk_score:>5.1f}  {inc.action:<8} {inc.summary}")
    print("\nMetrics")
    for k, v in report.metrics(truth).items():
        print(f"  {k:<20} {v}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
