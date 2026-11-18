from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from soctriage.api import app
from soctriage.cli import main
from soctriage.clustering import cluster, distance_matrix
from soctriage.mitre import enrich, map_techniques
from soctriage.normalizer import normalize
from soctriage.pipeline import run
from soctriage.schemas import Endpoint, SecurityAlert, Severity
from soctriage.synthetic import generate
from soctriage.triage import TemplateSummarizer, decide, risk_score, triage

T0 = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)


def alert(i, minutes=0, host="h1", proc="cmd.exe", cmd="", parent="explorer.exe", sev=Severity.LOW):
    return SecurityAlert(alert_id=str(i), time=T0 + timedelta(minutes=minutes), severity=sev, title="t",
                         endpoint=Endpoint(hostname=host, ip="10.0.0.1"), process_name=proc, command_line=cmd,
                         parent_process=parent)


# --- normalization -----------------------------------------------------------
def test_normalizes_both_vendor_formats_to_same_model():
    payloads, _ = generate(hosts=4, noise_per_host=2)
    a = next(p for p in payloads if p["vendor"] == "edr_a")
    b = next(p for p in payloads if p["vendor"] == "edr_b")
    na, nb = normalize(a), normalize(b)
    assert na.source == "edr_a" and nb.source == "edr_b"
    assert na.endpoint.hostname == na.endpoint.hostname.lower()
    assert nb.time.tzinfo is not None and 1 <= nb.severity <= 5


@pytest.mark.parametrize("payload", [{"vendor": "nope"}, {"vendor": "edr_a", "detection_id": "x"}])
def test_bad_payloads_raise_value_error(payload):
    with pytest.raises(ValueError):
        normalize(payload)


# --- MITRE mapping -----------------------------------------------------------
@pytest.mark.parametrize("cmd,expected", [
    ("powershell.exe -nop -enc SQBFAFgA", "T1059.001"),
    ("rundll32.exe comsvcs.dll MiniDump 624 lsass.dmp full", "T1003.001"),
    ("certutil.exe -urlcache -f http://x/a.dll a.dll", "T1105"),
    ("schtasks.exe /create /tn x /tr y", "T1053.005"),
    ("vssadmin.exe delete shadows /all /quiet", "T1490"),
])
def test_maps_known_techniques(cmd, expected):
    ids = [t.technique_id for t in map_techniques(alert(1, cmd=cmd, proc=cmd.split()[0]))]
    assert expected in ids


def test_benign_activity_maps_to_nothing():
    assert map_techniques(alert(1, proc="teams.exe", cmd="teams.exe --type=renderer", parent="teams.exe")) == []


# --- clustering ----------------------------------------------------------------
def test_clusters_by_host_and_time():
    alerts = [alert(1, 0), alert(2, 3), alert(3, 5, host="h2"), alert(4, 240)]
    incs = cluster(alerts)
    assert sorted(i.size for i in incs) == [1, 1, 2]
    assert [i.incident_id for i in incs] == ["INC-0001", "INC-0002", "INC-0003"]


def test_shared_lineage_pulls_alerts_closer():
    a, b = alert(1, 0, proc="powershell.exe"), alert(2, 10, proc="certutil.exe", parent="powershell.exe")
    c = alert(3, 10, proc="notepad.exe", parent="explorer2.exe")
    d = distance_matrix([a, b, c], timedelta(minutes=30))
    assert d[0, 1] < d[0, 2]
    assert cluster([]) == []


# --- triage ----------------------------------------------------------------------
def test_full_attack_chain_is_contained():
    chain = [enrich(alert(i, i, proc=p, cmd=c, parent="powershell.exe", sev=Severity.HIGH)) for i, (p, c) in
             enumerate([("rundll32.exe", "rundll32.exe comsvcs.dll MiniDump 1 lsass.dmp full"),
                        ("psexec.exe", "psexec.exe \\\\srv -s cmd.exe")])]
    inc = triage(cluster(chain))[0]
    assert inc.action == "contain" and inc.verdict == "true_positive"
    assert "Credential Access" in inc.summary and "CONTAIN" in inc.summary


def test_low_noise_is_suppressed_and_mid_risk_is_monitored():
    (inc,) = cluster([alert(1, proc="teams.exe", parent="teams.exe")])
    inc.risk_score = risk_score(inc)
    assert decide(inc) == ("benign", "suppress")
    (inc2,) = cluster([enrich(alert(2, proc="whoami.exe", cmd="whoami /all", sev=Severity.LOW))])
    inc2.risk_score = risk_score(inc2)
    assert decide(inc2) == ("needs_review", "monitor")


def test_single_credential_dump_is_escalated():
    (inc,) = cluster([enrich(alert(1, proc="rundll32.exe", cmd="rundll32.exe comsvcs.dll MiniDump 1 x full",
                                   sev=Severity.MEDIUM))])
    inc.risk_score = risk_score(inc)
    assert decide(inc)[1] in ("escalate", "contain")


def test_template_summarizer_handles_no_techniques():
    (inc,) = cluster([alert(1)])
    assert "no ATT&CK techniques" in TemplateSummarizer().summarize(inc)


# --- end to end ---------------------------------------------------------------------
def test_pipeline_finds_attacks_and_shrinks_the_queue():
    payloads, truth = generate(hosts=80)
    payloads.append({"vendor": "unknown"})
    report = run(payloads)
    m = report.metrics(truth)
    assert m["recall"] == 1.0 and m["precision"] == 1.0
    assert m["queue_reduction_pct"] > 95
    assert len(report.rejected) == 1
    assert report.metrics()["alerts_in"] == len(payloads)


def test_metrics_edge_cases():
    from soctriage.pipeline import TriageReport

    empty = TriageReport([], 0)
    assert empty.metrics(set()) == {"alerts_in": 0, "incidents": 0, "analyst_queue": 0, "suppressed": 0,
                                    "queue_reduction_pct": 0.0, "precision": 0.0, "recall": 1.0}


def test_api_and_cli(capsys):
    client = TestClient(app)
    assert client.get("/health").json() == {"status": "ok"}
    assert client.post("/triage", json=[]).status_code == 400
    payloads, _ = generate(hosts=8)
    body = client.post("/triage", json=payloads).json()
    assert {q["action"] for q in body["queue"]} <= {"contain", "escalate"} and body["queue"]
    assert main(["demo", "--hosts", "20"]) == 0
    assert "precision" in capsys.readouterr().out
