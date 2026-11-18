"""SOC AI alert triage: normalize EDR alerts to OCSF, map to MITRE ATT&CK, cluster, score and summarize."""
from .pipeline import TriageReport, run

__all__ = ["TriageReport", "run"]
__version__ = "0.1.0"
