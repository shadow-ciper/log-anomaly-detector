"""Authentication log anomaly detection.

Parses syslog-style auth logs and applies a small set of heuristic rules to
surface events worth an analyst's time. Every rule is deliberately noisy and
triage-oriented; none of them decide whether anything is malicious.
"""

__version__ = "0.1.0"

from .detectors import ALL_RULES, Finding, run_all
from .events import Event, parse_line, read_events

__all__ = [
    "ALL_RULES",
    "Event",
    "Finding",
    "parse_line",
    "read_events",
    "run_all",
]