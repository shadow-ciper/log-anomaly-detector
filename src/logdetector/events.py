from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Event:
    """One parsed log line. Anything we could not pull out stays in raw."""

    ts: datetime
    source: str
    event_type: str
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    action: str | None = None
    raw: str = ""
    fields: dict[str, str] = field(default_factory=dict)

    def get(self, key: str, default: str | None = None) -> str | None:
        return self.fields.get(key, default)


FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-f.:]+)"
)
ACCEPTED_PASSWORD = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[0-9a-f.:]+)"
)
SESSION_OPEN = re.compile(r"session opened for user (?P<user>\S+)")
SESSION_CLOSED = re.compile(r"session closed for user (?P<user>\S+)")

SYSLOG_TS = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<prog>[^:]+):\s*(?P<msg>.*)$"
)

IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}\b")

MONTHS = {
    m: i
    for i, m in enumerate(
        "jan feb mar apr may jun jul aug sep oct nov dec".split(), start=1
    )
}


def _parse_syslog_ts(mon: str, day: str, clock: str, year: int) -> datetime:
    hh, mm, ss = (int(p) for p in clock.split(":"))
    return datetime(year, MONTHS[mon.lower()], int(day), hh, mm, ss)


def parse_line(line: str, year: int) -> Event | None:
    """Turn a single syslog line into an Event, or None if it isn't interesting.

    We only build events for authentication traffic. Everything else in a real
    log file is noise for this tool's purposes and parsing it would cost more
    than it buys.
    """
    line = line.rstrip("\n")
    head = SYSLOG_TS.match(line)
    if not head:
        return None

    ts = _parse_syslog_ts(head["mon"], head["day"], head["clock"], year)
    source = head["host"]
    message = head["msg"]
    program = head["prog"].split("[")[0]

    if m := FAILED_PASSWORD.search(message):
        return Event(
            ts=ts,
            source=source,
            event_type="auth_failure",
            user=m["user"],
            src_ip=m["ip"],
            action="deny",
            raw=line,
            fields={"program": program},
        )

    if m := ACCEPTED_PASSWORD.search(message):
        return Event(
            ts=ts,
            source=source,
            event_type="auth_success",
            user=m["user"],
            src_ip=m["ip"],
            action="allow",
            raw=line,
            fields={"program": program},
        )

    if m := SESSION_OPEN.search(message):
        return Event(
            ts=ts,
            source=source,
            event_type="session_open",
            user=m["user"],
            action="allow",
            raw=line,
            fields={"program": program},
        )

    if m := SESSION_CLOSED.search(message):
        return Event(
            ts=ts,
            source=source,
            event_type="session_close",
            user=m["user"],
            action="close",
            raw=line,
            fields={"program": program},
        )

    # Keep unrecognised sshd/auth lines around. Analysts want to see what the
    # parser missed rather than find out three months later.
    if program in {"sshd", "sudo", "su", "pam_unix", "login"}:
        ips = IP.findall(message)
        return Event(
            ts=ts,
            source=source,
            event_type="auth_other",
            user=_guess_user(message),
            src_ip=ips[0] if ips else None,
            raw=line,
            fields={"program": program},
        )

    return None


def _guess_user(message: str) -> str | None:
    m = re.search(r"user(?:name)?[= ]+(?P<u>[a-zA-Z0-9._-]+)", message)
    return m["u"] if m else None


def read_events(paths: list[str], year: int) -> list[Event]:
    events: list[Event] = []
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if event := parse_line(line, year):
                    events.append(event)
    events.sort(key=lambda e: e.ts)
    return events