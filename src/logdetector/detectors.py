from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta

from .events import Event


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    ts: datetime
    user: str | None
    src_ip: str | None
    detail: str
    evidence: list[str]
    count: int = 1


# --- rule 1: brute force -------------------------------------------------
# Counts failures per key over a rolling window. One burst per key is reported
# rather than one per failure, otherwise a 5000-attempt run produces 5000 rows
# and the analyst stops reading the output.


def detect_brute_force(
    events: list[Event], window_minutes: int = 10, threshold: int = 5
) -> list[Finding]:
    findings: list[Finding] = []
    buckets: dict[tuple[str, str], deque[Event]] = defaultdict(deque)
    reported_at: dict[tuple[str, str], datetime] = {}

    for event in events:
        if event.event_type != "auth_failure":
            continue
        cutoff = event.ts - timedelta(minutes=window_minutes)
        for key in _brute_force_keys(event):
            bucket = buckets[key]
            bucket.append(event)
            while bucket and bucket[0].ts < cutoff:
                bucket.popleft()

            # A single attack trips both the user key and the IP key, so the
            # same burst would otherwise be reported twice. One finding per key
            # per window is enough; re-arm only after the key goes quiet.
            last = reported_at.get(key)
            if last is not None and event.ts - last < timedelta(minutes=window_minutes):
                continue

            if len(bucket) >= threshold:
                subject = f"user {event.user}" if key[0] == "user" else f"source {event.src_ip}"
                findings.append(
                    Finding(
                        rule="BRUTE_FORCE",
                        severity="high",
                        title=f"{len(bucket)} failed logins in {window_minutes}m",
                        ts=event.ts,
                        user=event.user,
                        src_ip=event.src_ip,
                        detail=(
                            f"{len(bucket)} failures against {subject} "
                            f"within {window_minutes} minutes"
                        ),
                        evidence=[e.raw for e in bucket],
                        count=len(bucket),
                    )
                )
                reported_at[key] = event.ts
    return _dedupe(findings, window_minutes=window_minutes)


def _brute_force_keys(event: Event) -> list[tuple[str, str]]:
    """A burst counts if either the user or the source IP repeats.

    Both matter and they catch different attacks: password spraying walks the
    user list from one host, while a single host hammering one account shows up
    only on the IP side.
    """
    keys = []
    if event.user:
        keys.append(("user", event.user))
    if event.src_ip:
        keys.append(("ip", event.src_ip))
    return keys


# --- shared helper -------------------------------------------------------


def _dedupe(findings: list[Finding], window_minutes: int | None = None) -> list[Finding]:
    """Collapse findings that describe the same activity from different angles.

    Brute force trips both the per-user and the per-IP counter. Those two
    records are one attack and must reach the analyst as one row.

    `window_minutes` scopes the merge. Without it, two genuinely separate
    attacks against the same account from the same host hours apart collapse
    into a single finding, which would hide the second one entirely.
    """
    merged: dict[tuple, Finding] = {}
    order: list[tuple] = []

    for f in findings:
        if window_minutes is None:
            key = (f.rule, f.user or "", f.src_ip or "")
        else:
            bucket = int(f.ts.timestamp() // (window_minutes * 60))
            key = (f.rule, f.user or "", f.src_ip or "", bucket)

        if key not in merged:
            merged[key] = f
            order.append(key)
            continue

        existing = merged[key]
        existing.count = max(existing.count, f.count)
        if f.detail not in existing.detail:
            existing.detail += f"; {f.detail}"
        seen = set(existing.evidence)
        existing.evidence = list(existing.evidence) + [
            line for line in f.evidence if line not in seen
        ]

    return [merged[k] for k in order]


# --- rule 2: successful login from an unfamiliar source ------------------


def detect_new_source_login(
    events: list[Event],
    known_sources: dict[str, set[str]] | None = None,
    min_history: int = 2,
) -> list[Finding]:
    """Flag a success from an IP the account essentially never uses.

    Two passes. The first counts successes per (user, source) across the whole
    input. The second flags sources that appear exactly once, for accounts that
    have a normal recurring pattern elsewhere.

    Deciding this needs the entire log. A single-pass "have I seen this IP
    before" check reports every new source the moment an account has any
    history, which for any fleet with more than one subnet means it reports
    everything.

    `known_sources` seeds the baseline with sources seen outside this log, so a
    source that recurs regularly in an earlier window is not flagged when a
    later window is analysed on its own.
    """
    seeded: dict[str, set[str]] = defaultdict(set)
    for user, ips in (known_sources or {}).items():
        seeded[user].update(ips)

    source_counts: dict[tuple[str, str], int] = defaultdict(int)
    for event in events:
        if event.event_type == "auth_success" and event.user and event.src_ip:
            source_counts[(event.user, event.src_ip)] += 1

    by_user: dict[str, set[str]] = defaultdict(set)
    for (user, ip), _ in source_counts.items():
        by_user[user].add(ip)

    findings: list[Finding] = []
    for (user, ip), count in sorted(source_counts.items()):
        if ip in seeded.get(user, set()):
            continue
        # The account needs enough distinct sources for "one of these is odd" to
        # mean anything.
        if len(by_user[user]) < min_history + 1:
            continue
        if count > 1:
            continue

        others = [
            s for (u, s), c in source_counts.items() if u == user and c > 1
        ]
        if not others:
            # Every source is a singleton. Nothing is unusual here, we simply
            # have too little data to say anything.
            continue

        event = next(
            e
            for e in events
            if e.event_type == "auth_success" and e.user == user and e.src_ip == ip
        )
        findings.append(
            Finding(
                rule="NEW_SOURCE_LOGIN",
                severity="medium",
                title="Successful login from a source used once in this window",
                ts=event.ts,
                user=user,
                src_ip=ip,
                detail=(
                    f"{ip} appears once for {user}; "
                    f"{len(set(others))} other source(s) for this account recur"
                ),
                evidence=[event.raw],
            )
        )

    return _dedupe(findings)


# --- rule 3: off-hours authentication ------------------------------------


def detect_off_hours(
    events: list[Event], start_hour: int = 22, end_hour: int = 6
) -> list[Finding]:
    """Flag successes that fall outside the organisation's normal working hours.

    Defaults cover a 22:00-06:00 window. Note this is a proxy for "unusual" and
    will fire on legitimate night shifts and on timezone differences between the
    log source and the analyst, so treat it as a triage aid.
    """
    findings: list[Finding] = []
    for event in events:
        if event.event_type != "auth_success":
            continue
        hour = event.ts.hour
        in_window = hour >= start_hour or hour < end_hour
        if not in_window:
            continue
        findings.append(
            Finding(
                rule="OFF_HOURS_LOGIN",
                severity="low",
                title="Authentication outside business hours",
                ts=event.ts,
                user=event.user,
                src_ip=event.src_ip,
                detail=f"Success at {event.ts:%H:%M} local log time",
                evidence=[event.raw],
            )
        )
    return _dedupe(findings)


# --- rule 4: activity volume baseline ------------------------------------


def detect_volume_anomaly(
    events: list[Event], z_threshold: float = 3.0, min_history_days: int = 5
) -> list[Finding]:
    """Flag days whose auth-failure count is an outlier against the baseline.

    Mean and standard deviation over all observed days, then per-day counts.
    With a handful of days this is weak; min_history_days guards against firing
    on a sample too small to have a distribution at all.
    """
    per_day: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.event_type != "auth_failure":
            continue
        per_day[event.ts.date().isoformat()].append(event)

    if len(per_day) < min_history_days:
        return []

    # Baseline stats are recomputed with the day under test excluded. Including
    # it lets a single large spike raise the standard deviation enough to push
    # its own z-score back under the threshold, which is exactly the day we
    # care about.
    findings: list[Finding] = []
    for day, day_events in sorted(per_day.items()):
        baseline = [len(v) for d, v in per_day.items() if d != day]
        n = len(baseline)
        mean = sum(baseline) / n
        variance = sum((c - mean) ** 2 for c in baseline) / (n - 1)
        std = variance**0.5

        if std == 0:
            # Every other day had an identical count. There is no spread to
            # measure against, so fall back to a plain comparison: anything
            # above the flat baseline stands out no matter how the z-score
            # would be defined.
            if len(day_events) <= mean:
                continue
            z = float("inf")
        else:
            z = (len(day_events) - mean) / std
            if z < z_threshold:
                continue
        worst = max(day_events, key=lambda e: (e.user or "", e.src_ip or ""))
        findings.append(
            Finding(
                rule="VOLUME_ANOMALY",
                severity="medium",
                title=(
                    f"Failure volume {z:.1f} sigma above baseline"
                    if z != float("inf")
                    else "Failure volume far above a flat baseline"
                ),
                ts=worst.ts,
                user=worst.user,
                src_ip=worst.src_ip,
                detail=(
                    f"{day}: {len(day_events)} failures vs baseline "
                    f"mean {mean:.1f} over {n} other days"
                    + (f" (sd {std:.1f})" if std else " (no variance)")
                ),
                evidence=[e.raw for e in day_events[:5]],
                count=len(day_events),
            )
        )
    return findings


ALL_RULES = {
    "brute-force": detect_brute_force,
    "new-source": detect_new_source_login,
    "off-hours": detect_off_hours,
    "volume": detect_volume_anomaly,
}


def run_all(events: list[Event], enabled: set[str] | None = None) -> list[Finding]:
    enabled = enabled or set(ALL_RULES)
    findings: list[Finding] = []
    for name, rule in ALL_RULES.items():
        if name in enabled:
            findings.extend(rule(events))
    findings.sort(key=lambda f: f.ts)
    return findings