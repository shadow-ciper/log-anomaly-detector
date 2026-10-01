from datetime import datetime

from logdetector.detectors import (
    detect_brute_force,
    detect_new_source_login,
    detect_off_hours,
    detect_volume_anomaly,
)
from logdetector.events import parse_line

YEAR = 2026


def line(msg: str, ts: str = "Mar 14 10:00:00", host: str = "web-01", prog: str = "sshd"):
    return f"{ts} {host} {prog}[1234]: {msg}"


def evt(msg: str, **kw):
    event = parse_line(line(msg, **kw), YEAR)
    assert event is not None
    return event


def test_parses_failed_password():
    e = evt("Failed password for invalid user admin from 203.0.113.44 port 22 ssh2")
    assert e.event_type == "auth_failure"
    assert e.user == "admin"
    assert e.src_ip == "203.0.113.44"
    assert e.action == "deny"


def test_parses_accepted_password():
    e = evt("Accepted password for deploy from 198.51.100.7 port 22 ssh2")
    assert e.event_type == "auth_success"
    assert e.user == "deploy"
    assert e.action == "allow"


def test_parses_session_open():
    e = evt("pam_unix(sshd:session): session opened for user deploy")
    assert e.event_type == "session_open"
    assert e.user == "deploy"


def test_ignores_unrelated_services():
    assert parse_line("Mar 14 10:00:00 web-01 CRON[999]: (root) CMD (ls)", YEAR) is None


def test_keeps_unrecognised_sshd_lines():
    e = evt("Received disconnect from 203.0.113.9 port 40000")
    assert e is not None
    assert e.event_type == "auth_other"


def test_brute_force_fires_once_at_threshold():
    events = [
        evt(f"Failed password for root from 203.0.113.{n} port 22 ssh2",
            ts=f"Mar 14 10:0{n}:00")
        for n in range(6)
    ]
    findings = detect_brute_force(events, window_minutes=10, threshold=5)
    # Threshold 5 means one finding, not six.
    assert len(findings) == 1
    assert findings[0].rule == "BRUTE_FORCE"
    assert findings[0].user == "root"


def test_brute_force_reports_single_attack_once():
    # Same host hammering one account trips both the per-user and the per-IP
    # counter. That is one attack and must surface as one finding.
    events = [
        evt("Failed password for root from 203.0.113.77 port 22 ssh2",
            ts=f"Mar 14 10:{n:02d}:00")
        for n in range(12)
    ]
    findings = detect_brute_force(events, window_minutes=10, threshold=5)
    assert len(findings) == 1
    assert "user root" in findings[0].detail
    assert "source 203.0.113.77" in findings[0].detail


def test_brute_force_re_arms_after_quiet_period():
    early = [
        evt("Failed password for root from 203.0.113.77 port 22 ssh2",
            ts=f"Mar 14 10:{n:02d}:00")
        for n in range(6)
    ]
    late = [
        evt("Failed password for root from 203.0.113.77 port 22 ssh2",
            ts=f"Mar 14 12:{n:02d}:00")
        for n in range(6)
    ]
    findings = detect_brute_force(early + late, window_minutes=10, threshold=5)
    assert len(findings) == 2


def test_new_source_quiet_without_history():
    events = [
        evt("Accepted publickey for deploy from 10.10.1.5 port 22 ssh2",
            ts="Mar 14 10:00:00")
    ]
    assert detect_new_source_login(events) == []


def test_new_source_flags_rare_source_when_others_recur():
    events = [
        evt("Accepted publickey for deploy from 10.10.1.5 port 22 ssh2",
            ts=f"Mar 1{day} 10:00:00")
        for day in range(1, 5)
    ] + [
        evt("Accepted publickey for deploy from 10.10.2.7 port 22 ssh2",
            ts=f"Mar 1{day} 11:00:00")
        for day in range(1, 5)
    ]
    events.append(
        evt("Accepted password for deploy from 198.51.100.23 port 22 ssh2",
            ts="Mar 14 12:00:00")
    )
    findings = detect_new_source_login(events)
    assert len(findings) == 1
    assert findings[0].src_ip == "198.51.100.23"


def test_new_source_does_not_flag_ordinary_recurring_hosts():
    # Regression: a single-pass "seen before" check flags every new IP once an
    # account has any history, which flagged all of these. Recurring sources
    # must stay silent.
    events = []
    for day in range(1, 6):
        for host in range(1, 4):
            events.append(
                evt(f"Accepted publickey for deploy from 10.10.1.{host} port 22 ssh2",
                    ts=f"Mar 1{day} {9 + host:02d}:00:00")
            )
    assert detect_new_source_login(events) == []


def test_new_source_respects_known_baseline():
    events = [
        evt("Accepted publickey for deploy from 10.10.1.5 port 22 ssh2",
            ts=f"Mar 1{day} 10:00:00")
        for day in range(1, 5)
    ] + [
        evt("Accepted publickey for deploy from 10.10.2.7 port 22 ssh2",
            ts=f"Mar 1{day} 11:00:00")
        for day in range(1, 5)
    ] + [
        evt("Accepted password for deploy from 198.51.100.23 port 22 ssh2",
            ts="Mar 14 12:00:00")
    ]
    # 198.51.100.23 is a known normal jump host, seeded from an earlier window.
    findings = detect_new_source_login(
        events, known_sources={"deploy": {"198.51.100.23"}}
    )
    assert findings == []


def test_brute_force_ignores_spread_out_attempts():
    events = [
        evt(f"Failed password for root from 203.0.113.{n} port 22 ssh2",
            ts=f"Mar 14 {10 + n:02d}:00:00")
        for n in range(6)
    ]
    assert detect_brute_force(events, window_minutes=10, threshold=5) == []


def test_brute_force_detects_single_user_from_many_hosts():
    events = [
        evt(f"Failed password for oracle from 198.51.100.{n} port 22 ssh2",
            ts=f"Mar 14 10:0{n}:00")
        for n in range(5)
    ]
    findings = detect_brute_force(events, threshold=5)
    assert any(f.user == "oracle" for f in findings)


def test_off_hours_only_matches_window():
    assert detect_off_hours([evt("Accepted password for deploy from 198.51.100.7 port 22",
                                 ts="Mar 14 03:00:00")])
    assert not detect_off_hours([evt("Accepted password for deploy from 198.51.100.7 port 22",
                                     ts="Mar 14 11:00:00")])


def test_volume_rule_needs_enough_history():
    events = [evt("Failed password for root from 203.0.113.1 port 22",
                  ts="Mar 14 10:00:00")]
    assert detect_volume_anomaly(events, min_history_days=5) == []


def test_volume_rule_flags_outlier_day():
    # Varied baseline so the z-score path is exercised, not the flat-baseline
    # fallback. Real days are never identical.
    events = []
    counts = {1: 2, 2: 4, 3: 3, 4: 5, 5: 2, 6: 4, 7: 30}
    for day, n in counts.items():
        for i in range(n):
            events.append(
                evt(f"Failed password for root from 203.0.113.{i} port 22",
                    ts=f"Mar {day:02d} 10:00:00")
            )
    findings = detect_volume_anomaly(events, z_threshold=3.0, min_history_days=5)
    assert len(findings) == 1
    assert "30 failures" in findings[0].detail
    assert "no variance" not in findings[0].detail


def test_volume_rule_handles_flat_baseline():
    events = []
    for day in range(1, 8):
        n = 20 if day == 7 else 2
        for i in range(n):
            events.append(
                evt(f"Failed password for root from 203.0.113.{i} port 22",
                    ts=f"Mar {day:02d} 10:00:00")
            )
    findings = detect_volume_anomaly(events, z_threshold=3.0, min_history_days=5)
    assert len(findings) == 1
    assert "no variance" in findings[0].detail


def test_volume_rule_does_not_flag_quiet_day_against_loud_baseline():
    events = []
    counts = {1: 20, 2: 22, 3: 18, 4: 21, 5: 19, 6: 20, 7: 2}
    for day, n in counts.items():
        for i in range(n):
            events.append(
                evt(f"Failed password for root from 203.0.113.{i} port 22",
                    ts=f"Mar {day:02d} 10:00:00")
            )
    # A drop in volume is not brute force, so the rule should stay quiet.
    assert detect_volume_anomaly(events, z_threshold=3.0, min_history_days=5) == []