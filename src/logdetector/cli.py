from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from .detectors import ALL_RULES, run_all
from .events import read_events

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="logdetector",
        description="Flag suspicious patterns in authentication logs.",
    )
    parser.add_argument("logs", nargs="+", help="log files to analyse")
    parser.add_argument(
        "--year",
        type=int,
        required=True,
        help="year to assume for timestamps (syslog omits it)",
    )
    parser.add_argument(
        "--rules",
        default="all",
        help="comma-separated subset of: " + ", ".join(sorted(ALL_RULES)),
    )
    parser.add_argument(
        "--json", action="store_true", help="emit findings as JSON instead of a table"
    )
    args = parser.parse_args(argv)

    enabled = None if args.rules == "all" else {r.strip() for r in args.rules.split(",")}
    unknown = (enabled or set()) - set(ALL_RULES)
    if unknown:
        parser.error(f"unknown rule(s): {', '.join(sorted(unknown))}")

    events = read_events(args.logs, args.year)
    if not events:
        print(
            "No authentication events parsed. Check that the files are syslog "
            "format and that --year is correct.",
            file=sys.stderr,
        )
        return 1

    findings = run_all(events, enabled)
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.ts))

    if args.json:
        print(json.dumps([_as_dict(f) for f in findings], indent=2))
    else:
        _print_report(events, findings)

    return 0 if findings else 0


def _as_dict(f) -> dict:
    return {
        "rule": f.rule,
        "severity": f.severity,
        "title": f.title,
        "timestamp": f.ts.isoformat(),
        "user": f.user,
        "src_ip": f.src_ip,
        "detail": f.detail,
        "evidence": f.evidence,
        "count": f.count,
    }


def _print_report(events, findings) -> None:
    print(f"\nParsed {len(events)} auth events from {len({e.source for e in events})} host(s)")
    by_type = Counter(e.event_type for e in events)
    print("  " + ", ".join(f"{k}={v}" for k, v in sorted(by_type.items())))

    if not findings:
        print("\nNo findings.")
        return

    print(f"\n{len(findings)} finding(s)\n")
    for i, f in enumerate(findings, 1):
        print(f"[{i}] {f.severity.upper():6} {f.rule}  {f.ts:%Y-%m-%d %H:%M:%S}")
        print(f"    {f.title}")
        print(f"    {f.detail}")
        print(f"    user={f.user or '-'}  src_ip={f.src_ip or '-'}")
        for line in f.evidence[:3]:
            print(f"      | {line}")
        if len(f.evidence) > 3:
            print(f"      | ... {len(f.evidence) - 3} more")
        print()


if __name__ == "__main__":
    raise SystemExit(main())