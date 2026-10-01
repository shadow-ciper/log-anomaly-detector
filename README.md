# log-anomaly-detector

Authentication log triage for Linux hosts. Parses syslog `sshd`/`sudo`/`pam` output
and surfaces authentication patterns worth an analyst's time.

The goal is a short, readable finding list — not a verdict. Every rule here is a
heuristic, and every rule can be wrong. What it does is collapse thousands of log
lines into the handful a human should actually look at.

## Quick start

```bash
git clone https://github.com/shadow-ciper/log-anomaly-detector
cd log-anomaly-detector
pip install -e .
logdetector samples/auth.log --year 2026
```

On the bundled sample that reports 3 findings from 46 events:

```
[1] HIGH   BRUTE_FORCE      2026-03-15 23:06:00  5 failures against user root within 10 minutes
[2] HIGH   BRUTE_FORCE      2026-03-15 23:24:00  5 failures against source 203.0.113.77 within 10 minutes
[3] LOW    OFF_HOURS_LOGIN  2026-03-15 23:42:00  Success at 23:42 local log time (user=oracle)
```

That sample contains a small password-spray followed by a successful login. Rule 1
catches the spray, rule 3 catches the intruder getting in afterwards.

## The rules

**`brute-force`** — Counts authentication failures per user *and* per source IP
over a rolling window, default 10 minutes / 5 failures. Both keys are needed: a
spray walks many accounts from one host (visible only on the IP key), while a
crack hammers one account from many hosts (visible only on the user key). Findings
from the two keys are merged so one attack produces one row.

**`new-source`** — Flags a successful login from an IP used exactly once by an
account whose other sources all recur. Two-pass over the whole input. A
single-pass "have I seen this IP" check flags every new source the moment an
account has any history, which on any real fleet means it flags everything.

**`off-hours`** — Successes outside a configurable window, default 22:00–06:00.
Deliberately noisy: night shifts, on-call rotations, and timezone drift between
the log host and the analyst all produce hits.

**`volume`** — Days whose failure count is an outlier against the baseline of all
other days. Needs at least 5 days. Handles a flat baseline (zero variance) where
no z-score is meaningful.

## Usage

```bash
# subset of rules
logdetector auth.log secure.log --year 2026 --rules brute-force,off-hours

# machine-readable output
logdetector auth.log --year 2026 --json

# multiple files across hosts
logdetector /var/log/auth.log /backup/auth.log.1 --year 2026
```

`--year` is required because syslog timestamps carry no year. Getting it wrong
silently reorders the input, which quietly breaks every time-window rule.

Exit code is 0 whether or not findings exist, so this drops into a pipeline
without a `set -e` blowing up on a quiet log. Findings go to stdout, errors to
stderr.

## Design notes

Two things cost real debugging time and are worth knowing about if you extend this:

**Time windows are the whole ballgame.** Both `brute-force` and `volume` are
one-pass over chronologically sorted events. The events are sorted in
`read_events` before any rule runs. Feeding unsorted input produces windows that
silently undercount.

**Statistical rules must not grade their own homework.** `volume` originally
computed its baseline including the day under test, so a single large spike
raised the standard deviation enough to push its own z-score back under the
threshold — precisely the day it existed to catch. The baseline now excludes the
day being scored.

## Known limitations

- **No rule correlation.** A spray (rule 2) followed by an off-hours success
  (rule 3) is two findings, not one linked incident. The sample output shows the
  relationship to a human reader; the tool does not make it explicit. This is the
  most obvious next feature.
- **Single timezone.** Timestamps are naive and compared as logged. Hosts in
  different zones will produce spurious off-hours hits.
- **`min_history` in `new-source` defaults to 2 distinct sources.** Accounts that
  legitimately log in from exactly one host are never flagged by that rule.
- **IPv6 regex is approximate.** It matches colon-separated groups broadly rather
  than validating address structure.

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

19 tests, run in CI on Python 3.10 and 3.12. Several are regression tests for
specific bugs found during development — the dedupe window scoping and the
baseline exclusion in `volume` each have one, because both were easy to
reintroduce.

## Layout

```
src/logdetector/
  events.py       syslog parsing into Event objects
  detectors.py    the four rules, plus merge/scoping helpers
  cli.py          argument handling and report rendering
tests/
samples/auth.log  synthetic sample with an embedded spray + successful login
```