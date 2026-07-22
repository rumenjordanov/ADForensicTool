# ADForensicTool

[![Tests](https://github.com/rumenjordanov/ADForensicTool/actions/workflows/tests.yml/badge.svg)](https://github.com/rumenjordanov/ADForensicTool/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Analyzes Windows/Active Directory **Security** event logs (`.evtx` exports
from Domain Controllers) after a suspected breach and reconstructs an
attack narrative — flagged events stitched into chains showing how an
attacker moved through the environment (brute force → successful logon →
privilege escalation → persistence). Output is a polished, analyst-ready
Excel workbook.

> Status: early / actively developed. Parsing and 4 detections
> (brute force, privilege escalation, audit-log-cleared, kerberoasting) work
> end to end. Cross-event correlation (attack chains) and plain-English
> narration are stubbed — see [Roadmap](#roadmap).

Want to see the output before installing anything? [`examples/sample_report.xlsx`](examples/sample_report.xlsx)
is a full report built from synthetic data (no real logs involved) covering
all 4 detections — download and open it directly. Regenerate it any time
with `python examples/generate_sample_report.py`.

## Install

Requires Python 3.11+.

```bash
git clone <this-repo-url>
cd ADForensicTool
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

For running the test suite:

```bash
pip install -r requirements-dev.txt
```

## Usage

```bash
python main.py --input path/to/security.evtx --output report.xlsx
```

Optional: point at a custom detection rules file (see [Detection rules](#detection-rules)):

```bash
python main.py --input security.evtx --output report.xlsx --rules my_rules.yaml
```

The input file is a `Security.evtx` export from a Domain Controller (or any
Windows host's Security log). Export one from Event Viewer via
*Windows Logs → Security → Save All Events As...*, or copy the file directly
from `C:\Windows\System32\winevt\Logs\Security.evtx` on the source host.

Other flags: `--rules <path>` (custom detection rules, see below), `--debug`
(show a full traceback on failure instead of a one-line error), `--version`.

## What's in the report

| Tab | Contents |
|---|---|
| Executive Summary | Branded dashboard: risk score + KPI tiles, native charts (findings by severity, findings by rule), key findings as bullets |
| Attack Chains | Flagged events grouped by rule (real multi-stage chains pending correlator implementation — see Roadmap) |
| Raw Flagged Events | Full detail table of every flagged event, color-coded by severity, filterable (autofilter enabled) |
| Account/Group Changes | Dedicated view of privileged-group membership changes |
| MITRE ATT&CK Coverage | Technique → observed-count table with a color-scale heatmap and a bar chart |

The Executive Summary tab is meant to be handed to a non-technical
stakeholder as-is: a title banner with the source filename and generation
timestamp, five KPI tiles (overall risk score, events parsed, events
flagged, critical/high counts), two charts, and a plain-language bullet
list of what fired and when. Visual styling (colors, fonts) is centralized
in [`excel_export/theme.py`](excel_export/theme.py) so every tab shares one
consistent look.

## Detection rules

Rules live in [`rules/default_rules.yaml`](rules/default_rules.yaml) and are
loaded by [`rules/engine.py`](rules/engine.py). Three rule *types* cover
everything that doesn't need cross-event-ID correlation:

- **threshold** — N+ matching events for the same actor within a time
  window (e.g. brute force: 5+ `4625`s for one user in 10 minutes)
- **always_flag** — every matching event is inherently suspicious
  (e.g. `1102` audit log cleared, `4728`/`4732`/`4756` privileged group changes)
- **field_match** — a raw event field equals one of a set of values
  (e.g. kerberoasting: `4769` with `TicketEncryptionType == 0x17`)

Add a new detection by adding an entry to the YAML — no code changes needed
unless it requires a new rule *type*. See the comments at the top of
`default_rules.yaml` for the full schema.

## Architecture

```
main.py               CLI entry point
console.py             Colored terminal output helpers ([*]/[+]/[!]/[-])
version.py              Single source of truth for the version string
parser/                .evtx -> normalized pandas DataFrame
rules/                 YAML-driven detection engine
correlator/             STUB: links flagged events into multi-stage chains
narrator/               STUB: turns chains into plain-English sentences
excel_export/           Builds the .xlsx report (theme.py holds the shared design system)
tests/                  pytest suite (synthetic event XML, no real .evtx needed)
```

The normalized DataFrame produced by `parser.evtx_parser.parse_evtx` has
these columns: `timestamp`, `event_id`, `user`, `source_ip`, `target_host`,
`logon_type`, `process_name`, `raw_message`, plus `event_data` (a dict of
every raw field on the event, for rule-specific logic that doesn't fit the
common schema).

## Testing

```bash
pytest
```

The suite parses synthetic Windows Security event XML (see
[`tests/fixtures/sample_events.py`](tests/fixtures/sample_events.py)) rather
than a real `.evtx` binary, so it runs without any lab environment. If
you're testing against a real `.evtx` from a lab VM, just point `main.py` at
it directly — the CLI path is exercised the same way either way. CI runs the
full suite on Python 3.11 and 3.12, on both Linux and Windows, on every
push/PR (see [`.github/workflows/tests.yml`](.github/workflows/tests.yml)).

All 4 wired detections have also been validated end-to-end against a real
isolated Active Directory lab (Windows Server, fresh forest), not just
synthetic fixtures — including catching a real parsing bug where
`TicketEncryptionType` is zero-padded (`0x00000017`) in raw event XML rather
than the short form (`0x17`) shown in tools like `Get-WinEvent`'s friendly
message rendering. `rules/engine.py` normalizes both forms to ints before
comparing, and there's a regression test for it.

## Roadmap

- [ ] `correlator/chain_builder.py` — link flagged events across different
      rules into real attack chains (see the design notes in that file's
      docstring)
- [ ] `narrator/narrate.py` — turn chains into timestamp-anchored sentences
- [ ] Successful-logon-after-brute-force and new-service/task-after-suspicious-logon
      detections (need correlation, not expressible by the current
      single-event-ID rule engine)
- [ ] Multi-file / multi-DC input support

## Contributing

New detections that fit the existing rule types (`threshold`, `always_flag`,
`field_match`) only require an addition to `rules/default_rules.yaml`. New
rule *types* go in `rules/engine.py`. PRs welcome.

## License

MIT — see [LICENSE](LICENSE).
