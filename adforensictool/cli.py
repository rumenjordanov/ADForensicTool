"""
ADForensicTool CLI entry point.

Usage:
    adforensictool --input path/to/security.evtx --output report.xlsx
    python -m adforensictool ...   (or python main.py ... from a source checkout)
"""
from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

import yaml

from adforensictool import console
from adforensictool.excel_export.report import build_report
from adforensictool.parser.evtx_parser import ParseStats, parse_evtx
from adforensictool.rules.allowlist import AllowEntry, apply_allowlist, load_allowlist, unknown_rule_references
from adforensictool.rules.engine import DEFAULT_RULES_PATH, RuleError, apply_rules, load_rules
from adforensictool.version import __version__

T = TypeVar("T")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ADForensicTool",
        description="Reconstruct an attack narrative from a Security.evtx export.",
    )
    parser.add_argument("--input", required=True, help="Path to a Security.evtx file")
    parser.add_argument("--output", required=True, help="Path to write the .xlsx report to")
    parser.add_argument(
        "--rules",
        default=str(DEFAULT_RULES_PATH),
        help="Path to a detection rules YAML file (default: rules/default_rules.yaml)",
    )
    parser.add_argument(
        "--allowlist",
        help="YAML file of known-benign activity to suppress from the results (see rules/allowlist.py)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show full tracebacks on failure instead of a one-line error message",
    )
    parser.add_argument("--version", action="version", version=f"ADForensicTool {__version__}")
    return parser.parse_args(argv)


def _load_config(loader: Callable[[Path], T], path: Path, kind: str) -> T | None:
    """Run a YAML config loader, turning expected failures into one clean
    error line. Returns None on failure (already reported)."""
    if not path.is_file():
        console.error(f"{kind} file not found: {path}")
        return None
    try:
        return loader(path)
    except yaml.YAMLError as exc:
        console.error(f"malformed {kind} file {path}: {exc}")
    except RuleError as exc:
        console.error(f"invalid {kind} file {path}: {exc}")
    return None


def _run(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    if not input_path.is_file():
        console.error(f"input file not found: {input_path}")
        return 1

    # Load all configuration before parsing: a typo in a rules/allowlist
    # file should fail in a second, not after minutes spent parsing a log.
    rules_path = Path(args.rules)
    console.info(f"Loading rules from {rules_path} ...")
    rules = _load_config(load_rules, rules_path, "rules")
    if rules is None:
        return 1
    if rules:
        console.success(f"Loaded {len(rules)} rule(s)")
    else:
        console.warn(f"{rules_path} contains no rules -- nothing will be flagged")

    allowlist: list[AllowEntry] = []
    if args.allowlist:
        allowlist_path = Path(args.allowlist)
        loaded = _load_config(load_allowlist, allowlist_path, "allowlist")
        if loaded is None:
            return 1
        allowlist = loaded
        console.success(f"Loaded {len(allowlist)} allowlist entr{'y' if len(allowlist) == 1 else 'ies'}")
        for rule_id in unknown_rule_references(allowlist, {r.id for r in rules}):
            console.warn(f"allowlist refers to unknown rule '{rule_id}' (typo?) -- that scope matches nothing")

    console.info(f"Parsing {input_path} ...")

    def _report_progress(count: int) -> None:
        console.progress(f"Parsing {input_path} ... {count} record(s) processed")

    stats = ParseStats()
    df = parse_evtx(str(input_path), progress_callback=_report_progress, stats=stats)
    console.progress_done()
    console.success(f"Parsed {len(df)} event(s)")
    if stats.records_skipped:
        console.warn(
            f"{stats.records_skipped} of {stats.records_read} record(s) could not be parsed and were skipped "
            "(corrupted export or possible tampering -- verify the source log)"
        )

    console.info("Applying detection rules ...")
    flagged = apply_rules(df, rules)
    flagged, suppressed = apply_allowlist(flagged, allowlist)
    console.success(f"{len(flagged)} event(s) flagged")
    for description, count in suppressed.items():
        console.info(f"  {count} flagged event(s) suppressed by allowlist: {description}")

    console.info(f"Writing report to {args.output} ...")
    build_report(
        df, flagged, rules, args.output, source_file=str(input_path), parse_stats=stats, suppressed=suppressed
    )
    console.success(f"Report written to {args.output}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return _run(args)
    except Exception as exc:
        if args.debug:
            raise
        console.error(f"{exc.__class__.__name__}: {exc} (re-run with --debug for a full traceback)")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
