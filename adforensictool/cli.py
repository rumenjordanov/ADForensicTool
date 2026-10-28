"""
ADForensicTool CLI entry point.

Usage:
    adforensictool --input path/to/security.evtx --output report.xlsx
    python -m adforensictool ...   (or python main.py ... from a source checkout)
"""
from __future__ import annotations

import argparse
from pathlib import Path

import yaml

from adforensictool import console
from adforensictool.excel_export.report import build_report
from adforensictool.parser.evtx_parser import parse_evtx
from adforensictool.rules.engine import DEFAULT_RULES_PATH, apply_rules, load_rules
from adforensictool.version import __version__


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
        "--debug",
        action="store_true",
        help="Show full tracebacks on failure instead of a one-line error message",
    )
    parser.add_argument("--version", action="version", version=f"ADForensicTool {__version__}")
    return parser.parse_args(argv)


def _run(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    if not input_path.is_file():
        console.error(f"input file not found: {input_path}")
        return 1

    rules_path = Path(args.rules)
    if not rules_path.is_file():
        console.error(f"rules file not found: {rules_path}")
        return 1

    console.info(f"Parsing {input_path} ...")

    def _report_progress(count: int) -> None:
        console.progress(f"Parsing {input_path} ... {count} record(s) processed")

    df = parse_evtx(str(input_path), progress_callback=_report_progress)
    console.progress_done()
    console.success(f"Parsed {len(df)} event(s)")

    console.info(f"Loading rules from {rules_path} ...")
    try:
        rules = load_rules(rules_path)
    except yaml.YAMLError as exc:
        console.error(f"malformed rules file {rules_path}: {exc}")
        return 1
    console.success(f"Loaded {len(rules)} rule(s)")

    console.info("Applying detection rules ...")
    flagged = apply_rules(df, rules)
    console.success(f"{len(flagged)} event(s) flagged")

    console.info(f"Writing report to {args.output} ...")
    build_report(df, flagged, rules, args.output, source_file=str(input_path))
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
