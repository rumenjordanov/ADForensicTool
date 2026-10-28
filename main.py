#!/usr/bin/env python3
"""Source-checkout convenience shim: `python main.py ...` runs the CLI.

The real entry point is adforensictool.cli (installed as the
`adforensictool` command, or `python -m adforensictool`).
"""
from adforensictool.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
