"""Command-line interface for macsec."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .checks import available_checks, run_checks
from .models import CheckContext
from .report import render_human, render_json
from .runner import CommandRunner


def _csv(value: str) -> set[str]:
    return {part.strip() for part in value.split(",") if part.strip()}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="macsec",
        description="Read-only, deterministic macOS security and health audit.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--list-checks", action="store_true", help="list check IDs and exit")
    p.add_argument("--only", metavar="IDS", help="comma-separated check IDs to run")
    p.add_argument("--skip", metavar="IDS", help="comma-separated check IDs to skip")
    p.add_argument("--json", action="store_true", help="emit JSON instead of the human report")
    p.add_argument("--output", metavar="PATH", help="write the report to PATH")
    p.add_argument("--include-evidence", action="store_true",
                   help="include raw command evidence (may contain local paths)")
    p.add_argument("--ports", action="store_true", help="include the listening-port check")
    p.add_argument("--updates", action="store_true", help="include the network software-update check")
    p.add_argument("--quiet", action="store_true", help="human report: show only non-passing checks")
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "never"],
                   default="high", help="exit non-zero at or above this severity (default: high)")
    return p


def _exit_code(results, fail_on: str) -> int:
    if fail_on == "never":
        return 0
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    threshold = order[fail_on]
    for r in results:
        if r.status in {"fail", "warn"} and order.get(r.severity, 9) <= threshold:
            return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_checks:
        for check, title, category in available_checks():
            print(f"{check:20} {category:12} {title}")
        return 0
    if not sys.platform.startswith("darwin"):
        print("macsec: this tool is for macOS.", file=sys.stderr)
        return 2
    ctx = CheckContext(
        runner=CommandRunner(),
        ports=args.ports,
        updates=args.updates,
    )
    results = run_checks(
        ctx,
        only=_csv(args.only) if args.only else None,
        skip=_csv(args.skip) if args.skip else None,
    )
    text = render_json(results, include_evidence=args.include_evidence) if args.json else render_human(results, quiet=args.quiet)
    if args.output:
        Path(args.output).expanduser().write_text(text, encoding="utf-8")
        print(f"report: {args.output}")
    else:
        print(text, end="")
    return _exit_code(results, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
