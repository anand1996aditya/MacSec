"""Stable human and JSON rendering."""

from __future__ import annotations

import json
from typing import Iterable

from .models import CheckResult, score_results
from . import __version__

SCHEMA_VERSION = "1.0"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
STATUS_ORDER = {"fail": 0, "warn": 1, "unknown": 2, "skipped": 3, "pass": 4}


def build_payload(results: Iterable[CheckResult], include_evidence: bool = False) -> dict:
    results = list(results)
    summary = score_results(results)
    checks = []
    for r in sorted(results, key=lambda x: (STATUS_ORDER.get(x.status, 9), SEVERITY_ORDER.get(x.severity, 9), x.check)):
        item = r.as_dict()
        if not include_evidence:
            item.pop("evidence", None)
        checks.append(item)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "macsec", "version": __version__},
        "summary": summary,
        "checks": checks,
    }


def render_json(results: Iterable[CheckResult], include_evidence: bool = False) -> str:
    payload = build_payload(results, include_evidence=include_evidence)
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_human(results: Iterable[CheckResult], quiet: bool = False) -> str:
    results = list(results)
    summary = score_results(results)
    lines = []
    lines.append("MacSec")
    lines.append("=" * 18)
    lines.append(f"Score: {summary['score']}/100 · verdict: {summary['verdict'].upper()}")
    lines.append(
        f"Pass {summary['passed']} · Warn {summary['warned']} · Fail {summary['failed']} "
        f"· Unknown {summary['unknown']} · Skipped {summary['skipped']}"
    )
    lines.append("")
    for r in sorted(results, key=lambda x: (STATUS_ORDER.get(x.status, 9), SEVERITY_ORDER.get(x.severity, 9), x.check)):
        if quiet and r.status == "pass":
            continue
        mark = {"pass": "[OK]", "warn": "[WARN]", "fail": "[FAIL]",
                "unknown": "[UNKNOWN]", "skipped": "[SKIP]"}.get(r.status, "[?]")
        lines.append(f"{mark:9} {r.check:20} {r.detail}")
        if r.remediation and r.status in {"warn", "fail"}:
            lines.append(f"{'':9} fix: {r.remediation}")
    if quiet and summary["passed"]:
        lines.append(f"{summary['passed']} checks passed.")
    lines.append("")
    return "\n".join(lines)
