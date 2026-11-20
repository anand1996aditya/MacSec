"""Typed result model for the audit."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_PENALTY = {"critical": 25, "high": 12, "medium": 5, "low": 1, "info": 0}
STATUS_ORDER = {"fail": 0, "warn": 1, "unknown": 2, "skipped": 3, "pass": 4}


@dataclass(frozen=True)
class CheckResult:
    """One deterministic check result. No timestamps or hostnames by default."""

    check: str
    title: str
    category: str
    status: str
    severity: str = "info"
    detail: str = ""
    evidence: str = ""
    remediation: str = ""

    def as_dict(self) -> dict:
        return {
            "check": self.check,
            "title": self.title,
            "category": self.category,
            "status": self.status,
            "severity": self.severity,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class CheckContext:
    """Shared command runner and options for all checks."""

    runner: object
    ports: bool = False
    updates: bool = False
    privileged: bool = False


def normalize_status(status: str) -> str:
    status = status.lower()
    if status not in STATUS_ORDER:
        raise ValueError(f"unknown status: {status}")
    return status


def make_result(
    check: str,
    title: str,
    category: str,
    status: str,
    severity: str = "info",
    detail: str = "",
    evidence: str = "",
    remediation: str = "",
) -> CheckResult:
    return CheckResult(
        check=check,
        title=title,
        category=category,
        status=normalize_status(status),
        severity=severity if severity in SEVERITY_ORDER else "info",
        detail=detail.strip(),
        evidence=evidence.strip()[:2000],
        remediation=remediation.strip(),
    )


def score_results(results: Iterable[CheckResult]) -> dict:
    results = list(results)
    counts = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    for r in results:
        if r.status in {"fail", "warn"}:
            counts[r.severity] = counts.get(r.severity, 0) + 1
    penalty = sum(SEVERITY_PENALTY[s] * n for s, n in counts.items())
    score = max(0, 100 - penalty)
    if counts["critical"] or counts["high"]:
        verdict = "fail"
    elif counts["medium"] or counts["low"] or any(r.status == "warn" for r in results):
        verdict = "attention"
    else:
        verdict = "pass"
    return {
        "score": score,
        "verdict": verdict,
        "counts": counts,
        "passed": sum(1 for r in results if r.status == "pass"),
        "failed": sum(1 for r in results if r.status == "fail"),
        "warned": sum(1 for r in results if r.status == "warn"),
        "unknown": sum(1 for r in results if r.status == "unknown"),
        "skipped": sum(1 for r in results if r.status == "skipped"),
        "total": len(results),
    }
