"""Deterministic command execution and safe command discovery."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class Completed:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def text(self) -> str:
        return (self.stdout or "").strip()


class CommandRunner:
    """Run read-only commands with a fixed locale and no password prompts.

    ``sudo -n`` is attempted only when ``allow_sudo`` is true. A failed
    passwordless sudo call falls back to the unprivileged command, and the
    caller can mark the result unknown.
    """

    def __init__(self, timeout: int = 20) -> None:
        self.timeout = timeout
        self.sudo = shutil.which("sudo")

    def run(self, argv: list[str], allow_sudo: bool = False) -> Completed:
        attempts: list[list[str]] = []
        if allow_sudo and self.sudo:
            attempts.append([self.sudo, "-n", *argv])
        attempts.append(list(argv))

        last = Completed(1, "", "")
        for attempt in attempts:
            try:
                proc = subprocess.run(
                    attempt,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    env=self._env(),
                )
                last = Completed(proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip())
            except FileNotFoundError:
                return Completed(127, "", f"command not found: {attempt[0]}")
            except subprocess.TimeoutExpired:
                return Completed(124, "", f"timed out after {self.timeout}s: {attempt[0]}")
            except OSError as exc:
                return Completed(1, "", str(exc))

            if last.returncode == 0:
                return last
            if "password is required" not in last.stderr.lower() and "not permitted" not in last.stderr.lower():
                return last
        return last

    @staticmethod
    def _env() -> dict[str, str]:
        env = dict(os.environ)
        env["LC_ALL"] = "C"
        env["LANG"] = "C"
        env["TZ"] = "UTC"
        return env

    @staticmethod
    def path(name: str) -> str | None:
        return shutil.which(name)
