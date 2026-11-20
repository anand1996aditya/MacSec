# Contributing

## Rules

- Read-only checks only. Never change a setting, install a package, or send data.
- No password prompt. Use `sudo -n` only through the shared runner.
- Deterministic output. Sort keys, fix order, and avoid timestamps in default
  output.
- One check, one concern. Keep remediation specific and actionable.
- No third-party dependencies. The standard library is enough.

## Workflow

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m macsec --list-checks
PYTHONPATH=src python3 -m macsec --json --output /tmp/report.json
```

Add a test for every new check. A check without a fake-runner test is not ready.

## Commit style

Use a short imperative subject. Explain the risk in the body. Do not commit
generated reports or machine-specific evidence.
