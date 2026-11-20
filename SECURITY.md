# Security policy

This tool is a read-only audit. It must never become a privilege-escalation or
data-exfiltration tool.

## Reporting a vulnerability

Report privately to the maintainers. Do not open a public issue for a
vulnerability that could expose a host.

## Scope

- The tool must not send data off the Mac.
- The tool must not write outside the requested report path.
- The tool must not prompt for a password or store credentials.
- `--include-evidence` output is local-sensitive and must not be published
  without review.

## Supported versions

Only the latest release and the `main` branch are supported.
