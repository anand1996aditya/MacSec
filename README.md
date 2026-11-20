# MacSec

Deterministic, read-only macOS security and health posture audit.

Run the same checks on any Mac, in the same order, and get the same result when
the machine is in the same state. The tool does not change settings, install
software, prompt for a password, or send data off the Mac.

## Quick start

```bash
git clone <repository-url> MacSec
cd MacSec
./install.sh
./run.sh
```

`install.sh` creates an isolated `.venv`, installs the package, and prints the
exact command to run. It does not use `sudo`.

Run the JSON report:

```bash
./run.sh --json --output report.json
```

Run only the checks that need attention:

```bash
./run.sh --quiet
```

## Why this exists

The original audit lived inside a private internal environment. This repository
makes it portable:

- one command on any supported macOS host;
- stable JSON for dashboards and baselines;
- explicit severity, remediation and exit codes;
- no dependency on a vault path, user state or cloud service;
- a test suite that runs in CI without a Mac in the runner.

## Requirements

- macOS 13 or later. Tested on macOS 26.
- Python 3.10 or later.
- No third-party Python packages.

If `python3` is older than 3.10:

```bash
brew install python@3.13
PYTHON=/opt/homebrew/bin/python3.13 ./install.sh
```

## Installation

### Isolated install — recommended

```bash
./install.sh
```

This creates `.venv/` inside the repository and installs the `macsec`
command there. `./run.sh` uses it automatically.

To choose another environment:

```bash
./install.sh --venv "$HOME/.venvs/macsec"
MHC_VENV="$HOME/.venvs/macsec" ./run.sh
```

### System or user install

```bash
python3 -m pip install .
macsec
```

### Run without installing

```bash
PYTHONPATH=src python3 -m macsec
```

## Usage

```bash
./run.sh                          # human report
./run.sh --quiet                  # only non-passing checks
./run.sh --json                   # JSON to stdout
./run.sh --json --output report.json
./run.sh --include-evidence       # add raw command output (local-sensitive)
./run.sh --ports                  # opt-in listening-port check
./run.sh --updates                # opt-in software-update check (network)
./run.sh --only sip,filevault     # subset
./run.sh --skip updates,ports     # exclude
./run.sh --list-checks
./run.sh --fail-on critical       # stricter CI gate
```

The installed command has the same interface:

```bash
macsec --json --output report.json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No finding at or above `--fail-on` (default: high) |
| `1` | A finding at or above `--fail-on` |
| `2` | The tool could not run on this host |

Use `--fail-on never` for a report-only run.

## What it checks

| Area | Checks |
| --- | --- |
| System | OS version/build, SIP, secure boot |
| Data | FileVault, screen lock, SSH key permissions, sudoers permissions |
| Network | Firewall, stealth mode, stale firewall rules, Remote Login, sharing services, listening ports (opt-in), hosts file |
| Execution | Gatekeeper, XProtect, automatic updates, system extensions, pending updates (opt-in) |
| Accounts | Guest account, automatic login, admin accounts, root account |
| Management | MDM enrolment, Time Machine destination |

24 checks in total. The full list is in [docs/CHECKS.md](docs/CHECKS.md).

## Deterministic contract

The default output is deterministic for a fixed machine state:

- checks run in a fixed registry order;
- commands run with `LC_ALL=C`, `LANG=C` and `TZ=UTC`;
- JSON keys are sorted and the schema version is explicit;
- no timestamps, hostnames, usernames or raw command evidence are included by
  default;
- `--include-evidence` adds raw command output for debugging and must be treated
  as local-sensitive;
- `--updates` and `--ports` are opt-in because they add network or process
  observation.

This does not mean two different Macs produce the same score. It means the same
Mac, in the same state, produces the same result.

## Repository layout

```text
install.sh                 isolated install
run.sh                     run from the checkout
verify.sh                  full local verification
src/macsec/    Python package
  checks.py                check registry and implementations
  cli.py                   arguments, output and exit codes
  models.py                result model and scoring
  report.py                stable JSON and human rendering
  runner.py                deterministic command execution
tests/                     unit tests with a fake runner
docs/CHECKS.md             check reference
.github/workflows/ci.yml   portable CI (Linux unit tests; macOS runtime checks are local)
```

## Development

```bash
./verify.sh
```

`verify.sh` runs:

1. Python compile check
2. Bash syntax check
3. Unit tests
4. Check-registry smoke test
5. JSON determinism check — two runs must be byte-identical
6. JSON schema assertions

Run without installing:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m macsec --list-checks
```

## Security model

- Read-only. No setting is changed.
- No password prompt. Privileged checks use `sudo -n` and are marked `unknown`
  when passwordless sudo is unavailable.
- No telemetry. No network call unless `--updates` is passed.
- No secret discovery. The tool does not read key material or environment
  secrets.
- Raw evidence is opt-in and local-sensitive.

## Troubleshooting

**`macsec: this tool is for macOS`**

The CLI refuses to run on Linux. Use `--list-checks` for registry smoke tests on
other platforms.

**`Python 3.10 or newer is required`**

Install a newer Python with Homebrew and pass it explicitly:

```bash
PYTHON=/opt/homebrew/bin/python3.13 ./install.sh
```

**A privileged check is `unknown`**

That is intentional. The tool never prompts for a password. Run the command
manually if you need its result, or grant passwordless sudo only for the specific
command.

**JSON output changes between runs**

Run `./verify.sh` and inspect the two JSON files it compares. Volatile fields
must not be added to the default report.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). A new check needs an implementation, a
fake-runner test and a row in `docs/CHECKS.md`.

## License

MIT. See [LICENSE](LICENSE).
