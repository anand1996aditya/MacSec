# Check reference

Every check is read-only. Severity describes the impact of the risky state, not
the confidence of the check.

| ID | Title | Category | Severity when warned/failed |
| --- | --- | --- | --- |
| `os` | Operating system | system | low (fail) |
| `sip` | System Integrity Protection | system | high |
| `filevault` | FileVault disk encryption | data | high |
| `firewall` | Application firewall | network | high / medium |
| `firewall_rules` | Firewall application rules | network | medium |
| `gatekeeper` | Gatekeeper | execution | high |
| `xprotect` | XProtect definitions | execution | medium |
| `auto_updates` | Automatic security updates | execution | medium |
| `remote_login` | Remote Login (SSH) | network | medium |
| `sharing` | Sharing services | network | medium |
| `guest` | Guest account | accounts | medium |
| `autologin` | Automatic login | accounts | medium |
| `admin_users` | Administrator accounts | accounts | info |
| `root_user` | Root account | accounts | medium |
| `screen_lock` | Screen lock | data | medium / low |
| `ssh_permissions` | SSH key permissions | data | medium |
| `sudoers` | Sudoers permissions | data | high |
| `mdm` | MDM enrolment | management | info |
| `system_extensions` | System extensions | execution | info |
| `secure_boot` | Secure boot | system | medium |
| `time_machine` | Time Machine | backup | medium |
| `hosts` | Hosts file | network | low |
| `listening_ports` | Listening TCP ports | network | info, opt-in |
| `updates` | Pending software updates | execution | medium, opt-in |

## Status values

- `pass` — the expected safe state was observed.
- `warn` — a weakness or an incomplete hardening step.
- `fail` — the unsafe state was observed.
- `unknown` — the check could not determine the state; usually a missing
  privilege or unavailable command.
- `skipped` — the check was intentionally not run (opt-in).

## Adding a check

1. Write a function in `checks.py` and decorate it with
   `@register("id", "Title", "category")`.
2. Return `make_result(...)` with `pass`, `warn`, `fail`, `unknown` or `skipped`.
3. Add a unit test with a fake `CommandRunner` mapping.
4. Add the row to this file.
5. Run the tests and `macsec --list-checks`.
