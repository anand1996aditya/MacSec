"""Read-only macOS posture checks.

Every check is a pure function of the command output plus the local
filesystem. Checks are registered in a fixed order, so JSON and human output
are stable across runs.
"""

from __future__ import annotations

import os
import platform
import plistlib
import re
import stat
from datetime import datetime, timezone
from pathlib import Path

from .models import CheckContext, CheckResult, make_result

CheckFn = callable
REGISTRY: list[tuple[str, str, str, CheckFn]] = []


def register(check: str, title: str, category: str):
    def deco(fn: CheckFn) -> CheckFn:
        REGISTRY.append((check, title, category, fn))
        return fn

    return deco


def available_checks() -> list[tuple[str, str, str]]:
    return [(c, t, cat) for c, t, cat, _ in REGISTRY]


def _run(ctx: CheckContext, argv: list[str], allow_sudo: bool = False):
    return ctx.runner.run(argv, allow_sudo=allow_sudo)


def _first(text: str) -> str:
    return (text or "").strip().splitlines()[0].strip() if (text or "").strip() else ""


def _unknown(check: str, title: str, category: str, detail: str, evidence: str = "") -> CheckResult:
    return make_result(check, title, category, "unknown", "info", detail, evidence)


@register("os", "Operating system", "system")
def check_os(ctx: CheckContext) -> CheckResult:
    r = _run(ctx, ["sw_vers"])
    if not r.ok:
        return make_result("os", "Operating system", "system", "fail", "low",
                           "Could not read the macOS version.", r.stderr,
                           "Run `sw_vers` manually.")
    values = {}
    for line in r.stdout.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            values[k.strip()] = v.strip()
    version = values.get("ProductVersion", "?")
    build = values.get("BuildVersion", "?")
    arch = platform.machine() or "?"
    return make_result("os", "Operating system", "system", "pass", "info",
                       f"macOS {version} ({build}) on {arch}.", r.stdout)


@register("sip", "System Integrity Protection", "system")
def check_sip(ctx: CheckContext) -> CheckResult:
    r = _run(ctx, ["csrutil", "status"])
    out = r.stdout.lower()
    if "enabled" in out and "disabled" not in out:
        return make_result("sip", "System Integrity Protection", "system", "pass", "info",
                           "System Integrity Protection is enabled.", r.stdout)
    if "disabled" in out:
        return make_result("sip", "System Integrity Protection", "system", "fail", "high",
                           "System Integrity Protection is disabled.", r.stdout,
                           "Boot into Recovery and run `csrutil enable`.")
    return _unknown("sip", "System Integrity Protection", "system",
                    "Could not determine SIP state.", r.stdout or r.stderr)


@register("filevault", "FileVault disk encryption", "data")
def check_filevault(ctx: CheckContext) -> CheckResult:
    r = _run(ctx, ["fdesetup", "status"])
    out = r.stdout.lower()
    if "filevault is on" in out:
        return make_result("filevault", "FileVault disk encryption", "data", "pass", "info",
                           "FileVault is on.", r.stdout)
    if "filevault is off" in out:
        return make_result("filevault", "FileVault disk encryption", "data", "fail", "high",
                           "FileVault is off.", r.stdout,
                           "Enable FileVault in System Settings → Privacy & Security.")
    return _unknown("filevault", "FileVault disk encryption", "data",
                    "Could not determine FileVault state.", r.stdout or r.stderr)


@register("firewall", "Application firewall", "network")
def check_firewall(ctx: CheckContext) -> CheckResult:
    state = _run(ctx, ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    stealth = _run(ctx, ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"])
    out = state.stdout.lower()
    if "enabled" not in out or "disabled" in out:
        return make_result("firewall", "Application firewall", "network", "fail", "high",
                           "The application firewall is not enabled.", state.stdout or state.stderr,
                           "Enable the firewall in System Settings → Network → Firewall.")
    if "disabled" in stealth.stdout.lower():
        return make_result("firewall", "Application firewall", "network", "warn", "medium",
                           "Firewall is on but stealth mode is off.", stealth.stdout,
                           "Enable stealth mode in Firewall → Options.")
    return make_result("firewall", "Application firewall", "network", "pass", "info",
                       "Firewall and stealth mode are enabled.", state.stdout)


@register("firewall_rules", "Firewall application rules", "network")
def check_firewall_rules(ctx: CheckContext) -> CheckResult:
    r = _run(ctx, ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--listapps"])
    if not r.ok:
        return _unknown("firewall_rules", "Firewall application rules", "network",
                        "Could not list firewall application rules.", r.stderr)
    missing, allowed = [], 0
    current = None
    for line in r.stdout.splitlines():
        m = re.match(r"\s*\d+\s*:\s*(.+?)\s*$", line)
        if m:
            current = m.group(1).rstrip()
            if "Allow incoming connections" in line:
                allowed += 1
            continue
        if current and "Allow incoming connections" in line:
            allowed += 1
        if current and "Allow incoming connections" in line and not os.path.exists(current):
            missing.append(current)
    evidence = f"{allowed} allow rule(s); {len(missing)} stale path(s)."
    if missing:
        return make_result("firewall_rules", "Firewall application rules", "network", "warn", "medium",
                           "Firewall rules point at missing applications.", evidence,
                           "Remove stale rules in Firewall → Options.")
    return make_result("firewall_rules", "Firewall application rules", "network", "pass", "info",
                       "No stale firewall application rules found.", evidence)


@register("gatekeeper", "Gatekeeper", "execution")
def check_gatekeeper(ctx: CheckContext) -> CheckResult:
    r = _run(ctx, ["/usr/sbin/spctl", "--status"])
    out = r.stdout.lower()
    if "assessments enabled" in out:
        return make_result("gatekeeper", "Gatekeeper", "execution", "pass", "info",
                           "Gatekeeper assessments are enabled.", r.stdout)
    if "assessments disabled" in out:
        return make_result("gatekeeper", "Gatekeeper", "execution", "fail", "high",
                           "Gatekeeper assessments are disabled.", r.stdout,
                           "Enable Gatekeeper: `sudo spctl --master-enable`.")
    return _unknown("gatekeeper", "Gatekeeper", "execution",
                    "Could not determine Gatekeeper state.", r.stdout or r.stderr)


@register("xprotect", "XProtect definitions", "execution")
def check_xprotect(ctx: CheckContext) -> CheckResult:
    plist = Path("/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist")
    try:
        data = plistlib.loads(plist.read_bytes())
    except OSError as exc:
        return _unknown("xprotect", "XProtect definitions", "execution",
                        "Could not read XProtect metadata.", str(exc))
    version = str(data.get("CFBundleShortVersionString", "?"))
    age_days = None
    try:
        age_days = (datetime.now(timezone.utc) - datetime.fromtimestamp(plist.stat().st_mtime, timezone.utc)).days
    except OSError:
        pass
    if age_days is not None and age_days > 30:
        return make_result("xprotect", "XProtect definitions", "execution", "warn", "medium",
                           f"XProtect definitions are {age_days} days old.", f"version={version}",
                           "Update macOS or install the latest XProtect update.")
    return make_result("xprotect", "XProtect definitions", "execution", "pass", "info",
                       f"XProtect {version} is present.", f"version={version}; age={age_days}d")


@register("auto_updates", "Automatic security updates", "execution")
def check_auto_updates(ctx: CheckContext) -> CheckResult:
    r = _run(ctx, ["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate"])
    if not r.ok:
        return _unknown("auto_updates", "Automatic security updates", "execution",
                        "Could not read software-update preferences.", r.stderr)
    keys = ("AutomaticCheckEnabled", "AutomaticDownload", "CriticalUpdateInstall", "ConfigDataInstall")
    values = {k: bool(re.search(rf"{k}\s*=\s*1", r.stdout)) for k in keys}
    if values["AutomaticCheckEnabled"] and values["CriticalUpdateInstall"] and values["ConfigDataInstall"]:
        return make_result("auto_updates", "Automatic security updates", "execution", "pass", "info",
                           "Automatic security updates are enabled.", r.stdout)
    return make_result("auto_updates", "Automatic security updates", "execution", "warn", "medium",
                       "One or more automatic security-update settings are off.", r.stdout,
                       "Enable automatic updates in System Settings → General → Software Update.")


@register("remote_login", "Remote Login (SSH)", "network")
def check_remote_login(ctx: CheckContext) -> CheckResult:
    r = _run(ctx, ["/usr/sbin/systemsetup", "-getremotelogin"], allow_sudo=True)
    out = r.stdout.lower()
    if "remote login: on" in out:
        return make_result("remote_login", "Remote Login (SSH)", "network", "warn", "medium",
                           "Remote Login is on.", r.stdout,
                           "Turn off Remote Login if it is not required.")
    if "remote login: off" in out:
        return make_result("remote_login", "Remote Login (SSH)", "network", "pass", "info",
                           "Remote Login is off.", r.stdout)
    return _unknown("remote_login", "Remote Login (SSH)", "network",
                    "Could not determine Remote Login state; the check may need admin rights.",
                    r.stdout or r.stderr)


@register("sharing", "Sharing services", "network")
def check_sharing(ctx: CheckContext) -> CheckResult:
    r = _run(ctx, ["launchctl", "list"])
    if not r.ok:
        return _unknown("sharing", "Sharing services", "network", "Could not list launchd services.", r.stderr)
    watched = {"com.apple.smbd": "SMB", "com.apple.screensharing": "Screen Sharing",
               "com.apple.AppleFileServer": "AFP", "com.apple.ftp-proxy": "FTP"}
    active = [label for key, label in watched.items() if re.search(rf"\b{re.escape(key)}\b", r.stdout)]
    if active:
        return make_result("sharing", "Sharing services", "network", "warn", "medium",
                           f"Sharing services are loaded: {', '.join(active)}.", r.stdout,
                           "Disable unused sharing services in System Settings → General → Sharing.")
    return make_result("sharing", "Sharing services", "network", "pass", "info",
                       "No common sharing service is loaded.", "")


@register("guest", "Guest account", "accounts")
def check_guest(ctx: CheckContext) -> CheckResult:
    r = _run(ctx, ["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"])
    out = r.stdout.strip()
    if out == "1":
        return make_result("guest", "Guest account", "accounts", "warn", "medium",
                           "The guest account is enabled.", out,
                           "Disable the guest account in System Settings → Users & Groups.")
    if out == "0":
        return make_result("guest", "Guest account", "accounts", "pass", "info",
                           "The guest account is disabled.", out)
    return _unknown("guest", "Guest account", "accounts", "Could not read guest-account state.", r.stderr)


@register("autologin", "Automatic login", "accounts")
def check_autologin(ctx: CheckContext) -> CheckResult:
    r = _run(ctx, ["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"])
    if r.ok and r.stdout.strip():
        return make_result("autologin", "Automatic login", "accounts", "warn", "medium",
                           "Automatic login is configured.", f"user={r.stdout.strip()}",
                           "Disable automatic login in System Settings → Users & Groups.")
    if not r.ok and not any(x in r.stderr.lower() for x in ("does not exist", "could not find key")):
        return _unknown("autologin", "Automatic login", "accounts", "Could not read automatic-login state.", r.stderr)
    return make_result("autologin", "Automatic login", "accounts", "pass", "info",
                       "Automatic login is not configured.", "")


@register("admin_users", "Administrator accounts", "accounts")
def check_admin_users(ctx: CheckContext) -> CheckResult:
    r = _run(ctx, ["dscl", ".", "-read", "/Groups/admin", "GroupMembership"])
    if not r.ok:
        return _unknown("admin_users", "Administrator accounts", "accounts",
                        "Could not read administrator group.", r.stderr)
    members = r.stdout.split(":", 1)[1].split() if ":" in r.stdout else []
    return make_result("admin_users", "Administrator accounts", "accounts", "pass", "info",
                       f"{len(members)} administrator account(s).", " ".join(members))


@register("root_user", "Root account", "accounts")
def check_root_user(ctx: CheckContext) -> CheckResult:
    r = _run(ctx, ["dscl", ".", "-read", "/Users/root", "AuthenticationAuthority"])
    if not r.ok:
        return _unknown("root_user", "Root account", "accounts", "Could not read root account.", r.stderr)
    if "DisabledUser" in r.stdout:
        return make_result("root_user", "Root account", "accounts", "pass", "info",
                           "The root account is disabled.", r.stdout)
    return make_result("root_user", "Root account", "accounts", "warn", "medium",
                       "The root account is enabled or its state is not disabled.", r.stdout,
                       "Disable root with `dsenableroot -d` if it is not required.")


@register("screen_lock", "Screen lock", "data")
def check_screen_lock(ctx: CheckContext) -> CheckResult:
    ask = _run(ctx, ["defaults", "read", "com.apple.screensaver", "askForPassword"])
    delay = _run(ctx, ["defaults", "read", "com.apple.screensaver", "askForPasswordDelay"])
    ask_on = ask.stdout.strip() == "1"
    try:
        seconds = int(delay.stdout.strip())
    except ValueError:
        seconds = None
    if ask_on and seconds is not None and seconds <= 5:
        return make_result("screen_lock", "Screen lock", "data", "pass", "info",
                           f"Password is required after {seconds}s.", f"askForPassword=1; delay={seconds}")
    if ask_on and seconds is not None:
        return make_result("screen_lock", "Screen lock", "data", "warn", "low",
                           f"Password is required after {seconds}s.", f"askForPassword=1; delay={seconds}",
                           "Set the screen-lock delay to 5 seconds or less.")
    return make_result("screen_lock", "Screen lock", "data", "warn", "medium",
                       "Screen lock password is not clearly configured.",
                       f"askForPassword={ask.stdout.strip()}; delay={delay.stdout.strip()}",
                       "Require a password immediately after sleep or screen saver.")


@register("ssh_permissions", "SSH key permissions", "data")
def check_ssh_permissions(ctx: CheckContext) -> CheckResult:
    home = Path.home()
    ssh_dir = home / ".ssh"
    if not ssh_dir.exists():
        return make_result("ssh_permissions", "SSH key permissions", "data", "pass", "info",
                           "No ~/.ssh directory is present.", "")
    problems = []
    try:
        mode = stat.S_IMODE(ssh_dir.stat().st_mode)
        if mode & 0o077:
            problems.append(f"~/.ssh mode {mode:o}")
    except OSError:
        pass
    for name in ("id_rsa", "id_ed25519", "authorized_keys"):
        p = ssh_dir / name
        if p.exists():
            try:
                mode = stat.S_IMODE(p.stat().st_mode)
                if mode & 0o077:
                    problems.append(f"{name} mode {mode:o}")
            except OSError:
                pass
    if problems:
        return make_result("ssh_permissions", "SSH key permissions", "data", "warn", "medium",
                           "SSH files are accessible by group or others.", "; ".join(problems),
                           "Use `chmod 700 ~/.ssh` and `chmod 600` for key files.")
    return make_result("ssh_permissions", "SSH key permissions", "data", "pass", "info",
                       "SSH directory and key permissions look restricted.", "")


@register("sudoers", "Sudoers permissions", "data")
def check_sudoers(ctx: CheckContext) -> CheckResult:
    paths = [Path("/etc/sudoers"), Path("/etc/sudoers.d")]
    problems = []
    for p in paths:
        if not p.exists():
            continue
        try:
            mode = stat.S_IMODE(p.stat().st_mode)
            if mode & 0o022:
                problems.append(f"{p} mode {mode:o}")
        except OSError:
            pass
    if problems:
        return make_result("sudoers", "Sudoers permissions", "data", "warn", "high",
                           "Sudoers files are writable by group or others.", "; ".join(problems),
                           "Restrict sudoers permissions to root:wheel and mode 0440.")
    return make_result("sudoers", "Sudoers permissions", "data", "pass", "info",
                       "Sudoers permissions look restricted.", "")


@register("mdm", "MDM enrolment", "management")
def check_mdm(ctx: CheckContext) -> CheckResult:
    r = _run(ctx, ["/usr/bin/profiles", "status", "-type", "enrollment"])
    if not r.ok:
        return _unknown("mdm", "MDM enrolment", "management", "Could not read MDM enrolment.", r.stderr)
    if re.search(r"MDM enrollment:\s*Yes", r.stdout, re.I):
        return make_result("mdm", "MDM enrolment", "management", "pass", "info",
                           "Device is enrolled in MDM.", r.stdout)
    return make_result("mdm", "MDM enrolment", "management", "pass", "info",
                       "Device is not enrolled in MDM.", r.stdout)


@register("system_extensions", "System extensions", "execution")
def check_system_extensions(ctx: CheckContext) -> CheckResult:
    r = _run(ctx, ["/usr/bin/systemextensionsctl", "list"])
    if not r.ok:
        return _unknown("system_extensions", "System extensions", "execution",
                        "Could not list system extensions.", r.stderr)
    active = [ln.strip() for ln in r.stdout.splitlines() if "[activated enabled]" in ln]
    return make_result("system_extensions", "System extensions", "execution", "pass", "info",
                       f"{len(active)} activated system extension(s).", "\n".join(active))


@register("secure_boot", "Secure boot", "system")
def check_secure_boot(ctx: CheckContext) -> CheckResult:
    r = _run(ctx, ["/usr/bin/csrutil", "authenticated-root", "status"])
    out = r.stdout.lower()
    if "enabled" in out:
        return make_result("secure_boot", "Secure boot", "system", "pass", "info",
                           "Authenticated root is enabled.", r.stdout)
    if "disabled" in out:
        return make_result("secure_boot", "Secure boot", "system", "warn", "medium",
                           "Authenticated root is disabled.", r.stdout,
                           "Enable authenticated root in Recovery if your hardware supports it.")
    return _unknown("secure_boot", "Secure boot", "system", "Could not determine secure-boot state.",
                    r.stdout or r.stderr)


@register("time_machine", "Time Machine", "backup")
def check_time_machine(ctx: CheckContext) -> CheckResult:
    r = _run(ctx, ["/usr/bin/tmutil", "destinationinfo"])
    if not r.ok or "No destinations configured" in r.stdout:
        return make_result("time_machine", "Time Machine", "backup", "warn", "medium",
                           "No Time Machine destination is configured.", r.stdout or r.stderr,
                           "Configure a Time Machine backup destination.")
    return make_result("time_machine", "Time Machine", "backup", "pass", "info",
                       "A Time Machine destination is configured.", _first(r.stdout))


@register("hosts", "Hosts file", "network")
def check_hosts(ctx: CheckContext) -> CheckResult:
    try:
        text = Path("/etc/hosts").read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return _unknown("hosts", "Hosts file", "network", "Could not read /etc/hosts.", str(exc))
    entries = []
    for line in text.splitlines():
        clean = line.split("#", 1)[0].strip()
        if not clean:
            continue
        parts = clean.split()
        if len(parts) >= 2 and parts[0] not in {"127.0.0.1", "::1"}:
            entries.append(clean)
    if entries:
        return make_result("hosts", "Hosts file", "network", "warn", "low",
                           "Custom hosts entries are present.", "\n".join(entries[:20]),
                           "Review custom hosts entries for unexpected redirects.")
    return make_result("hosts", "Hosts file", "network", "pass", "info",
                       "No custom hosts entries found.", "")


@register("listening_ports", "Listening TCP ports", "network")
def check_listening_ports(ctx: CheckContext) -> CheckResult:
    if not ctx.ports:
        return make_result("listening_ports", "Listening TCP ports", "network", "skipped", "info",
                           "Enable with --ports.", "")
    lsof = ctx.runner.path("lsof")
    if not lsof:
        return _unknown("listening_ports", "Listening TCP ports", "network", "lsof is not installed.")
    r = _run(ctx, [lsof, "-nP", "-iTCP", "-sTCP:LISTEN"])
    if not r.ok:
        return _unknown("listening_ports", "Listening TCP ports", "network",
                        "Could not list listening ports.", r.stderr)
    lines = [ln for ln in r.stdout.splitlines()[1:] if ln.strip()]
    return make_result("listening_ports", "Listening TCP ports", "network", "info", "info",
                       f"{len(lines)} listening TCP socket(s).", "\n".join(lines[:40]))


@register("updates", "Pending software updates", "execution")
def check_updates(ctx: CheckContext) -> CheckResult:
    if not ctx.updates:
        return make_result("updates", "Pending software updates", "execution", "skipped", "info",
                           "Enable with --updates (uses the network).", "")
    r = _run(ctx, ["softwareupdate", "-l"], allow_sudo=True)
    if not r.ok:
        return _unknown("updates", "Pending software updates", "execution",
                        "Could not query software updates.", r.stderr)
    if "No new software available" in r.stdout:
        return make_result("updates", "Pending software updates", "execution", "pass", "info",
                           "No software updates are pending.", r.stdout)
    return make_result("updates", "Pending software updates", "execution", "warn", "medium",
                       "Software updates are pending.", r.stdout,
                       "Install updates from System Settings → General → Software Update.")


def run_checks(ctx: CheckContext, only: set[str] | None = None, skip: set[str] | None = None) -> list[CheckResult]:
    only = only or set()
    skip = skip or set()
    results = []
    for check, title, category, fn in REGISTRY:
        if only and check not in only:
            continue
        if check in skip:
            continue
        try:
            result = fn(ctx)
        except Exception as exc:  # a broken check must not hide the rest
            result = make_result(check, title, category, "unknown", "info",
                                 f"Check failed: {exc}", "", "Report this as a bug.")
        results.append(result)
    return results
