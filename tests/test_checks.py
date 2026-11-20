import unittest

from macsec.checks import check_firewall, check_guest, check_sip
from macsec.models import CheckContext
from macsec.runner import Completed


class FakeRunner:
    def __init__(self, mapping):
        self.mapping = mapping
        self.calls = []

    def run(self, argv, allow_sudo=False):
        key = " ".join(argv)
        self.calls.append(key)
        value = self.mapping.get(key, ("", 1))
        if isinstance(value, Completed):
            return value
        out, rc = value
        return Completed(rc, out, "")

    def path(self, name):
        return name


def ctx(mapping):
    return CheckContext(runner=FakeRunner(mapping))


class CheckTests(unittest.TestCase):
    def test_sip_passes_when_enabled(self):
        result = check_sip(ctx({"csrutil status": ("System Integrity Protection status: enabled.", 0)}))
        self.assertEqual(result.status, "pass")
        self.assertEqual(result.check, "sip")

    def test_sip_fails_when_disabled(self):
        result = check_sip(ctx({"csrutil status": ("System Integrity Protection status: disabled.", 0)}))
        self.assertEqual(result.status, "fail")
        self.assertEqual(result.severity, "high")

    def test_firewall_requires_stealth(self):
        result = check_firewall(ctx({
            "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate": ("Firewall is enabled. (State = 1)", 0),
            "/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode": ("Stealth mode disabled", 0),
        }))
        self.assertEqual(result.status, "warn")
        self.assertEqual(result.severity, "medium")

    def test_guest_disabled(self):
        result = check_guest(ctx({
            "defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled": ("0", 0),
        }))
        self.assertEqual(result.status, "pass")


if __name__ == "__main__":
    unittest.main()
