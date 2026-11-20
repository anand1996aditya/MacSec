import json
import unittest

from macsec.models import CheckResult, score_results
from macsec.report import build_payload, render_json


class ReportTests(unittest.TestCase):
    def test_score_is_deterministic(self):
        results = [
            CheckResult("a", "A", "system", "pass"),
            CheckResult("b", "B", "data", "warn", "medium", detail="x"),
        ]
        one = score_results(results)
        two = score_results(results)
        self.assertEqual(one, two)
        self.assertEqual(one["score"], 95)
        self.assertEqual(one["verdict"], "attention")

    def test_json_has_stable_schema(self):
        payload = build_payload([CheckResult("a", "A", "system", "pass")])
        self.assertEqual(payload["schema_version"], "1.0")
        text = render_json([CheckResult("a", "A", "system", "pass")])
        self.assertEqual(json.loads(text)["tool"]["name"], "macsec")


if __name__ == "__main__":
    unittest.main()
