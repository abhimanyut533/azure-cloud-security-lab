"""Unit tests: python3 -m unittest discover -s tests -v"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import incident_report as ir  # noqa: E402
import posture_check as pc  # noqa: E402

FIX = ROOT / "tests" / "fixtures"


def rules(path):
    return sorted({f.rule for f in pc.check(pc.load_resources(json.loads((FIX / path).read_text())))})


class PostureCheckTests(unittest.TestCase):
    def test_insecure_plan_finds_all_misconfigs(self):
        self.assertEqual(rules("plan_insecure.json"), ["AZ-IAM-01", "AZ-NET-01", "AZ-STG-01", "AZ-STG-04"])

    def test_secure_plan_is_clean(self):
        self.assertEqual(rules("plan_secure.json"), [])

    def test_edge_cases(self):
        found = pc.check(pc.load_resources(json.loads((FIX / "state_edge_cases.json").read_text())))
        got = {(f.rule, f.severity) for f in found}
        self.assertIn(("AZ-NET-01", "high"), got)       # RDP inside 3380-3390 from Internet
        self.assertIn(("AZ-VM-01", "high"), got)        # password auth, inside a child module
        self.assertIn(("AZ-IAM-01", "medium"), got)     # Owner but only on a resource group
        self.assertIn(("AZ-LOG-01", "medium"), got)     # no activity log export
        self.assertIn(("AZ-LOG-02", "low"), got)        # 7-day retention
        self.assertEqual(sum(1 for f in found if f.rule == "AZ-NET-01"), 1)  # 443 and Deny not flagged

    def test_port_matching(self):
        self.assertTrue(pc.port_matches("*", 22))
        self.assertTrue(pc.port_matches("20-25", 22))
        self.assertFalse(pc.port_matches("2200", 22))
        self.assertFalse(pc.port_matches(None, 22))

    def test_cli_exit_code(self):
        bad = subprocess.run([sys.executable, str(ROOT / "scripts/posture_check.py"),
                              str(FIX / "plan_insecure.json"), "--fail-on", "high"], capture_output=True)
        good = subprocess.run([sys.executable, str(ROOT / "scripts/posture_check.py"),
                               str(FIX / "plan_secure.json"), "--fail-on", "high"], capture_output=True)
        self.assertEqual(bad.returncode, 1)
        self.assertEqual(good.returncode, 0)


class IncidentReportTests(unittest.TestCase):
    def test_detections_metadata(self):
        dets = ir.load_detections(ROOT / "detections")
        self.assertEqual(sorted(dets), ["C01", "C02", "C03", "C04", "C05"])
        for det in dets.values():
            for key in ("id", "name", "severity", "tactics", "techniques", "mitre", "iso27001", "description"):
                self.assertIn(key, det.meta, f"{det.key} missing {key}")
            self.assertIn(det.meta["severity"], ("High", "Medium", "Low", "Informational"))
            for tech in det.meta["techniques"].split(","):
                self.assertRegex(tech.strip(), r"^T\d{4}$")  # Sentinel wants top-level IDs

    def test_seven_digit_fraction_time(self):
        self.assertIsNotNone(ir.parse_time("2026-11-25T18:04:11.1234567Z"))

    def test_report_and_coverage(self):
        rows = ir.rows_offline(FIX / "alerts")
        alerts = [ir.to_alert(r) for r in rows]
        steps = ir.load_ground_truth(FIX / "attack_log_sample.csv")
        report = ir.build_report(alerts, ir.load_detections(ROOT / "detections"), "test", steps)
        self.assertIn("Coverage: 3/4", report)
        self.assertIn("❌ not detected", report)  # S4 has no alert in the fixtures
        self.assertIn("T1530", report)


if __name__ == "__main__":
    unittest.main()
