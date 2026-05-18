from pathlib import Path
import tempfile
import unittest

from src.log_parser import parse_log, parse_logs
from src.scan_detector import build_source_risk, detect_scans
from src.timeline import build_summary, build_timeline, build_triage_report


ROOT = Path(__file__).resolve().parents[1]


class PortScanLabTests(unittest.TestCase):
    def test_detector_flags_nmap_sample_only(self) -> None:
        events = parse_logs([ROOT / "data/normal-traffic.log", ROOT / "data/nmap-scan.log"])
        findings = detect_scans(events)

        self.assertEqual(1, len(findings))
        self.assertEqual("192.0.2.50", findings[0].source_ip)
        self.assertEqual(12, findings[0].port_count)
        self.assertEqual("high", findings[0].risk)
        self.assertEqual("mixed-service-recon", findings[0].scan_profile)

    def test_normal_sample_does_not_alert(self) -> None:
        events = parse_log(ROOT / "data/normal-traffic.log")
        self.assertEqual([], detect_scans(events))

    def test_timeline_report_contains_reason(self) -> None:
        events = parse_log(ROOT / "data/nmap-scan.log")
        findings = detect_scans(events)
        report = build_timeline(events, findings)

        self.assertIn("Port Scan Detection Report", report)
        self.assertIn("unique destination ports", report)
        self.assertIn("Recommended next step", report)

    def test_builds_source_risk_and_triage(self) -> None:
        events = parse_logs([ROOT / "data/normal-traffic.log", ROOT / "data/nmap-scan.log"])
        findings = detect_scans(events)
        summary = build_summary(events, findings)
        source_risk = build_source_risk(events, findings)
        triage = build_triage_report(summary, source_risk, findings)

        self.assertEqual(17, summary["events"])
        self.assertTrue(any(row["source_ip"] == "192.0.2.50" and row["max_risk"] == "high" for row in source_risk))
        self.assertIn("Port Scan Triage", triage)

    def test_parser_reports_bad_line_number(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.log"
            path.write_text("bad,line\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "bad.log:1"):
                parse_log(path)


if __name__ == "__main__":
    unittest.main()
