"""Build a Markdown timeline for detected port scans."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path

from src.log_parser import FirewallEvent, parse_logs
from src.scan_detector import ScanFinding, detect_scans, summarize_findings


def build_timeline(events: list[FirewallEvent], findings: list[ScanFinding]) -> str:
    summary = summarize_findings(findings)
    lines = [
        "# Port Scan Detection Report",
        "",
        f"- Events analyzed: {len(events)}",
        f"- Findings: {summary['total_findings']}",
        f"- High risk: {summary['high_risk']}",
        f"- Medium risk: {summary['medium_risk']}",
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines.append("No short-window multi-port scan pattern was detected.")
    for finding in findings:
        lines.extend(
            [
                f"### {finding.source_ip} -> {finding.destination_ip}",
                "",
                f"- Risk: {finding.risk}",
                f"- Window: {finding.first_seen} to {finding.last_seen}",
                f"- Unique ports: {finding.port_count}",
                f"- Events: {finding.event_count}",
                f"- Why: {finding.reason}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect Nmap-like port scan behavior from firewall logs")
    parser.add_argument("logs", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, default=Path("reports/detection-report.md"))
    parser.add_argument("--json-out", type=Path, default=Path("reports/findings.json"))
    args = parser.parse_args()

    events = parse_logs(args.logs)
    findings = detect_scans(events)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(build_timeline(events, findings), encoding="utf-8")
    args.json_out.write_text(json.dumps([asdict(finding) for finding in findings], indent=2) + "\n", encoding="utf-8")
    print(f"Analyzed {len(events)} event(s)")
    print(f"Detected {len(findings)} scan pattern(s)")


if __name__ == "__main__":
    main()
