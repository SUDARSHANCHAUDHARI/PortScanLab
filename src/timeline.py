"""Build a Markdown timeline for detected port scans."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path

from src.log_parser import FirewallEvent, parse_logs
from src.scan_detector import ScanFinding, build_source_risk, detect_scans, summarize_findings


def event_to_dict(event: FirewallEvent) -> dict:
    """Return a JSON-friendly firewall event."""
    return {
        "timestamp": event.timestamp.isoformat(),
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "destination_port": event.destination_port,
        "protocol": event.protocol,
        "action": event.action,
    }


def build_summary(events: list[FirewallEvent], findings: list[ScanFinding]) -> dict:
    """Return dashboard-friendly summary data."""
    summary = summarize_findings(findings)
    return {
        "events": len(events),
        "sources": len({event.source_ip for event in events}),
        "destinations": len({event.destination_ip for event in events}),
        "findings": summary["total_findings"],
        "high_risk": summary["high_risk"],
        "medium_risk": summary["medium_risk"],
    }


def build_timeline(events: list[FirewallEvent], findings: list[ScanFinding]) -> str:
    summary = build_summary(events, findings)
    lines = [
        "# Port Scan Detection Report",
        "",
        f"- Events analyzed: {summary['events']}",
        f"- Sources: {summary['sources']}",
        f"- Destinations: {summary['destinations']}",
        f"- Findings: {summary['findings']}",
        f"- High risk: {summary['high_risk']}",
        f"- Medium risk: {summary['medium_risk']}",
        "",
        "## Priority Queue",
        "",
    ]
    if not findings:
        lines.append("No immediate analyst queue was generated.")
    for index, finding in enumerate(findings[:5], start=1):
        lines.append(
            f"{index}. **{finding.risk}** {finding.source_ip} -> {finding.destination_ip}: "
            f"{finding.port_count} ports, profile={finding.scan_profile}"
        )
    lines.extend(
        [
            "",
            "## Findings",
            "",
        ]
    )
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
                f"- Denied: {finding.denied_count}",
                f"- Allowed: {finding.allowed_count}",
                f"- Profile: {finding.scan_profile}",
                f"- Ports sample: {', '.join(str(port) for port in finding.ports_sample)}",
                f"- Why: {finding.reason}",
                "- Recommended next step: Confirm whether this source is an approved scanner, then block or rate-limit if unauthorized.",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def build_triage_report(summary: dict, source_risk: list[dict], findings: list[ScanFinding]) -> str:
    """Return a compact triage handoff report."""
    lines = [
        "# Port Scan Triage",
        "",
        f"- Events analyzed: {summary['events']}",
        f"- Findings: {summary['findings']}",
        "",
        "## Source Risk",
        "",
    ]
    for row in source_risk:
        lines.append(
            f"- `{row['source_ip']}`: {row['max_risk']}, {row['events']} event(s), "
            f"{row['unique_destination_ports']} unique port(s), findings={row['findings']}"
        )
    lines.extend(["", "## Analyst Queue", ""])
    if not findings:
        lines.append("- No immediate analyst queue was generated.")
    for finding in findings[:8]:
        lines.append(
            f"- `{finding.risk}` {finding.source_ip} -> {finding.destination_ip}: "
            f"{finding.port_count} ports in {finding.duration_seconds:.0f}s"
        )
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect Nmap-like port scan behavior from firewall logs")
    parser.add_argument("logs", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, default=Path("reports/detection-report.md"))
    parser.add_argument("--json-out", type=Path, default=Path("reports/findings.json"))
    parser.add_argument("--events-out", type=Path, default=Path("reports/events.json"))
    parser.add_argument("--summary-out", type=Path, default=Path("reports/summary.json"))
    parser.add_argument("--source-risk-out", type=Path, default=Path("reports/source-risk.json"))
    parser.add_argument("--triage-out", type=Path, default=Path("reports/triage.md"))
    args = parser.parse_args()

    events = parse_logs(args.logs)
    findings = detect_scans(events)
    summary = build_summary(events, findings)
    source_risk = build_source_risk(events, findings)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(build_timeline(events, findings), encoding="utf-8")
    args.json_out.write_text(json.dumps([asdict(finding) for finding in findings], indent=2) + "\n", encoding="utf-8")
    args.events_out.write_text(json.dumps([event_to_dict(event) for event in events], indent=2) + "\n", encoding="utf-8")
    args.summary_out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    args.source_risk_out.write_text(json.dumps(source_risk, indent=2) + "\n", encoding="utf-8")
    args.triage_out.write_text(build_triage_report(summary, source_risk, findings), encoding="utf-8")
    print(f"Analyzed {len(events)} event(s)")
    print(f"Detected {len(findings)} scan pattern(s)")


if __name__ == "__main__":
    main()
