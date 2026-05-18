"""Detect short-window multi-port scan behavior."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from src.log_parser import FirewallEvent


@dataclass(frozen=True)
class ScanFinding:
    source_ip: str
    destination_ip: str
    port_count: int
    event_count: int
    denied_count: int
    allowed_count: int
    first_seen: str
    last_seen: str
    duration_seconds: float
    risk: str
    scan_profile: str
    ports_sample: list[int]
    reason: str


def classify_scan(unique_ports: set[int]) -> str:
    """Return a simple scan profile from the touched ports."""
    privileged = {port for port in unique_ports if port < 1024}
    remote_access = unique_ports & {22, 23, 3389, 5900}
    web_ports = unique_ports & {80, 443, 8080, 8443}
    if remote_access and web_ports:
        return "mixed-service-recon"
    if remote_access:
        return "remote-access-recon"
    if len(privileged) >= 6:
        return "common-service-sweep"
    return "multi-port-recon"


def detect_scans(
    events: list[FirewallEvent],
    *,
    min_unique_ports: int = 8,
    window_seconds: int = 60,
) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    grouped: dict[tuple[str, str], list[FirewallEvent]] = {}
    for event in events:
        grouped.setdefault((event.source_ip, event.destination_ip), []).append(event)

    window = timedelta(seconds=window_seconds)
    for (source_ip, destination_ip), group in grouped.items():
        ordered = sorted(group, key=lambda event: event.timestamp)
        best: list[FirewallEvent] = []
        for index, event in enumerate(ordered):
            candidate = [item for item in ordered[index:] if item.timestamp - event.timestamp <= window]
            if len({item.destination_port for item in candidate}) > len({item.destination_port for item in best}):
                best = candidate

        unique_ports = {event.destination_port for event in best}
        if len(unique_ports) < min_unique_ports:
            continue

        first_seen = best[0].timestamp
        last_seen = best[-1].timestamp
        duration = max((last_seen - first_seen).total_seconds(), 1.0)
        rate = len(unique_ports) / duration
        denied_count = sum(1 for event in best if event.action == "DENY")
        allowed_count = sum(1 for event in best if event.action == "ALLOW")
        risk = "high" if len(unique_ports) >= min_unique_ports * 2 or rate >= 0.4 else "medium"
        if denied_count == len(best) and len(unique_ports) >= min_unique_ports + 4:
            risk = "high"
        findings.append(
            ScanFinding(
                source_ip=source_ip,
                destination_ip=destination_ip,
                port_count=len(unique_ports),
                event_count=len(best),
                denied_count=denied_count,
                allowed_count=allowed_count,
                first_seen=first_seen.isoformat(),
                last_seen=last_seen.isoformat(),
                duration_seconds=duration,
                risk=risk,
                scan_profile=classify_scan(unique_ports),
                ports_sample=sorted(unique_ports)[:12],
                reason=f"{len(unique_ports)} unique destination ports touched within {window_seconds} seconds",
            )
        )

    return sorted(findings, key=lambda finding: (finding.risk != "high", -finding.port_count, finding.source_ip))


def summarize_findings(findings: list[ScanFinding]) -> dict[str, int]:
    return {
        "total_findings": len(findings),
        "high_risk": sum(1 for finding in findings if finding.risk == "high"),
        "medium_risk": sum(1 for finding in findings if finding.risk == "medium"),
    }


def build_source_risk(events: list[FirewallEvent], findings: list[ScanFinding]) -> list[dict]:
    """Return source-IP risk rows for dashboards."""
    rows = []
    for source_ip in sorted({event.source_ip for event in events} | {finding.source_ip for finding in findings}):
        source_events = [event for event in events if event.source_ip == source_ip]
        source_findings = [finding for finding in findings if finding.source_ip == source_ip]
        unique_ports = sorted({event.destination_port for event in source_events})
        rows.append(
            {
                "source_ip": source_ip,
                "events": len(source_events),
                "unique_destination_ports": len(unique_ports),
                "destinations": sorted({event.destination_ip for event in source_events}),
                "findings": len(source_findings),
                "max_risk": "high" if any(finding.risk == "high" for finding in source_findings) else ("medium" if source_findings else "low"),
                "ports_sample": unique_ports[:12],
            }
        )
    risk_order = {"high": 3, "medium": 2, "low": 1}
    return sorted(rows, key=lambda row: (-risk_order[row["max_risk"]], -row["findings"], row["source_ip"]))
