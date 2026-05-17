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
    first_seen: str
    last_seen: str
    duration_seconds: float
    risk: str
    reason: str


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
        risk = "high" if len(unique_ports) >= min_unique_ports * 2 or rate >= 0.4 else "medium"
        findings.append(
            ScanFinding(
                source_ip=source_ip,
                destination_ip=destination_ip,
                port_count=len(unique_ports),
                event_count=len(best),
                first_seen=first_seen.isoformat(),
                last_seen=last_seen.isoformat(),
                duration_seconds=duration,
                risk=risk,
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
