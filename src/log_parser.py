"""Parse simple firewall logs for port scan analysis."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass(frozen=True)
class FirewallEvent:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str
    action: str


def parse_line(line: str) -> FirewallEvent:
    """Parse CSV lines: timestamp,src_ip,dst_ip,dst_port,protocol,action."""
    parts = [part.strip() for part in line.split(",")]
    if len(parts) != 6:
        raise ValueError(f"expected 6 fields, got {len(parts)}")
    timestamp, source_ip, destination_ip, destination_port, protocol, action = parts
    return FirewallEvent(
        timestamp=datetime.fromisoformat(timestamp.replace("Z", "+00:00")),
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=int(destination_port),
        protocol=protocol.upper(),
        action=action.upper(),
    )


def parse_log(path: Path) -> list[FirewallEvent]:
    events: list[FirewallEvent] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            events.append(parse_line(stripped))
        except ValueError as exc:
            raise ValueError(f"{path}:{line_number}: {exc}") from exc
    return events


def parse_logs(paths: list[Path]) -> list[FirewallEvent]:
    events: list[FirewallEvent] = []
    for path in paths:
        events.extend(parse_log(path))
    return sorted(events, key=lambda event: event.timestamp)
