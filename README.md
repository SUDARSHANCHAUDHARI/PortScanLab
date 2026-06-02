# Port Scan Lab

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](#requirements)
[![Status](https://img.shields.io/badge/status-MVP-green)](#status)
[![Security](https://img.shields.io/badge/security-defensive%20lab-purple)](#safe-use)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Detection lab for identifying Nmap-style port scan and reconnaissance activity from firewall logs.

---

## Overview

Port Scan Lab is a defensive analysis lab tool that parses firewall logs, groups connection attempts by source IP, and detects port scanning patterns: wide port sweeps, mixed-service reconnaissance, and rapid scan windows. Outputs include scan findings, per-source risk tables, a Markdown timeline report, and analyst triage handoff.

## Features

- Parses common firewall log formats
- Detects wide-range port scans
- Identifies mixed-service reconnaissance (web + SSH + DB ports)
- Detects rapid scan windows (compact time bursts)
- Scores risk per source IP
- Outputs JSON findings, source risk table, Markdown timeline report, and triage handoff

## Requirements

- Python 3.10 or newer
- Linux, macOS, or Windows
- No third-party Python packages (standard library only)
- Optional: Docker for the demo container

## Installation

```bash
git clone https://github.com/SUDARSHANCHAUDHARI/PortScanLab.git
cd PortScanLab
pip install .
```

This registers the `port-scan-lab` CLI command.

To run without installing:

```bash
python3 main.py --help
```

## Usage

Analyze the included sample firewall logs:

```bash
python3 main.py --out reports/report.md
```

Generated outputs in `reports/`:

- `events.json` — parsed firewall events
- `findings.json` — detected scan findings
- `source-risk.json` — per-source risk table
- `summary.json` — counts and severity breakdown
- `report.md` — Markdown timeline report
- `triage.md` — analyst triage checklist

## Project Structure

```
PortScanLab/
├── src/            Log parser, scan detector, timeline builder
├── data/           Safe sample firewall logs (normal + nmap-scan)
├── reports/        Example generated output
├── docker/         Dockerfile + compose support
├── docs/           Architecture, security notes, demo
├── tests/          Unit tests
├── main.py         CLI entrypoint
├── pyproject.toml  Package metadata
└── LICENSE
```

## Testing

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

## Docker Demo

```bash
docker compose run --rm port-scan-demo
```

## Safe Use

This project is defensive and analysis-focused. Use only with logs and lab environments you own or have explicit written permission to assess. The included sample logs are synthetic and safe for public demo use.

## Status

Working CLI MVP with tests, sample data, and Docker support.

## Roadmap

- Live `iptables` log tailing mode
- Sigma rule import for scan signatures
- Per-protocol scan profile classification
- Allowlist for trusted scanners (internal vuln scans)
- GitHub release `v0.1.0-mvp`

## License

Released under the [MIT License](LICENSE). You are free to use, modify, and distribute this software with attribution.

## Author

**Sudarshan Chaudhari** — [SudarshanTechLabs](https://github.com/SUDARSHANCHAUDHARI)
Bangkok, Thailand

For inquiries: open an issue on [GitHub](https://github.com/SUDARSHANCHAUDHARI/PortScanLab/issues).
