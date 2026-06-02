# Port Scan Lab

[![Python](https://img.shields.io/badge/Python-3.12-blue)](#) [![Status](https://img.shields.io/badge/status-MVP-green)](#) [![Security](https://img.shields.io/badge/security-defensive%20lab-purple)](#)

Detection lab for identifying Nmap-like recon activity from firewall logs.

- **Portfolio group:** Cybersecurity lab project
- **Status:** MVP implemented, tested, committed, and pushed to GitHub
- **GitHub:** https://github.com/SUDARSHANCHAUDHARI/PortScanLab
- **Local path:** `/Users/screencloudsudarshan/SUDARSHAN_CODE/sudarshan_repos/CyberSecurity/PortScanLab`

## MVP Snapshot

This repository includes a working MVP with safe sample data, deterministic detection or analysis logic, local tests, and generated output reports where relevant. It is ready for README/demo polish or deeper product work.

## Safe Use

This project is defensive and analysis-focused. Use only with logs, systems, repositories, and lab environments you own or have permission to assess.

## Core Features

- ingest firewall logs
- detect many ports from same IP
- detect short-time scan pattern
- show scan timeline


## Install

```bash
pip install .
```

This registers the `port-scan-lab` command. Or run directly:

```bash
python3 main.py --help
```

## Quick Start

```bash
python3 -m src.timeline data/normal-traffic.log data/nmap-scan.log
python3 -m unittest discover -s tests -p 'test_*.py'
```

The CLI writes:

- `reports/detection-report.md`
- `reports/findings.json`
- `reports/events.json`
- `reports/summary.json`
- `reports/source-risk.json`
- `reports/triage.md`

## MVP Capabilities

- Parses safe synthetic firewall logs
- Detects many destination ports hit by the same source in a short window
- Classifies scan profiles such as mixed service recon and remote access recon
- Builds source-IP risk rows for analyst triage
- Separates normal traffic from Nmap-like recon behavior
- Produces a Markdown timeline, triage report, source risk table, and machine-readable JSON findings
- Includes unit tests and CI execution

## Demo Artifacts

- [Architecture](docs/ARCHITECTURE.md)
- [Security notes](docs/SECURITY_NOTES.md)
- [Demo walkthrough](docs/DEMO.md)
- [Release notes](docs/RELEASE_NOTES.md)
- [Sample detection report](reports/detection-report.md)
- [Sample triage report](reports/triage.md)
- [Sample source risk table](reports/source-risk.json)

## Docker Demo

```bash
docker compose run --rm port-scan-demo
```

## Roadmap

- Add allowlist/suppression support for approved scanners.
- Add UDP/TCP profile tuning and threshold config.
- Add timeline charts for scan bursts.
- Add SIEM-friendly JSONL export.
- Prepare GitHub release `v0.1.0-mvp`.
