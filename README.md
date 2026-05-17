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

## Quick Start

```bash
python3 -m src.timeline data/normal-traffic.log data/nmap-scan.log
python3 -m unittest discover -s tests -p 'test_*.py'
```

The CLI writes:

- `reports/detection-report.md`
- `reports/findings.json`

## MVP Capabilities

- Parses safe synthetic firewall logs
- Detects many destination ports hit by the same source in a short window
- Separates normal traffic from Nmap-like recon behavior
- Produces a Markdown timeline and machine-readable JSON findings
- Includes unit tests and CI execution

## Roadmap

- Polish sample output screenshots or terminal demos
- Add architecture diagram and deeper implementation notes
- Expand test coverage around edge cases
- Add Docker or local demo workflow where useful
- Prepare `v0.1.0-mvp` release notes
