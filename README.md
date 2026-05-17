# Port Scan Lab

**Goal:** Detect recon activity from Nmap scans.

**MVP:** Compare normal traffic vs port scan traffic.

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

## Repository Status

This repository contains a working Port Scan Lab MVP with safe lab fixtures, deterministic detection rules, generated report output, and tests.

## Production Foundation

- Private GitHub repository linked to `main`
- Initial MVP scaffold committed
- CI repository-health workflow
- Security policy
- Contribution guide
- Pull request and issue templates
- Production readiness checklist
- Safe ignore rules for local secrets and generated files
