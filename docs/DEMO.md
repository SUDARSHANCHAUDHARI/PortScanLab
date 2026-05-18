# Demo

Run the included normal and Nmap-like firewall logs:

```bash
python3 -m src.timeline data/normal-traffic.log data/nmap-scan.log
```

Expected output:

```text
Analyzed 17 event(s)
Detected 1 scan pattern(s)
```

Generated artifacts:

- `reports/events.json`
- `reports/findings.json`
- `reports/summary.json`
- `reports/source-risk.json`
- `reports/detection-report.md`
- `reports/triage.md`

The sample demonstrates a high-risk mixed-service recon pattern from `192.0.2.50` against `10.0.0.20`.
