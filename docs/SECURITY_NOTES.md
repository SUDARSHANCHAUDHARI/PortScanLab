# Security Notes

This project is defensive and analysis-only. Use it only with firewall logs from networks you own or have permission to monitor.

## Data Handling

- Firewall logs can contain internal IP ranges, public source IPs, ports, and timing.
- Redact private network names and sensitive host mappings before sharing reports.
- Do not commit production firewall logs.
- Sample data uses documentation IP ranges and synthetic internal addresses.

## Detection Caveats

- Port-scan findings are triage signals, not proof of compromise.
- Authorized vulnerability scanners can trigger the same patterns as hostile recon.
- Tune thresholds per network segment before production alerting.
