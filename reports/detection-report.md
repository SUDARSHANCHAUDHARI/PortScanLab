# Port Scan Detection Report

- Events analyzed: 17
- Sources: 5
- Destinations: 3
- Findings: 1
- High risk: 1
- Medium risk: 0

## Priority Queue

1. **high** 192.0.2.50 -> 10.0.0.20: 12 ports, profile=mixed-service-recon

## Findings

### 192.0.2.50 -> 10.0.0.20

- Risk: high
- Window: 2026-05-18T10:05:00+00:00 to 2026-05-18T10:05:33+00:00
- Unique ports: 12
- Events: 12
- Denied: 12
- Allowed: 0
- Profile: mixed-service-recon
- Ports sample: 21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389, 8080
- Why: 12 unique destination ports touched within 60 seconds
- Recommended next step: Confirm whether this source is an approved scanner, then block or rate-limit if unauthorized.
