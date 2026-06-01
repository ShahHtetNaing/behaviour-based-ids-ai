# Behaviour-Based Intrusion Prevention System Report

- Generated at: 2026-06-01T04:33:41.845995+00:00
- Records processed: 5
- Anomalies found: 1
- Anomaly ratio (%): 20.0
- Risk level: HIGH

## Detailed Anomalies

### Anomaly 1
- Timestamp: 2026-06-01T01:09:00
- Source: 10.0.0.9 -> Destination: 172.16.0.30
- Protocol/Port: tcp / 3389
- Volume: bytes=920000.0, packets=12450.0
- Duration: 4200.0 seconds
- Failed logins: 7.0
- Source file: sample_network_log.csv
- AI anomaly score: 0.002946
- Risk level: HIGH
- Impact category: Credential Attack
- What is it: A credential attack event was detected from 10.0.0.9 targeting 172.16.0.30:3389 over TCP.
- Current impact: Active authentication pressure on exposed services. Critical admin/remote services are being targeted now. Network performance degradation and service instability may occur. Access control is already rejecting suspicious sessions.
- Future impact: Account takeover, privilege escalation, and ransomware staging. Without action, attackers may gain valid credentials within hours.
- Why this is suspicious:
  - Brute-force login pattern
  - Sensitive service with unusually high transfer
  - Long-lived connection outside normal behavior
  - Packet flood signature
  - Failed/denied access pattern
- How to solve this (step-by-step):
  - Validate whether this traffic is expected by checking asset owner and change logs.
  - If unexpected, isolate the source host from critical network segments immediately.
  - Block or rate-limit suspicious source IP and destination port on firewall/IPS.
  - Force password reset and enable MFA if repeated login failures are present.
  - Run endpoint malware scan and review active processes on the source host.
  - Add a detection rule for this behavior pattern and monitor for recurrence for 72 hours.
