# CyberCloud-Lab

## Description
A full-stack cloud SOC environment built on AWS — from honeypot deployment to SIEM integration, detection engineering, and automated incident response.

This project simulates a real-world Security Operations Center (SOC) pipeline: capture live attack data with honeypots, ingest logs alongside AWS-native telemetry into a SIEM, write detection rules mapped to MITRE ATT&CK, investigate incidents, and automate response.
Goal: To develop practical experience and expand my knowledge of cloud and security tools.
---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        INTERNET                              │
│              (attackers, bots, scanners)                      │
└──────────┬──────────────────────┬────────────────────────────┘
           │ :2222 (SSH)          │ :8080 (HTTP)
           ▼                      ▼
┌──────────────────────────────────────────────────────────────┐
│                     EC2 INSTANCE                             │
│                                                              │
│   ┌─────────────────┐    ┌──────────────────┐                │
│   │  SSH Honeypot    │    │  HTTP Honeypot   │                │
│   │  (Paramiko)      │    │  (Flask/WP-login)│                │
│   └────────┬─────────┘    └────────┬─────────┘                │
│            │                       │                          │
│            ▼                       ▼                          │
│   ┌──────────────────────────────────────────┐                │
│   │     /var/log/honeypot/                   │                │
│   │     ├── ssh_honeypot.log  (NDJSON)       │                │
│   │     └── http_honeypot.log (NDJSON)       │                │
│   └──────────────────────────────────────────┘                │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│                    AWS SECURITY SERVICES                      │
│                                                              │
│   CloudTrail ──────┐                                         │
│   GuardDuty ───────┼──────▶  S3 Bucket (centralized logs)   │
│   VPC Flow Logs ───┘                                         │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│                      SIEM (Splunk)                 [PHASE 3] │
│                                                              │
│   Honeypot logs ────┐                                        │
│   CloudTrail ───────┼──────▶  Dashboards / Alerts / Reports  │
│   GuardDuty ────────┤                                        │
│   VPC Flow Logs ────┘                                        │
└──────────────────────────────────────────────────────────────┘
```

---

## Project Phases

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Deploy SIEM-ready SSH & HTTP honeypots with JSON logging | ✅ Complete |
| 2 | Enable CloudTrail, GuardDuty & VPC Flow Logs | ✅ Complete |
| 3 | Install Splunk, ingest all log sources into one dashboard | 🔄 In Progress |
| 4 | Spin up Windows VM, deploy Sysmon & Atomic Red Team | ⬚ Upcoming |
| 5 | Write detection rules mapped to MITRE ATT&CK | ⬚ Upcoming |
| 6 | Investigate real alerts, write formal incident reports | ⬚ Upcoming |
| 7 | Build automated response (Lambda / SOAR workflow) | ⬚ Upcoming |

---

## Phase 1: Honeypots

Two honeypots running as systemd services on an AWS EC2 instance, logging all activity as newline-delimited JSON (NDJSON) for direct SIEM ingestion.

### SSH Honeypot
- Built with Python + Paramiko
- Emulates a realistic Ubuntu SSH server with fake filesystem responses
- Captures: connection attempts, login credentials, shell commands
- Accepts select fake credentials to lure attackers into an interactive shell
- 20+ fake Linux command responses (`whoami`, `cat /etc/passwd`, `ps aux`, etc.)
- Session tracking via UUID — every event from one attacker is linked

### HTTP Honeypot
- Built with Python + Flask
- Mimics a WordPress `wp-login.php` page
- Captures: login attempts, admin panel probes, XML-RPC brute force, path scanning
- Catch-all route logs every request from scanning bots

### Sample Log Output
```json
{"timestamp": "2026-03-25T14:30:07+00:00", "event_type": "auth_attempt", "session_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "src_ip": "185.220.101.42", "src_port": 54321, "sensor": "ssh_honeypot", "username": "root", "password": "admin123", "success": false}
```
```json
{"timestamp": "2026-03-25T14:35:22+00:00", "event_type": "login_attempt", "src_ip": "103.41.167.88", "sensor": "http_honeypot", "username": "admin", "password": "P@ssw0rd!", "user_agent": "Mozilla/5.0"}
```

---

## Phase 2: AWS Security Services

All three services feed into a centralized S3 bucket for future SIEM ingestion.

- **CloudTrail** — Records every AWS API call (who launched an instance, changed a security group, created a user, etc.)
- **GuardDuty** — Analyzes CloudTrail, VPC Flow Logs, and DNS logs for threats (credential abuse, crypto mining, C2 communication)
- **VPC Flow Logs** — Captures all network traffic metadata (source/dest IPs, ports, bytes, accept/reject) at 1-minute intervals

---

## Tech Stack

- **Cloud:** AWS (EC2, S3, CloudTrail, GuardDuty, VPC Flow Logs)
- **Honeypots:** Python, Paramiko, Flask
- **SIEM:** Splunk Free (Phase 3)
- **OS:** Ubuntu Server 24.04 LTS
- **Logging:** Newline-delimited JSON (NDJSON) with RotatingFileHandler

---

## Setup

### Prerequisites
- AWS account (free tier eligible)
- Python 3.10+
- SSH key pair for EC2 access

### Quick Start
```bash
git clone https://github.com/IsaacV10/CyberCloud-Lab.git
cd CyberCloud-Lab
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Create log directory
sudo mkdir -p /var/log/honeypot
sudo chown $USER:$USER /var/log/honeypot

# Start honeypots
python3 ssh_honeypot.py -p 2222
python3 http_honeypot.py -p 8080
```

### Running as Services
Both honeypots are configured as systemd services for persistence across reboots. See `PHASE1_SETUP_GUIDE.md` for full deployment instructions including systemd configs, iptables redirects, and AWS security group rules.

---

## Security Group Configuration

| Port | Source | Purpose |
|------|--------|---------|
| 22 | My IP only | Admin SSH access |
| 80 | 0.0.0.0/0 | HTTP honeypot redirect |
| 2222 | 0.0.0.0/0 | SSH honeypot direct |
| 8080 | 0.0.0.0/0 | HTTP honeypot direct |
