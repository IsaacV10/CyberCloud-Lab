# CyberCloud-Lab
 
A full-stack cloud SOC environment built on AWS, covering honeypot deployment, SIEM integration, threat detection, incident response, and automated remediation.

This project simulates a real-world Security Operations Center (SOC). It captures real attack data using honeypots, ingests logs along with AWS telemetry into a SIEM, and builds detection rules mapped to the MITRE ATT&CK framework. It also includes incident investigation workflows and automated responses to detected threats.
## Architecture
 
```
┌──────────────────────────────────────────────────────────────────┐
│                          INTERNET                                │
│                (attackers, bots, scanners)                       │
└──────────┬──────────────────────┬────────────────────────────────┘
           │ :2222 (SSH)          │ :8080 (HTTP)
           ▼                      ▼
┌────────────────────────────────────────────────────────────────── ┐
│                     LINUX EC2 INSTANCE                            │
│                                                                   │
│   ┌───────────────── ┐    ┌──────────────────┐                    │ 
│   │  SSH Honeypot    │    │  HTTP Honeypot   │                    │
│   │  (Paramiko)      │    │  (Flask/WP-login)│                    │
│   └────────┬─────────┘    └────────┬─────────┘                    │
│            │                       │                              │
│            ▼                       ▼                              │
│   ┌──────────────────────────────────────────┐                    │
│   │     /var/log/honeypot/ (NDJSON)          │                    │
│   └──────────────────┬───────────────────────┘                    │
│                      │                                            │
│              ┌───────▼────────┐                                   │
│              │  SPLUNK SIEM   │◄──── Windows Sysmon + Security    │
│              │  (port 8000)   │      (via Universal Forwarder)    │
│              └───────┬────────┘                                   │
│                      │                                            │
│              Dashboards / Alerts / Detection Rules                │
└────────────────────────────────────────────────────────────────── ┘
 
┌──────────────────────────────────────────────────────────────────┐
│                  WINDOWS SERVER 2025 EC2                         │
│                                                                  │
│   Sysmon (SwiftOnSecurity config)                                │
│   Atomic Red Team (adversary simulation)                         │
│   Splunk Universal Forwarder ──────► Splunk on Linux instance    │
└──────────────────────────────────────────────────────────────────┘
 
┌──────────────────────────────────────────────────────────────────┐
│                    AWS SECURITY SERVICES                         │
│                                                                  │
│   CloudTrail ──────┐                                             │
│   GuardDuty ───────┼──────► S3 Bucket (centralized logs)         │
│   VPC Flow Logs ───┘                                             │
│                                                                  │
│   GuardDuty ──► EventBridge ──► Lambda (auto-block IPs)          │
└──────────────────────────────────────────────────────────────────┘
```

 ## Project Phases
 The project was organized into 7 distinct phase. 
| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Deploy SIEM-ready SSH & HTTP honeypots with JSON logging | ✅ Complete |
| 2 | Enable CloudTrail, GuardDuty & VPC Flow Logs | ✅ Complete |
| 3 | Install Splunk SIEM, ingest all log sources, build dashboards | ✅ Complete |
| 4 | Deploy Windows Server 2025, Sysmon & Atomic Red Team | ✅ Complete |
| 5 | Write 6 detection rules mapped to MITRE ATT&CK | ✅ Complete |
| 6 | Investigate real attacks, write formal incident reports | ✅ Complete |
| 7 | Build automated response with Lambda & EventBridge | ✅ Complete 




