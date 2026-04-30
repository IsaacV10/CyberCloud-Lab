# Phase 3: SIEM Deployment (Splunk)
 
## Overview
 
Phase 3 establishes the central nervous system of the SOC environment. Splunk Enterprise (Free tier) was installed on the same EC2 instance running the honeypots, serving as the centralized SIEM where all log sources converge into a single searchable platform with dashboards, visualizations, and alerting capabilities.
 
Without a SIEM, security data sits in isolated log files across different systems. An analyst would have to manually SSH into each server, grep through raw text, and mentally correlate events across sources. Splunk eliminates that by ingesting everything into one place where you can search across all data sources simultaneously, build visualizations to spot patterns, and create alerts that fire automatically when something suspicious happens.
 
## Installation
 
### Prerequisites
 
Splunk Enterprise requires more resources than a basic web server. The following preparations were made on the t2.micro EC2 instance:
 
- **Disk expansion:** The default 8GB EBS volume was expanded to 20GB to accommodate Splunk's indexes and the growing honeypot log data
- **Swap file:** A 4GB swap file was created since the t2.micro only has ~1GB of RAM and Splunk is memory-intensive
- **Partition resize:** After expanding the EBS volume, the partition and filesystem were resized to use the new space
### Installation Steps
 
1. Downloaded the Splunk Enterprise `.deb` package from Splunk's website
2. Installed with `dpkg -i splunk.deb` which places all files under `/opt/splunk/`
3. Started Splunk with `splunk start --accept-license` and set the admin password
4. Enabled boot-start so Splunk survives reboots via `splunk enable boot-start`
5. Added port 8000 to the EC2 security group (My IP only) for web interface access

### Performance Tuning
 
Running Splunk on a t2.micro required several optimizations:
 
- **Disabled introspection logging** to prevent Splunk's internal monitoring from consuming disk space (the `_introspection` index grew to 2.1GB before being cleaned)
- **Changed all detection alerts from real-time to scheduled** (every 5 minutes) because real-time searches consumed too much CPU and memory, causing Splunk's web server to fail to start
- **Regular cleanup** of dispatch directory and rotated logs to maintain adequate free disk space

## Data Sources
 
### Honeypot Logs (Local File Monitoring)
 
Both honeypot log files were added as data inputs through Splunk's web interface:
 
| Setting | SSH Honeypot | HTTP Honeypot |
|---------|-------------|---------------|
| Input Type | File Monitor | File Monitor |
| Path | `/var/log/honeypot/ssh_honeypot.log` | `/var/log/honeypot/http_honeypot.log` |
| Source Type | `_json` | `_json` |
| Index | main | main |
| Monitor Mode | Continuous | Continuous |
### Windows Endpoint Logs (Splunk Universal Forwarder)
 
The Splunk Universal Forwarder was installed on the Windows Server 2025 instance to ship endpoint logs to Splunk over TCP port 9997.
 
| Setting | Details |
|---------|---------|
| Forwarder Version | Splunk Universal Forwarder (latest) |
| Receiving Port | 9997 (configured on the Splunk indexer) |
| Transport | TCP (within VPC, private IP) |
| Sysmon Logs | `WinEventLog://Microsoft-Windows-Sysmon/Operational` |
| Security Logs | `WinEventLog://Security` |
| Source Type | `XmlWinEventLog` |
| XML Rendering | Enabled (`renderXml = true`) |
 
**Forwarder Configuration (`inputs.conf`):**
```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = true
index = main
 
[WinEventLog://Security]
disabled = 0
renderXml = true
index = main
```
 
**Permissions Issue Resolved:** The Sysmon log channel initially returned "Access Denied" (error code 5) when the forwarder tried to subscribe. This was resolved by granting the Local System account read access to the Sysmon event log channel using `wevtutil`.
**Field Extraction:** Windows event logs arrive as raw XML.

## Splunk Dashboard: Honeypot Attack Monitor
 
A Dashboard Studio dashboard was built to provide a real-time operational view of all attack activity across both honeypots.

<img width="1429" height="1082" alt="Screenshot 2026-04-25 225227" src="https://github.com/user-attachments/assets/67525c79-6367-4192-9225-561fde6efb69" />

