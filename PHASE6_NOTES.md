# Phase 6: Incident Investigation & Reporting
 
## Overview
 
During this phase I gathered looked for key to real attack data captured by the honeypot infrastructure. Two incidents were selected from the live data, investigated using Splunk, and documented as formal incident reports following industry-standard SOC reporting formats.

## Investigation Starting Point
 
The investigation began by understanding the full scope of captured data. With 111,355 events across 14 event types, the SIEM provided a comprehensive dataset to work with.
 
<img width="2563" height="857" alt="Screenshot 2026-04-25 225811" src="https://github.com/user-attachments/assets/9e6c49c5-d27b-4eff-9f62-632968622962" />

*Splunk search: `index=main sourcetype=_json | stats count by event_type` — 111,355 total events including 23,802 auth attempts, 28,023 connections, 2,153 HTTP requests, and 12 attacker commands.*

## Finding the Incidents
 
The most valuable events in any honeypot dataset are the **commands** — they show what attackers do after gaining access. Out of 111,355 events, only 12 command events were captured, making each one significant.
 
<img width="1272" height="650" alt="Screenshot 2026-04-25 230025" src="https://github.com/user-attachments/assets/6df03338-9b05-4ac8-a73c-bb64be9c4de8" />

*Splunk search: `index=main sourcetype=_json event_type="command" | table timestamp src_ip username command session_id` — All 12 commands captured, showing the recon bot (31.56.209.39), another probe (117.72.157.108), and testing sessions (70.108.8.131).*

## Incident 2: Automated Reconnaissance Bot
 
### INC-2026-002 Summary
 
| Field | Details |
|-------|---------|
| Incident ID | INC-2026-002 |
| Severity | CRITICAL |
| Source IP | 31.56.209.39 |
| Visits | 2 (April 17 and April 21, 2026) |
| Credentials Used | admin:admin (default) |
| Command Executed | Container detection payload |
| MITRE ATT&CK | T1078.001, T1059.004, T1082, T1497 |
