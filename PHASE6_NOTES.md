Phase 6: Incident Investigation & Reporting

Overview
Phase 6 applies the SOC analyst workflow to real attack data captured by the honeypot infrastructure. Two incidents were selected from the live data, investigated using Splunk, enriched with open-source threat intelligence, and documented as formal incident reports following industry-standard SOC reporting formats.

Incidents Captured: 
- INC-2026-001: SSH Brute Force Campaign (47.250.181.61, 8,726 attempts, T1110.001)
- INC-2026-002: Automated Recon Bot (31.56.209.39, container detection, T1059.004/T1082)

Incident 1: SSH Brute Force Campaign
INC-2026-001 Summary
FieldDetailsIncident IDINC-2026-001SeverityHIGHSource IP47.250.181.61Duration61 hours (April 13-16, 2026)Total Attempts8,726 authentication attemptsTarget Accountroot (exclusively)MITRE ATT&CKT1110.001 - Brute Force: Password Guessing


Incident 2: Automated Reconnaissance Bot
INC-2026-002 Summary
FieldDetailsIncident IDINC-2026-002SeverityCRITICALSource IP31.56.209.39Visits2 (April 17 and April 21, 2026)Credentials Usedadmin:admin (default)Command ExecutedContainer detection payloadMITRE ATT&CKT1078.001, T1059.004, T1082, T1497

