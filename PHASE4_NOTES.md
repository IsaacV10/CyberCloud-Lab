# Phase 4: Windows Endpoint & Attack Simulation
 
## Overview
 
Phase 4 adds endpoint visibility to the environment. A Windows Server 2025 EC2 instance was deployed with Sysmon for detailed endpoint logging and Atomic Red Team for adversary simulation. The Splunk Universal Forwarder ships all endpoint logs to the central SIEM, completing the multi-layer visibility: network (honeypots), cloud (CloudTrail/GuardDuty), and endpoint (Sysmon).
## Sysmon
 
Sysmon (System Monitor) logs detailed system activity that standard Windows Event Logs miss — full command lines, parent process chains, network connections per process, registry modifications, and cross-process memory access. The SwiftOnSecurity configuration filters out normal system noise while capturing security-relevant events.
 
**Key Event IDs used in this project:**
 
| Event ID | Name | Detects |
|----------|------|---------|
| 1 | Process Create | Malicious command execution |
| 10 | Process Access | Credential dumping (memory reads) |
| 13 | Registry Value Set | Persistence via startup keys |
 ## Splunk Universal Forwarder
 
The forwarder ships Sysmon and Windows Security logs to the central Splunk instance:
 
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
 
An initial "Access Denied" error (code 5) on the Sysmon channel was resolved by granting read access via `wevtutil`.
 
## Atomic Red Team Simulations
 
Six MITRE ATT&CK techniques were executed to generate realistic attack telemetry and validate detection coverage:
 
| Technique | Name | Tactic | What It Simulates |
|-----------|------|--------|-------------------|
| T1136.001 | Create Account | Persistence | Attacker creates a backdoor user account |
| T1082 | System Info Discovery | Discovery | Attacker gathers OS version, hostname, hardware details |
| T1059.001 | PowerShell | Execution | Attacker runs malicious PowerShell scripts |
## Searching Endpoint Data in Splunk
 
**All Windows events:**
```
index=* host="EC2AMAZ*"
```
 
**Process creation with command lines:**
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" | spath | where 'Event.System.EventID'=1 | table _time Event.EventData.Data{@Name}.Image Event.EventData.Data{@Name}.CommandLine Event.EventData.Data{@Name}.User
```
 
## Key Takeaways
 
- Sysmon logged all the devices activities in this case, the infected windows computer. 
- Atomic Red Team was the tool used to simulate an infected device within my infrastructure. This was done in an isolated and within a sandbox environment. 
- Combining network, cloud, and endpoint data in a single SIEM provides the multi-layer visibility required for comprehensive threat detection
