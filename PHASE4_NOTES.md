Phase 4: Windows Endpoint & Attack Simulation
Overview
Phase 4 adds endpoint visibility to the SOC environment. A Windows Server 2025 EC2 instance was deployed with Sysmon for detailed endpoint logging and Atomic Red Team for adversary simulation. The Splunk Universal Forwarder ships all endpoint logs to the central SIEM, completing the multi-layer visibility: network (honeypots), cloud (CloudTrail/GuardDuty), and endpoint (Sysmon).
Sysmon
Sysmon (System Monitor) logs detailed system activity that standard Windows Event Logs miss — full command lines, parent process chains, network connections per process, registry modifications, and cross-process memory access. The SwiftOnSecurity configuration filters out normal system noise while capturing security-relevant events.
Key Event IDs used in this project:
Event IDNameDetects1Process CreateMalicious command execution10Process AccessCredential dumping (LSASS memory reads)13Registry Value SetPersistence via startup keys
Splunk Universal Forwarder
The forwarder ships Sysmon and Windows Security logs to the central Splunk instance:
ini[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = true
index = main

[WinEventLog://Security]
disabled = 0
renderXml = true
index = main
An initial "Access Denied" error (code 5) on the Sysmon channel was resolved by granting read access via wevtutil.
Atomic Red Team Simulations
Six MITRE ATT&CK techniques were executed to generate realistic attack telemetry and validate detection coverage:
TechniqueNameTacticWhat It SimulatesT1136.001Create AccountPersistenceAttacker creates a backdoor user accountT1082System Info DiscoveryDiscoveryAttacker gathers OS version, hostname, hardware detailsT1059.001PowerShellExecutionAttacker runs malicious PowerShell scripts
Searching Endpoint Data in Splunk
All Windows events:
index=* host="EC2AMAZ*"
Process creation with command lines:
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" | spath | where 'Event.System.EventID'=1 | table _time Event.EventData.Data{@Name}.Image Event.EventData.Data{@Name}.CommandLine Event.EventData.Data{@Name}.User
Key Takeaways

Sysmon provides the detailed endpoint telemetry that standard Windows logging lacks
Atomic Red Team enables controlled adversary simulation mapped directly to MITRE ATT&CK for validating detection rules
Combining network, cloud, and endpoint data in a single SIEM provides the multi-layer visibility required for comprehensive threat detection
