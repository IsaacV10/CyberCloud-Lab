# Phase 7: Automated Response
- Lambda function (CyberCloud-AutoBlock) auto-blocks attacker IPs
- EventBridge rule triggers Lambda on GuardDuty findings
- Blocked IPs tracked in dedicated CyberCloud-BlockList security group
- Extracts IPs from network connections, port probes, and API call findings
- Duplicate IP detection prevents redundant rules
