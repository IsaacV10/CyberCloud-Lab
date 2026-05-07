# Phase 2: AWS Security Services

## Overview

Phase 2 adds cloud-layer visibility to the System environment. While Phase 1 captures attacks hitting the honeypots directly, Phase 2 monitors what's happening at the AWS infrastructure level — who's making API calls to your account, what network traffic is flowing through your VPC, and whether any of that activity looks malicious.

In a real enterprise, attackers don't just target the applications. They go after cloud credentials, misconfigured IAM roles, and exposed services. These three AWS services provide the visibility needed to detect those types of threats.

## Services Enabled

### CloudTrail

**What it does:** Records every API call made in your AWS account. Every time anyone (or any service) does anything — launches an instance, modifies a security group, creates an IAM user, deletes a bucket, changes a policy — CloudTrail logs it with a timestamp, the identity of the caller, the source IP, and what was changed.

**Why it matters for a SOC:** CloudTrail is the audit trail for your cloud environment. If someone compromises your AWS credentials and starts spinning up crypto mining instances or creating backdoor IAM users, CloudTrail has the complete record of everything they did. It's the first place an analyst looks during a cloud incident investigation.

**Configuration:**
- Trail name: `CyberCloud-lab-trail`
- Scope: Multi-region (logs events from all AWS regions)
- Event types: Management events (API calls that manage AWS resources)
- Storage: S3 bucket (`aws-cloudtrail-logs-048204778161-3bf84036`)

<img width="1608" height="1085" alt="Screenshot 2026-04-26 013327" src="https://github.com/user-attachments/assets/5545427a-1bdc-458e-b527-ed606ddf5b5d" />


### GuardDuty

**What it does:** Continuously analyzes CloudTrail logs, VPC Flow Logs, and DNS query logs using machine learning and threat intelligence feeds to automatically detect suspicious activity. It identifies threats like credential brute forcing, cryptocurrency mining, command-and-control communication, data exfiltration, and unauthorized API usage.

**Why it matters for a SOC:** GuardDuty acts as an automated threat detection engine. Instead of an analyst manually searching through millions of log entries, GuardDuty surfaces the events that matter as "findings" with severity ratings. In this project, GuardDuty findings also trigger the automated Lambda response built in Phase 7.

**Configuration:**
- Enabled with default settings
- Analyzes: CloudTrail events, VPC Flow Logs, DNS logs
- Finding types detected in this environment:
  - `Policy:IAMUser/RootCredentialUsage` — Root account usage detected
  - `Recon:EC2/PortProbeUnprotectedPort` — Unprotected port being probed
  - `Policy:IAMUser/CreateRole` — New IAM role creation using root credentials

<img width="1273" height="837" alt="Screenshot 2026-04-26 013355" src="https://github.com/user-attachments/assets/0fb56f12-8a10-43f4-b8f9-9ceb9036f0ac" />


### VPC Flow Logs

**What it does:** Captures metadata about all network traffic flowing through the VPC. For every connection attempt — whether accepted or rejected by security groups — it records the source IP, destination IP, source port, destination port, protocol, number of bytes transferred, and whether the traffic was allowed or denied.

**Why it matters for a SOC:** VPC Flow Logs provide network-layer visibility. They reveal port scanning activity, lateral movement between instances, data exfiltration patterns (large outbound transfers to unknown IPs), and connections to known malicious infrastructure. When combined with honeypot logs and CloudTrail data in the SIEM, they enable multi-layer correlation — seeing the same attacker across network, application, and cloud layers.

**Configuration:**
- Enabled on the project VPC
- Filter: All traffic (both accepted and rejected)
- Aggregation interval: 1 minute
- Destination: Same S3 bucket as CloudTrail logs

## How These Connect to the Pipeline for the system

```
CloudTrail ─────┐
                │
GuardDuty ──────┼──── S3 Bucket ──── Future SIEM Ingestion (Splunk)
                │
VPC Flow Logs ──┘
                         │
                    GuardDuty ──── EventBridge ──── Lambda (Phase 7)
```

All three services write their data to a centralized S3 bucket. In a production environment, this data would be ingested into Splunk for correlation with endpoint and application logs. GuardDuty findings additionally trigger the automated response pipeline built in Phase 7 via EventBridge.

## Key Takeaways

- Cloud security monitoring requires visibility at multiple layers: API activity (CloudTrail), automated threat detection (GuardDuty), and network metadata (VPC Flow Logs)
- These services complement the application-layer data captured by honeypots and the endpoint-layer data captured by Sysmon
- Centralizing all logs in a single S3 bucket simplifies SIEM ingestion and enables cross-source correlation
- GuardDuty's automated findings reduce the burden on analysts by surfacing only the events that require investigation
