# Phase 5: Detection 

## Overview

Phase 5 builds the detection rules that turn raw log data into actionable alerts. In a SOC, analysts don't watch logs scroll by all day — they rely on automated rules that fire when specific suspicious patterns appear. Six Splunk alerts were created, each mapped to a MITRE ATT&CK technique, covering brute force attacks, persistence mechanisms, malicious execution, and credential theft.

## Detection Rules

### 1. Brute Force Detected (T1110)

**Severity:** High | **Schedule:** Every 5 minutes | **Data Source:** SSH/HTTP Honeypot

```
index=main sourcetype=_json event_type="auth_attempt" success="false" | stats count by src_ip | where count > 5
```

**What it catches:** Any IP that fails login more than 5 times within the search window. This is the most common attack pattern on the internet — bots cycling through password lists against SSH and web login pages.

**Why it matters:** Brute force is often the first stage of an attack. Detecting it early allows blocking the IP before a successful login occurs.

---

### 2. New User Account Created (T1136.001)

**Severity:** Critical | **Schedule:** Every 5 minutes | **Data Source:** Windows Security

```
index=* source="WinEventLog:*" | spath | where 'Event.System.EventID'=4720
```

**What it catches:** Windows Security Event 4720 fires whenever a new user account is created on the machine. Attackers create backdoor accounts to maintain access.

**Why it matters:** New account creation on a server is a high-fidelity alert — it rarely happens in normal operations and almost always indicates either an attacker establishing persistence or an unauthorized administrative action.

---

### 3. Suspicious PowerShell Execution (T1059.001)

**Severity:** High | **Schedule:** Every 5 minutes | **Data Source:** Windows Sysmon

```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" | spath | where 'Event.System.EventID'=1 | search "Event.EventData.Data{@Name}.CommandLine"="*powershell*" AND ("Event.EventData.Data{@Name}.CommandLine"="*-enc*" OR "Event.EventData.Data{@Name}.CommandLine"="*Invoke-*" OR "Event.EventData.Data{@Name}.CommandLine"="*bypass*" OR "Event.EventData.Data{@Name}.CommandLine"="*hidden*" OR "Event.EventData.Data{@Name}.CommandLine"="*downloadstring*")
```

**What it catches:** PowerShell execution with suspicious arguments: `-enc` (encoded commands to hide intent), `Invoke-` (attack tool execution), `bypass` (security policy evasion), `hidden` (invisible execution), and `downloadstring` (downloading malware from the internet).

**Why it matters:** PowerShell is the most commonly abused tool on Windows. These specific flags are strong indicators of malicious use versus normal administrative scripting.

---

### 4. Scheduled Task Created (T1053.005)

**Severity:** High | **Schedule:** Every 5 minutes | **Data Source:** Windows Sysmon

```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" | spath | where 'Event.System.EventID'=1 | search "Event.EventData.Data{@Name}.CommandLine"="*schtasks*" AND "Event.EventData.Data{@Name}.CommandLine"="*/create*"
```

**What it catches:** The `schtasks /create` command being executed, which creates a new Windows scheduled task. Attackers use scheduled tasks to run malware on a timer or at system startup.

**Why it matters:** Scheduled tasks are a common persistence mechanism — they survive reboots and execute automatically without the attacker needing to maintain an active session.

---

### 5. Registry Run Key Persistence (T1547.001)

**Severity:** Critical | **Schedule:** Every 5 minutes | **Data Source:** Windows Sysmon

```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" | spath | where 'Event.System.EventID'=13 | search "Event.EventData.Data{@Name}.TargetObject"="*\\CurrentVersion\\Run*"
```

**What it catches:** Sysmon Event ID 13 (registry value set) targeting the `CurrentVersion\Run` registry keys. Any program added to these keys executes automatically at user logon.

**Why it matters:** Registry Run keys are one of the oldest and most common persistence techniques. This is a critical severity alert because legitimate software rarely modifies these keys without user interaction.

---

### 6. Credential Dumping — LSASS Access (T1003.001)

**Severity:** Critical | **Schedule:** Every 5 minutes | **Data Source:** Windows Sysmon

```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" | spath | where 'Event.System.EventID'=10 | search "Event.EventData.Data{@Name}.TargetImage"="*lsass.exe*"
```

**What it catches:** Sysmon Event ID 10 (process access) where any process reads the memory of `lsass.exe`. LSASS holds password hashes and Kerberos tickets for every logged-in user. Tools like Mimikatz target this process to steal credentials.

**Why it matters:** LSASS access by a non-system process is one of the strongest indicators of credential theft. This is critical severity because a successful credential dump gives the attacker the ability to authenticate as any user on the machine.

## MITRE ATT&CK Coverage Map

| Tactic | Technique | ID | Alert |
|--------|-----------|-----|-------|
| Credential Access | Brute Force: Password Guessing | T1110 | Brute Force Detected |
| Persistence | Create Account: Local Account | T1136.001 | New User Account Created |
| Execution | Command and Scripting: PowerShell | T1059.001 | Suspicious PowerShell Execution |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | Scheduled Task Created |
| Persistence | Boot or Logon Autostart: Registry Run Keys | T1547.001 | Registry Run Key Persistence |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | Credential Dumping |

## Alert Configuration

All alerts were initially configured as real-time searches but were changed to scheduled searches after real-time processing consumed all available CPU and memory on the t2.micro instance, preventing Splunk from starting.

| Setting | Value |
|---------|-------|
| Alert type | Scheduled |
| Run frequency | Every 5 minutes |
| Time range | Last 15 minutes |
| Trigger condition | Number of results > 0 |
| Action | Add to Triggered Alerts |

The 5-minute schedule with a 15-minute lookback window provides near-real-time detection with overlap to prevent gaps, while using minimal system resources.

## Key Takeaways

- Detection rules should be mapped to MITRE ATT&CK techniques to provide a standardized framework for communicating coverage and gaps
- Severity levels should reflect the actual risk: brute force attempts are High (common, often blocked), while credential dumping and persistence are Critical (indicate active compromise)
- Scheduled searches provide nearly the same detection capability as real-time searches at a fraction of the resource cost
- Each rule targets a specific phase of the attack lifecycle: initial access (brute force), execution (PowerShell), persistence (accounts, tasks, registry), and credential access (LSASS)
