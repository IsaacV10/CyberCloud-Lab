# Phase 7: Automated Incident Response (SOAR)
- Lambda function (CyberCloud-AutoBlock) auto-blocks attacker IPs
- EventBridge rule triggers Lambda on GuardDuty findings
- Blocked IPs tracked in dedicated CyberCloud-BlockList security group
- Extracts IPs from network connections, port probes, and API call findings
- Duplicate IP detection prevents redundant rules
AWS Lambda function triggered by EventBridge when GuardDuty generates a finding. The function extracts the attacker IP and automatically adds it to a block-list security group.
## Overview
 
Phase 7 implements automated threat response using AWS serverless services. When GuardDuty detects a threat, the attacker's IP is automatically blocked without human intervention. This reduces response time from minutes or hours to under one second.

### Step 1: Create the Lambda Function
The function contains Python code that parses incoming GuardDuty findings, extracts the attacker's IP address from the event data, and adds a block rule to a designated security group. It handles three types of GuardDuty actions: network connection actions, port probe actions, and AWS API call actions. It also includes duplicate detection to prevent adding the same IP twice.
<img width="1272" height="984" alt="Screenshot 2026-04-26 003219" src="https://github.com/user-attachments/assets/33db50cc-6910-419b-8d74-708454691d0b" />

### Step 2: Configure Environment Variables
Added an environment variable to the Lambda function's configuration:
 
- **Key:** `Block_SG_ID`
- **Value:** `sg-022bd0e3f3494bb89`
This tells the Lambda function which security group to write block rules to. Using an environment variable instead of hardcoding the value in the code allows the security group to be changed without modifying the function code.

<img width="1275" height="655" alt="Screenshot 2026-04-26 004809" src="https://github.com/user-attachments/assets/28d1073a-ddc4-47be-8ff9-4e53013e12b0" />

### Step 3: Configure IAM Permissions
 
Attached the `AmazonEC2FullAccess` policy to the Lambda function's execution role (`MyCyberCloud-Autoblock-role`). The Lambda function needs EC2 permissions to:
 
- Read security group rules
- Add new inbound rules to block IPs 
In a production environment, a more restrictive custom policy would be used following the principle of least privilege.

<img width="1538" height="785" alt="Screenshot 2026-04-26 005013" src="https://github.com/user-attachments/assets/9d045e66-5781-4c83-ab93-381e1e5c62f7" />

### Step 4: Create the BlockList Security Group
 
Created a dedicated security group to serve as the block list:
 
- **Name:** Cybercloud-Blocklist
- **Description:** Blocked IPs from automated GuardDuty
- **VPC:** Enterprise Virtual Network
Each time the Lambda blocks an IP, it adds an inbound rule to this security group with the IP address and a description including the finding type and severity. This creates a living audit trail of every automated block action.
<img width="1273" height="1063" alt="Screenshot 2026-04-26 004600" src="https://github.com/user-attachments/assets/6048cb7c-cfd1-48c7-83b3-605824a05f6c" />

### Step 5: Create the EventBridge Rule
 
Created an EventBridge rule to connect GuardDuty to the Lambda function:
The rule's target is the MyCyberCloud-Autoblock Lambda function. Every time GuardDuty generates a finding, EventBridge automatically invokes the Lambda function with the finding details.
 
<img width="1374" height="1069" alt="Screenshot 2026-04-26 010412" src="https://github.com/user-attachments/assets/0f4e85c5-74b9-4e9f-b473-d9a871dcb3ba" />
### Step 6: Test the Pipeline
 
Created a test event simulating a GuardDuty SSH brute force finding:
 
```json
{
  "detail": {
    "type": "UnauthorizedAccess:EC2/SSHBruteForce",
    "severity": 8,
    "title": "SSH brute force attack detected",
    "accountId": "048204778161",
    "region": "us-east-2",
    "service": {
      "action": {
        "networkConnectionAction": {
          "remoteIpDetails": {
            "ipAddressV4": "203.0.113.99"
          }
        }
      }
    }
  }
}
```
 
**First test** returned a 500 error due to special characters in the security group rule description field. AWS security group descriptions only allow alphanumeric characters and basic punctuation.
 
<img width="1406" height="696" alt="Screenshot 2026-04-26 010430" src="https://github.com/user-attachments/assets/0dc9ac60-7c49-44ef-aa02-7e059227c05e" />

 
**Second test** after fixing the description format returned a 200 success. The Lambda function correctly:
 
1. Parsed the GuardDuty finding
2. Extracted the attacker IP (203.0.113.99)
3. Added the IP to the BlockList security group
4. Returned a confirmation with the finding type, severity, blocked IP, and timestamp
<img width="1254" height="747" alt="Screenshot 2026-04-26 010709" src="https://github.com/user-attachments/assets/bb4edb6e-cd74-4960-b2f0-0eefe9cf523f" />



