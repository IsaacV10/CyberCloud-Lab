# Phase 1: Honeypot Deployment

## Overview

Phase 1 deploys two internet-facing honeypots on an AWS EC2 instance to capture real attack data. These honeypots are the primary data generators for the entire SOC pipeline — everything downstream (SIEM dashboards, detection rules, incident reports, automated response) depends on the data collected here.

A honeypot is a decoy system designed to look like a legitimate target. Attackers connect to it thinking they've found a vulnerable server, and every action they take is logged. The honeypots in this project capture SSH brute force attempts, credential stuffing, post-authentication commands, web login attacks, and automated bot scanning activity.

Both honeypots output structured JSON logs specifically designed for SIEM ingestion, run as systemd services for persistence across reboots, and use rotating log files to manage disk space.

## Infrastructure

| Component | Details |
|-----------|---------|
| Instance | AWS EC2 t2.micro (free tier) |
| OS | Ubuntu Server 24.04 LTS |
| Region | us-east-2 (Ohio) |
| IP | Elastic IP assigned (static, survives reboots) |
| SSH Honeypot Port | 2222 (open to 0.0.0.0/0) |
| HTTP Honeypot Port | 8080 (open to 0.0.0.0/0) |
| Admin SSH Port | 22 (restricted to My IP only) |

<img width="1490" height="501" alt="Screenshot 2026-04-30 002234" src="https://github.com/user-attachments/assets/7a7973bf-43be-49a4-af59-6e5be42c265d" />


## SSH Honeypot

### What It Does

The SSH honeypot emulates a realistic Ubuntu SSH server. When an attacker connects, they see a standard SSH banner and are prompted for credentials. If they enter one of the preconfigured fake credentials (like root:toor or admin:admin), they're dropped into a simulated shell environment where every command they type is logged.

### Technical Implementation

- **Language:** Python 3
- **Library:** Paramiko (SSH protocol implementation)
- **Banner:** `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` (mimics a real Ubuntu server)
- **Authentication:** Accepts select fake credentials to lure attackers into the shell
- **Shell Emulation:** 20+ fake Linux command responses that return realistic output
- **Session Tracking:** UUID assigned to each connection, linking all events from one attacker session
- **Logging:** NDJSON to `/var/log/honeypot/ssh_honeypot.log` with RotatingFileHandler (10MB per file, 5 backups)

### Fake Credentials Accepted

| Username | Password |
|----------|----------|
| root | toor |
| admin | admin |
| ubuntu | ubuntu |
| user | password |

These were chosen because they appear in common brute force dictionaries. Accepting them allows observation of post-authentication attacker behavior.

### Fake Command Responses

When an attacker enters the shell, these commands return realistic output:

| Command | Response |
|---------|----------|
| `whoami` | root |
| `id` | uid=0(root) gid=0(root) groups=0(root) |
| `pwd` | /root |
| `ls` | Desktop Documents Downloads .bashrc .ssh notes.txt |
| `ls -la` | Full directory listing with permissions and timestamps |
| `cat /etc/passwd` | Realistic passwd file with root, daemon, sshd, ubuntu users |
| `cat /etc/shadow` | Permission denied (realistic — even fake root can't always read shadow) |
| `ps aux` | Process listing showing init, sshd, bash |
| `ifconfig` | Network interface with internal IP 172.31.22.5 |
| `uname -a` | Linux kernel version string |
| `hostname` | ip-172-31-22-5 |
| `df -h` | Disk usage showing 20G volume |
| `uptime` | 47 days uptime |
| `env` | Environment variables |
| `history` | Fake command history (apt update, systemctl status) |
| `cat notes.txt` | "TODO: rotate SSH keys, update firewall rules" |

Any unrecognized command returns `bash: <command>: command not found`, mimicking a real shell.

### Event Types Logged

| Event Type | Description |
|------------|-------------|
| `connection_open` | New TCP connection established |
| `auth_attempt` | Login attempt with username, password, and success/failure |
| `auth_pubkey` | Public key authentication attempt (always rejected) |
| `command` | Command entered in the interactive shell |
| `command_exec` | Direct command execution via `ssh user@host <command>` |
| `shell_closed` | Attacker exited the shell |
| `connection_closed` | TCP connection terminated |
| `connection_timeout` | No channel opened within 30 seconds |
| `no_shell_request` | Channel opened but no shell requested |
| `ssh_error` | SSH protocol error during session |
| `error` | General error during connection handling |

## HTTP Honeypot

### What It Does

The HTTP honeypot serves a realistic WordPress login page. WordPress is the most popular CMS on the internet and `wp-login.php` is one of the most commonly targeted endpoints by automated bots. Attackers and bots attempting to brute force WordPress admin credentials will find and interact with this page.

### Technical Implementation

- **Language:** Python 3
- **Framework:** Flask
- **Login Page:** Pixel-perfect WordPress `wp-login.php` clone with CSS styling
- **XML-RPC:** Fake `xmlrpc.php` endpoint (commonly targeted for WordPress brute force)
- **Admin Panel:** Fake `wp-admin` page with loading spinner and redirect
- **Catch-All Route:** Every path not explicitly defined returns a 404 and is logged
- **Logging:** NDJSON to `/var/log/honeypot/http_honeypot.log` with RotatingFileHandler

### Endpoints

| Path | Method | Purpose |
|------|--------|---------|
| `/` | GET | Redirects to `/wp-login.php` |
| `/wp-login.php` | GET/POST | WordPress login page — captures credentials on POST |
| `/wp-admin` | GET | Fake admin dashboard with loading spinner |
| `/xmlrpc.php` | GET/POST | XML-RPC endpoint — captures brute force payloads |
| `/<any path>` | ALL | Catch-all — logs bot scanning activity |

### Event Types Logged

| Event Type | Description |
|------------|-------------|
| `http_request` | Every HTTP request (logged via Flask `before_request`) |
| `login_attempt` | POST to `/wp-login.php` with username and password |
| `admin_access` | Request to `/wp-admin` |
| `xmlrpc_probe` | Request to `/xmlrpc.php` with payload |
| `probe` | Request to any unrecognized path |

## Log Format

Both honeypots output newline-delimited JSON (NDJSON). Each line is a self-contained JSON object with a standardized set of fields:

### SSH Honeypot Log Example

```json
{
  "timestamp": "2026-04-13T22:59:53.626904+00:00",
  "event_type": "auth_attempt",
  "session_id": "bd17d682-5d6e-44b5-a7e5-a6629baafd2c",
  "src_ip": "47.250.181.61",
  "src_port": 54321,
  "sensor": "ssh_honeypot",
  "username": "root",
  "password": "admin123",
  "success": false
}
```

### HTTP Honeypot Log Example

```json
{
  "timestamp": "2026-04-25T22:07:56.996845+00:00",
  "event_type": "login_attempt",
  "src_ip": "172.234.246.109",
  "sensor": "http_honeypot",
  "username": "admin",
  "password": "P@ssw0rd!",
  "user_agent": "Mozilla/5.0"
}
```

### Why NDJSON

- **SIEM-ready:** Splunk's `_json` source type parses every field automatically with zero custom configuration
- **Searchable:** Every field becomes a searchable, filterable field in Splunk
- **Structured:** Unlike plain-text logs, JSON doesn't require regex parsing which is error-prone and brittle
- **Extensible:** New fields can be added without breaking existing parsing

## Deployment

### Running as Systemd Services

Both honeypots are configured as systemd services for automatic startup and crash recovery:

**SSH Honeypot Service (`/etc/systemd/system/ssh-honeypot.service`):**
```ini
[Unit]
Description=SSH Honeypot
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/CyberCloud-Lab
ExecStart=/home/ubuntu/CyberCloud-Lab/venv/bin/python3 ssh_honeypot.py -p 2222
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**HTTP Honeypot Service (`/etc/systemd/system/http-honeypot.service`):**
```ini
[Unit]
Description=HTTP Honeypot
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/CyberCloud-Lab
ExecStart=/home/ubuntu/CyberCloud-Lab/venv/bin/python3 http_honeypot.py -p 8080
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**Service Management:**
```bash
sudo systemctl enable ssh-honeypot http-honeypot    # Auto-start on boot
sudo systemctl start ssh-honeypot http-honeypot     # Start now
sudo systemctl status ssh-honeypot http-honeypot    # Check status
```

### Security Group Rules

| Port | Source | Purpose |
|------|--------|---------|
| 22 | My IP only | Admin SSH access |
| 80 | 0.0.0.0/0 | HTTP honeypot redirect |
| 2222 | 0.0.0.0/0 | SSH honeypot (direct) |
| 8080 | 0.0.0.0/0 | HTTP honeypot (direct) |

Honeypot ports are open to the entire internet to attract attackers. Admin access is restricted to a single IP.

## Results

Within the first month of operation, the honeypots captured:

| Metric | Value |
|--------|-------|
| Total events | 111,355 |
| SSH connections | 28,023 |
| SSH auth attempts | 23,802 |
| SSH commands captured | 12 |
| HTTP requests | 2,153 |
| HTTP login attempts | 10 |
| HTTP probes (path scanning) | 1,637 |
| Unique attacker IPs | Multiple from dozens of countries |

The SSH honeypot attracted significantly more traffic than the HTTP honeypot, which is expected since SSH port scanning is one of the most common automated attack techniques on the internet.

## File Structure

```
CyberCloud-Lab/
├── ssh_honeypot.py              # SSH honeypot source code
├── http_honeypot.py             # HTTP honeypot source code
├── requirements.txt             # Python dependencies (paramiko, flask)
├── server.key                   # RSA host key (auto-generated)
└── /var/log/honeypot/           # Log output directory
    ├── ssh_honeypot.log         # SSH honeypot JSON logs
    └── http_honeypot.log        # HTTP honeypot JSON logs
```

## Key Takeaways

- Structured logging (JSON) from the start eliminates painful parsing work later when ingesting into a SIEM
- Session ID tracking is essential for reconstructing complete attack chains from individual log entries
- Accepting select fake credentials provides visibility into post-authentication attacker behavior, which is far more valuable than just recording failed logins
- Running as systemd services ensures continuous data collection even after instance reboots or process crashes
- The SSH honeypot attracts significantly more automated traffic than the HTTP honeypot due to the prevalence of SSH scanning botnets
