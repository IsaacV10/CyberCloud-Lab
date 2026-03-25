#!/usr/bin/env python3
"""
SSH Honeypot
==================================
A Paramiko-based SSH honeypot that logs all activity as newline-delimited JSON (NDJSON).
Designed to feed directly into Splunk, Elastic, or any SIEM that supports JSON.
"""

import argparse
import json
import logging
import os
import socket
import threading
import uuid
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

import paramiko

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
HOST_KEY_FILE = "server.key"
LOG_DIR = "/var/log/honeypot"
LOG_FILE = os.path.join(LOG_DIR, "ssh_honeypot.log")
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB per file
LOG_BACKUP_COUNT = 5

# Fake credentials that "succeed" (lures attackers into the shell)
FAKE_USERS = {
    "root": "toor",
    "admin": "admin",
    "ubuntu": "ubuntu",
    "user": "password",
}

# Fake filesystem responses
FAKE_COMMANDS = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "pwd": "/root",
    "uname -a": "Linux ip-172-31-22-5 5.15.0-1052-aws #57-Ubuntu SMP x86_64 GNU/Linux",
    "uname": "Linux",
    "hostname": "ip-172-31-22-5",
    "cat /etc/hostname": "ip-172-31-22-5",
    "ls": "Desktop  Documents  Downloads  .bashrc  .ssh  notes.txt",
    "ls -la": (
        "total 36\n"
        "drwx------ 5 root root 4096 Jan 12 08:30 .\n"
        "drwxr-xr-x 3 root root 4096 Jan 12 08:30 ..\n"
        "-rw-r--r-- 1 root root 3106 Oct 15  2021 .bashrc\n"
        "drwxr-xr-x 2 root root 4096 Jan 12 08:30 Desktop\n"
        "drwxr-xr-x 2 root root 4096 Jan 12 08:30 Documents\n"
        "drwxr-xr-x 2 root root 4096 Jan 12 08:30 Downloads\n"
        "drwx------ 2 root root 4096 Jan 12 08:30 .ssh\n"
        "-rw-r--r-- 1 root root   47 Jan 12 08:32 notes.txt"
    ),
    "cat notes.txt": "TODO: rotate SSH keys, update firewall rules",
    "cat /etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash"
    ),
    "cat /etc/shadow": "cat: /etc/shadow: Permission denied",
    "ifconfig": (
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001\n"
        "        inet 172.31.22.5  netmask 255.255.240.0  broadcast 172.31.31.255\n"
        "        ether 0a:1b:2c:3d:4e:5f  txqueuelen 1000  (Ethernet)"
    ),
    "ip addr": (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
        "    inet 127.0.0.1/8 scope host lo\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001\n"
        "    inet 172.31.22.5/20 brd 172.31.31.255 scope global dynamic eth0"
    ),
    "uptime": " 08:32:15 up 47 days, 12:05,  1 user,  load average: 0.08, 0.03, 0.01",
    "df -h": (
        "Filesystem      Size  Used Avail Use% Mounted on\n"
        "/dev/xvda1       20G  4.2G   15G  22% /"
    ),
    "ps aux": (
        "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
        "root         1  0.0  0.4 167276 11456 ?        Ss   Jan12   0:08 /sbin/init\n"
        "root       412  0.0  0.2  72308  6128 ?        Ss   Jan12   0:00 /usr/sbin/sshd -D\n"
        "root       987  0.0  0.1  21476  5088 ?        S    08:30   0:00 bash"
    ),
    "env": (
        "SHELL=/bin/bash\n"
        "USER=root\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        "HOME=/root\n"
        "LOGNAME=root"
    ),
    "history": (
        "    1  apt update\n"
        "    2  apt upgrade -y\n"
        "    3  systemctl status sshd\n"
        "    4  cat /var/log/auth.log\n"
        "    5  exit"
    ),
}


# ---------------------------------------------------------------------------
# JSON Logger
# ---------------------------------------------------------------------------
class JSONHoneypotLogger:
    """Writes one JSON object per line — ready for SIEM ingestion."""

    def __init__(self, log_path: str = LOG_FILE):
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        self.logger = logging.getLogger("honeypot_json")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False  # don't duplicate to root logger

        # Rotate at MAX_LOG_SIZE, keep LOG_BACKUP_COUNT old files
        handler = RotatingFileHandler(
            log_path,
            maxBytes=MAX_LOG_SIZE,
            backupCount=LOG_BACKUP_COUNT,
        )
        handler.setFormatter(logging.Formatter("%(message)s"))  # raw JSON
        self.logger.addHandler(handler)

    def log(self, event_type: str, session_id: str, src_ip: str, src_port: int, **extra):
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "session_id": session_id,
            "src_ip": src_ip,
            "src_port": src_port,
            "sensor": "ssh_honeypot",
        }
        record.update(extra)
        self.logger.info(json.dumps(record, default=str))


# Global logger instance
hp_logger = JSONHoneypotLogger()

# Also keep a console logger for live monitoring
console = logging.getLogger("console")
console.setLevel(logging.INFO)
_ch = logging.StreamHandler()
_ch.setFormatter(logging.Formatter("%(asctime)s  %(message)s"))
console.addHandler(_ch)


# ---------------------------------------------------------------------------
# Paramiko Server Interface
# ---------------------------------------------------------------------------
class HoneypotServer(paramiko.ServerInterface):
    """Handles SSH authentication — accepts known fake creds, logs everything."""

    def __init__(self, session_id: str, src_ip: str, src_port: int):
        self.session_id = session_id
        self.src_ip = src_ip
        self.src_port = src_port
        self.username = None
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        self.username = username
        accepted = FAKE_USERS.get(username) == password

        hp_logger.log(
            event_type="auth_attempt",
            session_id=self.session_id,
            src_ip=self.src_ip,
            src_port=self.src_port,
            username=username,
            password=password,
            success=accepted,
        )
        console.info(
            f"[{self.session_id[:8]}] AUTH  {self.src_ip}:{self.src_port}  "
            f"user={username}  pass={password}  {'✓' if accepted else '✗'}"
        )

        return paramiko.AUTH_SUCCESSFUL if accepted else paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        hp_logger.log(
            event_type="auth_pubkey",
            session_id=self.session_id,
            src_ip=self.src_ip,
            src_port=self.src_port,
            username=username,
            key_fingerprint=key.get_fingerprint().hex(),
        )
        return paramiko.AUTH_FAILED  # never accept keys

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, *args):
        return True

    def check_channel_exec_request(self, channel, command):
        """Handle direct 'ssh user@host <command>' style exec requests."""
        cmd = command.decode("utf-8", errors="replace").strip()
        hp_logger.log(
            event_type="command_exec",
            session_id=self.session_id,
            src_ip=self.src_ip,
            src_port=self.src_port,
            username=self.username,
            command=cmd,
        )
        console.info(
            f"[{self.session_id[:8]}] EXEC  {self.src_ip}  cmd='{cmd}'"
        )
        response = FAKE_COMMANDS.get(cmd, f"bash: {cmd}: command not found")
        channel.send(response + "\n")
        channel.send_exit_status(0)
        channel.close()
        return True


# ---------------------------------------------------------------------------
# Shell emulation
# ---------------------------------------------------------------------------
def handle_shell(channel, server: HoneypotServer):
    """Interactive shell loop — captures every command the attacker types."""
    prompt = f"root@ip-172-31-22-5:~# "
    channel.send(f"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-1052-aws x86_64)\r\n\r\n")
    channel.send(f" * Documentation:  https://help.ubuntu.com\r\n")
    channel.send(f" * Management:     https://landscape.canonical.com\r\n")
    channel.send(f" * Support:        https://ubuntu.com/advantage\r\n\r\n")
    channel.send(f"Last login: Mon Jan 12 08:30:15 2025 from 10.0.0.1\r\n")
    channel.send(prompt)

    command_buffer = b""
    while True:
        try:
            byte = channel.recv(1)
            if not byte:
                break

            # Enter key
            if byte in (b"\r", b"\n"):
                channel.send(b"\r\n")
                cmd = command_buffer.decode("utf-8", errors="replace").strip()
                command_buffer = b""

                if not cmd:
                    channel.send(prompt)
                    continue

                # Log the command
                hp_logger.log(
                    event_type="command",
                    session_id=server.session_id,
                    src_ip=server.src_ip,
                    src_port=server.src_port,
                    username=server.username,
                    command=cmd,
                )
                console.info(
                    f"[{server.session_id[:8]}] CMD   {server.src_ip}  cmd='{cmd}'"
                )

                if cmd in ("exit", "quit", "logout"):
                    channel.send("logout\r\n")
                    break

                response = FAKE_COMMANDS.get(cmd)
                if response is None:
                    # Handle partial matches (e.g., 'ls /tmp')
                    base_cmd = cmd.split()[0] if cmd.split() else cmd
                    if base_cmd in ("wget", "curl", "apt", "yum", "pip"):
                        response = f"bash: {base_cmd}: command not found"
                    elif base_cmd == "cd":
                        response = ""  # silently accept cd
                    else:
                        response = f"bash: {cmd}: command not found"

                if response:
                    channel.send(response.replace("\n", "\r\n") + "\r\n")
                channel.send(prompt)

            # Backspace
            elif byte in (b"\x7f", b"\x08"):
                if command_buffer:
                    command_buffer = command_buffer[:-1]
                    channel.send(b"\x08 \x08")

            # Tab (ignore)
            elif byte == b"\t":
                pass

            # Ctrl+C
            elif byte == b"\x03":
                channel.send(b"^C\r\n")
                command_buffer = b""
                channel.send(prompt)

            # Ctrl+D on empty line = exit
            elif byte == b"\x04":
                if not command_buffer:
                    channel.send(b"\r\nlogout\r\n")
                    break

            # Arrow keys / escape sequences (consume and ignore)
            elif byte == b"\x1b":
                channel.recv(2)  # consume the rest of the escape seq

            # Normal character
            else:
                command_buffer += byte
                channel.send(byte)

        except Exception:
            break

    hp_logger.log(
        event_type="shell_closed",
        session_id=server.session_id,
        src_ip=server.src_ip,
        src_port=server.src_port,
        username=server.username,
    )


# ---------------------------------------------------------------------------
# Connection handler (one thread per connection)
# ---------------------------------------------------------------------------
def handle_connection(client_sock, client_addr):
    src_ip, src_port = client_addr
    session_id = str(uuid.uuid4())

    hp_logger.log(
        event_type="connection_open",
        session_id=session_id,
        src_ip=src_ip,
        src_port=src_port,
    )
    console.info(f"[{session_id[:8]}] CONN  {src_ip}:{src_port} connected")

    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = SSH_BANNER

        # Load or generate host key
        if os.path.isfile(HOST_KEY_FILE):
            host_key = paramiko.RSAKey(filename=HOST_KEY_FILE)
        else:
            console.info("Generating new RSA host key...")
            host_key = paramiko.RSAKey.generate(2048)
            host_key.write_private_key_file(HOST_KEY_FILE)

        transport.add_server_key(host_key)

        server = HoneypotServer(session_id, src_ip, src_port)
        transport.start_server(server=server)

        # Wait for a channel (timeout 30s)
        channel = transport.accept(30)
        if channel is None:
            hp_logger.log(
                event_type="connection_timeout",
                session_id=session_id,
                src_ip=src_ip,
                src_port=src_port,
            )
            console.info(f"[{session_id[:8]}] TIMEOUT  {src_ip} — no channel opened")
            return

        # Wait for shell request
        server.event.wait(10)
        if not server.event.is_set():
            hp_logger.log(
                event_type="no_shell_request",
                session_id=session_id,
                src_ip=src_ip,
                src_port=src_port,
            )
            console.info(f"[{session_id[:8]}] NO_SHELL  {src_ip} — no shell requested")
            return

        handle_shell(channel, server)

    except paramiko.SSHException as e:
        hp_logger.log(
            event_type="ssh_error",
            session_id=session_id,
            src_ip=src_ip,
            src_port=src_port,
            error=str(e),
        )
    except Exception as e:
        hp_logger.log(
            event_type="error",
            session_id=session_id,
            src_ip=src_ip,
            src_port=src_port,
            error=str(e),
        )
    finally:
        hp_logger.log(
            event_type="connection_closed",
            session_id=session_id,
            src_ip=src_ip,
            src_port=src_port,
        )
        console.info(f"[{session_id[:8]}] CLOSE {src_ip}:{src_port} disconnected")
        try:
            client_sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Main server loop
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="SSH Honeypot — SIEM-Ready Edition")
    parser.add_argument("-a", "--address", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("-p", "--port", type=int, default=2222, help="Bind port (default: 2222)")
    parser.add_argument("-l", "--log-file", default=LOG_FILE, help="Log file path")
    args = parser.parse_args()

    # Reinitialize logger if custom path given
    global hp_logger
    if args.log_file != LOG_FILE:
        hp_logger = JSONHoneypotLogger(args.log_file)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((args.address, args.port))
    server_sock.listen(100)

    console.info(f"SSH Honeypot listening on {args.address}:{args.port}")
    console.info(f"Logging JSON events to {args.log_file}")
    console.info("Press Ctrl+C to stop.\n")

    try:
        while True:
            client_sock, client_addr = server_sock.accept()
            t = threading.Thread(target=handle_connection, args=(client_sock, client_addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        console.info("\nShutting down honeypot...")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()
