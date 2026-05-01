"""
Shared parsing utilities for Volatility 3 output.
Column positions verified against Volatility 3 Framework 2.27.0
"""

MALWARE_KEYWORDS = [
    "mimikatz", "psexec", "meterpreter", "nc.exe",
    "ncat", "cobalt", "beacon", "empire", "powersploit",
    "netcat", "pwdump", "fgdump", "wce.exe", "gsecdump"
]

SUSPICIOUS_KEYWORDS = [
    "ftpbasicsvr",  # FTP server — unusual on workstation
    "ftk",          # Forensic tool — suspicious as ghost process
    "snmp",         # SNMP — often exploited
    "iashost",      # IAS — remote authentication service
]

C2_PORTS = [4444, 4445, 1337, 31337, 8888, 9999, 6666, 443, 80]


def parse_process_list(raw: str) -> dict:
    """
    Parse Volatility 3 windows.pslist.PsList output.
    Tab-separated columns:
    PID  PPID  ImageFileName  Offset  Threads  Handles  SessionId  Wow64  CreateTime...
    """
    lines = raw.strip().split("\n")
    processes = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("Volatility") or stripped.startswith("PID"):
            continue
        if stripped.startswith("WARNING") or stripped.startswith("Progress"):
            continue

        parts = stripped.split()
        if len(parts) < 3:
            continue

        try:
            pid = parts[0]
            ppid = parts[1]
            name = parts[2]

            if not pid.isdigit():
                continue

            processes.append({
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "create_time": parts[8] if len(parts) > 8 else "UNKNOWN"
            })
        except (IndexError, ValueError):
            continue

    # Flag confirmed malware names
    confirmed_malware = [
        p for p in processes
        if any(k in p["name"].lower() for k in MALWARE_KEYWORDS)
    ]

    # Flag suspicious process names
    suspicious = [
        p for p in processes
        if any(k in p["name"].lower() for k in SUSPICIOUS_KEYWORDS)
        and p not in confirmed_malware
    ]

    all_flagged = confirmed_malware + suspicious

    return {
        "total": len(processes),
        "processes": processes,
        "flagged": all_flagged,
        "confirmed_malware": confirmed_malware,
        "suspicious": suspicious,
        "flag_count": len(all_flagged)
    }


def parse_network_connections(raw: str) -> dict:
    """
    Parse Volatility 3 windows.netscan.NetScan output.
    Tab-separated columns:
    Offset  Proto  LocalAddr  LocalPort  ForeignAddr  ForeignPort  State  PID  Owner  Created
    """
    lines = raw.strip().split("\n")
    connections = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("Volatility") or stripped.startswith("Offset"):
            continue
        if stripped.startswith("WARNING") or stripped.startswith("Progress"):
            continue

        parts = stripped.split()
        if len(parts) < 7:
            continue

        try:
            proto = parts[1]
            local_addr = parts[2]
            local_port = parts[3]
            remote_ip = parts[4]
            remote_port_str = parts[5]
            state = parts[6]

            if not remote_port_str.isdigit():
                continue

            remote_port = int(remote_port_str)
            connections.append({
                "proto": proto,
                "local": f"{local_addr}:{local_port}",
                "remote": f"{remote_ip}:{remote_port}",
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "state": state
            })
        except (IndexError, ValueError):
            continue

    flagged = [
        c for c in connections
        if c.get("remote_port") in C2_PORTS
        and c.get("remote_ip") not in ["0.0.0.0", "127.0.0.1", "::"]
    ]

    return {
        "total": len(connections),
        "connections": connections,
        "flagged": flagged,
        "flag_count": len(flagged)
    }


def parse_persistence(raw: str) -> dict:
    """Parse RegRipper output for persistence keys."""
    PERSIST_PATTERNS = [
        "CurrentVersion\\Run",
        "CurrentVersion\\RunOnce",
        "Winlogon",
        "AppInit_DLLs",
        "Services"
    ]
    lines = raw.strip().split("\n")
    keys = []
    for line in lines:
        for pattern in PERSIST_PATTERNS:
            if pattern.lower() in line.lower():
                keys.append(line.strip())
    return {"keys": keys, "count": len(keys)}
