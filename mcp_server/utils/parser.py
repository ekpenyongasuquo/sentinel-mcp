"""
Shared parsing utilities.
Raw SIFT tool output NEVER reaches the LLM — always parse here first.
"""


MALWARE_KEYWORDS = [
    "mimikatz", "psexec", "meterpreter", "nc.exe",
    "ncat", "cobalt", "beacon", "empire", "powersploit"
]

C2_PORTS = [4444, 4445, 1337, 31337, 8888, 9999, 6666]


def parse_process_list(raw: str) -> dict:
    lines = [l for l in raw.strip().split("\n") if l and not l.startswith("*")]
    processes = []
    for line in lines[2:]:
        parts = line.split()
        if len(parts) >= 4:
            processes.append({
                "pid": parts[2],
                "name": parts[1],
                "ppid": parts[3]
            })
    flagged = [
        p for p in processes
        if any(k in p["name"].lower() for k in MALWARE_KEYWORDS)
    ]
    return {
        "total": len(processes),
        "processes": processes,
        "flagged": flagged,
        "flag_count": len(flagged)
    }


def parse_network_connections(raw: str) -> dict:
    lines = [l for l in raw.strip().split("\n") if l and not l.startswith("*")]
    connections = []
    for line in lines[2:]:
        parts = line.split()
        if len(parts) >= 5:
            connections.append({
                "pid": parts[0],
                "proto": parts[1],
                "local": parts[2],
                "remote": parts[3],
                "state": parts[4] if len(parts) > 4 else "UNKNOWN"
            })
    flagged = []
    for c in connections:
        remote = c.get("remote", "")
        if ":" in remote:
            try:
                port = int(remote.split(":")[-1])
                if port in C2_PORTS:
                    flagged.append({**c, "remote_port": port,
                                    "remote_ip": remote.split(":")[0]})
            except ValueError:
                pass
    return {
        "total": len(connections),
        "connections": connections,
        "flagged": flagged,
        "flag_count": len(flagged)
    }


def parse_persistence(raw: str) -> dict:
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