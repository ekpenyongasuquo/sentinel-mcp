from datetime import datetime, timezone


def generate_remediation_playbook(evidence: dict, iocs: list) -> dict:
    """
    Generates a prioritised remediation playbook from investigation findings.
    All actions require human approval — never auto-executed.
    """
    actions = []

    # P1 — Terminate malicious processes
    for proc in evidence.get("processes", {}).get("flagged", []):
        actions.append({
            "priority": 1,
            "type": "TERMINATE_PROCESS",
            "command": f"taskkill /PID {proc['pid']} /F",
            "justification": (
                f"{proc['name']} PID {proc['pid']} — malicious keyword match"
            ),
            "risk": "LOW — process termination is reversible",
            "requires_approval": True
        })

    # P1 — Block C2 connections
    for ioc in [i for i in iocs if i.get("type") == "C2_IP"]:
        actions.append({
            "priority": 1,
            "type": "BLOCK_NETWORK",
            "command": (
                f'netsh advfirewall firewall add rule name="SENTINEL-BLOCK" '
                f'dir=out remoteip={ioc["value"]} action=block'
            ),
            "justification": f"C2 traffic detected to {ioc['value']}",
            "risk": "MEDIUM — verify IP before blocking",
            "requires_approval": True
        })

    # P2 — Remove persistence keys
    for key in evidence.get("persistence", {}).get("keys", []):
        actions.append({
            "priority": 2,
            "type": "REMOVE_PERSISTENCE",
            "command": f'reg delete "{key}" /f',
            "justification": f"Malicious persistence key: {key}",
            "risk": "MEDIUM — verify key is malicious before deletion",
            "requires_approval": True
        })

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_actions": len(actions),
        "actions": sorted(actions, key=lambda x: x["priority"]),
        "human_approval_required": True,
        "note": (
            "All actions are recommendations. "
            "Human analyst must approve before execution."
        )
    }