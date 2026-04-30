import asyncio, json, argparse, sys, os
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'mcp_server'))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'mcp_server', 'utils'))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'mcp_server', 'tools'))

from investigation_engine import InvestigationEngine
from prompts import SENIOR_ANALYST_PROMPT
from logger import log_agent_iteration
from llm_backend import get_backend
from memory import ProcessListTool, NetworkScanTool, ModulesTool, StringsTool
from disk import MFTTimelineTool, PrefetchTool, PersistenceTool


class DirectMCPClient:
    async def get_process_list(self, image_path):
        return (await ProcessListTool().run(image_path)).data
    async def get_network_connections(self, image_path):
        return (await NetworkScanTool().run(image_path)).data
    async def get_loaded_modules(self, image_path):
        return (await ModulesTool().run(image_path)).data
    async def search_strings(self, image_path, pattern):
        return (await StringsTool().run(image_path, pattern=pattern)).data
    async def extract_mft_timeline(self, image_path):
        return (await MFTTimelineTool().run(image_path)).data
    async def analyze_prefetch(self, image_path):
        return (await PrefetchTool().run(image_path)).data
    async def check_persistence(self, image_path):
        return (await PersistenceTool().run(image_path)).data


def compress_evidence(evidence: dict) -> str:
    """
    Convert evidence to a SHORT plain text summary.
    Phi-3 handles plain text much better than JSON.
    Keep under 800 words total.
    """
    summary = evidence.get("summary", {})
    iocs = evidence.get("iocs", [])[:5]  # top 5 IOCs only
    timeline = evidence.get("attack_timeline", [])[:3]  # top 3 events
    cross = evidence.get("evidence", {}).get("cross_validation", {})
    flagged_procs = evidence.get("evidence", {}).get(
        "processes", {}).get("flagged", [])[:3]
    flagged_nets = evidence.get("evidence", {}).get(
        "network", {}).get("flagged", [])[:3]
    persist = evidence.get("evidence", {}).get(
        "persistence", {}).get("keys", [])[:3]

    lines = [
        "=== DFIR EVIDENCE SUMMARY ===",
        f"Suspicious processes found: {summary.get('suspicious_processes', 0)}",
        f"C2 connections found: {summary.get('c2_connections', 0)}",
        f"Ghost processes found: {summary.get('ghost_processes', 0)}",
        f"Persistence keys found: {summary.get('persistence_keys', 0)}",
        f"Total IOCs: {evidence.get('ioc_count', 0)}",
        "",
        "=== TOP FLAGGED PROCESSES ===",
    ]
    for p in flagged_procs:
        lines.append(f"- {p.get('name','?')} PID:{p.get('pid','?')} PPID:{p.get('ppid','?')}")
    if not flagged_procs:
        lines.append("None detected")

    lines += ["", "=== FLAGGED NETWORK CONNECTIONS ==="]
    for n in flagged_nets:
        lines.append(f"- {n.get('proto','?')} {n.get('local','?')} -> {n.get('remote','?')} [{n.get('state','?')}]")
    if not flagged_nets:
        lines.append("None detected")

    lines += ["", "=== PERSISTENCE KEYS ==="]
    for k in persist:
        lines.append(f"- {k}")
    if not persist:
        lines.append("None detected")

    lines += ["", "=== TOP IOCs ==="]
    for ioc in iocs:
        lines.append(f"- [{ioc.get('type','?')}] {ioc.get('value','?')} "
                     f"confidence:{ioc.get('confidence','?')}")
    if not iocs:
        lines.append("None detected")

    lines += ["", "=== CROSS VALIDATION ==="]
    memory_only = cross.get("memory_only", [])[:5]
    lines.append(f"Ghost processes (memory only, no disk trace): {memory_only or 'None'}")

    if timeline:
        lines += ["", "=== ATTACK TIMELINE ==="]
        for e in timeline:
            lines.append(f"- [{e.get('time','?')}] {e.get('source','?')}: {e.get('event','?')}")

    return "\n".join(lines)


SHORT_PROMPT = """You are a senior DFIR analyst. Review the forensic evidence below and write a concise report with:

1. EXECUTIVE SUMMARY (3 sentences maximum)
2. KEY FINDINGS (list each with [CONFIRMED], [INFERRED], or [POSSIBLE])
3. TOP 3 ACTIONS (P1 immediate, P2 containment, P3 cleanup)

Be specific. Use the evidence provided. Keep total response under 400 words."""


async def run_sentinel(image_path: str, output_path: str, max_iterations: int = 1) -> dict:
    start = datetime.now(timezone.utc)
    print(f"\n[Sentinel-MCP] Starting investigation")
    print(f"[Sentinel-MCP] Image: {image_path}")
    print(f"[Sentinel-MCP] Output: {output_path}\n")

    client = DirectMCPClient()
    engine = InvestigationEngine(client)
    evidence = await engine.investigate(image_path)

    print(f"\n[Sentinel-MCP] Evidence collection complete")
    print(f"[Sentinel-MCP] IOCs found: {evidence['ioc_count']}")
    print(f"[Sentinel-MCP] Summary: {evidence['summary']}\n")

    # Convert to short plain text for Phi-3
    compressed_text = compress_evidence(evidence)
    print(f"[Sentinel-MCP] Evidence text length: {len(compressed_text)} chars")

    backend = get_backend()
    user_prompt = f"{compressed_text}\n\nWrite the forensic report now."

    print(f"[Iteration 1/1] Sending to {backend.__class__.__name__}...\n")
    response_text = ""
    for chunk in backend.stream(SHORT_PROMPT, user_prompt):
        print(chunk, end="", flush=True)
        response_text += chunk

    log_agent_iteration(0, response_text, backend.__class__.__name__)

    elapsed = (datetime.now(timezone.utc) - start).seconds
    result = {
        "report": response_text,
        "evidence_summary": evidence["summary"],
        "ioc_count": evidence["ioc_count"],
        "elapsed_seconds": elapsed,
        "llm_backend": backend.__class__.__name__,
        "raw_evidence_text": compressed_text
    }

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n\n[Sentinel-MCP] Investigation complete in {elapsed}s")
    print(f"[Sentinel-MCP] Report saved to: {output_path}")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinel-MCP DFIR Agent")
    parser.add_argument("--image", required=True, help="Path to memory or disk image")
    parser.add_argument("--output", default="logs/report.json", help="Output path")
    parser.add_argument("--iterations", type=int, default=1, help="Max iterations")
    args = parser.parse_args()
    asyncio.run(run_sentinel(args.image, args.output, args.iterations))
