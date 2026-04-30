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


def compress_evidence(evidence: dict) -> dict:
    """
    Reduce evidence size before sending to Phi-3.
    Only send summary and IOCs — not full raw data.
    Phi-3 has small context window — keep it under 2000 tokens.
    """
    compressed = {
        "summary": evidence.get("summary", {}),
        "ioc_count": evidence.get("ioc_count", 0),
        "iocs": evidence.get("iocs", []),
        "attack_timeline": evidence.get("attack_timeline", [])[:10],
        "cross_validation": evidence.get("evidence", {}).get("cross_validation", {}),
        "flagged_processes": evidence.get("evidence", {}).get("processes", {}).get("flagged", []),
        "flagged_network": evidence.get("evidence", {}).get("network", {}).get("flagged", []),
        "persistence_keys": evidence.get("evidence", {}).get("persistence", {}).get("keys", []),
    }
    return compressed


async def run_sentinel(image_path: str, output_path: str, max_iterations: int = 2) -> dict:
    start = datetime.now(timezone.utc)
    print(f"\n[Sentinel-MCP] Starting investigation")
    print(f"[Sentinel-MCP] Image: {image_path}")
    print(f"[Sentinel-MCP] Output: {output_path}\n")

    client = DirectMCPClient()
    engine = InvestigationEngine(client)
    evidence = await engine.investigate(image_path)

    print(f"\n[Sentinel-MCP] Evidence collection complete")
    print(f"[Sentinel-MCP] IOCs found: {evidence['ioc_count']}")
    print(f"[Sentinel-MCP] Phases: {evidence['phases_completed']}\n")

    # Compress evidence for Phi-3 context window
    compressed = compress_evidence(evidence)
    print(f"[Sentinel-MCP] Evidence compressed for LLM context window")

    backend = get_backend()
    user_prompt = (
        f"You are analysing forensic evidence from a DFIR investigation.\n"
        f"Evidence summary:\n{json.dumps(compressed, indent=2)}\n\n"
        f"Produce a concise forensic report with:\n"
        f"1. EXECUTIVE SUMMARY (3 sentences)\n"
        f"2. KEY FINDINGS with confidence levels [CONFIRMED/INFERRED/POSSIBLE]\n"
        f"3. TOP 3 RECOMMENDED ACTIONS\n"
        f"Keep the report under 500 words."
    )

    iteration = 0
    report = ""
    while iteration < max_iterations:
        print(f"[Iteration {iteration+1}/{max_iterations}] "
              f"Sending to {backend.__class__.__name__}...\n")
        response_text = ""
        for chunk in backend.stream(SENIOR_ANALYST_PROMPT, user_prompt):
            print(chunk, end="", flush=True)
            response_text += chunk
        log_agent_iteration(iteration, response_text, backend.__class__.__name__)
        report = response_text
        break

    elapsed = (datetime.now(timezone.utc) - start).seconds
    result = {
        "report": report,
        "evidence_summary": evidence["summary"],
        "ioc_count": evidence["ioc_count"],
        "elapsed_seconds": elapsed,
        "llm_backend": backend.__class__.__name__,
        "iterations": iteration + 1
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
    parser.add_argument("--iterations", type=int, default=2, help="Max iterations")
    args = parser.parse_args()
    asyncio.run(run_sentinel(args.image, args.output, args.iterations))
