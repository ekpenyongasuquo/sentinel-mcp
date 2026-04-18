import asyncio
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path

from llm_backend import get_backend
from investigation_engine import InvestigationEngine
from prompts import SENIOR_ANALYST_PROMPT
from utils.logger import log_agent_iteration

# ── MCP client placeholder ───────────────────────────────────────────────────
# In full deployment this connects to the running MCP server.
# For now we import tool functions directly for simplicity.
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "mcp_server"))

from tools.memory import ProcessListTool, NetworkScanTool, ModulesTool, StringsTool
from tools.disk import MFTTimelineTool, PrefetchTool, PersistenceTool


class DirectMCPClient:
    """
    Direct tool client — calls SIFT tools without a running MCP server process.
    Suitable for single-machine deployment inside the SIFT VM.
    """

    async def get_process_list(self, image_path: str) -> dict:
        return (await ProcessListTool().run(image_path)).data

    async def get_network_connections(self, image_path: str) -> dict:
        return (await NetworkScanTool().run(image_path)).data

    async def get_loaded_modules(self, image_path: str) -> dict:
        return (await ModulesTool().run(image_path)).data

    async def search_strings(self, image_path: str, pattern: str) -> dict:
        return (await StringsTool().run(image_path, pattern=pattern)).data

    async def extract_mft_timeline(self, image_path: str) -> dict:
        return (await MFTTimelineTool().run(image_path)).data

    async def analyze_prefetch(self, image_path: str) -> dict:
        return (await PrefetchTool().run(image_path)).data

    async def check_persistence(self, image_path: str) -> dict:
        return (await PersistenceTool().run(image_path)).data


async def run_sentinel(
    image_path: str,
    output_path: str,
    max_iterations: int = 3
) -> dict:
    """
    Full Sentinel-MCP pipeline:
    1. Investigation Engine — autonomous tool chaining
    2. LLM Backend — structured reasoning over evidence
    3. Self-correction loop — validates CONFIRMED findings
    4. Report saved to output_path
    """
    start = datetime.now(timezone.utc)
    print(f"\n[Sentinel-MCP] Starting investigation")
    print(f"[Sentinel-MCP] Image: {image_path}")
    print(f"[Sentinel-MCP] Output: {output_path}\n")

    # Step 1 — Investigation Engine
    client = DirectMCPClient()
    engine = InvestigationEngine(client)
    evidence = await engine.investigate(image_path)

    print(f"\n[Sentinel-MCP] Evidence collection complete")
    print(f"[Sentinel-MCP] IOCs found: {evidence['ioc_count']}")
    print(f"[Sentinel-MCP] Phases: {evidence['phases_completed']}\n")

    # Step 2 — LLM reasoning
    backend = get_backend()
    user_prompt = (
        f"Analyse this forensic evidence and produce the full report:\n\n"
        f"{json.dumps(evidence, indent=2)}"
    )

    iteration = 0
    report = ""

    while iteration < max_iterations:
        print(f"[Iteration {iteration + 1}/{max_iterations}] "
              f"Sending to {backend.__class__.__name__}...\n")

        response_text = ""
        for chunk in backend.stream(SENIOR_ANALYST_PROMPT, user_prompt):
            print(chunk, end="", flush=True)
            response_text += chunk

        log_agent_iteration(iteration, response_text,
                            backend.__class__.__name__)

        # Self-correction pass
        if "[CONFIRMED]" in response_text and iteration < max_iterations - 1:
            print(f"\n\n[Self-correction] Reviewing CONFIRMED findings...\n")
            user_prompt = (
                f"{response_text}\n\n"
                f"Review every [CONFIRMED] finding above. "
                f"For any finding where you cannot cite a specific tool "
                f"call and artifact, downgrade it to [INFERRED] and "
                f"explain why. Output the revised full report only."
            )
            iteration += 1
        else:
            report = response_text
            break

    # Step 3 — Save report
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
    parser.add_argument("--image", required=True,
                        help="Path to memory or disk image")
    parser.add_argument("--output", default="logs/report.json",
                        help="Output path for JSON report")
    parser.add_argument("--iterations", type=int, default=3,
                        help="Max self-correction iterations")
    args = parser.parse_args()

    asyncio.run(run_sentinel(args.image, args.output, args.iterations))