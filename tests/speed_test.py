import asyncio
import time
import json
import argparse
import os
import sys
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent / "agent"))
sys.path.insert(0, str(Path(__file__).parent.parent / "mcp_server"))

from investigation_engine import InvestigationEngine
from agent import DirectMCPClient


async def run_speed_test(image_path: str, mode: str):
    """
    Measures time for each investigation phase independently.
    Target: full triage under 4 minutes.
    """
    os.environ["LLM_MODE"] = mode

    print(f"\n[Speed Test] Mode: {mode.upper()}")
    print(f"[Speed Test] Image: {image_path}\n")

    timings = {}
    client = DirectMCPClient()

    # Time Phase 1
    print("[Timing] Phase 1 — parallel triage...")
    t = time.time()
    procs, nets = await asyncio.gather(
        client.get_process_list(image_path),
        client.get_network_connections(image_path)
    )
    timings["phase1_seconds"] = round(time.time() - t, 2)
    print(f"         Done in {timings['phase1_seconds']}s")

    # Time Phase 2 (if signals found)
    has_procs = len(procs.get("flagged", [])) > 0
    has_nets = len(nets.get("flagged", [])) > 0

    if has_procs or has_nets:
        print("[Timing] Phase 2 — deep dive...")
        t = time.time()
        if has_procs:
            await asyncio.gather(
                client.check_persistence(image_path),
                client.get_loaded_modules(image_path)
            )
        timings["phase2_seconds"] = round(time.time() - t, 2)
        print(f"         Done in {timings['phase2_seconds']}s")
    else:
        timings["phase2_seconds"] = 0
        print("[Timing] Phase 2 — skipped (no signals)")

    # Time Phase 3
    print("[Timing] Phase 3 — cross-validation...")
    t = time.time()
    await asyncio.gather(
        client.extract_mft_timeline(image_path),
        client.analyze_prefetch(image_path)
    )
    timings["phase3_seconds"] = round(time.time() - t, 2)
    print(f"         Done in {timings['phase3_seconds']}s")

    # Total investigation time
    timings["total_investigation_seconds"] = round(
        timings["phase1_seconds"] +
        timings["phase2_seconds"] +
        timings["phase3_seconds"], 2
    )

    # Print results
    print(f"\n{'=' * 50}")
    print(f"SPEED TEST RESULTS — {mode.upper()} MODE")
    print(f"{'=' * 50}")
    print(f"Phase 1 (triage):       {timings['phase1_seconds']}s")
    print(f"Phase 2 (deep dive):    {timings['phase2_seconds']}s")
    print(f"Phase 3 (cross-val):    {timings['phase3_seconds']}s")
    print(f"Total investigation:    {timings['total_investigation_seconds']}s")
    print(f"Target:                 < 240s (4 minutes)")
    passed = timings["total_investigation_seconds"] < 240
    print(f"Result:                 {'PASS ✓' if passed else 'SLOW — optimise parsers'}")

    # Save results
    output_file = f"logs/speed_report_{mode}.json"
    with open(output_file, "w") as f:
        json.dump({
            "mode": mode,
            "image": image_path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "timings": timings,
            "target_met": passed
        }, f, indent=2)
    print(f"\nFull report saved to: {output_file}")
    return timings


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Sentinel-MCP Speed Test")
    parser.add_argument("--image", required=True,
                        help="Path to test image")
    parser.add_argument("--mode", default="offline",
                        choices=["offline", "cloud"],
                        help="LLM mode to test")
    args = parser.parse_args()

    asyncio.run(run_speed_test(args.image, args.mode))