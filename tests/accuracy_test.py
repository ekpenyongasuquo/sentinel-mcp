import asyncio
import json
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "agent"))
sys.path.insert(0, str(Path(__file__).parent.parent / "mcp_server"))

from agent import run_sentinel

# ── GROUND TRUTH ─────────────────────────────────────────────────────────────
# Update these with the actual known-good values from your sample case data
GROUND_TRUTH = {
    "malicious_processes": ["mimikatz.exe", "psexec.exe"],
    "c2_ips": ["192.168.1.100"],
    "persistence_keys": [
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil"
    ],
    "ghost_processes": []
}


def score_run(evidence_summary: dict, iocs: list) -> dict:
    """Score one agent run against ground truth."""
    found_proc_names = [
        i["value"] for i in iocs
        if i.get("type") == "PERSISTENCE"
    ]
    found_ips = [
        i["value"] for i in iocs
        if i.get("type") == "C2_IP"
    ]

    proc_tp = len([p for p in found_proc_names
                   if p in GROUND_TRUTH["malicious_processes"]])
    proc_fp = len([p for p in found_proc_names
                   if p not in GROUND_TRUTH["malicious_processes"]])
    proc_fn = len([p for p in GROUND_TRUTH["malicious_processes"]
                   if p not in found_proc_names])

    ip_tp = len([i for i in found_ips if i in GROUND_TRUTH["c2_ips"]])
    ip_fp = len([i for i in found_ips if i not in GROUND_TRUTH["c2_ips"]])

    total_tp = proc_tp + ip_tp
    total_fp = proc_fp + ip_fp
    total_fn = proc_fn

    precision = round(total_tp / (total_tp + total_fp), 2) \
        if (total_tp + total_fp) > 0 else 0
    recall = round(total_tp / (total_tp + total_fn), 2) \
        if (total_tp + total_fn) > 0 else 0
    hallucination_rate = round(total_fp / (total_tp + total_fp), 2) \
        if (total_tp + total_fp) > 0 else 0

    return {
        "true_positives": total_tp,
        "false_positives": total_fp,
        "false_negatives": total_fn,
        "precision": precision,
        "recall": recall,
        "hallucination_rate": hallucination_rate
    }


async def run_accuracy_test(image_path: str, mode: str, runs: int = 5):
    """Run the agent N times and average the scores."""
    import os
    os.environ["LLM_MODE"] = mode

    print(f"\n[Accuracy Test] Mode: {mode.upper()} | Runs: {runs}")
    print(f"[Accuracy Test] Image: {image_path}\n")

    scores = []
    for i in range(runs):
        print(f"\n--- Run {i + 1}/{runs} ---")
        output = f"logs/accuracy_run_{mode}_{i + 1}.json"
        result = await run_sentinel(image_path, output)

        with open(output) as f:
            data = json.load(f)

        evidence = data.get("evidence", {})
        iocs = evidence.get("iocs", [])
        score = score_run(data.get("evidence_summary", {}), iocs)
        scores.append(score)
        print(f"\nRun {i + 1} score: {score}")

    # Average across all runs
    avg = {
        "mode": mode,
        "runs": runs,
        "avg_precision": round(
            sum(s["precision"] for s in scores) / runs, 2),
        "avg_recall": round(
            sum(s["recall"] for s in scores) / runs, 2),
        "avg_hallucination_rate": round(
            sum(s["hallucination_rate"] for s in scores) / runs, 2),
        "individual_runs": scores
    }

    output_file = f"logs/accuracy_report_{mode}.json"
    with open(output_file, "w") as f:
        json.dump(avg, f, indent=2)

    print(f"\n{'=' * 50}")
    print(f"ACCURACY REPORT — {mode.upper()} MODE")
    print(f"{'=' * 50}")
    print(f"Average Precision:         {avg['avg_precision']}")
    print(f"Average Recall:            {avg['avg_recall']}")
    print(f"Average Hallucination Rate:{avg['avg_hallucination_rate']}")
    print(f"Full report saved to:      {output_file}")
    return avg


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Sentinel-MCP Accuracy Test")
    parser.add_argument("--image", required=True,
                        help="Path to test image")
    parser.add_argument("--mode", default="offline",
                        choices=["offline", "cloud"],
                        help="LLM mode to test")
    parser.add_argument("--runs", type=int, default=5,
                        help="Number of test runs")
    args = parser.parse_args()

    asyncio.run(run_accuracy_test(args.image, args.mode, args.runs))