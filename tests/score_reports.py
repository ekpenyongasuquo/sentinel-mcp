import json
import os
import glob

# Ground truth
GROUND_TRUTH = {
    "known_suspicious_processes": ["ftpbasicsvr.exe", "snmp.exe", "iashost.exe", "ftk"],
    "known_c2_ips": ["54.213.58.70", "54.230.117.162", "93.184.216.139"],
    "known_ghost_processes": ["ftk"],
    "known_persistence_keys": 6,
    "total_expected_iocs": 4
}

def score_report(report_path: str) -> dict:
    """Score a single report against ground truth."""
    with open(report_path) as f:
        data = json.load(f)

    summary = data.get("evidence_summary", {})
    ioc_count = data.get("ioc_count", 0)
    report_text = data.get("report", "").lower()

    # Score process detection
    procs_found = summary.get("suspicious_processes", 0)
    procs_expected = len(GROUND_TRUTH["known_suspicious_processes"])
    proc_recall = round(min(procs_found, procs_expected) / procs_expected, 2)

    # Score C2 detection
    c2_found = summary.get("c2_connections", 0)
    c2_expected = len(GROUND_TRUTH["known_c2_ips"])
    c2_recall = round(min(c2_found, c2_expected) / c2_expected, 2)

    # Score persistence detection
    persist_found = summary.get("persistence_keys", 0)
    persist_expected = GROUND_TRUTH["known_persistence_keys"]
    persist_recall = round(min(persist_found, persist_expected) / persist_expected, 2)

    # Score ghost process detection
    ghost_found = summary.get("ghost_processes", 0)
    ghost_expected = len(GROUND_TRUTH["known_ghost_processes"])
    ghost_recall = round(min(ghost_found, ghost_expected) / ghost_expected, 2)

    # Check if C2 IPs appear in report text
    ips_in_report = sum(
        1 for ip in GROUND_TRUTH["known_c2_ips"]
        if ip in report_text
    )

    # Overall score
    overall = round(
        (proc_recall + c2_recall + persist_recall + ghost_recall) / 4, 2
    )

    # Hallucination check — did report invent non-existent IPs?
    fake_indicators = []
    import re
    found_ips = re.findall(r'\d+\.\d+\.\d+\.\d+', report_text)
    for ip in found_ips:
        if ip not in GROUND_TRUTH["known_c2_ips"] and ip not in ["0.0.0.0", "127.0.0.1"]:
            fake_indicators.append(ip)

    hallucination_rate = round(
        len(fake_indicators) / max(len(found_ips), 1), 2
    ) if found_ips else 0.0

    return {
        "report_file": os.path.basename(report_path),
        "llm_backend": data.get("llm_backend", "unknown"),
        "elapsed_seconds": data.get("elapsed_seconds", 0),
        "ioc_count": ioc_count,
        "scores": {
            "suspicious_process_recall": proc_recall,
            "c2_detection_recall": c2_recall,
            "persistence_recall": persist_recall,
            "ghost_process_recall": ghost_recall,
            "overall_recall": overall,
            "c2_ips_named_in_report": ips_in_report,
            "hallucination_rate": hallucination_rate,
            "hallucinated_ips": fake_indicators
        }
    }


def main():
    print("\n=== SENTINEL-MCP ACCURACY REPORT ===")
    print(f"Ground truth: {GROUND_TRUTH['total_expected_iocs']} expected IOCs\n")

    # Find all report files
    report_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '..', 'logs'
    )
    reports = glob.glob(os.path.join(report_dir, "report*.json"))
    reports += glob.glob(os.path.join(report_dir, "test*.json"))

    if not reports:
        print("No report files found in logs/")
        return

    results = []
    for path in sorted(reports):
        try:
            result = score_report(path)
            results.append(result)
            scores = result["scores"]
            print(f"File: {result['report_file']}")
            print(f"  Backend:           {result['llm_backend']}")
            print(f"  Time:              {result['elapsed_seconds']}s")
            print(f"  IOCs found:        {result['ioc_count']}/4")
            print(f"  Process recall:    {scores['suspicious_process_recall']}")
            print(f"  C2 recall:         {scores['c2_detection_recall']}")
            print(f"  Persistence recall:{scores['persistence_recall']}")
            print(f"  Ghost recall:      {scores['ghost_process_recall']}")
            print(f"  Overall recall:    {scores['overall_recall']}")
            print(f"  C2 IPs in report:  {scores['c2_ips_named_in_report']}/3")
            print(f"  Hallucination rate:{scores['hallucination_rate']}")
            if scores['hallucinated_ips']:
                print(f"  Hallucinated IPs:  {scores['hallucinated_ips']}")
            print()
        except Exception as e:
            print(f"  Error scoring {path}: {e}\n")

    # Summary
    if results:
        avg_recall = round(
            sum(r["scores"]["overall_recall"] for r in results) / len(results), 2
        )
        avg_hallucination = round(
            sum(r["scores"]["hallucination_rate"] for r in results) / len(results), 2
        )
        avg_time = round(
            sum(r["elapsed_seconds"] for r in results) / len(results)
        )

        print("=" * 50)
        print("SUMMARY ACROSS ALL RUNS")
        print("=" * 50)
        print(f"Total reports scored:     {len(results)}")
        print(f"Average overall recall:   {avg_recall}")
        print(f"Average hallucination:    {avg_hallucination}")
        print(f"Average time (seconds):   {avg_time}")

        # Save accuracy report
        accuracy_report = {
            "ground_truth": GROUND_TRUTH,
            "individual_results": results,
            "summary": {
                "total_runs": len(results),
                "avg_overall_recall": avg_recall,
                "avg_hallucination_rate": avg_hallucination,
                "avg_elapsed_seconds": avg_time
            }
        }
        output = os.path.join(report_dir, "accuracy_report.json")
        with open(output, "w") as f:
            json.dump(accuracy_report, f, indent=2)
        print(f"\nFull accuracy report saved to: logs/accuracy_report.json")


if __name__ == "__main__":
    main()
