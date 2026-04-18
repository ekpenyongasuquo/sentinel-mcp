import json
import os
from datetime import datetime, timezone


LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "logs")
os.makedirs(LOG_DIR, exist_ok=True)


def _write(entry: dict):
    filename = os.path.join(LOG_DIR, f"execution_{datetime.now().strftime('%Y%m%d')}.json")
    with open(filename, "a") as f:
        f.write(json.dumps(entry) + "\n")


def log_tool_call(tool_name: str, elapsed: float, summary: str = ""):
    _write({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "TOOL_CALL",
        "tool": tool_name,
        "elapsed_seconds": elapsed,
        "summary": summary
    })


def log_investigation_step(phase: str, detail: str):
    _write({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "INVESTIGATION",
        "phase": phase,
        "detail": detail
    })


def log_agent_iteration(iteration: int, response_text: str, backend: str):
    _write({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "AGENT_ITERATION",
        "iteration": iteration,
        "backend": backend,
        "response_length": len(response_text),
        "preview": response_text[:200]
    })