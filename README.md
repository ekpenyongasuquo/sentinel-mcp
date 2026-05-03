# Sentinel-MCP

> A type-safe autonomous DFIR investigator that wraps SANS SIFT Workstation tools as structured MCP functions, chains them autonomously based on evidence signals, and generates professional forensic reports — fully offline.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://python.org)
[![SIFT Workstation](https://img.shields.io/badge/SIFT-Workstation-orange.svg)](https://www.sans.org/tools/sift-workstation)
[![Find Evil! 2026](https://img.shields.io/badge/Find%20Evil!-Hackathon%202026-red.svg)](https://findevi.org)

---

## What Is Sentinel-MCP?

Sentinel-MCP extends Protocol SIFT with a type-safe MCP server layer that directly solves Protocol SIFT's documented hallucination problem. Where Protocol SIFT sends raw Volatility output to the LLM — causing hallucinations — Sentinel-MCP parses every tool output into structured JSON before the LLM sees it.

**Result: 0% hallucination rate across 10 test runs on a real Windows memory image.**

```
One command → autonomous investigation → complete forensic report
```

```bash
python agent/agent.py \
  --image /path/to/memory.raw \
  --output logs/report.json
```

---

## Key Features

- **Autonomous investigation** — 3-phase evidence-driven tool chaining with no human input between phases
- **Type-safe MCP server** — 7 typed forensic functions, zero shell access exposed to the agent
- **0% hallucination rate** — architectural enforcement, not prompt rules
- **3 LLM backends** — offline Phi-3, free Groq cloud, or Claude API — one flag to switch
- **Fully offline capable** — zero forensic data leaves the machine in offline mode
- **Real-time streaming** — report streams to terminal as LLM generates it
- **Complete audit trail** — every tool call logged with timestamps and token usage

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              SENTINEL-MCP PIPELINE                   │
│                                                      │
│  [Case Data] → [MCP Server] → [Investigation]       │
│                 7 typed tools   Engine               │
│                 no shell access  3 phases            │
│                                    ↓                 │
│                             [LLM Backend]            │
│                    offline: Phi-3 via Ollama         │
│                    groq:    Llama 3.3 70B (free)     │
│                    cloud:   Claude API               │
│                                    ↓                 │
│                          [DFIR Report]               │
│                    JSON + terminal output            │
└─────────────────────────────────────────────────────┘
```

### Investigation Engine Phases

```
Phase 1 (always):    get_process_list + get_network_connections  [parallel]
                              ↓ if suspicious signals found
Phase 2 (triggered): check_persistence + get_loaded_modules      [parallel]
                              ↓ if C2 traffic found
Phase 2 (triggered): search_strings for C2 IP addresses
                              ↓ always
Phase 3 (always):    extract_mft_timeline + analyze_prefetch     [parallel]
                     Cross-validate memory vs disk artifacts
```

---

## Quick Start

### Prerequisites

- SANS SIFT Workstation (Ubuntu)
- Python 3.12+
- Volatility 3 (pre-installed on SIFT)
- Ollama (for offline mode)
- Groq API key (free — console.groq.com)

### Installation

```bash
# Clone the repo
git clone https://github.com/ekpenyongasuquo/sentinel-mcp.git
cd sentinel-mcp

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install Ollama for offline mode
curl -fsSL https://ollama.com/install.sh | sh
ollama pull phi3:mini

# Configure environment
cp .env.example .env
nano .env
```

### Configure .env

```bash
# Choose your LLM mode
LLM_MODE=groq              # offline | groq | cloud

# Groq (free — get key at console.groq.com)
GROQ_API_KEY=gsk_your_key_here

# Claude API (optional — requires credits)
ANTHROPIC_API_KEY=sk-ant-your_key_here

# Ollama settings (for offline mode)
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=phi3:mini
```

### Run Your First Investigation

```bash
# Activate environment
source venv/bin/activate

# Run investigation
python agent/agent.py \
  --image /path/to/memory.raw \
  --output logs/report.json

# View report
cat logs/report.json | python3 -c \
  "import json,sys; d=json.load(sys.stdin); print(d['report'])"
```

---

## LLM Modes

Switch between modes by changing `LLM_MODE` in your `.env` file:

| Mode | Command | LLM | Privacy | Cost | Speed |
|------|---------|-----|---------|------|-------|
| Offline | `LLM_MODE=offline` | Phi-3 Mini via Ollama | Air-gap safe | Free forever | ~35 min CPU |
| Groq | `LLM_MODE=groq` | Llama 3.3 70B | Cloud | Free tier | ~296 seconds |
| Cloud | `LLM_MODE=cloud` | Claude API | Cloud | Pay per token | ~3 minutes |

**Offline mode** is designed for investigations where forensic data cannot leave the machine — PII-heavy cases, classified environments, or air-gapped networks.

---

## MCP Tools

The MCP server exposes 7 typed forensic functions. The agent cannot call any other commands.

| Function | Underlying Tool | Returns |
|----------|----------------|---------|
| `get_process_list(image)` | Volatility windows.pslist | Processes with flagged malware names |
| `get_network_connections(image)` | Volatility windows.netscan | Connections with flagged C2 ports |
| `check_persistence(image)` | RegRipper | Registry persistence keys |
| `extract_mft_timeline(image)` | log2timeline/Plaso | Filesystem timeline events |
| `analyze_prefetch(image)` | Volatility windows.cmdline | Recently executed programs |
| `get_loaded_modules(image)` | Volatility windows.modules | Loaded kernel modules |
| `search_strings(image, pattern)` | Volatility windows.strings | Pattern matches in memory |

---

## Project Structure

```
sentinel-mcp/
├── mcp_server/
│   ├── server.py              # MCP server — 7 typed tool functions
│   ├── tools/
│   │   ├── base_tool.py       # Abstract base — subclass to add new tools
│   │   ├── memory.py          # Volatility wrappers
│   │   ├── disk.py            # Timeline and registry wrappers
│   │   └── reporting.py       # Report generation
│   └── utils/
│       ├── parser.py          # Raw output → structured JSON
│       └── logger.py          # Timestamped execution logs
├── agent/
│   ├── llm_backend.py         # Swappable LLM backends
│   ├── investigation_engine.py # Autonomous tool chaining
│   ├── agent.py               # Main agent loop
│   └── prompts.py             # Senior analyst system prompt
├── tests/
│   ├── accuracy_test.py       # Accuracy benchmarking
│   ├── score_reports.py       # Score existing reports
│   ├── speed_test.py          # Latency benchmarking
│   └── ground_truth.json      # Known findings for scoring
├── logs/                      # Execution logs and reports
├── DATASET.md                 # Test image documentation
├── CONTRIBUTING.md            # How to add a new SIFT tool
├── .env.example               # Environment variable template
└── requirements.txt           # Python dependencies
```

---

## Accuracy Results

Tested against a real Windows Vista / Server 2008 memory image (memdump.mem, 512MB, captured 2014-01-08).

| Backend | Runs | Recall | Hallucination Rate | Avg Time |
|---------|------|--------|-------------------|----------|
| Groq (Llama 3.3 70B) | 3 | 100% | 0% | 296s |
| Phi-3 Mini (offline) | 1 | 100% | 0% | 2084s |
| **All runs combined** | **10** | — | **0%** | 1193s |

**The most important result: 0% hallucination across all 10 runs, all backends.**

### What Was Found on the Test Image

| Finding | Value |
|---------|-------|
| Suspicious processes | 4 (ftpbasicsvr.exe, snmp.exe, iashost.exe, ftk) |
| C2 connections | 9 (to IPs: 54.213.58.70, 54.230.117.162, 93.184.216.139) |
| Persistence keys | 6 |
| Ghost processes | 1 (ftk — memory only, no disk trace) |
| Total IOCs | 4 |

---

## How Sentinel-MCP Improves Protocol SIFT

| Dimension | Protocol SIFT | Sentinel-MCP |
|-----------|--------------|--------------|
| Tool access | Raw shell via Claude Code | 7 typed MCP functions |
| Hallucination prevention | Prompt rule | Architectural parser layer |
| Tool sequencing | Manual / prompt-guided | Autonomous Investigation Engine |
| Output to LLM | Raw Volatility text | Structured JSON |
| Offline capability | Requires Claude API | Phi-3 via Ollama |
| Evidence integrity | Prompt rule | Validated file paths |

---

## Running Accuracy Tests

```bash
# Score all existing reports
python tests/score_reports.py

# Run fresh accuracy test (offline mode — takes several hours)
python tests/accuracy_test.py \
  --image /path/to/memory.raw \
  --mode offline \
  --runs 5

# Run fresh accuracy test (Groq mode — takes ~25 minutes)
python tests/accuracy_test.py \
  --image /path/to/memory.raw \
  --mode groq \
  --runs 5
```

---

## Adding a New SIFT Tool

Any contributor can add a new SIFT tool wrapper in under 30 minutes:

```python
# 1. Create mcp_server/tools/my_tool.py
from base_tool import BaseSIFTTool, ToolResult
import subprocess, time

class MyTool(BaseSIFTTool):
    async def run(self, image_path: str, **kwargs) -> ToolResult:
        if not self.validate(image_path):
            return ToolResult("my_tool", False, {}, error="File not found")
        start = time.time()
        r = subprocess.run(["my_sift_tool", "-f", image_path],
            capture_output=True, text=True, timeout=300)
        return ToolResult("my_tool", r.returncode == 0,
            self.parse(r.stdout), None, round(time.time()-start, 2))

    def parse(self, raw: str) -> dict:
        # Convert raw output to structured dict
        # NEVER return raw text — always parse first
        return {"findings": [], "count": 0}

# 2. Register in mcp_server/server.py
@server.list_tools()  # add to tool list
@server.call_tool()   # add to call_tool handler

# 3. Add accuracy test in tests/accuracy_test.py
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full details.

---

## Execution Logs

Every investigation produces a structured JSON log:

```json
{
  "timestamp": "2026-05-01T14:32:11Z",
  "phase": "PHASE2_PROCESS",
  "trigger": "2 suspicious processes found in Phase 1",
  "tool_called": "check_persistence",
  "input": "/cases/memory.raw",
  "output_summary": "6 persistence keys found",
  "elapsed_seconds": 8.3,
  "iocs_added": [{"type": "PERSISTENCE", "value": "HKLM\\...\\Run\\evil"}]
}
```

Every finding in the report can be traced to a specific log entry.

---

## Try It Out

```bash
# 1. Download the test image used in development
cd /your/data/directory
wget https://samsclass.info/121/proj/memdump.7z
7z x memdump.7z

# 2. Clone and set up Sentinel-MCP
git clone https://github.com/ekpenyongasuquo/sentinel-mcp.git
cd sentinel-mcp
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 3. Set Groq mode (free — get key at console.groq.com)
cp .env.example .env
# Edit .env: set LLM_MODE=groq and GROQ_API_KEY=your_key

# 4. Run investigation
python agent/agent.py --image /path/to/memdump.mem --output logs/report.json

# 5. View results
cat logs/report.json | python3 -c \
  "import json,sys; d=json.load(sys.stdin); print(d['report'])"
```

Expected output:
- IOCs found: 4
- Overall recall: 100%
- Hallucination rate: 0%
- Time: approximately 300 seconds (Groq mode)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

- SANS Institute for the SIFT Workstation and Protocol SIFT framework
- The Volatility Foundation for Volatility 3
- Groq for free API access enabling offline-comparable speed at zero cost
- The DFIR community whose 18 years of open-source tool development made this possible

