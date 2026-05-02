# Dataset Documentation

## Primary Test Image

| Field | Value |
|-------|-------|
| Filename | memdump.mem |
| Size | 512 MB |
| Format | Raw memory dump |
| Source | samsclass.info (public forensics training data) |
| OS | Windows Vista / Server 2008 SP1 32-bit |
| Captured | 2014-01-08 17:54:20 UTC |
| Volatility Profile | windows.ntkrpamp (PAE) |
| SHA256 | d3b13f2224cab20440a4bb3c5c971662be6e61f431340f319cef7312bb6177f4 |

## How to Obtain This Image

```bash
cd /your/case/directory
wget https://samsclass.info/121/proj/memdump.7z
sudo apt install p7zip-full -y
7z x memdump.7z
```

## What Sentinel-MCP Found

| Finding Type | Count | Examples |
|---|---|---|
| Suspicious processes | 4 | ftpbasicsvr.exe, snmp.exe, iashost.exe, ftk |
| C2 connections | 9 | 54.213.58.70, 54.230.117.162, 93.184.216.139 |
| Persistence keys | 6 | services v.20191024 |
| Ghost processes | 1 | ftk (memory only, no disk trace) |
| Total IOCs | 4 | — |

## Ground Truth

Documented in `tests/ground_truth.json`

Known findings verified against:
- Volatility 3 windows.pslist manual review
- Volatility 3 windows.netscan manual review
- Volatility 3 windows.cmdline manual review

## Reproducibility

To reproduce results exactly:

```bash
# Set up environment
cd /home/sansforensics/sentinel-mcp
source venv/bin/activate

# Run investigation
python agent/agent.py \
  --image /path/to/memdump.mem \
  --output logs/reproduced_report.json

# Score results
python tests/score_reports.py
```

Expected output:
- IOCs found: 4
- Overall recall: 1.0
- Hallucination rate: 0.0
- Time: approximately 300 seconds (Groq mode)

## Evidence Integrity

The original memdump.mem file is never modified.
The MCP server validates all file paths before execution.
All analysis output is written to ./logs/ only.
SHA256 of input file remains unchanged after any analysis run.
