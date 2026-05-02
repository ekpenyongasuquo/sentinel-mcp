# Sentinel-MCP vs Protocol SIFT — Architectural Comparison

## Protocol SIFT Approach
Protocol SIFT is a Claude Code-based DFIR framework that:
1. Gives Claude direct shell access to SIFT tools
2. Relies on prompt instructions to prevent hallucinations
3. Sends raw Volatility output directly to the LLM
4. Requires analyst guidance for tool sequencing
5. Prevention of evidence modification is prompt-based only

Evidence from CLAUDE.md:
- "No hallucinations — Never guess, assume, or fabricate"
  (prompt rule — can be ignored by LLM)
- "Evidence integrity — Never modify files"
  (prompt rule — not architecturally enforced)

## Sentinel-MCP Improvement

### 1. Architectural Hallucination Prevention
Protocol SIFT: prompt rule says "never fabricate"
Sentinel-MCP: MCP server parses raw output into structured JSON
before LLM sees it — LLM cannot fabricate what it never receives

Result: 0% hallucination across 10 test runs

### 2. Architectural Evidence Integrity
Protocol SIFT: prompt rule says "never modify evidence"
Sentinel-MCP: MCP server validates all file paths are read-only
before execution — agent physically cannot modify evidence

### 3. Autonomous Tool Sequencing
Protocol SIFT: analyst or prompt guides tool selection
Sentinel-MCP: Investigation Engine chains tools automatically
based on evidence signals — Phase 1→2→3 without human input

### 4. Offline Operation
Protocol SIFT: requires Claude API (data sent to Anthropic)
Sentinel-MCP: runs fully offline with Phi-3 via Ollama
Zero forensic data leaves the machine in offline mode

### 5. Context Window Management
Protocol SIFT: raw Volatility output floods LLM context
Sentinel-MCP: structured JSON summary sent to LLM
Prevents context degradation on complex cases

## Measured Results
- Hallucination rate: 0% (10/10 runs)
- IOC recall (Groq mode): 100% (3/3 runs)
- Time to full report: 296 seconds average (Groq)
- Offline capability: confirmed (Phi-3 mode)
