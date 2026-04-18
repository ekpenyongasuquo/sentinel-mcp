# Contributing to Sentinel-MCP

Thank you for contributing to the SANS DFIR community.

## How to Add a New SIFT Tool (30 minutes)

1. Create `mcp_server/tools/your_tool.py`
2. Subclass `BaseSIFTTool` from `base_tool.py`
3. Implement `run()` — call the SIFT binary with subprocess
4. Implement `parse()` — return structured dict, never raw text
5. Register in `mcp_server/server.py` with `@server.tool()` decorator
6. Add accuracy test in `tests/accuracy_test.py`

## Code Standards
- Type hints required on all functions
- Docstrings required on all classes and methods
- Raw tool output must never reach the LLM — always parse first
- All file paths must be validated before tool execution
- Every tool call must be logged via `log_tool_call()`

## Adding a New LLM Backend
Subclass `LLMBackend` in `agent/llm_backend.py`.
Implement `complete()` and `stream()`.
Add your mode name to `get_backend()` factory function.