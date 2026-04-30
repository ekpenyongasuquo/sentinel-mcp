#!/bin/bash
cd /home/sansforensics/sentinel-mcp

# Create __init__.py files
touch mcp_server/__init__.py
touch mcp_server/tools/__init__.py
touch mcp_server/utils/__init__.py
touch agent/__init__.py
touch tests/__init__.py

# Fix server.py
cat > mcp_server/server.py << 'PYEOF'
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from tools.memory import ProcessListTool, NetworkScanTool, ModulesTool, StringsTool
from tools.disk import MFTTimelineTool, PrefetchTool, PersistenceTool
from utils.logger import log_tool_call

server = Server("sentinel-mcp")

@server.tool()
async def get_process_list(image_path: str) -> dict:
    """List all running processes."""
    return (await ProcessListTool().run(image_path)).data

@server.tool()
async def get_network_connections(image_path: str) -> dict:
    """List all network connections."""
    return (await NetworkScanTool().run(image_path)).data

@server.tool()
async def get_loaded_modules(image_path: str) -> dict:
    """List all loaded kernel modules."""
    return (await ModulesTool().run(image_path)).data

@server.tool()
async def search_strings(image_path: str, pattern: str) -> dict:
    """Search memory image for a specific string pattern."""
    return (await StringsTool().run(image_path, pattern=pattern)).data

@server.tool()
async def extract_mft_timeline(image_path: str) -> dict:
    """Extract filesystem timeline."""
    return (await MFTTimelineTool().run(image_path)).data

@server.tool()
async def analyze_prefetch(image_path: str) -> dict:
    """Analyse recently executed programs."""
    return (await PrefetchTool().run(image_path)).data

@server.tool()
async def check_persistence(image_path: str) -> dict:
    """Check registry for persistence mechanisms."""
    return (await PersistenceTool().run(image_path)).data

async def main():
    print("[Sentinel-MCP] MCP server starting...")
    async with stdio_server() as (r, w):
        await server.run(r, w, server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
PYEOF

echo "Fix complete!"