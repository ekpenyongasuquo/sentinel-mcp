import asyncio, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tools'))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'utils'))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from pydantic import BaseModel
from tools.memory import ProcessListTool, NetworkScanTool, ModulesTool, StringsTool
from tools.disk import MFTTimelineTool, PrefetchTool, PersistenceTool
import json

server = Server("sentinel-mcp")

@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(name="get_process_list",
             description="List all running processes. Flags known malicious names.",
             inputSchema={"type":"object","properties":{"image_path":{"type":"string"}},"required":["image_path"]}),
        Tool(name="get_network_connections",
             description="List all network connections. Flags known C2 ports.",
             inputSchema={"type":"object","properties":{"image_path":{"type":"string"}},"required":["image_path"]}),
        Tool(name="get_loaded_modules",
             description="List all loaded kernel modules.",
             inputSchema={"type":"object","properties":{"image_path":{"type":"string"}},"required":["image_path"]}),
        Tool(name="search_strings",
             description="Search memory image for a string pattern.",
             inputSchema={"type":"object","properties":{"image_path":{"type":"string"},"pattern":{"type":"string"}},"required":["image_path","pattern"]}),
        Tool(name="extract_mft_timeline",
             description="Extract filesystem timeline from disk image.",
             inputSchema={"type":"object","properties":{"image_path":{"type":"string"}},"required":["image_path"]}),
        Tool(name="analyze_prefetch",
             description="Analyse recently executed programs from memory.",
             inputSchema={"type":"object","properties":{"image_path":{"type":"string"}},"required":["image_path"]}),
        Tool(name="check_persistence",
             description="Check registry for persistence mechanisms.",
             inputSchema={"type":"object","properties":{"image_path":{"type":"string"}},"required":["image_path"]}),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    image_path = arguments.get("image_path", "")
    pattern = arguments.get("pattern", "")

    if name == "get_process_list":
        result = (await ProcessListTool().run(image_path)).data
    elif name == "get_network_connections":
        result = (await NetworkScanTool().run(image_path)).data
    elif name == "get_loaded_modules":
        result = (await ModulesTool().run(image_path)).data
    elif name == "search_strings":
        result = (await StringsTool().run(image_path, pattern=pattern)).data
    elif name == "extract_mft_timeline":
        result = (await MFTTimelineTool().run(image_path)).data
    elif name == "analyze_prefetch":
        result = (await PrefetchTool().run(image_path)).data
    elif name == "check_persistence":
        result = (await PersistenceTool().run(image_path)).data
    else:
        result = {"error": f"Unknown tool: {name}"}

    return [TextContent(type="text", text=json.dumps(result, indent=2))]

async def main():
    print("[Sentinel-MCP] MCP server starting...")
    async with stdio_server() as (r, w):
        await server.run(r, w, server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
