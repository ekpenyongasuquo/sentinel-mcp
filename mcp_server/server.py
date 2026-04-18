import asyncio
from mcp.server import Server
from mcp.server.stdio import stdio_server
from tools.memory import ProcessListTool, NetworkScanTool, ModulesTool, StringsTool
from tools.disk import MFTTimelineTool, PrefetchTool, PersistenceTool
from tools.reporting import generate_remediation_playbook
from utils.logger import log_tool_call

server = Server("sentinel-mcp")


@server.tool()
async def get_process_list(image_path: str) -> dict:
    """List all running processes. Flags known malicious process names."""
    return (await ProcessListTool().run(image_path)).data


@server.tool()
async def get_network_connections(image_path: str) -> dict:
    """List all network connections. Flags known C2 ports."""
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
    """Extract filesystem timeline from disk image using log2timeline."""
    return (await MFTTimelineTool().run(image_path)).data


@server.tool()
async def analyze_prefetch(image_path: str) -> dict:
    """Analyse recently executed programs from memory."""
    return (await PrefetchTool().run(image_path)).data


@server.tool()
async def check_persistence(image_path: str) -> dict:
    """Check registry for persistence mechanisms using RegRipper."""
    return (await PersistenceTool().run(image_path)).data


async def main():
    print("[Sentinel-MCP] MCP server starting...")
    async with stdio_server() as (r, w):
        await server.run(r, w, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())