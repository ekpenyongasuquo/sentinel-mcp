import subprocess
import time
from .base_tool import BaseSIFTTool, ToolResult
from ..utils.parser import parse_process_list, parse_network_connections
from ..utils.logger import log_tool_call


class ProcessListTool(BaseSIFTTool):
    """Wraps Volatility windows.pslist — lists all running processes."""

    async def run(self, image_path: str, **kwargs) -> ToolResult:
        if not self.validate(image_path):
            return ToolResult("get_process_list", False, {},
                              error=f"File not found: {image_path}")
        start = time.time()
        cmd = ["vol", "-f", image_path, "windows.pslist.PsList"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        elapsed = round(time.time() - start, 2)
        data = self.parse(r.stdout)
        log_tool_call("get_process_list", elapsed,
                      f"{data['total']} procs, {data['flag_count']} flagged")
        return ToolResult("get_process_list", r.returncode == 0,
                          data, r.stderr or None, elapsed)

    def parse(self, raw: str) -> dict:
        return parse_process_list(raw)


class NetworkScanTool(BaseSIFTTool):
    """Wraps Volatility windows.netscan — lists network connections."""

    async def run(self, image_path: str, **kwargs) -> ToolResult:
        if not self.validate(image_path):
            return ToolResult("get_network_connections", False, {},
                              error=f"File not found: {image_path}")
        start = time.time()
        cmd = ["vol", "-f", image_path, "windows.netscan.NetScan"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        elapsed = round(time.time() - start, 2)
        data = self.parse(r.stdout)
        log_tool_call("get_network_connections", elapsed,
                      f"{data['total']} conns, {data['flag_count']} flagged")
        return ToolResult("get_network_connections", r.returncode == 0,
                          data, r.stderr or None, elapsed)

    def parse(self, raw: str) -> dict:
        return parse_network_connections(raw)


class ModulesTool(BaseSIFTTool):
    """Wraps Volatility windows.modules — lists loaded kernel modules."""

    async def run(self, image_path: str, **kwargs) -> ToolResult:
        if not self.validate(image_path):
            return ToolResult("get_loaded_modules", False, {},
                              error=f"File not found: {image_path}")
        start = time.time()
        cmd = ["vol", "-f", image_path, "windows.modules.Modules"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        elapsed = round(time.time() - start, 2)
        data = self.parse(r.stdout)
        log_tool_call("get_loaded_modules", elapsed,
                      f"{data['count']} modules found")
        return ToolResult("get_loaded_modules", r.returncode == 0,
                          data, r.stderr or None, elapsed)

    def parse(self, raw: str) -> dict:
        lines = [l for l in raw.strip().split("\n") if l and not l.startswith("*")]
        modules = []
        for line in lines[2:]:
            parts = line.split()
            if len(parts) >= 2:
                modules.append({"base": parts[0], "name": parts[1]})
        return {"count": len(modules), "modules": modules}


class StringsTool(BaseSIFTTool):
    """Wraps Volatility windows.strings — searches memory for a pattern."""

    async def run(self, image_path: str, pattern: str = "", **kwargs) -> ToolResult:
        if not self.validate(image_path):
            return ToolResult("search_strings", False, {},
                              error=f"File not found: {image_path}")
        start = time.time()
        cmd = ["vol", "-f", image_path, "windows.strings.Strings",
               "--string-file", "/dev/stdin"]
        r = subprocess.run(cmd, input=pattern, capture_output=True,
                           text=True, timeout=120)
        elapsed = round(time.time() - start, 2)
        data = self.parse(r.stdout)
        log_tool_call("search_strings", elapsed,
                      f"{data['count']} matches for '{pattern}'")
        return ToolResult("search_strings", r.returncode == 0,
                          data, r.stderr or None, elapsed)

    def parse(self, raw: str) -> dict:
        lines = [l for l in raw.strip().split("\n") if l]
        return {"count": len(lines), "matches": lines[:50]}