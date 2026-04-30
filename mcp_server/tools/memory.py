import subprocess, time, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from base_tool import BaseSIFTTool, ToolResult
from parser import parse_process_list, parse_network_connections
from logger import log_tool_call

class ProcessListTool(BaseSIFTTool):
    async def run(self, image_path, **kwargs):
        if not self.validate(image_path):
            return ToolResult("get_process_list", False, {}, error=f"File not found: {image_path}")
        start = time.time()
        r = subprocess.run(["vol", "-f", image_path, "windows.pslist.PsList"], capture_output=True, text=True, timeout=120)
        elapsed = round(time.time()-start, 2)
        data = self.parse(r.stdout)
        log_tool_call("get_process_list", elapsed, f"{data['total']} procs")
        return ToolResult("get_process_list", r.returncode==0, data, r.stderr or None, elapsed)
    def parse(self, raw):
        return parse_process_list(raw)

class NetworkScanTool(BaseSIFTTool):
    async def run(self, image_path, **kwargs):
        if not self.validate(image_path):
            return ToolResult("get_network_connections", False, {}, error=f"File not found: {image_path}")
        start = time.time()
        r = subprocess.run(["vol", "-f", image_path, "windows.netscan.NetScan"], capture_output=True, text=True, timeout=120)
        elapsed = round(time.time()-start, 2)
        data = self.parse(r.stdout)
        log_tool_call("get_network_connections", elapsed, f"{data['total']} conns")
        return ToolResult("get_network_connections", r.returncode==0, data, r.stderr or None, elapsed)
    def parse(self, raw):
        return parse_network_connections(raw)

class ModulesTool(BaseSIFTTool):
    async def run(self, image_path, **kwargs):
        if not self.validate(image_path):
            return ToolResult("get_loaded_modules", False, {}, error=f"File not found: {image_path}")
        start = time.time()
        r = subprocess.run(["vol", "-f", image_path, "windows.modules.Modules"], capture_output=True, text=True, timeout=120)
        elapsed = round(time.time()-start, 2)
        data = self.parse(r.stdout)
        log_tool_call("get_loaded_modules", elapsed, f"{data['count']} modules")
        return ToolResult("get_loaded_modules", r.returncode==0, data, r.stderr or None, elapsed)
    def parse(self, raw):
        lines = [l for l in raw.strip().split("\n") if l and not l.startswith("*")]
        modules = []
        for line in lines[2:]:
            parts = line.split()
            if len(parts) >= 2:
                modules.append({"base": parts[0], "name": parts[1]})
        return {"count": len(modules), "modules": modules}

class StringsTool(BaseSIFTTool):
    async def run(self, image_path, pattern="", **kwargs):
        if not self.validate(image_path):
            return ToolResult("search_strings", False, {}, error=f"File not found: {image_path}")
        start = time.time()
        r = subprocess.run(["vol", "-f", image_path, "windows.strings.Strings", "--string-file", "/dev/stdin"], input=pattern, capture_output=True, text=True, timeout=120)
        elapsed = round(time.time()-start, 2)
        data = self.parse(r.stdout)
        log_tool_call("search_strings", elapsed, f"{data['count']} matches")
        return ToolResult("search_strings", r.returncode==0, data, r.stderr or None, elapsed)
    def parse(self, raw):
        lines = [l for l in raw.strip().split("\n") if l]
        return {"count": len(lines), "matches": lines[:50]}
