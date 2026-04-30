import subprocess, time, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from base_tool import BaseSIFTTool, ToolResult
from parser import parse_persistence
from logger import log_tool_call

TIMEOUT = 300  # 5 minutes per tool call

class MFTTimelineTool(BaseSIFTTool):
    async def run(self, image_path, **kwargs):
        if not self.validate(image_path):
            return ToolResult("extract_mft_timeline", False, {}, error=f"File not found: {image_path}")
        start = time.time()
        r = subprocess.run(["log2timeline.py", "--storage-file", "/tmp/plaso.dump", image_path],
            capture_output=True, text=True, timeout=TIMEOUT)
        elapsed = round(time.time()-start, 2)
        data = self.parse(r.stdout)
        log_tool_call("extract_mft_timeline", elapsed, f"{data['event_count']} events")
        return ToolResult("extract_mft_timeline", r.returncode==0, data, r.stderr or None, elapsed)
    def parse(self, raw):
        lines = [l for l in raw.strip().split("\n") if l]
        events = []
        for line in lines[:100]:
            parts = line.split(",")
            if len(parts) >= 3:
                events.append({"timestamp": parts[0].strip(),
                    "source": parts[1].strip(), "description": parts[2].strip()})
        return {"event_count": len(lines), "timeline": events}

class PrefetchTool(BaseSIFTTool):
    async def run(self, image_path, **kwargs):
        if not self.validate(image_path):
            return ToolResult("analyze_prefetch", False, {}, error=f"File not found: {image_path}")
        start = time.time()
        r = subprocess.run(["vol", "-f", image_path, "windows.cmdline.CmdLine"],
            capture_output=True, text=True, timeout=TIMEOUT)
        elapsed = round(time.time()-start, 2)
        data = self.parse(r.stdout)
        log_tool_call("analyze_prefetch", elapsed, f"{len(data['executables'])} executables")
        return ToolResult("analyze_prefetch", r.returncode==0, data, r.stderr or None, elapsed)
    def parse(self, raw):
        lines = [l for l in raw.strip().split("\n") if l and not l.startswith("*")]
        executables = []
        for line in lines[2:]:
            parts = line.split()
            if len(parts) >= 2:
                executables.append({"pid": parts[0], "name": parts[1]})
        return {"executables": executables, "count": len(executables)}

class PersistenceTool(BaseSIFTTool):
    async def run(self, image_path, **kwargs):
        if not self.validate(image_path):
            return ToolResult("check_persistence", False, {}, error=f"File not found: {image_path}")
        start = time.time()
        r = subprocess.run(["rip.pl", "-r", image_path, "-f", "system"],
            capture_output=True, text=True, timeout=TIMEOUT)
        elapsed = round(time.time()-start, 2)
        data = self.parse(r.stdout)
        log_tool_call("check_persistence", elapsed, f"{data['count']} keys")
        return ToolResult("check_persistence", r.returncode==0, data, r.stderr or None, elapsed)
    def parse(self, raw):
        return parse_persistence(raw)
