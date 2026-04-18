import subprocess
import time
from .base_tool import BaseSIFTTool, ToolResult
from ..utils.parser import parse_persistence
from ..utils.logger import log_tool_call


class MFTTimelineTool(BaseSIFTTool):
    """Wraps log2timeline/plaso — extracts MFT filesystem timeline."""

    async def run(self, image_path: str, **kwargs) -> ToolResult:
        if not self.validate(image_path):
            return ToolResult("extract_mft_timeline", False, {},
                              error=f"File not found: {image_path}")
        start = time.time()
        cmd = ["log2timeline.py", "--storage-file", "/tmp/plaso.dump",
               image_path]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        elapsed = round(time.time() - start, 2)
        data = self.parse(r.stdout)
        log_tool_call("extract_mft_timeline", elapsed,
                      f"{data['event_count']} timeline events")
        return ToolResult("extract_mft_timeline", r.returncode == 0,
                          data, r.stderr or None, elapsed)

    def parse(self, raw: str) -> dict:
        lines = [l for l in raw.strip().split("\n") if l]
        events = []
        for line in lines[:100]:
            parts = line.split(",")
            if len(parts) >= 3:
                events.append({
                    "timestamp": parts[0].strip(),
                    "source": parts[1].strip(),
                    "description": parts[2].strip()
                })
        return {"event_count": len(lines), "timeline": events}


class PrefetchTool(BaseSIFTTool):
    """Wraps Volatility windows.cmdline — extracts recently executed programs."""

    async def run(self, image_path: str, **kwargs) -> ToolResult:
        if not self.validate(image_path):
            return ToolResult("analyze_prefetch", False, {},
                              error=f"File not found: {image_path}")
        start = time.time()
        cmd = ["vol", "-f", image_path, "windows.cmdline.CmdLine"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        elapsed = round(time.time() - start, 2)
        data = self.parse(r.stdout)
        log_tool_call("analyze_prefetch", elapsed,
                      f"{len(data['executables'])} executables found")
        return ToolResult("analyze_prefetch", r.returncode == 0,
                          data, r.stderr or None, elapsed)

    def parse(self, raw: str) -> dict:
        lines = [l for l in raw.strip().split("\n") if l and not l.startswith("*")]
        executables = []
        for line in lines[2:]:
            parts = line.split()
            if len(parts) >= 2:
                executables.append({"pid": parts[0], "name": parts[1]})
        return {"executables": executables, "count": len(executables)}


class PersistenceTool(BaseSIFTTool):
    """Wraps RegRipper — checks registry for persistence mechanisms."""

    async def run(self, image_path: str, **kwargs) -> ToolResult:
        if not self.validate(image_path):
            return ToolResult("check_persistence", False, {},
                              error=f"File not found: {image_path}")
        start = time.time()
        cmd = ["rip.pl", "-r", image_path, "-f", "system"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        elapsed = round(time.time() - start, 2)
        data = self.parse(r.stdout)
        log_tool_call("check_persistence", elapsed,
                      f"{data['count']} persistence keys found")
        return ToolResult("check_persistence", r.returncode == 0,
                          data, r.stderr or None, elapsed)

    def parse(self, raw: str) -> dict:
        return parse_persistence(raw)