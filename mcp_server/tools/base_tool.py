from abc import ABC, abstractmethod
from dataclasses import dataclass
import time
import os


@dataclass
class ToolResult:
    tool_name: str
    success: bool
    data: dict
    error: str | None = None
    execution_time_seconds: float = 0.0


class BaseSIFTTool(ABC):
    """
    Abstract base class for all SIFT tool wrappers.
    To add a new tool: subclass this, implement run() and parse().
    The validate() method is provided free — use it in every run().
    """

    @abstractmethod
    async def run(self, image_path: str, **kwargs) -> ToolResult:
        """Execute the underlying SIFT tool. Return structured ToolResult."""
        pass

    @abstractmethod
    def parse(self, raw_output: str) -> dict:
        """
        Convert raw SIFT tool output to structured dict.
        NEVER return raw text — always parse before returning.
        """
        pass

    def validate(self, path: str) -> bool:
        """Shared path validation — all subclasses get this for free."""
        return os.path.exists(path) and os.path.isfile(path)