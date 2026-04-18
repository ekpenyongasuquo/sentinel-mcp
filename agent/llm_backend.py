import os
import json
import requests
from abc import ABC, abstractmethod
from dotenv import load_dotenv

load_dotenv()


class LLMBackend(ABC):
    """
    Abstract LLM backend.
    Swap between Phi-3 (offline) and Claude (cloud) with one env variable.
    Both backends receive identical prompts and return identical response format.
    To add a third backend: subclass this and implement complete() and stream().
    """

    @abstractmethod
    def complete(self, system: str, user: str) -> str:
        """Send system + user prompt. Return full response text."""
        pass

    @abstractmethod
    def stream(self, system: str, user: str):
        """Stream response tokens. Yields str chunks."""
        pass


class OllamaBackend(LLMBackend):
    """
    Offline backend — Phi-3 via Ollama.
    Zero forensic data leaves the machine. Air-gap safe.
    """

    def __init__(self):
        self.base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.model = os.getenv("OLLAMA_MODEL", "phi3:mini")
        print(f"[LLM] Mode: OFFLINE — {self.model} via Ollama (air-gap safe)")

    def _build_prompt(self, system: str, user: str) -> str:
        return (
            f"<|system|>\n{system}\n"
            f"<|user|>\n{user}\n"
            f"<|assistant|>"
        )

    def complete(self, system: str, user: str) -> str:
        payload = {
            "model": self.model,
            "prompt": self._build_prompt(system, user),
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_ctx": 8192
            }
        }
        try:
            r = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=300
            )
            return r.json().get("response", "")
        except requests.exceptions.ConnectionError:
            return "[ERROR] Ollama not running. Start with: ollama serve"

    def stream(self, system: str, user: str):
        payload = {
            "model": self.model,
            "prompt": self._build_prompt(system, user),
            "stream": True,
            "options": {
                "temperature": 0.1,
                "num_ctx": 8192
            }
        }
        try:
            with requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                stream=True,
                timeout=300
            ) as r:
                for line in r.iter_lines():
                    if line:
                        chunk = json.loads(line)
                        yield chunk.get("response", "")
                        if chunk.get("done"):
                            break
        except requests.exceptions.ConnectionError:
            yield "[ERROR] Ollama not running. Start with: ollama serve"


class ClaudeBackend(LLMBackend):
    """
    Cloud backend — Claude API via Anthropic.
    Maximum reasoning quality. Requires ANTHROPIC_API_KEY in .env
    """

    def __init__(self):
        import anthropic
        self.client = anthropic.Anthropic()
        self.model = "claude-opus-4-5"
        print(f"[LLM] Mode: CLOUD — {self.model} via Anthropic API")

    def complete(self, system: str, user: str) -> str:
        r = self.client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=system,
            messages=[{"role": "user", "content": user}]
        )
        return r.content[0].text

    def stream(self, system: str, user: str):
        with self.client.messages.stream(
            model=self.model,
            max_tokens=4096,
            system=system,
            messages=[{"role": "user", "content": user}]
        ) as s:
            yield from s.text_stream


def get_backend() -> LLMBackend:
    """
    Factory function — reads LLM_MODE from .env and returns correct backend.
    LLM_MODE=offline  → OllamaBackend (default, privacy-first)
    LLM_MODE=cloud    → ClaudeBackend
    """
    mode = os.getenv("LLM_MODE", "offline").lower()
    if mode == "cloud":
        return ClaudeBackend()
    return OllamaBackend()