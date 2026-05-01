import os, json, requests
from abc import ABC, abstractmethod
from dotenv import load_dotenv
load_dotenv()


class LLMBackend(ABC):
    @abstractmethod
    def complete(self, system: str, user: str) -> str:
        pass

    @abstractmethod
    def stream(self, system: str, user: str):
        pass


class OllamaBackend(LLMBackend):
    """Offline backend — Phi-3 via Ollama. Zero data leaves the machine."""

    def __init__(self):
        self.base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.model = os.getenv("OLLAMA_MODEL", "phi3:mini")
        print(f"[LLM] Mode: OFFLINE — {self.model} via Ollama (air-gap safe)")

    def _build_prompt(self, system: str, user: str) -> str:
        return f"<|system|>\n{system}\n<|user|>\n{user}\n<|assistant|>"

    def complete(self, system: str, user: str) -> str:
        payload = {
            "model": self.model,
            "prompt": self._build_prompt(system, user),
            "stream": False,
            "options": {"temperature": 0.1, "num_ctx": 4096}
        }
        try:
            r = requests.post(f"{self.base_url}/api/generate",
                json=payload, timeout=600)
            return r.json().get("response", "")
        except requests.exceptions.ConnectionError:
            return "[ERROR] Ollama not running. Start with: ollama serve"
        except requests.exceptions.ReadTimeout:
            return "[ERROR] Phi-3 timed out."

    def stream(self, system: str, user: str):
        payload = {
            "model": self.model,
            "prompt": self._build_prompt(system, user),
            "stream": True,
            "options": {"temperature": 0.1, "num_ctx": 4096}
        }
        try:
            with requests.post(f"{self.base_url}/api/generate",
                    json=payload, stream=True, timeout=600) as r:
                for line in r.iter_lines():
                    if line:
                        chunk = json.loads(line)
                        yield chunk.get("response", "")
                        if chunk.get("done"):
                            break
        except requests.exceptions.ConnectionError:
            yield "[ERROR] Ollama not running. Start with: ollama serve"
        except requests.exceptions.ReadTimeout:
            yield "[ERROR] Phi-3 timed out."


class ClaudeBackend(LLMBackend):
    """Cloud backend — Claude Haiku via Anthropic API."""

    def __init__(self):
        import anthropic
        self.client = anthropic.Anthropic()
        self.model = "claude-haiku-4-5-20251001"
        print(f"[LLM] Mode: CLOUD — {self.model} via Anthropic API")

    def complete(self, system: str, user: str) -> str:
        r = self.client.messages.create(
            model=self.model, max_tokens=4096,
            system=system,
            messages=[{"role": "user", "content": user}]
        )
        return r.content[0].text

    def stream(self, system: str, user: str):
        with self.client.messages.stream(
            model=self.model, max_tokens=4096,
            system=system,
            messages=[{"role": "user", "content": user}]
        ) as s:
            yield from s.text_stream


class GroqBackend(LLMBackend):
    """Free cloud backend — Groq API. No credit card required."""

    def __init__(self):
        from groq import Groq
        self.client = Groq(api_key=os.getenv("GROQ_API_KEY"))
        self.model = "llama-3.3-70b-versatile"
        print(f"[LLM] Mode: GROQ — {self.model} via Groq API (free)")

    def complete(self, system: str, user: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            temperature=0.1,
            max_tokens=4096
        )
        return response.choices[0].message.content

    def stream(self, system: str, user: str):
        stream = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            temperature=0.1,
            max_tokens=4096,
            stream=True
        )
        for chunk in stream:
            content = chunk.choices[0].delta.content
            if content:
                yield content


class GeminiBackend(LLMBackend):
    """Free cloud backend — Google Gemini API. No credit card required."""

    def __init__(self):
        import google.generativeai as genai
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        self.model = genai.GenerativeModel("gemini-2.0-flash")
        print(f"[LLM] Mode: GEMINI — gemini-2.0-flash via Google AI (free)")

    def complete(self, system: str, user: str) -> str:
        response = self.model.generate_content(f"{system}\n\n{user}")
        return response.text

    def stream(self, system: str, user: str):
        response = self.model.generate_content(
            f"{system}\n\n{user}", stream=True)
        for chunk in response:
            if chunk.text:
                yield chunk.text


def get_backend() -> LLMBackend:
    """
    Factory — reads LLM_MODE from .env
    offline → Phi-3 via Ollama (default, air-gap safe)
    cloud   → Claude Haiku via Anthropic API
    groq    → Llama 3.3 70B via Groq (free, fast)
    gemini  → Gemini 2.0 Flash via Google AI (free)
    """
    mode = os.getenv("LLM_MODE", "offline").lower()
    if mode == "cloud":
        return ClaudeBackend()
    elif mode == "groq":
        return GroqBackend()
    elif mode == "gemini":
        return GeminiBackend()
    return OllamaBackend()
