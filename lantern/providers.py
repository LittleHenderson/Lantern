"""Model providers. Bring your own key; nothing here is hosted by Lantern.

Three adapters cover nearly every provider:
  * anthropic       - Anthropic Messages API
  * openai          - any OpenAI-compatible /chat/completions endpoint: OpenAI, OpenRouter,
                      Mistral, Google's OpenAI-compatible endpoint, Ollama, vLLM, LM Studio, llama.cpp
  * fixture         - offline stub used by tests and `--dry-run` style experiments

Keys come from environment variables, or from `lantern serve` Settings (kept in memory, or in
~/.lantern/keys.json with mode 0600 only when the user ticks "remember").
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable

PRESETS = {
    # name: (adapter, base_url, env var for key)
    "anthropic": ("anthropic", "https://api.anthropic.com", "ANTHROPIC_API_KEY"),
    "openai": ("openai", "https://api.openai.com/v1", "OPENAI_API_KEY"),
    "openrouter": ("openai", "https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
    "mistral": ("openai", "https://api.mistral.ai/v1", "MISTRAL_API_KEY"),
    "gemini": ("openai", "https://generativelanguage.googleapis.com/v1beta/openai", "GEMINI_API_KEY"),
    "ollama": ("openai", "http://localhost:11434/v1", None),
    "lmstudio": ("openai", "http://localhost:1234/v1", None),
}


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0


class ProviderError(RuntimeError):
    pass


class Provider:
    name = "base"

    def __init__(self, model: str):
        self.model = model
        self.usage = Usage()

    @property
    def label(self) -> str:
        return f"{self.name}/{self.model}"

    def complete(self, system: str, user: str, max_tokens: int = 2000) -> str:  # pragma: no cover
        raise NotImplementedError


def _post(url: str, headers: dict, body: dict, timeout: int = 120, retries: int = 3) -> dict:
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise ProviderError(f"refusing non-HTTP URL: {url}")
    data = json.dumps(body).encode()
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, headers={"content-type": "application/json", **headers})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310: scheme checked above
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:500]
            if e.code in (429, 500, 502, 503, 529) and attempt < retries - 1:
                time.sleep(2 ** attempt * 2)
                continue
            raise ProviderError(f"HTTP {e.code} from {url}: {detail}") from None
        except urllib.error.URLError as e:
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
                continue
            raise ProviderError(f"cannot reach {url}: {e.reason}") from None
    raise ProviderError("unreachable")


class AnthropicProvider(Provider):
    name = "anthropic"

    def __init__(self, model: str, api_key: str, base_url: str = "https://api.anthropic.com"):
        super().__init__(model)
        self.api_key, self.base_url = api_key, base_url.rstrip("/")

    def complete(self, system: str, user: str, max_tokens: int = 2000) -> str:
        d = _post(f"{self.base_url}/v1/messages",
                  {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
                  {"model": self.model, "max_tokens": max_tokens, "system": system,
                   "messages": [{"role": "user", "content": user}]})
        u = d.get("usage", {})
        self.usage.input_tokens += u.get("input_tokens", 0)
        self.usage.output_tokens += u.get("output_tokens", 0)
        return "".join(b.get("text", "") for b in d.get("content", []) if b.get("type") == "text")


class OpenAICompatProvider(Provider):
    name = "openai"

    def __init__(self, model: str, base_url: str, api_key: str | None = None, label: str = "openai"):
        super().__init__(model)
        self.base_url, self.api_key, self.name = base_url.rstrip("/"), api_key, label

    def complete(self, system: str, user: str, max_tokens: int = 2000) -> str:
        headers = {"authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        body = {"model": self.model, "max_tokens": max_tokens,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "response_format": {"type": "json_object"}}
        try:
            d = _post(f"{self.base_url}/chat/completions", headers, body)
        except ProviderError as e:
            if "response_format" not in str(e):
                raise
            body.pop("response_format")  # some local servers reject it
            d = _post(f"{self.base_url}/chat/completions", headers, body)
        u = d.get("usage") or {}
        self.usage.input_tokens += u.get("prompt_tokens", 0)
        self.usage.output_tokens += u.get("completion_tokens", 0)
        return d["choices"][0]["message"]["content"] or ""


class FixtureProvider(Provider):
    """Offline provider: `respond(system, user) -> str`. Used by tests and demos."""
    name = "fixture"

    def __init__(self, respond: Callable[[str, str], str], model: str = "stub"):
        super().__init__(model)
        self.respond = respond
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str, max_tokens: int = 2000) -> str:
        self.calls.append((system, user))
        self.usage.input_tokens += (len(system) + len(user)) // 4
        out = self.respond(system, user)
        self.usage.output_tokens += len(out) // 4
        return out


def make_provider(spec: str, base_url: str | None = None, api_key: str | None = None) -> Provider:
    """spec is "preset/model", e.g. "anthropic/claude-sonnet-4-5", "ollama/llama3.1",
    "openrouter/meta-llama/llama-3.1-70b-instruct", or "openai-compatible/<model>" with base_url."""
    preset, _, model = spec.partition("/")
    if not model:
        raise ValueError("use PROVIDER/MODEL, e.g. anthropic/<model-name> or ollama/<model-name>")
    if preset == "openai-compatible":
        if not base_url:
            raise ValueError("openai-compatible needs --base-url")
        return OpenAICompatProvider(model, base_url, api_key or os.environ.get("LANTERN_API_KEY"),
                                    label="openai-compatible")
    if preset not in PRESETS:
        raise ValueError(f"unknown provider '{preset}'. Known: {', '.join(PRESETS)} or openai-compatible")
    adapter, default_url, env = PRESETS[preset]
    key = api_key or (os.environ.get(env) if env else None)
    if env and not key:
        raise ValueError(f"set {env} to use {preset}")
    if adapter == "anthropic":
        return AnthropicProvider(model, key, base_url or default_url)
    return OpenAICompatProvider(model, base_url or default_url, key, label=preset)
