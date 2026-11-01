"""Model providers.

Default: DeepSeek (`deepseek/deepseek-flash`). Two ways to use it:
  * your own key:  export DEEPSEEK_API_KEY=...        (no Lantern limit; you pay DeepSeek directly)
  * free allowance: `lantern login --token ...`        (calls go through the Lantern gateway, which
                    holds the project's DeepSeek key and meters each user; see gateway/)

Any other provider works too (bring your own key), including local models that keep code on your
machine. Three adapters cover nearly every provider:
  * anthropic       - Anthropic Messages API
  * openai          - any OpenAI-compatible /chat/completions endpoint: DeepSeek, OpenAI, OpenRouter,
                      Mistral, Google's OpenAI-compatible endpoint, Ollama, vLLM, LM Studio, llama.cpp
  * fixture         - offline stub used by tests and demos

Keys come from environment variables, or from `lantern serve` Settings (kept in memory, or in
~/.lantern/keys.json with mode 0600 only when the user ticks "remember"). The allowance token (not a
provider key) is stored in ~/.config/lantern/ by `lantern login`.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

DEFAULT_MODEL = "deepseek/deepseek-flash"

# Where the hosted free allowance lives. Set at release time once the gateway is deployed;
# LANTERN_GATEWAY_URL overrides it (self-hosting, staging, tests).
DEFAULT_GATEWAY_URL = ""

PRESETS = {
    # name: (adapter, base_url, env var for key)
    "deepseek": ("openai", "https://api.deepseek.com/v1", "DEEPSEEK_API_KEY"),
    "anthropic": ("anthropic", "https://api.anthropic.com", "ANTHROPIC_API_KEY"),
    "openai": ("openai", "https://api.openai.com/v1", "OPENAI_API_KEY"),
    "openrouter": ("openai", "https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
    "mistral": ("openai", "https://api.mistral.ai/v1", "MISTRAL_API_KEY"),
    "gemini": ("openai", "https://generativelanguage.googleapis.com/v1beta/openai", "GEMINI_API_KEY"),
    "ollama": ("openai", "http://localhost:11434/v1", None),
    "lmstudio": ("openai", "http://localhost:1234/v1", None),
}
# Extra request fields per provider. DeepSeek: thinking off (faster, cheaper; the validator does the checking).
EXTRA_BODY = {"deepseek": {"thinking": {"type": "disabled"}}}
LOCAL_PRESETS = {"ollama", "lmstudio"}

# Shown before code leaves the machine for the first time with a given provider.
DATA_NOTICES = {
    "deepseek": ("DeepSeek's privacy policy says it stores data on servers in the People's Republic of "
                 "China and may use inputs to improve its models."),
    "lantern": ("The free allowance runs on DeepSeek through the Lantern gateway. The gateway counts "
                "usage and does not store your code; DeepSeek's privacy policy says it stores data in "
                "the People's Republic of China and may use inputs to improve its models."),
}


def config_dir() -> Path:
    base = os.environ.get("LANTERN_CONFIG_DIR") or os.path.join(
        os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "lantern")
    return Path(base)


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0


class ProviderError(RuntimeError):
    def __init__(self, message: str, status: int | None = None, body: str = ""):
        super().__init__(message)
        self.status, self.body = status, body


class AllowanceExhausted(ProviderError):
    """The hosted free allowance is used up (or paused). Not retried; the run stops cleanly."""


ALLOWANCE_HELP = (
    "To keep going, use your own DeepSeek key (about $1-2 per 1,000 explanations):\n"
    "  1. create a key at https://platform.deepseek.com\n"
    "  2. export DEEPSEEK_API_KEY=sk-...\n"
    "  3. run the same command again; finished explanations are cached and not re-billed.\n"
    "Or choose any other provider with --model (e.g. ollama/<model> to stay fully local).")


class Provider:
    name = "base"
    local = False

    def __init__(self, model: str):
        self.model = model
        self.usage = Usage()

    @property
    def label(self) -> str:
        return f"{self.name}/{self.model}"

    def complete(self, system: str, user: str, max_tokens: int = 2000) -> str:  # pragma: no cover
        raise NotImplementedError


def _post(url: str, headers: dict, body: dict, timeout: int = 120, retries: int = 3) -> dict:
    """POST JSON; returns the parsed body."""
    return _post_full(url, headers, body, timeout=timeout, retries=retries)[0]


def _post_full(url: str, headers: dict, body: dict, timeout: int = 120, retries: int = 3,
               no_retry: tuple[int, ...] = ()) -> tuple[dict, dict]:
    """POST JSON; returns (parsed body, response headers)."""
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise ProviderError(f"refusing non-HTTP URL: {url}")
    data = json.dumps(body).encode()
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, headers={"content-type": "application/json", **headers})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310: scheme checked above
                return json.loads(resp.read()), dict(resp.headers.items())
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:800]
            if e.code in (429, 500, 502, 503, 529) and e.code not in no_retry and attempt < retries - 1:
                time.sleep(2 ** attempt * 2)
                continue
            raise ProviderError(f"HTTP {e.code} from {url}: {detail}", status=e.code, body=detail) from None
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

    def __init__(self, model: str, base_url: str, api_key: str | None = None, label: str = "openai",
                 extra_body: dict | None = None, local: bool = False):
        super().__init__(model)
        self.base_url, self.api_key, self.name = base_url.rstrip("/"), api_key, label
        self.extra_body = extra_body or {}
        self.local = local
        self.last_headers: dict = {}

    def _body(self, system: str, user: str, max_tokens: int) -> dict:
        return {"model": self.model, "max_tokens": max_tokens,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "response_format": {"type": "json_object"}, **self.extra_body}

    def _send(self, body: dict) -> tuple[dict, dict]:
        headers = {"authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        return _post(f"{self.base_url}/chat/completions", headers, body), {}

    def complete(self, system: str, user: str, max_tokens: int = 2000) -> str:
        body = self._body(system, user, max_tokens)
        try:
            d, self.last_headers = self._send(body)
        except ProviderError as e:
            if "response_format" not in str(e) and "thinking" not in str(e):
                raise
            body.pop("response_format", None)  # some local servers reject these fields
            body.pop("thinking", None)
            d, self.last_headers = self._send(body)
        u = d.get("usage") or {}
        self.usage.input_tokens += u.get("prompt_tokens", 0)
        self.usage.output_tokens += u.get("completion_tokens", 0)
        return d["choices"][0]["message"]["content"] or ""


class LanternHostedProvider(OpenAICompatProvider):
    """The free allowance: OpenAI-compatible calls to the Lantern gateway with a user token.

    The gateway, not this client, holds the DeepSeek key, picks the model, and enforces limits.
    When the allowance runs out it answers 402 and this raises AllowanceExhausted.
    """

    def __init__(self, token: str, gateway_url: str, model: str = "deepseek-flash"):
        super().__init__(model, gateway_url, token, label="lantern")

    def _send(self, body: dict) -> tuple[dict, dict]:
        try:
            return _post_full(f"{self.base_url}/chat/completions",
                              {"authorization": f"Bearer {self.api_key}"}, body, no_retry=(503,))
        except ProviderError as e:
            if e.status in (402, 503):
                try:
                    err = json.loads(e.body).get("error", {})
                except (ValueError, AttributeError):
                    err = {}
                if e.status == 402 or err.get("type") == "allowance_paused":
                    raise AllowanceExhausted(f"{err.get('message') or 'Free allowance used up.'}\n{ALLOWANCE_HELP}",
                                             status=e.status, body=e.body) from None
            if e.status == 401:
                raise ProviderError("The Lantern allowance token was not accepted. Run `lantern login` "
                                    "again, or use your own key (see `lantern explain --help`).",
                                    status=401) from None
            raise

    @property
    def cache_model(self) -> str:
        return f"deepseek/{self.model}"   # same model as using your own DeepSeek key

    @property
    def remaining(self) -> dict:
        h = {k.lower(): v for k, v in self.last_headers.items()}
        return {k: h.get(f"x-lantern-remaining-{k}") for k in ("requests", "tokens")}


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


# ------------------------------------------------------------------------------------------------
# Allowance token and gateway
# ------------------------------------------------------------------------------------------------

def gateway_url() -> str:
    return (os.environ.get("LANTERN_GATEWAY_URL") or DEFAULT_GATEWAY_URL).rstrip("/")


def load_token() -> str | None:
    tok = os.environ.get("LANTERN_TOKEN")
    if tok:
        return tok.strip()
    p = config_dir() / "token"
    return p.read_text(encoding="utf-8").strip() if p.exists() else None


def save_token(token: str) -> Path:
    d = config_dir()
    d.mkdir(parents=True, exist_ok=True)
    p = d / "token"
    p.write_text(token.strip() + "\n", encoding="utf-8")
    try:
        p.chmod(0o600)
    except OSError:
        pass
    return p


def allowance_status(token: str | None = None, url: str | None = None) -> dict:
    token, url = token or load_token(), url or gateway_url()
    if not token or not url:
        raise ProviderError("no allowance token or gateway configured")
    req = urllib.request.Request(f"{url}/allowance", headers={"authorization": f"Bearer {token}"})
    if urllib.parse.urlsplit(req.full_url).scheme not in ("http", "https"):
        raise ProviderError("refusing non-HTTP URL")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310: scheme checked above
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise ProviderError(f"HTTP {e.code} from gateway", status=e.code) from None
    except urllib.error.URLError as e:
        raise ProviderError(f"cannot reach gateway: {e.reason}") from None


# ------------------------------------------------------------------------------------------------
# Choosing a provider
# ------------------------------------------------------------------------------------------------

def make_provider(spec: str, base_url: str | None = None, api_key: str | None = None) -> Provider:
    """spec is "preset/model", e.g. "deepseek/deepseek-flash", "anthropic/<model>", "ollama/<model>",
    "openrouter/<vendor>/<model>", "lantern/deepseek-flash" (free allowance), or
    "openai-compatible/<model>" with base_url."""
    preset, _, model = spec.partition("/")
    if not model:
        raise ValueError("use PROVIDER/MODEL, e.g. deepseek/deepseek-flash or ollama/<model-name>")
    if preset == "lantern":
        token, url = api_key or load_token(), base_url or gateway_url()
        if not token:
            raise ValueError("no allowance token: run `lantern login --token <token>`, or set DEEPSEEK_API_KEY")
        if not url:
            raise ValueError("the hosted allowance isn't configured in this build; set LANTERN_GATEWAY_URL "
                             "or use your own key (DEEPSEEK_API_KEY)")
        return LanternHostedProvider(token, url, model)
    if preset == "openai-compatible":
        if not base_url:
            raise ValueError("openai-compatible needs --base-url")
        host = (urllib.parse.urlsplit(base_url).hostname or "").lower()
        return OpenAICompatProvider(model, base_url, api_key or os.environ.get("LANTERN_API_KEY"),
                                    label="openai-compatible",
                                    local=host in ("localhost", "127.0.0.1", "::1"))  # code stays on this machine
    if preset not in PRESETS:
        raise ValueError(f"unknown provider '{preset}'. Known: {', '.join(PRESETS)}, lantern, or openai-compatible")
    adapter, default_url, env = PRESETS[preset]
    extra = EXTRA_BODY.get(preset)
    key = api_key or (os.environ.get(env) if env else None)
    if env and not key:
        raise ValueError(f"set {env} to use {preset}")
    if adapter == "anthropic":
        return AnthropicProvider(model, key, base_url or default_url)
    url = base_url or default_url
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    return OpenAICompatProvider(model, url, key, label=preset, extra_body=extra,
                                local=preset in LOCAL_PRESETS or host in ("localhost", "127.0.0.1", "::1"))


def resolve_default(explicit: str | None = None) -> tuple[str, str]:
    """Pick the model spec when the user didn't pass --model. Returns (spec, reason).

    Order: --model > LANTERN_MODEL > your own DeepSeek key > free allowance token > setup help.
    """
    if explicit:
        return explicit, "chosen with --model"
    if os.environ.get("LANTERN_MODEL"):
        return os.environ["LANTERN_MODEL"], "from LANTERN_MODEL"
    if os.environ.get("DEEPSEEK_API_KEY"):
        return DEFAULT_MODEL, "default model, your DeepSeek key"
    if load_token():
        return "lantern/" + DEFAULT_MODEL.split("/", 1)[1], "default model, free Lantern allowance"
    raise ValueError(
        "No model is set up yet. Pick one:\n"
        "  free allowance:   lantern login --token <token>\n"
        "  your own key:     export DEEPSEEK_API_KEY=sk-...   (default model: deepseek-flash)\n"
        "  fully local:      lantern explain . --model ollama/<model>\n"
        "  any provider:     lantern explain . --model anthropic/<model>  (or openai/, gemini/, openrouter/...)")


# ------------------------------------------------------------------------------------------------
# Consent before code leaves the machine
# ------------------------------------------------------------------------------------------------

def _consent_file() -> Path:
    return config_dir() / "consent.json"


def has_consent(provider: str) -> bool:
    try:
        return provider in json.loads(_consent_file().read_text(encoding="utf-8")).get("providers", [])
    except (OSError, ValueError):
        return False


def record_consent(provider: str) -> None:
    p = _consent_file()
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    data["providers"] = sorted(set(data.get("providers", [])) | {provider})
    p.write_text(json.dumps(data, indent=1), encoding="utf-8")


def disclosure(provider: Provider) -> str:
    who = provider.name
    lines = [f"Lantern will send the source code of each function it explains to {who} "
             f"({provider.label}) to write the explanations."]
    if who in DATA_NOTICES:
        lines.append(DATA_NOTICES[who])
    lines.append("To keep code on this machine, use a local model instead: --model ollama/<model>.")
    return "\n".join(lines)


def ensure_consent(provider: Provider, assume_yes: bool = False, stream=None) -> bool:
    """Ask once per provider before source code is sent anywhere. Local models never ask."""
    if provider.local or isinstance(provider, FixtureProvider):
        return True
    if has_consent(provider.name) or os.environ.get("LANTERN_ACCEPT_DATA_SHARING") == "1":
        return True
    out = stream or sys.stderr
    print(disclosure(provider), file=out)
    if assume_yes:
        record_consent(provider.name)
        return True
    if not sys.stdin.isatty():
        print("Re-run with --yes (or set LANTERN_ACCEPT_DATA_SHARING=1) to agree.", file=out)
        return False
    ans = input("Continue? [y/N] ").strip().lower()
    if ans in ("y", "yes"):
        record_consent(provider.name)
        return True
    return False
