import pytest

from lantern.providers import ProviderError, _post, make_provider


def test_rejects_non_http_urls():
    with pytest.raises(ProviderError):
        _post("file:///etc/passwd", {}, {})


def test_make_provider_requires_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
        make_provider("anthropic/some-model")


def test_local_providers_need_no_key():
    p = make_provider("ollama/llama3.1")
    assert p.base_url == "http://localhost:11434/v1" and p.api_key is None


def test_openai_compatible_needs_base_url():
    with pytest.raises(ValueError):
        make_provider("openai-compatible/x")
    p = make_provider("openai-compatible/x", base_url="http://localhost:8000/v1")
    assert p.label == "openai-compatible/x"


def test_deepseek_preset(monkeypatch):
    import json
    from lantern import providers
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    with pytest.raises(ValueError, match="DEEPSEEK_API_KEY"):
        providers.make_provider("deepseek/deepseek-chat")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k")
    p = providers.make_provider("deepseek/deepseek-chat")
    assert p.label == "deepseek/deepseek-chat" and p.base_url == "https://api.deepseek.com/v1"
    seen = {}

    def fake_post(url, headers, body, timeout=120, retries=3):
        seen.update(url=url, auth=headers.get("authorization"), model=body["model"])
        return {"choices": [{"message": {"content": json.dumps({"ok": 1})}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5}}
    monkeypatch.setattr(providers, "_post", fake_post)
    assert json.loads(p.complete("s", "u")) == {"ok": 1}
    assert seen == {"url": "https://api.deepseek.com/v1/chat/completions", "auth": "Bearer k", "model": "deepseek-chat"}
    assert p.usage.input_tokens == 10


def test_deepseek_is_default_with_own_key(monkeypatch):
    from lantern.providers import resolve_default
    monkeypatch.delenv("LANTERN_MODEL", raising=False)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-x")
    assert resolve_default()[0] == "deepseek/deepseek-flash"
    assert resolve_default("ollama/llama3")[0] == "ollama/llama3"            # --model wins
    monkeypatch.setenv("LANTERN_MODEL", "gemini/x")
    assert resolve_default()[0] == "gemini/x"


def test_deepseek_request_shape():
    from lantern.providers import make_provider
    p = make_provider("deepseek/deepseek-flash", api_key="sk-x")
    body = p._body("sys json", "user", 100)
    assert body["thinking"] == {"type": "disabled"} and body["response_format"] == {"type": "json_object"}


def test_consent_asked_once_and_never_for_local(tmp_path, monkeypatch, capsys):
    from lantern.providers import ensure_consent, has_consent, make_provider
    monkeypatch.setenv("LANTERN_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("LANTERN_ACCEPT_DATA_SHARING", raising=False)
    assert ensure_consent(make_provider("ollama/llama3")) is True              # local: no prompt
    ds = make_provider("deepseek/deepseek-flash", api_key="sk-x")
    assert ensure_consent(ds) is False                                          # non-interactive, no --yes
    assert "People's Republic of China" in capsys.readouterr().err
    assert ensure_consent(ds, assume_yes=True) is True and has_consent("deepseek")
    assert ensure_consent(ds) is True                                           # remembered


def test_hosted_402_raises_allowance_exhausted(monkeypatch):
    import lantern.providers as P
    p = P.LanternHostedProvider("lt_x", "https://gw.test/v1")

    def boom(*a, **k):
        raise P.ProviderError("HTTP 402", status=402, body='{"error": {"type": "quota_exceeded", "message": "Used up."}}')
    monkeypatch.setattr(P, "_post_full", boom)
    with pytest.raises(P.AllowanceExhausted, match="DEEPSEEK_API_KEY"):
        p.complete("s", "u")


def test_localhost_endpoints_never_ask_for_consent(tmp_path, monkeypatch):
    from lantern.providers import ensure_consent, make_provider
    monkeypatch.setenv("LANTERN_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("LANTERN_ACCEPT_DATA_SHARING", raising=False)
    assert ensure_consent(make_provider("openai-compatible/demo", base_url="http://127.0.0.1:9/v1")) is True
    assert ensure_consent(make_provider("openai-compatible/demo", base_url="https://example.com/v1")) is False
