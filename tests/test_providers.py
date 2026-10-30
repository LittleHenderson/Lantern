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
