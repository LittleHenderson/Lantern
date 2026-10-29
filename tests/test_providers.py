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
