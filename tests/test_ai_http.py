"""Model calls made by plain web requests to a model provider's address (lantern/aiapp.py, `http_model_calls`).

Each file that is read as making such calls stands beside twins that must not be: the address only in a remark,
a request in a file that names no provider, an address on a page that links to the provider's documentation."""
from lantern import aiapp
from lantern.engine import build_graph
from lantern.security import _ai_status, scan


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


TABLE = '''import json
import urllib.request

ENDPOINTS = {"claude": "https://api.anthropic.com/v1/messages", "gpt": "https://api.openai.com/v1/chat/completions"}


def ask(which, prompt, key):
    body = json.dumps({"prompt": prompt}).encode()
    req = urllib.request.Request(ENDPOINTS[which], data=body, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())
'''
JS = '''export async function ask(prompt) {
  const r = await fetch("https://api.deepseek.com/chat/completions", { method: "POST", body: JSON.stringify({ prompt }) });
  return r.json();
}
'''


def test_requests_in_a_file_that_names_a_provider_are_model_calls(tmp_path):
    _write(tmp_path, {"app/llm.py": TABLE, "web/ask.js": JS})
    sec = scan(build_graph(tmp_path))
    ai = sec["ai"]
    http = [c for c in ai["calls"] if c.get("how") == "http"]
    assert {(c["file"], c["line"]) for c in http} == {("app/llm.py", 9), ("app/llm.py", 10), ("web/ask.js", 2)}
    assert {c["provider"] for c in http} == {"Anthropic, OpenAI", "DeepSeek"}
    assert ai["is_ai_app"] and ai["by_http"] == 3
    assert "py:app.llm.ask" in ai["by_node"]
    status = next(t["status"] for t in sec["tools"] if t["tool"] == "lantern-ai")
    assert "3 plain web requests" in status and "no model" not in status
    assert not any(f["rule"].startswith("LA-") for f in sec["findings"])    # listed, not used by the paid-call rules


def test_twins_are_no_model_calls(tmp_path):
    _write(tmp_path, {
        "a.py": "# we used to call https://api.openai.com/v1 here\nimport requests\n\ndef get(u):\n    return requests.get(u)\n",
        "b.py": "import requests\n\ndef get():\n    return requests.get('https://example.com/data')\n",
        "c.py": "DOCS = 'https://api.openai.com/docs'\n\ndef link():\n    return DOCS\n",
    })
    ai = scan(build_graph(tmp_path))["ai"]
    assert [c for c in ai["calls"] if c.get("how") == "http"] == []
    assert ai["hosts_named_only"] == ["c.py"]       # names the address and makes no request: said, not counted


def test_the_record_says_what_it_did_not_see():
    assert "would not show" in _ai_status({"calls": []})
    said = _ai_status({"calls": [], "hosts_named_only_count": 2})
    assert "2 files name a model provider's address" in said and "may be made elsewhere" in said
    lib = _ai_status({"calls": [{"kind": "model"}]})
    assert "1 call through a provider's library" in lib


def test_a_host_inside_a_longer_name_is_none():
    assert not aiapp.HOST.search("https://notapi.openai.com/x")
    assert not aiapp.HOST.search("https://api.openai.com.evil.example/x")
    assert not aiapp.HOST.search("myapi.anthropic.company")
    assert aiapp.HOST.search("see https://api.openai.com.").group(1) == "api.openai.com"
    assert aiapp.HOST.search("'https://api.anthropic.com/v1'").group(1) == "api.anthropic.com"
