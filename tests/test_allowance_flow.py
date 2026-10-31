"""End to end: free allowance through a real local gateway, clean stop at the limit, then the
user's own DeepSeek key picks up where the allowance stopped without re-paying for cached work."""

import json
import re
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")
uvicorn = pytest.importorskip("uvicorn")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "gateway"))
from lantern_gateway.app import Settings, create_app  # noqa: E402

from lantern import providers  # noqa: E402
from lantern.engine import build_graph  # noqa: E402
from lantern.explain import run, select_nodes  # noqa: E402
from lantern.security import scan  # noqa: E402

FIX = Path(__file__).parent / "fixtures" / "shop"
ADMIN = "admin-" + "y" * 20


def good_answer(user: str) -> str:
    unit = re.search(r"^UNIT: (\S+)", user, re.M).group(1)
    lo, hi = map(int, re.search(r"lines (\d+)-(\d+)", user).groups())
    sym = re.search(r"ALLOWED SYMBOLS.*?\n\s+((?:py|js):\S+)", user, re.S).group(1)
    fids = re.findall(r"id=([0-9a-f]{12})", user)
    text = "The helper takes a request, checks it, and hands back an answer."
    return json.dumps({
        "lens1": {"summary": f"{unit} works.", "inputs": [], "outputs": "x", "side_effects": [], "errors": [], "role": "r"},
        "lens2": {"text": text, "example": "Ask for soup, get soup.", "analogy": "Like a waiter."},
        "lens3": {"text": text, "pairs": [
            {"plain": "The helper", "technical": unit, "anchor": {"type": "symbol", "id": sym}},
            {"plain": "takes a request", "technical": "args", "anchor": {"type": "term", "term": "argument"}},
            {"plain": "hands back an answer", "technical": "return", "anchor": {"type": "lines", "start": lo, "end": hi}}]},
        "findings": [{"id": f, "lens1": "a", "lens2": "b", "fix": "c"} for f in fids]})


def fake_deepseek(log):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        log.append(body)
        system, user = body["messages"][0]["content"], body["messages"][-1]["content"]
        content = '{"world": "a hotel"}' if system.startswith("Pick ONE") else good_answer(user)
        return httpx.Response(200, json={"choices": [{"index": 0, "message": {"role": "assistant", "content": content}}],
                                         "usage": {"prompt_tokens": 500, "completion_tokens": 500}})
    return httpx.MockTransport(handler)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture
def gateway(tmp_path):
    log = []
    settings = Settings(upstream_url="https://api.deepseek.test", upstream_key="sk-owner", admin_secret=ADMIN,
                        db_path=str(tmp_path / "gw.db"), free_requests=4, free_tokens=10**7, daily_requests=50)
    app = create_app(settings, transport=fake_deepseek(log))
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    url = f"http://127.0.0.1:{port}/v1"
    tok = httpx.post(f"{url}/tokens", json={"label": "t"}, headers={"authorization": f"Bearer {ADMIN}"}).json()["token"]
    yield url, tok, log
    server.should_exit = True
    th.join(timeout=5)


def test_free_allowance_then_own_key(gateway, tmp_path, monkeypatch):
    url, tok, log = gateway
    monkeypatch.setenv("LANTERN_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("LANTERN_GATEWAY_URL", url)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("LANTERN_TOKEN", raising=False)
    monkeypatch.delenv("LANTERN_MODEL", raising=False)

    with pytest.raises(ValueError, match="No model is set up"):
        providers.resolve_default()
    providers.save_token(tok)
    spec, why = providers.resolve_default()
    assert spec == "lantern/deepseek-flash" and "allowance" in why

    g = build_graph(FIX)
    findings = scan(g)["findings"]
    nids = select_nodes(g)
    assert len(nids) > 3
    hosted = providers.make_provider(spec)
    res = run(g, hosted, findings, tmp_path / "cache", nids, metaphor="a hotel")
    st = res["stats"]
    assert st["generated"] == 4 and st["validated"] == 4          # 4 free requests, then stop
    assert "free Lantern allowance" in st["stopped"] and "DEEPSEEK_API_KEY" in st["stopped"]
    assert hosted.remaining["requests"] == "0"
    assert providers.allowance_status()["remaining_requests"] == 0
    assert all(b["model"] == "deepseek-flash" for b in log)

    # The user adds their own key; the default switches to it and cached work isn't re-billed.
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-user")
    spec2, why2 = providers.resolve_default()
    assert spec2 == "deepseek/deepseek-flash" and "your DeepSeek key" in why2
    own = providers.make_provider(spec2)
    sent = []

    def fake_send(body):
        sent.append(body)
        user = body["messages"][-1]["content"]
        return {"choices": [{"message": {"content": good_answer(user)}}], "usage": {}}, {}
    monkeypatch.setattr(own, "_send", fake_send)
    res2 = run(g, own, findings, tmp_path / "cache", nids, metaphor="a hotel")
    assert res2["stats"]["cached"] == 4 and res2["stats"]["generated"] == len(nids) - 4
    assert res2["stats"]["stopped"] is None
    assert sent and all(b["thinking"] == {"type": "disabled"} and b["response_format"] == {"type": "json_object"}
                        for b in sent)
