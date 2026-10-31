import json

import pytest

fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "gateway"))
from fastapi.testclient import TestClient  # noqa: E402

from lantern_gateway.app import Settings, create_app  # noqa: E402

ADMIN = "admin-" + "x" * 20


def upstream(calls):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append({"auth": request.headers["authorization"], "body": body})
        return httpx.Response(200, json={
            "id": "c1", "model": body["model"],
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": '{"ok": 1}'}}],
            "usage": {"prompt_tokens": 700, "completion_tokens": 1100}})
    return httpx.MockTransport(handler)


@pytest.fixture
def gw(tmp_path):
    calls = []
    s = Settings(upstream_url="https://upstream.test", upstream_key="sk-owner-secret", model="deepseek-flash",
                 admin_secret=ADMIN, db_path=str(tmp_path / "g.db"), free_requests=3, free_tokens=10_000,
                 daily_requests=10, global_daily_usd=5.0)
    app = create_app(s, transport=upstream(calls))
    client = TestClient(app)
    tok = client.post("/v1/tokens", json={"label": "tester"}, headers={"authorization": f"Bearer {ADMIN}"}).json()["token"]
    return client, tok, calls, s


def chat(client, tok, **over):
    body = {"model": "anything", "max_tokens": 99999, "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": "json please"}, {"role": "user", "content": "explain f"}],
            "tools": [{"type": "function"}], **over}
    return client.post("/v1/chat/completions", json=body, headers={"authorization": f"Bearer {tok}"})


def test_minting_requires_admin(gw):
    client, *_ = gw
    assert client.post("/v1/tokens", json={}, headers={"authorization": "Bearer nope"}).status_code == 403
    assert client.post("/v1/tokens", json={}).status_code == 403


def test_proxy_narrows_request_and_hides_key(gw):
    client, tok, calls, _ = gw
    r = chat(client, tok)
    assert r.status_code == 200
    assert r.json()["choices"][0]["message"]["content"] == '{"ok": 1}'
    sent = calls[0]
    assert sent["auth"] == "Bearer sk-owner-secret"                     # server key goes upstream...
    assert "sk-owner-secret" not in r.text                              # ...never back to the client
    assert sent["body"]["model"] == "deepseek-flash"                    # client can't choose the model
    assert sent["body"]["max_tokens"] == 3000                           # capped
    assert "tools" not in sent["body"]                                  # extras dropped
    assert sent["body"]["thinking"] == {"type": "disabled"}
    assert r.headers["x-lantern-remaining-requests"] == "2"


def test_allowance_runs_out_with_402(gw):
    client, tok, _, _ = gw
    for _ in range(3):
        assert chat(client, tok).status_code == 200
    r = chat(client, tok)
    assert r.status_code == 402 and r.json()["error"]["type"] == "quota_exceeded"
    a = client.get("/v1/allowance", headers={"authorization": f"Bearer {tok}"}).json()
    assert a["remaining_requests"] == 0 and a["used_tokens"] == 5400


def test_global_daily_budget_pauses_everyone(gw):
    client, tok, _, s = gw
    s.global_daily_usd = 0.001    # one call (~$0.0015 at peak rates) exceeds it
    assert chat(client, tok).status_code == 200
    r = chat(client, tok)
    assert r.status_code == 503 and r.json()["error"]["type"] == "allowance_paused"


def test_rejects_bad_tokens_and_odd_payloads(gw):
    client, tok, _, _ = gw
    assert chat(client, "lt_wrong").status_code == 401
    assert chat(client, tok, messages=[{"role": "tool", "content": "x"}]).status_code == 400
    assert chat(client, tok, messages=[{"role": "user", "content": "x" * 300_000}]).status_code == 413


def test_store_keeps_no_code(gw, tmp_path):
    client, tok, _, s = gw
    chat(client, tok, messages=[{"role": "user", "content": "SECRET_SOURCE_CODE_MARKER"}])
    assert b"SECRET_SOURCE_CODE_MARKER" not in Path(s.db_path).read_bytes()
    assert tok.encode() not in Path(s.db_path).read_bytes()             # only the token's hash is stored
