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


def _two_upstreams(deepseek_status, calls):
    """DeepSeek answers with `deepseek_status`; Anthropic answers a Messages-API reply with prose around the JSON."""
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append({"host": request.url.host, "body": body, "headers": dict(request.headers)})
        if request.url.host == "upstream.test":
            if deepseek_status == "down":
                raise httpx.ConnectError("no route")
            return httpx.Response(deepseek_status, json={"error": {"message": "Insufficient Balance", "account": "secret"}})
        return httpx.Response(200, json={"id": "msg_1", "model": "claude-haiku-5-5", "stop_reason": "end_turn",
                                         "content": [{"type": "text", "text": 'Here you go:\n{"ok": 2}\nDone.'}],
                                         "usage": {"input_tokens": 1000, "output_tokens": 2000}})
    return httpx.MockTransport(handler)


@pytest.mark.parametrize("deepseek_status", [402, 429, 503, "down"])
def test_fallback_to_anthropic_when_deepseek_fails(tmp_path, deepseek_status):
    calls = []
    s = Settings(upstream_url="https://upstream.test", upstream_key="sk-owner", model="deepseek-flash", admin_secret=ADMIN,
                 db_path=str(tmp_path / "g.db"), fallback_url="https://anthropic.test", fallback_key="sk-ant-owner")
    client = TestClient(create_app(s, transport=_two_upstreams(deepseek_status, calls)))
    tok = client.post("/v1/tokens", json={"label": "t"}, headers={"authorization": f"Bearer {ADMIN}"}).json()["token"]
    r = chat(client, tok)
    assert r.status_code == 200, r.text
    assert r.json()["choices"][0]["message"]["content"] == '{"ok": 2}'     # prose trimmed, JSON kept
    assert r.json()["model"] == "claude-haiku-5-5" and r.headers["x-lantern-model"] == "claude-haiku-5-5"
    assert [c["host"] for c in calls] == ["upstream.test", "anthropic.test"]
    ant = calls[1]
    assert ant["headers"]["x-api-key"] == "sk-ant-owner" and "authorization" not in ant["headers"]
    assert ant["body"]["system"] == "json please" and ant["body"]["messages"] == [{"role": "user", "content": "explain f"}]
    assert ant["body"]["max_tokens"] == 3000 and "tools" not in ant["body"]
    assert "secret" not in r.text                                              # DeepSeek's error body never leaks
    st = client.get("/v1/admin/stats", headers={"authorization": f"Bearer {ADMIN}"}).json()["allowance"]
    assert st["by_model"] == [{"model": "claude-haiku-5-5", "requests": 1, "usd": round(1000 / 1e6 * 0.10 + 2000 / 1e6 * 0.50, 4)}]
    assert st["requests_today"] == 1


def test_no_fallback_without_a_key_and_none_when_deepseek_works(tmp_path):
    calls = []
    s = Settings(upstream_url="https://upstream.test", upstream_key="sk-owner", model="deepseek-flash", admin_secret=ADMIN,
                 db_path=str(tmp_path / "g.db"), fallback_key="")
    client = TestClient(create_app(s, transport=_two_upstreams(402, calls)))
    tok = client.post("/v1/tokens", json={"label": "t"}, headers={"authorization": f"Bearer {ADMIN}"}).json()["token"]
    r = chat(client, tok)
    assert r.status_code == 502 and r.json()["error"]["type"] == "upstream_error"
    assert [c["host"] for c in calls] == ["upstream.test"]
    assert client.get("/v1/health").json()["fallback"] is None
    # DeepSeek healthy: the fallback is never touched even when configured
    calls2 = []
    s2 = Settings(upstream_url="https://upstream.test", upstream_key="sk-owner", model="deepseek-flash", admin_secret=ADMIN,
                  db_path=str(tmp_path / "g2.db"), fallback_key="sk-ant-owner")
    client2 = TestClient(create_app(s2, transport=upstream(calls2)))
    tok2 = client2.post("/v1/tokens", json={"label": "t"}, headers={"authorization": f"Bearer {ADMIN}"}).json()["token"]
    r2 = chat(client2, tok2)
    assert r2.status_code == 200 and r2.headers["x-lantern-model"] == "deepseek-flash" and len(calls2) == 1
    assert client2.get("/v1/health").json()["fallback"] == "claude-haiku-5-5"
