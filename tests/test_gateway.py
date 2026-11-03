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
    s = Settings(primary="deepseek", deepseek_url="https://upstream.test", deepseek_key="sk-owner-secret", deepseek_model="deepseek-flash",
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
        if body.get("tool_choice") == {"type": "tool", "name": "json"}:   # JSON mode -> forced tool call
            content = [{"type": "tool_use", "id": "t1", "name": "json", "input": {"answer": {"ok": 2}}}]   # wrapped once
        else:
            content = [{"type": "text", "text": 'Here you go:\n{"ok": 2}\nDone.'}]
        return httpx.Response(200, json={"id": "msg_1", "model": "claude-haiku-5-5", "stop_reason": "end_turn",
                                         "content": content, "usage": {"input_tokens": 1000, "output_tokens": 2000}})
    return httpx.MockTransport(handler)


@pytest.mark.parametrize("deepseek_status", [402, 429, 503, "down"])
def test_fallback_to_anthropic_when_deepseek_fails(tmp_path, deepseek_status):
    calls = []
    s = Settings(primary="deepseek", deepseek_url="https://upstream.test", deepseek_key="sk-owner", deepseek_model="deepseek-flash", admin_secret=ADMIN,
                 db_path=str(tmp_path / "g.db"), anthropic_url="https://anthropic.test", anthropic_key="sk-ant-owner")
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
    assert ant["body"]["max_tokens"] == 3000 and ant["body"]["tools"][0]["name"] == "json"
    assert ant["body"]["thinking"] == {"type": "disabled"} and "function" not in json.dumps(ant["body"]["tools"])
    assert "secret" not in r.text                                              # DeepSeek's error body never leaks
    st = client.get("/v1/admin/stats", headers={"authorization": f"Bearer {ADMIN}"}).json()["allowance"]
    assert st["by_model"] == [{"model": "claude-haiku-5-5", "requests": 1, "usd": round(1000 / 1e6 * 0.10 + 2000 / 1e6 * 0.50, 4)}]
    assert st["requests_today"] == 1


def test_no_fallback_without_a_key_and_none_when_deepseek_works(tmp_path):
    calls = []
    s = Settings(primary="deepseek", deepseek_url="https://upstream.test", deepseek_key="sk-owner", deepseek_model="deepseek-flash", admin_secret=ADMIN,
                 db_path=str(tmp_path / "g.db"), anthropic_key="")
    client = TestClient(create_app(s, transport=_two_upstreams(402, calls)))
    tok = client.post("/v1/tokens", json={"label": "t"}, headers={"authorization": f"Bearer {ADMIN}"}).json()["token"]
    r = chat(client, tok)
    assert r.status_code == 502 and r.json()["error"]["type"] == "upstream_error"
    assert [c["host"] for c in calls] == ["upstream.test"]
    assert client.get("/v1/health").json()["fallback"] is None
    # DeepSeek healthy: the fallback is never touched even when configured
    calls2 = []
    s2 = Settings(primary="deepseek", deepseek_url="https://upstream.test", deepseek_key="sk-owner", deepseek_model="deepseek-flash", admin_secret=ADMIN,
                  db_path=str(tmp_path / "g2.db"), anthropic_key="sk-ant-owner")
    client2 = TestClient(create_app(s2, transport=upstream(calls2)))
    tok2 = client2.post("/v1/tokens", json={"label": "t"}, headers={"authorization": f"Bearer {ADMIN}"}).json()["token"]
    r2 = chat(client2, tok2)
    assert r2.status_code == 200 and r2.headers["x-lantern-model"] == "deepseek-flash" and len(calls2) == 1
    assert client2.get("/v1/health").json()["fallback"] == "claude-haiku-5-5"


def test_default_order_is_anthropic_first_then_deepseek(tmp_path):
    calls = []
    s = Settings(anthropic_url="https://anthropic.test", anthropic_key="sk-ant-owner",
                 deepseek_url="https://upstream.test", deepseek_key="sk-owner", admin_secret=ADMIN, db_path=str(tmp_path / "g.db"))
    assert s.primary == "anthropic" and [p["name"] for p in s.order()] == ["anthropic", "deepseek"]
    assert s.model == "claude-haiku-5-5"
    client = TestClient(create_app(s, transport=_two_upstreams(402, calls)))   # DeepSeek would fail, Anthropic answers
    from lantern_gateway import __version__
    assert client.get("/v1/health").json() == {"ok": True, "version": __version__, "model": "claude-haiku-5-5",
                                               "configured": True, "primary": "anthropic", "fallback": "deepseek-flash"}
    tok = client.post("/v1/tokens", json={"label": "t"}, headers={"authorization": f"Bearer {ADMIN}"}).json()["token"]
    r = chat(client, tok)
    assert r.status_code == 200 and r.headers["x-lantern-model"] == "claude-haiku-5-5"
    assert [c["host"] for c in calls] == ["anthropic.test"]          # DeepSeek never touched
    # Anthropic down -> DeepSeek answers (here DeepSeek is the healthy OpenAI-shaped fake)
    calls2 = []
    def both(request):
        calls2.append(request.url.host)
        if request.url.host == "anthropic.test":
            return httpx.Response(400, json={"type": "error", "error": {"type": "invalid_request_error",
                                             "message": "Your credit balance is too low to access the Anthropic API."}})
        return upstream([]).handler(request)
    client2 = TestClient(create_app(s, transport=httpx.MockTransport(both)))
    tok2 = client2.post("/v1/tokens", json={"label": "t"}, headers={"authorization": f"Bearer {ADMIN}"}).json()["token"]
    r2 = chat(client2, tok2)
    assert r2.status_code == 200 and r2.headers["x-lantern-model"] == "deepseek-flash" and calls2 == ["anthropic.test", "upstream.test"]
    assert "credit balance" not in r2.text


def test_health_names_version_and_model_but_no_counters(tmp_path):
    import tomllib
    from pathlib import Path as _P
    from lantern_gateway import __version__
    assert __version__ == tomllib.loads((_P(__file__).parents[1] / "gateway/pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    s = Settings(anthropic_key="sk-ant-owner", admin_secret=ADMIN, db_path=str(tmp_path / "g.db"))
    client = TestClient(create_app(s))
    tok = client.post("/v1/tokens", json={"label": "t"}, headers={"authorization": f"Bearer {ADMIN}"}).json()["token"]
    assert tok
    h = client.get("/v1/health").json()
    assert set(h) == {"ok", "version", "model", "configured", "primary", "fallback"}
    assert h["version"] == __version__ and h["model"] == "claude-haiku-5-5"
    assert not any(w in json.dumps(h) for w in ("used", "usd", "spend", "requests", "tokens", "users"))


def test_retention_deletes_idle_hashes_and_old_counters(tmp_path):
    import datetime as dt
    import sqlite3

    from lantern_gateway.app import Store, _hash
    db = str(tmp_path / "r.db")
    st = Store(db)
    old_tok, new_tok = st.mint("old"), st.mint("new")
    acct_tok = st.sign_in("github:1", "idle")
    rotated = st.sign_in("github:2", "busy")
    st.sign_in("github:2", "busy")                       # rotates: the first hash is disabled now
    st.record(_hash(new_tok), "2026-11-03", 10, 0.01, "m")
    st.record_usage("a" * 32, "2026-11-03", "0.9", "linux", {"analyze": 1})
    long_ago = "2026-07-01T00:00:00+00:00"
    st.db.execute("update users set last_used = ? where token_hash in (?, ?)", (long_ago, _hash(old_tok), _hash(acct_tok)))
    st.db.execute("update users set last_used = ? where token_hash = ?", (long_ago, _hash(rotated)))
    for day in ("2026-07-01", "2026-08-05"):          # 125 and 90 days before 2026-11-03
        st.record(_hash(new_tok), day, 1, 0.001, "m")
    st.record_usage("b" * 32, "2026-07-01", "0.8", "mac", {"analyze": 2})
    st.db.execute("update installs set last_seen = ? where install = ?", (long_ago, "b" * 32))
    st.db.commit()

    out = st.prune("2026-11-03", 90)
    assert out["token_hashes"] == 3                   # two idle tokens and the rotated-out hash
    assert out["spend"] == 1 and out["models"] == 1 and out["usage"] == 1 and out["installs"] == 1
    assert st.user(old_tok) is None and st.user(acct_tok) is None and st.user(rotated) is None
    assert st.user(new_tok)["used_requests"] == 3      # lifetime counter kept while the token is in use
    days = [r[0] for r in st.db.execute("select day from daily order by day")]
    assert days == ["2026-08-05", "2026-11-03"]        # exactly 90 days old is kept
    assert [r[0] for r in st.db.execute("select account from accounts")] == ["github:2"]
    assert st.prune("2026-11-03", 0) == {}             # 0 keeps everything

    # A later sign-in on the deleted account starts fresh; the busy account still carries its counters.
    again = st.sign_in("github:1", "idle")
    assert st.user(again)["used_requests"] == 0
    # The column is added to a database created before it existed.
    legacy = sqlite3.connect(str(tmp_path / "legacy.db"))
    legacy.execute("create table users (token_hash text primary key, label text, created text, "
                   "used_requests integer default 0, used_tokens integer default 0, disabled integer default 0)")
    legacy.execute("insert into users (token_hash, created) values ('h', ?)", (dt.datetime.now(dt.UTC).isoformat(),))
    legacy.commit()
    legacy.close()
    st2 = Store(str(tmp_path / "legacy.db"))
    assert st2.prune(dt.datetime.now(dt.UTC).date().isoformat(), 90)["token_hashes"] == 0   # falls back to created


def test_gateway_prunes_once_a_day(gw):
    client, tok, _, s = gw
    store = client.app.state.store
    assert s.retention_days == 90 and store.pruned_day      # ran at start-up
    store.pruned_day = "2000-01-01"
    chat(client, tok)
    assert store.pruned_day != "2000-01-01"                 # and again on the first request of a new day
