"""Cloud service, milestone 6: plain-words explanations and Ask Lantern through the person's own free allowance.

A real gateway runs on a local port (its model is a fake DeepSeek), so the explanations go the whole way: the
worker copies the repository again at the run's commit, `lantern explain` runs in the restricted process with the
person's token, the report is rebuilt, and the copy is deleted. Nothing reaches a model before the person agrees.
"""

import json
import os
import re
import sqlite3
import sys
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")
uvicorn = pytest.importorskip("uvicorn")
if os.name != "posix":
    pytest.skip("the cloud worker runs on Linux (its restricted process is POSIX)", allow_module_level=True)

from test_allowance_flow import free_port, good_answer  # noqa: E402
from test_cloud_runs import LINK, SOURCE_LINE, bearer, clone_from, origin, wait, workdir  # noqa: E402,F401
from fastapi.testclient import TestClient  # noqa: E402
from lantern_cloud import worker as worker_mod  # noqa: E402
from lantern_cloud.app import create_app  # noqa: E402
from lantern_cloud.settings import Settings  # noqa: E402
from lantern_gateway.app import Settings as GwSettings  # noqa: E402
from lantern_gateway.app import create_app as create_gateway  # noqa: E402

INVENTED = "deadbeef0000"


def fake_model(sent):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        sent.append(body)
        system, user = body["messages"][0]["content"], body["messages"][-1]["content"]
        if system.startswith("Pick ONE"):
            content = '{"world": "a hotel"}'
        elif "QUESTION:" in user:
            ids = re.findall(r"\[([0-9a-f]{12})\]", user)
            content = json.dumps({"answer": f"Fix [{ids[0]}] first, then [{INVENTED}]." if ids else "Lantern maps your app."})
        else:
            content = good_answer(user)
        return httpx.Response(200, json={"choices": [{"index": 0, "message": {"role": "assistant", "content": content}}],
                                         "usage": {"prompt_tokens": 50, "completion_tokens": 50}})
    return httpx.MockTransport(handler)


def live_gateway(tmp_path, free_requests=500):
    sent = []
    gw = create_gateway(GwSettings(primary="deepseek", deepseek_url="https://api.deepseek.test", deepseek_key="sk-owner",
                                   admin_secret="a" * 24, db_path=str(tmp_path / "gw.db"), free_requests=free_requests,
                                   free_tokens=10**8, daily_requests=10**4), transport=fake_model(sent))
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(gw, host="127.0.0.1", port=port, log_level="error"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.05)
    return gw, f"http://127.0.0.1:{port}/v1", sent, server, th


@pytest.fixture
def env(tmp_path, clone_from):  # noqa: F811
    gw, url, sent, server, th = live_gateway(tmp_path)
    s = Settings(gateway_url=url, public_url="http://testserver", db_path=str(tmp_path / "cloud.db"),
                 results_dir=str(tmp_path / "results"), work_dir=workdir(tmp_path), audits=False)
    app = create_app(s)
    cloud = TestClient(app)
    tok = gw.state.store.sign_in("github:1", "github:octo")
    yield cloud, tok, s, sent, app
    server.should_exit = True
    th.join(timeout=5)


def done_run(cloud, tok):
    rid = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()["id"]
    assert wait(cloud, tok, rid)["status"] == "done"
    return rid


def wait_explain(cloud, tok, rid, timeout=180):
    end = time.time() + timeout
    while time.time() < end:
        r = cloud.get(f"/v1/runs/{rid}", headers=bearer(tok)).json()
        if r["explain"]["status"] not in ("queued", "running"):
            return r
        time.sleep(0.4)
    raise AssertionError("explanations did not finish")


def test_nothing_goes_to_a_model_before_the_person_agrees(env):
    cloud, tok, s, sent, _ = env
    st = cloud.get("/v1/ai", headers=bearer(tok)).json()
    assert st["consent"] is False and "Anthropic" in st["notice"] and "DeepSeek" in st["notice"]
    assert st["allowance"]["remaining_requests"] == 500
    rid = done_run(cloud, tok)
    for r in (cloud.post(f"/v1/runs/{rid}/explain", headers=bearer(tok)),
              cloud.post("/v1/ask", json={"question": "what is this?"}, headers=bearer(tok))):
        assert r.status_code == 412 and r.json()["error"]["type"] == "consent_needed"
        assert "DeepSeek" in r.json()["error"]["message"]
    assert sent == []
    assert cloud.post("/v1/ai/consent", json={"agree": "yes"}, headers=bearer(tok)).status_code == 400
    assert cloud.post("/v1/ai/consent", json={"agree": True}, headers=bearer(tok)).json()["consent"] is True
    assert cloud.get("/v1/ai", headers=bearer(tok)).json()["consent"] is True
    # changing one's mind turns it off again
    cloud.post("/v1/ai/consent", json={"agree": False}, headers=bearer(tok))
    assert cloud.post("/v1/ask", json={"question": "x"}, headers=bearer(tok)).status_code == 412
    # a cookie request needs the website's header, like every other change
    c = TestClient(env[4])
    c.cookies.set("lt", tok)
    assert c.post("/v1/ai/consent", json={"agree": True}).status_code == 403


def test_explain_a_finished_run_with_the_allowance(env):
    cloud, tok, s, sent, _ = env
    rid = done_run(cloud, tok)
    before = cloud.get(f"/v1/runs/{rid}", headers=bearer(tok)).json()
    assert before["explain"] == {"status": None, "error": None, "summary": None, "log": ""}
    cloud.post("/v1/ai/consent", json={"agree": True}, headers=bearer(tok))
    r = cloud.post(f"/v1/runs/{rid}/explain", headers=bearer(tok))
    assert r.status_code == 202 and r.json()["explain"]["status"] in ("queued", "running")
    done = wait_explain(cloud, tok, rid)
    ex = done["explain"]
    assert ex["status"] == "done", ex
    assert ex["summary"]["validated"] >= 3 and ex["summary"]["functions"] >= ex["summary"]["validated"]
    assert ex["summary"]["stopped"] is None
    res = Path(s.results_dir) / rid
    exps = json.loads((res / "explanations.json").read_text(encoding="utf-8"))["explanations"]
    assert any(v.get("validated") for v in exps.values())
    html = (res / "report.html").read_text(encoding="utf-8")
    assert "Like a waiter." in html                       # the report was rebuilt with the explanations...
    assert SOURCE_LINE not in html                        # ...at the privacy chosen before the run (no code kept)
    assert json.loads((res / "run.json").read_text(encoding="utf-8"))["privacy"] == "structure"
    assert json.loads((res / "graph.json").read_text(encoding="utf-8"))["repo_root"] != ""   # the stored map is untouched
    assert list(Path(s.work_dir).iterdir()) == []           # the second copy of the repository is gone too
    assert done["log_tail"] == before["log_tail"]           # the run's own log stays as it was
    # the model saw the code (that is what the person agreed to); the token never reached the database
    assert sent and any("SOURCE:" in b["messages"][-1]["content"] for b in sent)
    assert tok not in Path(s.db_path).read_bytes().decode("latin-1")
    # explaining again does not pay twice for the same functions (the cache is kept with the results)
    n = len(sent)
    cloud.post(f"/v1/runs/{rid}/explain", headers=bearer(tok))
    assert wait_explain(cloud, tok, rid)["explain"]["status"] == "done" and len(sent) == n


def test_explain_refuses_when_the_repository_moved_on(env, monkeypatch):
    cloud, tok, s, sent, _ = env
    rid = done_run(cloud, tok)
    cloud.post("/v1/ai/consent", json={"agree": True}, headers=bearer(tok))
    monkeypatch.setattr(worker_mod, "_commit", lambda repo: "f" * 40)
    cloud.post(f"/v1/runs/{rid}/explain", headers=bearer(tok))
    ex = wait_explain(cloud, tok, rid)["explain"]
    assert ex["status"] == "error" and "has changed since this check" in ex["error"]
    assert not (Path(s.results_dir) / rid / "explanations.json").exists() and sent == []
    assert list(Path(s.work_dir).iterdir()) == []


def test_explain_only_for_the_owner_and_finished_runs_and_once_at_a_time(env):
    cloud, tok, s, sent, app = env
    rid = done_run(cloud, tok)
    assert cloud.post("/v1/ai/consent", json={"agree": True}, headers=bearer(tok)).status_code == 200
    store = app.state.store
    assert store.queue_explain(rid) and not store.queue_explain(rid)      # a second click while queued is refused
    r = cloud.post(f"/v1/runs/{rid}/explain", headers=bearer(tok))
    assert r.status_code == 409 and "already writing" in r.json()["error"]["message"]
    # deleting waits for the explanations
    assert cloud.delete(f"/v1/runs/{rid}", headers=bearer(tok)).status_code == 409
    assert cloud.delete("/v1/me", headers=bearer(tok)).status_code == 409
    store.update_run(rid, explain_status=None)
    assert cloud.delete(f"/v1/runs/{rid}", headers=bearer(tok)).status_code == 200


def test_a_restart_reports_explanations_that_were_waiting(env):
    cloud, tok, s, sent, app = env
    rid = done_run(cloud, tok)
    app.state.store.queue_explain(rid)
    app.state.worker.shutdown()
    worker_mod.Worker(s, app.state.store)       # a new process: the token was only in the old one's memory
    ex = cloud.get(f"/v1/runs/{rid}", headers=bearer(tok)).json()["explain"]
    assert ex["status"] == "error" and "Click Explain again" in ex["error"]


def test_ask_lantern_answers_from_the_runs_facts(env):
    cloud, tok, s, sent, _ = env
    rid = done_run(cloud, tok)
    cloud.post("/v1/ai/consent", json={"agree": True}, headers=bearer(tok))
    r = cloud.post("/v1/ask", json={"run": rid, "question": "What should I fix first?",
                                    "focus": {"finding": "x" * 999, "node": 5}}, headers=bearer(tok))
    assert r.status_code == 200, r.text
    a = r.json()
    assert a["cited"] and a["cited"][0] in a["answer"]
    assert "[unknown finding]" in a["answer"] and INVENTED not in a["answer"] and a["invented"] == 1
    prompt = sent[-1]["messages"][-1]["content"]
    assert "FACTS for project 'shop'" in prompt and "QUESTION: What should I fix first?" in prompt
    assert SOURCE_LINE not in prompt                      # facts from the results, never the code
    # with no run, it answers about Lantern itself
    assert cloud.post("/v1/ask", json={"question": "What is Lantern?"}, headers=bearer(tok)).json()["answer"]
    assert "no project is selected" in sent[-1]["messages"][-1]["content"]
    # a run that is not theirs, an empty question
    assert cloud.post("/v1/ask", json={"run": "nope", "question": "x"}, headers=bearer(tok)).status_code == 404
    assert cloud.post("/v1/ask", json={"question": "  "}, headers=bearer(tok)).status_code == 400


def test_a_used_up_allowance_is_said_plainly(tmp_path):
    gw, url, sent, server, th = live_gateway(tmp_path, free_requests=1)
    try:
        s = Settings(gateway_url=url, db_path=str(tmp_path / "c.db"), results_dir=str(tmp_path / "r"),
                     work_dir=str(tmp_path / "w"), audits=False)
        cloud = TestClient(create_app(s, start_worker=False))
        tok = gw.state.store.sign_in("github:1", "github:octo")
        cloud.post("/v1/ai/consent", json={"agree": True}, headers=bearer(tok))
        assert cloud.post("/v1/ask", json={"question": "hi"}, headers=bearer(tok)).status_code == 200
        r = cloud.post("/v1/ask", json={"question": "hi again"}, headers=bearer(tok))
        assert r.status_code == 402 and r.json()["error"]["type"] == "allowance"
        assert "used up" in r.json()["error"]["message"]
        assert cloud.get("/v1/ai", headers=bearer(tok)).json()["allowance"]["remaining_requests"] == 0
    finally:
        server.should_exit = True
        th.join(timeout=5)


def test_delete_me_forgets_the_consent_too(env):
    cloud, tok, s, sent, _ = env
    cloud.post("/v1/ai/consent", json={"agree": True}, headers=bearer(tok))
    assert cloud.delete("/v1/me", headers=bearer(tok)).status_code == 200
    db = sqlite3.connect(s.db_path)
    assert db.execute("select count(*) from users where ai_consent is not null").fetchone()[0] == 0
    db.close()
    assert cloud.get("/v1/ai", headers=bearer(tok)).json()["consent"] is False    # signing in again: asked again


def _multipart(data: bytes, name="shot.png", ctype="image/png"):
    b = "----lantern" + os.urandom(8).hex()
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
            f"Content-Type: {ctype}\r\n\r\n").encode() + data + f"\r\n--{b}--\r\n".encode()
    return body, {"content-type": f"multipart/form-data; boundary={b}"}


def test_ask_reads_a_screenshots_text_like_the_app(env):
    PIL = pytest.importorskip("PIL")  # noqa: F841
    import shutil as _sh
    from test_ocr import KNOWN, _png
    cloud, tok, s, sent, app = env
    body, h = _multipart(_png())
    assert TestClient(app).post("/v1/ask/screenshot", content=body, headers=h).status_code == 401
    c = TestClient(app)
    c.cookies.set("lt", tok)
    assert c.post("/v1/ask/screenshot", content=body, headers=h).status_code == 403       # not from Lantern's page
    r = c.post("/v1/ask/screenshot", content=body, headers={**h, "x-lantern-site": "1"})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["width"] == 900 and j["format"] == "PNG"
    if _sh.which("tesseract"):
        assert "4821" in j["text"] and KNOWN.split()[0] in j["text"].upper()
    else:
        assert j["text"] is None and j["how"] is None and "cannot read text" in j["reason"]
    assert sent == []                                  # reading a screenshot never involves the model
    # not an image, too many pixels, too large
    bad, h2 = _multipart(b"<svg onload=alert(1)>", "x.svg", "image/svg+xml")
    assert cloud.post("/v1/ask/screenshot", content=bad, headers={**h2, **bearer(tok)}).status_code == 400
    big, h3 = _multipart(_png(size=(9000, 5000)))
    r = cloud.post("/v1/ask/screenshot", content=big, headers={**h3, **bearer(tok)})
    assert r.status_code == 400 and "too large" in r.json()["error"]["message"]
    huge, h4 = _multipart(b"\x89PNG" + b"0" * (9 * 1024 * 1024))
    assert cloud.post("/v1/ask/screenshot", content=huge, headers={**h4, **bearer(tok)}).status_code == 413
