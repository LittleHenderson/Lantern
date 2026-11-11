"""Cloud service, milestone 6: plain-words explanations and Ask Lantern through the person's own free allowance.

A real gateway runs on a local port (its model is a fake DeepSeek), so the explanations go the whole way: the
worker copies the repository again at the run's commit, `lantern explain` runs in the restricted process with the
person's token, the report is rebuilt, and the copy is deleted. Nothing reaches a model before the person agrees.
"""

import json
import os
import re
import shutil
import sqlite3
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
from test_cloud_runs import (LINK, SOURCE_LINE, bearer, clone_from, holds, left_by_a_step, origin,  # noqa: E402,F401
                             wait, workdir)
from fastapi.testclient import TestClient  # noqa: E402
from lantern_cloud import worker as worker_mod  # noqa: E402
from lantern_cloud.app import create_app  # noqa: E402
from lantern_cloud.settings import Settings  # noqa: E402
from lantern_gateway.app import Settings as GwSettings  # noqa: E402
from lantern_gateway.app import create_app as create_gateway  # noqa: E402

INVENTED = "deadbeef0000"
SECRET = "KEPT-FROM-EVERY-RUN-7351"


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


def test_explanations_that_cannot_be_saved_change_nothing(env, monkeypatch):
    """The rewritten pages are put in place only when every one of them has been written: a save that fails half-way
    leaves the explanations, the report and the evidence page as they were, and nothing half-written beside them.
    Until 2026-11-10 the first two files were already replaced when the third could not be written, and the person
    was told "Nothing was changed"."""
    cloud, tok, s, sent, _ = env
    rid = done_run(cloud, tok)
    res = Path(s.results_dir) / rid

    def pages():
        return {n: (res / n).read_bytes() if (res / n).is_file() else None for n in worker_mod.EXPLAINED_FILES}
    before = pages()
    assert before["report.html"] and before["evidence.html"]
    cloud.post("/v1/ai/consent", json={"agree": True}, headers=bearer(tok))
    real, real_obj = shutil.copyfile, shutil.copyfileobj

    def third_page(dst) -> bool:                                               # the third of the four pages
        return Path(str(dst)).parent == res and "evidence.html" in Path(str(dst)).name

    def full_disk(src, dst, *a, **kw):
        if third_page(dst):
            raise OSError(28, "No space left on device")
        return real(src, dst, *a, **kw)

    def full_disk_obj(src, to, *a, **kw):          # the same disk, for a page written through an open file
        if third_page(getattr(to, "name", "")):
            raise OSError(28, "No space left on device")
        return real_obj(src, to, *a, **kw)
    monkeypatch.setattr(shutil, "copyfile", full_disk)
    monkeypatch.setattr(shutil, "copyfileobj", full_disk_obj)
    cloud.post(f"/v1/runs/{rid}/explain", headers=bearer(tok))
    ex = wait_explain(cloud, tok, rid)["explain"]
    assert ex["status"] == "error" and "Nothing was changed" in ex["error"], ex
    assert pages() == before, "a page was replaced although the save failed"
    assert [p.name for p in res.iterdir() if p.name.endswith(".new")] == []
    # the safe twin: with the disk well again, the same click writes them all
    monkeypatch.setattr(shutil, "copyfile", real)
    monkeypatch.setattr(shutil, "copyfileobj", real_obj)
    cloud.post(f"/v1/runs/{rid}/explain", headers=bearer(tok))
    assert wait_explain(cloud, tok, rid)["explain"]["status"] == "done"
    after = pages()
    assert after["explanations.json"] and after["report.html"] != before["report.html"]
    assert [p.name for p in res.iterdir() if p.name.endswith(".new")] == []


@pytest.mark.parametrize("where,what,how", [("out/cache/planted.json", "planted.json", "link"),
                                            ("out/report.html", "report.html", "link"),
                                            ("out/explanations.json", "explanations.json", "second name"),
                                            ("out/cache", "cache", "link"),
                                            ("out", "", "link")],
                         ids=["a link in the cache", "a page is a link", "a page has a second name",
                              "the cache folder is a link", "the whole folder is a link"])
def test_explanations_never_bring_a_linked_file_into_the_results(env, monkeypatch, tmp_path, where, what, how):
    """The step that writes explanations has the network and fewer rights than the service. Only plain files of its
    own folder are taken: a link it leaves, among the pages or in the cache folder, is never followed, and a file
    with a second name somewhere else is not read. Until 2026-11-10 the file a link pointed at was copied into the
    run's results."""
    cloud, tok, s, sent, _ = env
    rid = done_run(cloud, tok)
    res = Path(s.results_dir) / rid
    before = {n: (res / n).read_bytes() if (res / n).is_file() else None for n in worker_mod.EXPLAINED_FILES}
    other = tmp_path / "elsewhere"
    (other / "cache").mkdir(parents=True)
    for name in (*worker_mod.EXPLAINED_FILES, "planted.json", "cache/0123456789abcdef01234567.json"):
        (other / name).write_text(json.dumps({"stats": {}, "explanations": {}, "secret": SECRET}), encoding="utf-8")
    real = left_by_a_step(monkeypatch, "explain", where, other / what if what else other, how)
    cloud.post("/v1/ai/consent", json={"agree": True}, headers=bearer(tok))
    cloud.post(f"/v1/runs/{rid}/explain", headers=bearer(tok))
    ex = wait_explain(cloud, tok, rid)["explain"]
    assert holds(res, SECRET) == [], "a file outside the run is in its results"
    assert ex["status"] == "error" and "not a plain file" in ex["error"] and "nothing was changed" in ex["error"], ex
    assert {n: (res / n).read_bytes() if (res / n).is_file() else None for n in worker_mod.EXPLAINED_FILES} == before
    assert not (res / "cache").exists() and [q.name for q in res.iterdir() if q.name.endswith(".new")] == []
    if where == "out/report.html":       # the safe twin: the same click without the link writes the explanations
        monkeypatch.setattr(worker_mod.Worker, "_jailed", real)
        cloud.post(f"/v1/runs/{rid}/explain", headers=bearer(tok))
        assert wait_explain(cloud, tok, rid)["explain"]["status"] == "done"
        assert (res / "explanations.json").is_file() and list((res / "cache").glob("*.json"))


def test_explanations_stopped_at_the_time_limit_keep_what_was_written(env, monkeypatch):
    """The message at the time limit says "The ones already written are kept; click Explain again to go on". They
    are: each explanation is saved as it is written, and those files are kept with the run, so the next try does not
    pay for them again. Until 2026-11-10 they were thrown away with the work folder while the message said so, and
    every new try paid for the same explanations again."""
    cloud, tok, s, sent, _ = env
    rid = done_run(cloud, tok)
    res = Path(s.results_dir) / rid
    before = {n: (res / n).read_bytes() if (res / n).is_file() else None for n in worker_mod.EXPLAINED_FILES}
    real = worker_mod.Worker._jailed

    def out_of_time(self, key, root, cmd, **kw):
        rc, output, _ = real(self, key, root, cmd, **kw)                        # the step writes what it writes,
        for name in worker_mod.EXPLAINED_FILES:                                 # but for its pages,
            (root / "tmp" / "out" / name).unlink(missing_ok=True)
        return None, output, True                                               # when it is stopped at the time limit
    monkeypatch.setattr(worker_mod.Worker, "_jailed", out_of_time)
    cloud.post("/v1/ai/consent", json={"agree": True}, headers=bearer(tok))
    cloud.post(f"/v1/runs/{rid}/explain", headers=bearer(tok))
    ex = wait_explain(cloud, tok, rid)["explain"]
    assert ex["status"] == "error" and "was stopped" in ex["error"] and "already written are kept" in ex["error"], ex
    kept = sorted(q.name for q in (res / "cache").glob("*.json"))
    paid = len([b for b in sent if not b["messages"][0]["content"].startswith("Pick ONE")])
    assert kept and len(kept) == paid, (kept, paid)
    assert {n: (res / n).read_bytes() if (res / n).is_file() else None for n in worker_mod.EXPLAINED_FILES} == before
    # the next try goes on from there: no explanation that was kept is asked for (and paid for) again
    monkeypatch.setattr(worker_mod.Worker, "_jailed", real)
    cloud.post(f"/v1/runs/{rid}/explain", headers=bearer(tok))
    ex = wait_explain(cloud, tok, rid)["explain"]
    assert ex["status"] == "done" and ex["summary"]["validated"] == len(kept), ex
    assert len([b for b in sent if not b["messages"][0]["content"].startswith("Pick ONE")]) == paid


def test_at_the_time_limit_a_planted_link_is_not_followed_either(env, monkeypatch, tmp_path):
    """Stopped at the time limit with a link in the cache folder: nothing of that folder is kept, and the message
    does not say that anything was."""
    cloud, tok, s, sent, _ = env
    rid = done_run(cloud, tok)
    res = Path(s.results_dir) / rid
    secret = tmp_path / "not-a-result.json"
    secret.write_text(json.dumps({"secret": SECRET}), encoding="utf-8")

    def out_of_time(self, key, root, cmd, **kw):
        cache = root / "tmp" / "out" / "cache"
        cache.mkdir(parents=True, exist_ok=True)
        (cache / "0123456789abcdef01234567.json").write_text('{"written": "before the time limit"}', encoding="utf-8")
        os.symlink(secret, cache / "planted.json")
        return None, "", True
    monkeypatch.setattr(worker_mod.Worker, "_jailed", out_of_time)
    cloud.post("/v1/ai/consent", json={"agree": True}, headers=bearer(tok))
    cloud.post(f"/v1/runs/{rid}/explain", headers=bearer(tok))
    ex = wait_explain(cloud, tok, rid)["explain"]
    assert ex["status"] == "error" and "was stopped" in ex["error"] and "kept" not in ex["error"], ex
    assert holds(res, SECRET) == [] and not (res / "cache").exists()
    assert list(Path(s.work_dir).iterdir()) == []


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


def refusing_gateway(tmp_path, upstream_status):
    """A live gateway whose model company always answers `upstream_status` (a dead key, no credit, an outage)."""
    gw = create_gateway(GwSettings(primary="deepseek", deepseek_url="https://api.deepseek.test", deepseek_key="sk-owner",
                                   admin_secret="a" * 24, db_path=str(tmp_path / "gw.db")),
                        transport=httpx.MockTransport(lambda r: httpx.Response(upstream_status, json={"error": "no"})))
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(gw, host="127.0.0.1", port=port, log_level="error"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.05)
    return gw, f"http://127.0.0.1:{port}/v1", server, th


@pytest.mark.parametrize("upstream, words", [(401, "refused Lantern's key"), (402, "run out of credit")])
def test_ask_says_why_the_model_did_not_answer(tmp_path, upstream, words):
    gw, url, server, th = refusing_gateway(tmp_path, upstream)
    try:
        s = Settings(gateway_url=url, db_path=str(tmp_path / "c.db"), results_dir=str(tmp_path / "r"),
                     work_dir=str(tmp_path / "w"), audits=False)
        cloud = TestClient(create_app(s, start_worker=False))
        tok = gw.state.store.sign_in("github:1", "github:octo")
        cloud.post("/v1/ai/consent", json={"agree": True}, headers=bearer(tok))
        r = cloud.post("/v1/ask", json={"question": "what is this app about?"}, headers=bearer(tok))
        assert r.status_code == 503
        msg = r.json()["error"]["message"]
        assert words in msg and "Lantern's side" in msg and "did not answer" not in msg
    finally:
        server.should_exit = True
        th.join(timeout=5)


def test_ask_with_a_sign_in_the_gateway_dropped_asks_to_sign_in_again(tmp_path):
    gw, url, sent, server, th = live_gateway(tmp_path)
    try:
        s = Settings(gateway_url=url, db_path=str(tmp_path / "c.db"), results_dir=str(tmp_path / "r"),
                     work_dir=str(tmp_path / "w"), audits=False)
        cloud = TestClient(create_app(s, start_worker=False))
        store = gw.state.store
        tok = store.sign_in("github:1", "github:octo")
        cloud.post("/v1/ai/consent", json={"agree": True}, headers=bearer(tok))
        assert cloud.get("/v1/me", headers=bearer(tok)).status_code == 200    # "signed in" is now remembered
        store.db.execute("update users set disabled = 1 where token_hash = ?", (store.user(tok)["hash"],))
        store.db.commit()                                     # the gateway stops accepting it
        r = cloud.post("/v1/ask", json={"question": "hi"}, headers=bearer(tok))
        assert r.status_code == 401 and r.json()["error"]["type"] == "signed_out"
        assert "Sign in again" in r.json()["error"]["message"]
        assert cloud.get("/v1/me", headers=bearer(tok)).status_code == 401    # the remembered answer is dropped
    finally:
        server.should_exit = True
        th.join(timeout=5)
