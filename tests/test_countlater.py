"""`LW-LIMIT-COUNTED-LATER`: a limit that is looked at before the work and counted after it.

A function that turns a request away with "payment required" or "too many requests" when a number says so, then
waits for something, and only then writes the use down, holds its limit for one request at a time: requests sent
at the same moment all read the number before any of them is counted. A heuristic (it reads the function's own
lines and does not know that the look and the count are about the same number), so each dangerous example stands
beside twins that must stay quiet.
"""
import time

from lantern import countlater
from lantern.engine import build_graph
from lantern.security import scan

RULE = "LW-LIMIT-COUNTED-LATER"

API_PY = '''from fastapi import FastAPI, HTTPException

from .store import limiter, lock, metrics, model, slow, store

app = FastAPI()


@app.post("/ask")
async def ask(user_id: str, text: str):
    if store.used(user_id) >= store.limit(user_id):
        raise HTTPException(status_code=402, detail="No credits left")
    answer = await model.complete(text)
    store.record(user_id, 1)
    return {"answer": answer}


@app.post("/ask-held")
async def ask_held(user_id: str, text: str):
    if not store.hold(user_id, 1):
        raise HTTPException(status_code=402, detail="No credits left")
    answer = await model.complete(text)
    return {"answer": answer}


@app.post("/ask-counted-first")
async def ask_counted_first(user_id: str, text: str):
    if store.used(user_id) >= store.limit(user_id):
        raise HTTPException(status_code=402, detail="No credits left")
    store.record(user_id, 1)
    answer = await model.complete(text)
    return {"answer": answer}


@app.post("/ask-one-at-a-time")
async def ask_one_at_a_time(user_id: str, text: str):
    async with lock:
        if store.used(user_id) >= store.limit(user_id):
            raise HTTPException(status_code=402, detail="No credits left")
        answer = await model.complete(text)
        store.record(user_id, 1)
    return {"answer": answer}


@app.post("/ask-too-long")
async def ask_too_long(text: str):
    if len(text) > 4000:
        raise HTTPException(status_code=429, detail="Too long, too often")
    answer = await model.complete(text)
    metrics.increment("asked")
    return {"answer": answer}


@app.post("/ask-signed-in")
async def ask_signed_in(user_id: str, text: str):
    if not store.knows(user_id):
        raise HTTPException(status_code=401, detail="Sign in first")
    answer = await model.complete(text)
    store.record(user_id, 1)
    return {"answer": answer}


@app.post("/count-only")
async def count_only(user_id: str):
    if store.used(user_id) >= store.limit(user_id):
        raise HTTPException(status_code=402, detail="No credits left")
    store.record(user_id, 1)
    return {"ok": True}


@app.post("/report")
async def report(sender: str, text: str):
    if not limiter.take("report", sender, 20, 3600):
        raise HTTPException(status_code=429, detail="Too many reports", headers=slow(limiter.wait(3600)))
    seen = await store.seen(sender)
    if seen is None:
        raise HTTPException(status_code=429, detail="Too many new senders", headers=slow(limiter.wait(86400)))
    store.record_usage(sender, text)
    return {"ok": True}
'''

WEB_PY = '''from flask import Flask, jsonify, request

from .accounts import client, current, db

app = Flask(__name__)


@app.post("/draw")
def draw():
    user = current()
    if user.credits <= 0:
        return jsonify(error="no credits"), 402
    image = client.images.generate(prompt=request.json["prompt"])
    user.credits -= 1
    db.session.commit()
    return jsonify(url=image.url)


@app.post("/draw-paid-first")
def draw_paid_first():
    user = current()
    if user.credits <= 0:
        return jsonify(error="no credits"), 402
    user.credits -= 1
    db.session.commit()
    image = client.images.generate(prompt=request.json["prompt"])
    return jsonify(url=image.url)
'''

SERVER_JS = '''const express = require('express');
const { db, openai, metrics } = require('./things');

const app = express();

async function ask(req, res) {
  const user = await db.user.findUnique({ where: { id: req.userId } });
  if (user.credits <= 0) {
    return res.status(402).json({ error: 'No credits left' });
  }
  const answer = await openai.chat.completions.create({ model: 'm', messages: req.body.messages });
  await db.user.update({ where: { id: user.id }, data: { credits: { decrement: 1 } } });
  res.json(answer);
}

async function askTakenFirst(req, res) {
  const took = await db.user.updateMany({
    where: { id: req.userId, credits: { gt: 0 } }, data: { credits: { decrement: 1 } } });
  if (took.count === 0) {
    return res.status(402).json({ error: 'No credits left' });
  }
  const answer = await openai.chat.completions.create({ model: 'm', messages: req.body.messages });
  res.json(answer);
}

async function askOften(req, res) {
  const seen = await db.visits.count({ where: { who: req.ip } });
  if (seen > 100) {
    return res.status(429).json({ error: 'Slow down' });
  }
  const answer = await openai.chat.completions.create({ model: 'm', messages: req.body.messages });
  await db.visits.create({ data: { who: req.ip } });
  res.json(answer);
}

async function askMeasured(req, res) {
  if (req.body.messages.length > 20) {
    return res.status(429).json({ error: 'Too many messages' });
  }
  const answer = await openai.chat.completions.create({ model: 'm', messages: req.body.messages });
  metrics.increment('asked');
  res.json(answer);
}

app.post('/api/ask', ask);
app.post('/api/ask-taken-first', askTakenFirst);
app.post('/api/ask-often', askOften);
app.post('/api/ask-measured', askMeasured);
'''


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def test_a_limit_counted_after_the_work_is_named_and_its_safe_twins_are_not(tmp_path):
    """Dangerous: the look, the awaited work (or a paid call), then the count. Safe twins: the count is the look
    itself (a hold), the count stands before the work, the three are under a lock, the count shares no name with
    the look, the refusal is no limit (401), nothing is waited for between the two, a count taken in one step
    with its own condition before the work, a visit written down by adding a row (no count the check knows: it
    says nothing there), and a limiter that takes one in the look itself (the false alarm of the first measurement,
    on Lantern's own gateway)."""
    _write(tmp_path, {"server/__init__.py": "", "server/api.py": API_PY, "server/web.py": WEB_PY,
                      "api/package.json": '{"dependencies": {"express": "^4.19.0"}}', "api/server.js": SERVER_JS})
    g = build_graph(tmp_path)
    all_of = scan(g)["findings"]
    found = sorted((f["file"], f["line"], f["snippet"]) for f in all_of if f["rule"] == RULE)
    assert found == [
        ("api/server.js", 8, "if (user.credits <= 0) {"),
        ("server/api.py", 10, "if store.used(user_id) >= store.limit(user_id):"),
        ("server/web.py", 11, "if user.credits <= 0:"),
    ], found
    one = next(f for f in all_of if f["rule"] == RULE and f["file"] == "server/api.py")
    assert one["tool_confidence"] == "LOW" and one["rank"] == "medium" and one["cwe"] == 367
    assert "`ask`" in one["title"] and "Heuristic" in one["more_info"]
    assert "line 12" in one["more_info"] and "line 13" in one["more_info"], one["more_info"]
    story = one["scenario"]
    assert "at the same moment" in " ".join(story["steps"]) and "before any of them is written down" in story["harm"]


def test_nothing_is_said_of_test_code_and_of_examples(tmp_path):
    """Test files and the examples of a project's documents are not the app."""
    _write(tmp_path, {"tests/__init__.py": "", "tests/test_api.py": API_PY.replace("from .store", "from server.store"),
                      "docs/example.py": API_PY})
    assert [f for f in scan(build_graph(tmp_path))["findings"] if f["rule"] == RULE] == []


def test_a_function_built_to_hold_the_check_up_is_read_in_bounded_time(tmp_path):
    """Thousands of looks, each with its refusal, and no count: every look is tried against the lines after it."""
    body = "".join(f"    if store.used(u{i}) >= {i}:\n        raise HTTPException(status_code=429)\n"
                   f"    r{i} = await model.complete(u{i})\n" for i in range(3000))
    _write(tmp_path, {"app/__init__.py": "", "app/api.py": "async def ask(store, model, " + ", ".join(
        f"u{i}=0" for i in range(3000)) + "):\n" + body + "    return 1\n"})
    g = build_graph(tmp_path)
    began = time.monotonic()
    assert countlater.counted_later(g) == []
    assert time.monotonic() - began < 5
