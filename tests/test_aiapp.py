"""AI-app pack: paid calls on the map, wallet drain, model output into tools, notebook secrets."""

import json
from pathlib import Path

import pytest

from lantern.engine import build_graph
from lantern.security import scan

FIX = Path(__file__).parent / "fixtures"


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


@pytest.fixture(scope="module")
def aiapp():
    g = build_graph(FIX / "aiapp")
    return g, scan(g)


def test_paid_calls_are_pinned_to_functions(aiapp):
    g, sec = aiapp
    ai = sec["ai"]
    assert ai["is_ai_app"] and ai["kinds"] == ["model", "payment"] and "OpenAI" in ai["providers"]
    by = ai["by_node"]
    assert by["py:api.main.ask_model"][0]["kind"] == "model"
    assert by["py:api.main.create_charge"][0] == {"kind": "payment", "provider": "Stripe", "line": 46}
    assert "py:api.main.chat" not in by                       # the route itself makes no call; ask_model does


def test_wallet_drain_needs_login_and_rate_limit(aiapp):
    _, sec = aiapp
    wd = {f["line"]: f for f in sec["findings"] if f["rule"] == "LA-WALLET-DRAIN"}
    assert wd[14]["rank"] == "high" and "anyone can call it" in wd[14]["title"]        # /api/chat: no login, no limit
    assert wd[22]["rank"] == "high"                                                      # /api/agent/run
    assert wd[31]["rank"] == "medium" and "no rate limit" in wd[31]["title"]             # /api/checkout: login, no limit
    assert all(f["tool_confidence"] == "LOW" for f in wd.values())                       # heuristic, says so


def test_model_output_into_a_shell_is_critical(aiapp):
    _, sec = aiapp
    f = next(f for f in sec["findings"] if f["rule"] == "LA-MODEL-OUTPUT-TO-TOOL")
    assert f["line"] == 27 and f["rank"] == "critical" and "shell command" in f["title"]
    assert "`command` is set from a model response on line 26" in f["more_info"]
    info = next(f for f in sec["findings"] if f["rule"] == "LA-PROMPT-FROM-INPUT")
    assert info["rank"] == "low" and info["line"] == 25


def test_notebook_secrets_in_cells_and_outputs(aiapp):
    _, sec = aiapp
    nb = [f for f in sec["findings"] if f["rule"] == "LA-NOTEBOOK-SECRET"]
    assert sorted(f["title"] for f in nb) == ["Hugging Face token in a notebook saved output (cell 3)",
                                              "OpenAI key in a notebook code cell (cell 2)"]      # sorted by rank, then file/line
    assert all(f["rank"] == "critical" and f["snippet"].endswith("…") and len(f["snippet"]) <= 8 for f in nb)
    assert sec["ai"]["notebooks"] == [{"file": "notebooks/experiments.ipynb", "code_cells": 2, "ai": ["model"], "secrets": 2}]


def test_rate_limited_and_logged_in_routes_are_quiet(tmp_path):
    _write(tmp_path, {
        "requirements.txt": "fastapi\nslowapi\nanthropic\n",
        "app.py": '''from fastapi import FastAPI, Depends
import anthropic
from slowapi import Limiter

app = FastAPI()
limiter = Limiter(key_func=lambda: "ip")

def get_current_user():
    return "u"

@app.post("/ask")
@limiter.limit("5/minute")
def ask(q: str, user=Depends(get_current_user)):
    return anthropic.Anthropic().messages.create(model="claude-haiku-5-5", max_tokens=100, messages=[{"role": "user", "content": q}])
''',
    })
    g = build_graph(tmp_path)
    sec = scan(g)
    assert sec["ai"]["providers"] == ["Anthropic"]
    assert not [f for f in sec["findings"] if f["rule"].startswith("LA-")]


def test_placeholders_and_other_languages(tmp_path):
    _write(tmp_path, {
        "web/package.json": '{"name": "x", "dependencies": {"ai": "^4.0.0", "next": "14.0.0"}}',
        "web/app/api/ask/route.ts": '''import { generateText } from "ai";
export async function POST(req: Request) {
  const { prompt } = await req.json();
  const { text } = await generateText({ model: "gpt-4o", prompt });
  return Response.json({ text });
}
''',
        "notes.ipynb": json.dumps({"cells": [{"cell_type": "code", "source": ["api_key = 'your-api-key-here-xxxx'\n"], "outputs": []}],
                                   "nbformat": 4, "nbformat_minor": 5, "metadata": {}}),
    })
    g = build_graph(tmp_path)
    sec = scan(g)
    calls = sec["ai"]["calls"]
    assert calls and calls[0]["provider"] == "OpenAI" and calls[0]["node"] == "js:web/app/api/ask/route::POST"
    wd = [f for f in sec["findings"] if f["rule"] == "LA-WALLET-DRAIN"]
    assert len(wd) == 1 and wd[0]["rank"] == "high"
    assert not [f for f in sec["findings"] if f["rule"] == "LA-NOTEBOOK-SECRET"]      # a placeholder is not a key


# ------------------------------------------------------------------ the story says what the finding says

def _paid(sec, line):
    f = next(f for f in sec["findings"] if f["rule"] == "LA-WALLET-DRAIN" and f["line"] == line)
    return f, f["scenario"], f.get("headline")


def test_the_paid_call_story_says_what_the_finding_says_about_a_login(aiapp):
    """A route that asks for a login and has no limit: the finding says so, and so do the record beside it, the
    story and the heading. Until 2026-11-15 every paid-call story said "not signed in" and every heading "Anyone",
    whatever the finding itself had found."""
    _, sec = aiapp
    f, story, head = _paid(sec, 31)                                         # POST /api/checkout: a login, no limit
    assert f["title"].endswith("with no rate limit") and f["paid"] == {"login": True, "limit": False}
    assert story["steps"][-1] == ("They sign in with an account of their own, and they send POST /api/checkout "
                                  "again and again.")
    assert not any("not signed in" in s for s in story["steps"])
    assert head == "Anyone with an account can make POST /api/checkout spend your money on paid calls"
    assert story["after_fix"] == "The route has a limit on how often one person can call it."
    assert "nothing stops it" in story["harm"]                  # still true: a login does not stop a script
    # the twin beside it, no login and no limit, keeps every word it had
    f, story, head = _paid(sec, 14)                                         # POST /api/chat
    assert f["title"].endswith("anyone can call it as often as they like")
    assert f["paid"] == {"login": False, "limit": False}
    assert story["steps"][-1] == "They are not signed in, and they send POST /api/chat again and again."
    assert head == "Anyone can make POST /api/chat spend your money on paid calls"
    assert story["after_fix"] == "The route needs a signed-in user and has a limit on how often one person can call it."
    assert "nothing stops it" in story["harm"]


def test_the_paid_call_story_with_a_limit_and_no_login(tmp_path):
    """The third reading: a limit is there and no login. Anyone can still call it, so the heading stays; the story
    no longer says "again and again" with nothing to stop it, and the fix it names is the login alone."""
    _write(tmp_path, {
        "requirements.txt": "fastapi\nslowapi\nanthropic\n",
        "app.py": '''from fastapi import FastAPI
import anthropic
from slowapi import Limiter

app = FastAPI()
limiter = Limiter(key_func=lambda: "ip")

@app.post("/ask")
@limiter.limit("5/minute")
def ask(q: str):
    return anthropic.Anthropic().messages.create(model="claude-haiku-5-5", max_tokens=100, messages=[{"role": "user", "content": q}])
''',
    })
    sec = scan(build_graph(tmp_path))
    f, story, head = _paid(sec, 8)                              # a decorated route is reported on its first line
    assert f["rank"] == "medium" and f["title"].endswith("without a login check")
    assert f["paid"] == {"login": False, "limit": True}
    assert story["steps"][-1] == "They are not signed in, and they send POST /ask as often as the limit lets them."
    assert "nothing stops it" not in story["harm"] and "up to that limit" in story["harm"]
    assert story["after_fix"] == "The route needs a signed-in user."
    assert head == "Anyone can make POST /ask spend your money on paid calls"


def test_a_paid_call_finding_with_no_record_is_read_from_its_title_or_left_as_it_was(aiapp):
    """Results written before the record existed carry only the title: its fixed ending says the same. A finding of
    the same kind from another tool, whose title says nothing of the two, keeps the older words."""
    from lantern import scenarios
    g, sec = aiapp
    old = {k: v for k, v in _paid(sec, 31)[0].items() if k not in ("paid", "scenario", "headline")}
    assert old["title"] == "POST /api/checkout spends money (payment API) with no rate limit"
    steps = scenarios.for_finding(old, g)["steps"]
    assert steps[-1] == "They sign in with an account of their own, and they send POST /api/checkout again and again."
    assert scenarios.headline(old, g) == "Anyone with an account can make POST /api/checkout spend your money on paid calls"
    other = dict(old, rule="X-770", title="Requests are not limited")
    assert scenarios.kind_of(other) == "wallet"
    assert scenarios.for_finding(other, g)["steps"][-1] == ("They are not signed in, and they send POST /api/checkout "
                                                            "again and again.")
    assert scenarios.headline(other, g) == "Anyone can make POST /api/checkout spend your money on paid calls"
    # a record wins over the title: what the rule found is the fact, the title is its sentence
    both = dict(old, paid={"login": False, "limit": False})
    assert scenarios.headline(both, g) == "Anyone can make POST /api/checkout spend your money on paid calls"
