"""AI-app pack: paid calls on the map, wallet drain, model output into tools, notebook secrets."""

import json
from pathlib import Path

import pytest

from lantern.aiapp import find_calls, notebooks, scan_ai
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
