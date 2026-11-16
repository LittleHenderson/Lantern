"""AI-app pack: paid calls on the map, wallet drain, model output into tools, notebook secrets."""

import json
import time
from pathlib import Path

import lantern_files
import pytest

from lantern import aiapp as finder
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


# ------------------------------------------------------------------ a call that is only written about is no call
# Until 2026-11-16 every line that did not begin as a comment was read as code: a remark at a line's end, the second
# line of a docstring and the lines of a text kept over several lines all "made" paid calls. Lantern's own check of
# itself pinned a Stripe payment to `lantern/flow_js.py` for a remark there, and the first real pull request that got
# the "what this change does" comment was told its code leads to a call that costs money.
WRITTEN_ABOUT_PY = '''\
"""Notes. Payments are made elsewhere: stripe.checkout.Session.create(...) is the billing service's call,
and the summary once came from client.chat.completions.create(model="m")."""
from fastapi import FastAPI

app = FastAPI()
HELP = """
To send a mail by hand:
    resend.emails.send({"to": "a@example.com"})
"""


@app.get("/api/notes")
def notes(q: str):
    rows = load(q)        # not stripe.checkout.Session.create(...): billing is another service
    return rows           # the old way: client.chat.completions.create(model="m", messages=[])


def load(q):
    """Once this was
    openai.ChatCompletion.create(model="m")
    and a search in pgvector."""
    return [q]            # no pgvector here, and no `embedding <-> q`
'''
WRITTEN_ABOUT_JS = '''\
// stripe.checkout.sessions.create() is the billing service's call, not this page's
/* the old way:
   const r = await openai.chat.completions.create({ model: "m" })
*/
export async function notes(q) {
  const rows = await fetch("/api/notes?q=" + q);   // not openai.chat.completions.create(...)
  return rows.json();   /* nor new Stripe(key) */
}
'''
WRITTEN_ABOUT_GO = '''\
package main

// the billing service asks stripe.checkout, not this program
func help() string {
	return `
To pay by hand:
  stripe.checkout.sessions.create()
`
}

func main() {
	println(help()) // not groq.Ask(q)
}
'''
WRITTEN_ABOUT_RB = '''\
class Notes
  def list(q)
    rows = find(q)   # not stripe.checkout.sessions.create
    rows
  end
end
'''
CALLS_PY = '''\
"""Notes with a summary."""
from fastapi import FastAPI
from openai import OpenAI
import stripe

app = FastAPI()
client = OpenAI()


@app.get("/api/summary")
def summary(q: str):
    return client.chat.completions.create(model="m", messages=[{"role": "user", "content": q}])   # the summary


@app.post("/api/pay")
def pay(plan: str):
    return stripe.checkout.Session.create(success_url="https://shop.example/#done", mode=plan)


def nearest(cur, v):
    cur.execute("""
        select id from notes
        order by embedding <-> %s limit 5
    """, (v,))      # a vector store, read out of the text of its query
    return cur.fetchall()
'''
CALLS_JS = '''\
import OpenAI from "openai";
const openai = new OpenAI();
export async function summary(q) {
  const url = "https://api.example.com//v1";
  const all = "src/**/*.ts";
  return openai.chat.completions.create({ model: "m", messages: [{ role: "user", content: q + url + all }] });  /* the summary */
}
export function tidy(s) {
  return s.replace(/`/g, "'").replace(/^https?:\\/\\//, "");
}
export async function draw(p) {
  return openai.images.generate({ prompt: p });
}
'''
CALLS_GO = '''\
package main

func answer(q string) string {
	return groq.Ask(q) // the answer
}

func main() {
	println(answer("q"))
}
'''
CALLS_RB = '''\
class Mailer
  def hello(to)
    Resend.send(to)
    resend.emails.send(to: to)   # the welcome mail
  end
end
'''


def _line(text, part):
    [n] = [i for i, line in enumerate(text.splitlines(), 1) if part in line]
    return n


def test_a_call_that_is_only_written_about_is_no_call(tmp_path):
    _write(tmp_path, {"api/__init__.py": "", "api/main.py": WRITTEN_ABOUT_PY, "web/src/api.js": WRITTEN_ABOUT_JS,
                      "tool/go.mod": "module tool\n", "tool/main.go": WRITTEN_ABOUT_GO, "jobs/notes.rb": WRITTEN_ABOUT_RB})
    g = build_graph(tmp_path)
    assert {"py:api.main.notes", "js:web/src/api::notes", "rb:Notes.list"} <= set(g.nodes)     # every file was read
    sec = scan(g)
    assert sec["ai"]["calls"] == [], sec["ai"]["calls"]
    assert sec["ai"]["is_ai_app"] is False and sec["ai"]["by_node"] == {}
    assert not [f for f in sec["findings"] if f["rule"].startswith("LA-")]


def test_the_same_calls_written_as_code_are_found_beside_remarks_and_texts(tmp_path):
    _write(tmp_path, {"api/__init__.py": "", "api/main.py": CALLS_PY, "web/src/calls.js": CALLS_JS,
                      "tool/go.mod": "module tool\n", "tool/main.go": CALLS_GO, "jobs/mailer.rb": CALLS_RB})
    g = build_graph(tmp_path)
    sec = scan(g)
    found = {(c["file"], c["line"], c["kind"]) for c in sec["ai"]["calls"]}
    assert found == {
        ("api/main.py", _line(CALLS_PY, "chat.completions"), "model"),         # a remark after the call hides nothing
        ("api/main.py", _line(CALLS_PY, "stripe.checkout"), "payment"),        # a `#` inside a text is no remark
        ("api/main.py", _line(CALLS_PY, "<->"), "vector"),                     # a query kept as text over several lines
        ("web/src/calls.js", _line(CALLS_JS, "chat.completions"), "model"),    # after `//` and `/*` inside texts
        ("web/src/calls.js", _line(CALLS_JS, "images.generate"), "image"),     # after a pattern that holds a backtick
        ("tool/main.go", _line(CALLS_GO, "groq.Ask"), "model"),
        ("jobs/mailer.rb", _line(CALLS_RB, "resend.emails.send"), "email"),
    }, sorted(found)
    by = sec["ai"]["by_node"]
    assert by["py:api.main.summary"][0]["kind"] == "model" and by["js:web/src/calls::draw"][0]["kind"] == "image"
    drained = {f["line"] for f in sec["findings"] if f["rule"] == "LA-WALLET-DRAIN" and f["file"] == "api/main.py"}
    assert drained == {_line(CALLS_PY, '@app.get("/api/summary")'), _line(CALLS_PY, '@app.post("/api/pay")')}   # a route's first line


def test_what_is_read_as_code_line_by_line():
    py = ['x = 1  # stripe.checkout', 's = """', 'stripe.checkout  <->', '"""  # <->', 'q = "a # b"  # c',
          "t = '''one line'''", 'u = """never closed', 'stripe.checkout']
    code, text = finder.read_as_code(py, "a.py")
    assert [len(x) for x in code] == [len(x) for x in py] == [len(x) for x in text]         # every place stays where it was
    assert code[0].rstrip() == "x = 1" and text[0].rstrip() == "x = 1"
    assert code[2].strip() == "" and text[2] == py[2]                    # a text over lines: no code, still text
    assert text[3].rstrip() == '"""' and code[3].strip() == ""
    assert code[4].rstrip() == 'q = "a # b"' and code[5] == py[5]        # a text on one line is left to the line's own reading
    assert code[6:] == py[6:] and text[6:] == py[6:]                     # what nothing closes is left as it is written
    doc = ['"""About', 'pgvector."""', "def f(cur):", '    "one line about pgvector"', "    g(", '        """a <-> b"""', "    )",
           "    x = \\", '        "c <-> d"', "    r'''e", "    <->'''", "y = (", '    "f <-> g"', ")"]
    code, text = finder.read_as_code(doc, "a.py")
    assert [len(x) for x in text] == [len(x) for x in doc]
    assert [x.strip() for x in text[:4]] == ["", "", "def f(cur):", ""]   # a text that is a statement by itself is a remark
    assert text[5] == doc[5] and text[8] == doc[8] and text[12] == doc[12]    # one handed on or given a name is kept
    assert text[9].strip() == "r" and text[10].strip() == ""              # a docstring written with a letter in front
    js = ['a("//x", `/*`, 1) // b', 'c(/\\/\\//) /* d', 'e */ f()', 'g = "src/**/*.ts"; h() /* i */', 'j = `', 'k()', '`']
    code, text = finder.read_as_code(js, "a.ts")
    assert code[0].rstrip() == 'a("//x", `/*`, 1)' and code[1].rstrip() == "c(/\\/\\//)"
    assert code[2].strip() == "f()" and code[3].rstrip() == 'g = "src/**/*.ts"; h()'
    assert code[4:] == js[4:] and code == text      # a JavaScript template over lines is not judged (see Known gaps)
    go = ["s := `", "stripe.checkout", "` // x"]
    code, text = finder.read_as_code(go, "a.go")
    assert code[1].strip() == "" and text[1] == go[1] and text[2].rstrip() == "`"
    rb = ['a = "#{b}" # c', "d = '#' # e"]
    code, _ = finder.read_as_code(rb, "a.rb")
    assert [x.rstrip() for x in code] == ['a = "#{b}"', "d = '#'"]
    # text made to hold the reading up: many starts that nothing closes (looked at once each, however many)
    began = time.monotonic()
    for hostile in (["/*"] * 200000, ['"""'] * 200001, ["`"] * 200001, ["'" + "\\" * 60] * 20000):
        for name in ("a.py", "a.ts", "a.go", "a.rb"):
            finder.read_as_code(hostile, name)
    assert time.monotonic() - began < 30


def test_lantern_itself_writes_about_paid_calls_and_makes_none():
    """Lantern's own code names many paid services (its patterns, its remarks, the tiny apps of its tests) and calls
    none through their libraries: its model calls are plain HTTP requests (Known gaps)."""
    root = Path(__file__).resolve().parents[1]
    files = lantern_files.modules(deep=True)                # the package as Python loaded it
    files += sorted(p for top in ("gateway", "cloud") for p in (root / top).rglob("*.py"))
    assert len(files) > 100
    paid, written_about = [], 0
    for p in files:
        lines = p.read_text(encoding="utf-8").splitlines()
        rel = lantern_files.named(p)
        written_about += sum(1 for line in lines if "new Stripe(" in line or ".chat.completions.create(" in line)
        paid += [(rel, n, kind) for n, kind, _ in finder.named(lines, rel) if kind in finder.PAID_KINDS]
    assert written_about >= 1          # the remark in lantern/flow_js.py that read as a payment
    assert paid == []
