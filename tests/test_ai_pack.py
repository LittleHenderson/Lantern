"""The AI-app pack, second version (roadmap of 2026-11-14, stage 5): what the model wrote, followed across functions and
files to a command, a query, `eval`, an address or a file (`LA-MODEL-OUTPUT-TO-TOOL`).

Until this stage the rule read one function's own lines: a value set from a model's answer, then used on a later line of
the same function. The model's answer handed back by one function and run by another, or read out of a tool call the
model asked for, was named nowhere. Now the data-flow step (`lantern/flow.py`) takes what a model call gives back as text
the model wrote, from the library's own name for the call, and follows it like what a request sent.

Each dangerous example stands beside twins that must stay quiet and look-alikes that are no model at all. Nothing here
is run, and no model is asked.
"""
from lantern.engine import build_graph
from lantern.security import scan

RULE = "LA-MODEL-OUTPUT-TO-TOOL"

LLM_PY = '''import subprocess

import anthropic
from openai import OpenAI

client = OpenAI()
claude = anthropic.Anthropic()


def ask(prompt):
    r = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": prompt}])
    return r.choices[0].message.content


def ask_claude(prompt):
    m = claude.messages.create(model="claude-haiku-5-5", max_tokens=200,
                               messages=[{"role": "user", "content": prompt}])
    return m.content[0].text


def run_reply(prompt):
    reply = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": prompt}]).choices[0].message.content
    subprocess.run(reply, shell=True)


def run_checked(prompt):
    answer = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": prompt}]).choices[0].message.content
    if answer not in ("ls", "pwd"):
        raise ValueError("not an allowed command")
    subprocess.run(answer, shell=True)
'''

TOOLS_PY = '''import sqlite3
import subprocess

import requests
from twilio.rest import Client as Twilio

from app.llm import ask, ask_claude, claude

db = sqlite3.connect("notes.db")
sms = Twilio()
ALLOWED = ["ls", "pwd", "date"]


# ---- dangerous: what the model wrote is run, asked for or opened as it came, in another function or file
def run(cmd):
    return subprocess.run(cmd, shell=True)


def agent(task):
    cmd = ask("Write one shell command for: " + task)
    run(cmd)


def agent_claude(task):
    run(ask_claude(task))


def report(task):
    db.execute("insert into notes(body) values ('" + ask(task) + "')")


def follow(task):
    return requests.get(ask("Give one address for: " + task)).text


def keep(task, text):
    with open(ask_claude("Name a file for: " + task), "w") as f:
        f.write(text)


def calc(task):
    return eval(ask("Write one Python expression for: " + task))


def act(task):
    m = claude.messages.create(model="claude-haiku-5-5", max_tokens=200, tools=[],
                               messages=[{"role": "user", "content": task}])
    for block in m.content:
        if block.type == "tool_use":
            subprocess.run(block.input["command"], shell=True)


# ---- safe twins: checked against a list of the code's own, made a number, handed as a value, never an address's host
def allowed(task):
    cmd = ask(task)
    if cmd not in ALLOWED:
        raise ValueError("not an allowed command")
    subprocess.run(cmd, shell=True)


def wait(task):
    n = int(ask("How many seconds? " + task))
    subprocess.run(f"sleep {n}", shell=True)


def store(task):
    db.execute("insert into notes(body) values (?)", (ask(task),))


def search(task):
    return requests.get("https://api.example.com/search", params={"q": ask(task)}).json()


def say(task):
    print(ask(task))


def echo(task):
    subprocess.run(["echo", ask(task)])


# ---- look-alikes: no model wrote these
def texted(to):
    msg = sms.messages.create(to=to, from_="+15550100", body="Your code")
    subprocess.run("echo " + msg.sid, shell=True)


def ask_llm(prompt):
    return "ls"


def pretend(task):
    subprocess.run(ask_llm(task), shell=True)
'''

ROUTES_PY = '''import subprocess

from flask import Flask, request
from flask_login import login_required

from app.llm import ask
from app.models import Note

app = Flask(__name__)


@app.route("/do")
def do():
    subprocess.run(ask(request.args["q"]), shell=True)
    return "done"


@app.route("/note")
@login_required
def note():
    found = Note.query.get(ask(request.args["q"]))
    return {"body": found.body}


@app.route("/answer")
def answer():
    return "<p>" + ask(request.args["q"]) + "</p>"
'''

MODELS_PY = '''from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer)
    body = db.Column(db.Text)
'''

LLM_TS = '''import OpenAI from "openai";
import { generateText } from "ai";

const openai = new OpenAI();

export async function ask(p: string) {
  const r = await openai.chat.completions.create({ model: "gpt-4o", messages: [{ role: "user", content: p }] });
  return r.choices[0].message.content;
}

export async function write(p: string) {
  const { text } = await generateText({ model: "openai/gpt-4o", prompt: p });
  return text;
}

export async function plan(p: string) {
  const r = await openai.chat.completions.create({ model: "gpt-4o", tools: [], messages: [{ role: "user", content: p }] });
  return r.choices[0].message.tool_calls;
}
'''

AGENT_TS = '''import { exec, execSync, execFile } from "child_process";
import fs from "fs";
import { ask, write, plan } from "./llm";

const ALLOWED = ["ls", "pwd"];

export async function agent(task: string) {
  const cmd = await ask(task);
  exec(cmd);
}

export async function writer(task: string) {
  execSync(await write(task));
}

export async function tidy(task: string) {
  for (const call of await plan(task)) {
    const args = JSON.parse(call.function.arguments);
    fs.rmSync(args.path, { recursive: true });
  }
}

export async function picked(task: string) {
  const line = await ask(task);
  if (!ALLOWED.includes(line)) throw new Error("not allowed");
  exec(line);
}

export async function logged(task: string) {
  execFile("git", ["log", "--grep", await ask(task)]);
}
'''

FILES = {"app/__init__.py": "", "app/llm.py": LLM_PY, "app/tools.py": TOOLS_PY, "app/routes.py": ROUTES_PY,
         "app/models.py": MODELS_PY, "web/package.json": '{"dependencies": {"openai": "^4.0.0", "ai": "^4.0.0"}}',
         "web/src/llm.ts": LLM_TS, "web/src/agent.ts": AGENT_TS}


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="\n")
    return root


def _at(text: str, line: str) -> int:
    """The line number of the one line of `text` that reads `line` (leading and trailing space aside)."""
    lines = [x.strip() for x in text.split("\n")]
    assert lines.count(line) == 1, line
    return lines.index(line) + 1


def test_what_the_model_wrote_is_followed_into_another_function_and_file(tmp_path):
    """Dangerous: the model's answer handed back by a helper and run by another function (a shell command, a query
    built from it, an address asked for, a file opened to write, `eval`), the input of a tool call the model asked
    for (Anthropic's `tool_use`), JavaScript's `generateText` and the arguments of a tool call read with `JSON.parse`,
    and a route that hands what the visitor sent to the model and runs its answer. Safe twins: the answer checked
    against a list of the code's own first (Python's `not in`, JavaScript's `includes`), made a number, handed to
    the database as a value, sent as a field of an address whose host is written in the code, printed, or handed to a
    program whose name is written in the code. Look-alikes: another service's `messages.create` (Twilio) and a function
    of the project named like a model call that gives back fixed text. The older reading, inside one function, found
    one of these (`run_reply`); it is still one finding there, now with the steps. It also took a value checked
    against the code's own list in the same function for one (`run_checked`): where the data-flow step saw the model's
    text arrive there checked on every way, that is no finding."""
    sec = scan(build_graph(_write(tmp_path, FILES)))
    found = sorted((f["file"], f["line"]) for f in sec["findings"] if f["rule"] == RULE)
    tools, ts = "app/tools.py", "web/src/agent.ts"
    expected = [(tools, _at(TOOLS_PY, line)) for line in (
        "return subprocess.run(cmd, shell=True)",
        "db.execute(\"insert into notes(body) values ('\" + ask(task) + \"')\")",
        "return requests.get(ask(\"Give one address for: \" + task)).text",
        "with open(ask_claude(\"Name a file for: \" + task), \"w\") as f:",
        "return eval(ask(\"Write one Python expression for: \" + task))",
        "subprocess.run(block.input[\"command\"], shell=True)")]
    expected += [("app/routes.py", _at(ROUTES_PY, 'subprocess.run(ask(request.args["q"]), shell=True)')),
                 ("app/llm.py", _at(LLM_PY, "subprocess.run(reply, shell=True)"))]
    expected += [(ts, _at(AGENT_TS, line)) for line in ("exec(cmd);", "execSync(await write(task));",
                                                       "fs.rmSync(args.path, { recursive: true });")]
    assert found == sorted(expected), found
    by = {(f["file"], f["line"]): f for f in sec["findings"] if f["rule"] == RULE}
    one = by[(tools, _at(TOOLS_PY, "return subprocess.run(cmd, shell=True)"))]
    assert one["tool"] == "lantern-flow" and one["tool_confidence"] == "LOW" and one["cwe"] == 94, one
    assert one["title"] == "Text the model wrote is used as a shell command", one["title"]
    fl = one["flow"]
    assert fl["origin"] == "model" and fl["class"] == "shell", fl
    assert (fl["source"]["file"], fl["source"]["line"]) in (
        ("app/llm.py", _at(LLM_PY, 'r = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", '
                                   '"content": prompt}])')),
        ("app/llm.py", _at(LLM_PY, 'm = claude.messages.create(model="claude-haiku-5-5", max_tokens=200,'))), fl
    assert "the model wrote" in fl["source"]["what"], fl["source"]
    assert fl["count"] == 2, fl                 # `agent` and `agent_claude` reach the same line
    assert one["rank"] == "high" and one["input"] is None, (one["rank"], one.get("input"))
    assert "Heuristic" in one["more_info"] and "prompt" in one["more_info"], one["more_info"]
    assert any(e["fact"].startswith("Text the model wrote was followed to this line")
               for e in one["case"]["evidence"]), one["case"]["evidence"]
    # the older reading's finding: one finding on its line, its own words kept, and the steps beside them
    old = by[("app/llm.py", _at(LLM_PY, "subprocess.run(reply, shell=True)"))]
    assert old["more_info"].startswith("`reply` is set from a model response on line"), old["more_info"]
    assert old["flow"]["origin"] == "model", old.get("flow")
    # a route that hands the visitor's text to the model and runs its answer: critical, and still this rule
    do = by[("app/routes.py", _at(ROUTES_PY, 'subprocess.run(ask(request.args["q"]), shell=True)'))]
    assert do["rank"] == "critical", do["rank"]


def test_what_the_model_wrote_is_not_taken_for_what_a_request_sent(tmp_path):
    """The model's answer is followed to the actions this rule names, and to no other rule's: a record it picks is
    not "a record picked by an id from the request" (LT-AUTHZ-OWNER), a page it is written into is not a page the
    visitor wrote (LT-XSS), and the command it is run as is this rule's and not LT-SHELL's. Those are not claimed,
    so they are said nowhere."""
    sec = scan(build_graph(_write(tmp_path, FILES)))
    from_flows = sorted((f["rule"], f["file"], f["line"]) for f in sec["findings"]
                        if f["rule"].startswith("LT-") and f["file"].startswith(("app/", "web/")))
    assert from_flows == [], from_flows
    shell = [f for f in sec["findings"] if f.get("flow") and f["rule"] != RULE]
    assert all((f["flow"].get("origin") or "server") not in ("model", "tool") for f in shell), \
        [(f["rule"], f["file"], f["line"]) for f in shell]


def test_one_line_is_one_finding_and_a_requests_own_flow_stays():
    """How the data-flow step's flows meet the older reading's findings (`aiapp.from_flows`, `aiapp.made_safe`), on
    findings written by hand. A flow that ends on the line of an older finding is written on it; a flow that ends on
    the next line is a finding of its own when another flow ends on the older finding's line, and is written on the
    older finding when none does (one statement over two lines) unless the data-flow step saw that line checked. An
    older finding that already shows what a request sent keeps that flow. An older finding is taken out only where the
    data-flow step saw its own line checked, never for a check on the line beside it."""
    from lantern.aiapp import from_flows, made_safe
    shell = "Text the model wrote is used as a shell command"

    def older(line, flow=None):
        f = {"rule": RULE, "title": shell, "file": "a.py", "line": line, "category": "code"}
        if flow is not None:
            f["flow"] = flow
        return f

    def flow(line, origin="model", conf="LOW"):
        return {"class": "shell", "confidence": conf, "severity": "HIGH", "origin": origin,
                "source": {"file": "b.py", "line": 1, "what": "`x()` gives back text the model wrote"},
                "sink": {"file": "a.py", "line": line, "what": "`subprocess.run`"},
                "steps": [{"file": "b.py", "line": 1, "what": "w"}, {"file": "a.py", "line": line, "what": "w"}],
                "others": [], "count": 1}

    two, split, beside, asked, near, at, held = (older(10), older(21), older(31), older(40, flow(40, "server")),
                                                 older(50), older(60), older(70, flow(70)))
    findings = [two, split, beside, asked, near, at, held]
    by_file = {"a.py": list(findings)}
    shaped = {("shell", "a.py", 10): flow(10), ("shell", "a.py", 11): flow(11), ("shell", "a.py", 20): flow(20),
              ("shell", "a.py", 30): flow(30), ("shell", "a.py", 40): flow(40, conf="HIGH")}
    safe = {("a.py", 31, "shell"), ("a.py", 51, "shell"), ("a.py", 60, "shell"), ("a.py", 70, "shell")}
    made, on_older = from_flows(shaped, by_file, safe=safe)
    assert sorted(f["line"] for f in made) == [11, 30], [(f["line"], f["title"]) for f in made]
    assert on_older == 3, on_older
    assert two["flow"]["sink"]["line"] == 10 and two["flow"]["count"] == 1, two["flow"]
    assert split["flow"]["sink"]["line"] == 20, split.get("flow")
    assert "flow" not in beside, beside["flow"]
    assert asked["flow"]["origin"] == "server" and asked["flow"]["count"] == 1, asked["flow"]
    assert made_safe(findings, safe) == 2
    assert [f["line"] for f in findings] == [10, 21, 40, 50, 70], [f["line"] for f in findings]
