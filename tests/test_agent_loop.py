"""The AI-app pack, second version (roadmap of 2026-11-14, stage 5): an agent loop with no cap on its paid calls
(`LA-UNBOUNDED-AGENT-LOOP`).

An agent loop asks a paid model, runs the tools it asks for, and asks again until the model says it is done. Where
nothing but the model's answer ends it (no count of rounds, no clock, no budget), a model that keeps asking for tools,
or words put into what it reads that tell it to, keep it going, and every round is billed. Lantern reads such a loop
from the code: a loop (or a function that calls itself again) that makes a paid model call in each round, directly or
through a helper of another file, where the condition that ends it reads the model's answer, and where no counter
the loop changes, no clock and no budget is read where it decides to go on. A library's own agent loop whose limit is
switched off (LangChain's `AgentExecutor(max_iterations=None)`, the AI SDK's `stopWhen` with no step count or
`maxSteps: Infinity`) is the same problem.

Each dangerous loop stands beside safe twins that differ in the one thing that bounds it, and look-alikes: a model on
this computer (nothing is paid for each call), a loop that a queue ends, a call tried again after a failure, a person
who says yes to each round, a chat object of the project's own. Nothing here is run, and no model is asked.
"""
from lantern.engine import build_graph
from lantern.security import scan

RULE = "LA-UNBOUNDED-AGENT-LOOP"

LLM_PY = '''import anthropic
from openai import OpenAI

claude = anthropic.Anthropic()
gpt = OpenAI()


def ask(messages):
    return claude.messages.create(model="claude-haiku-5-5", max_tokens=1024, messages=messages)


def ask_gpt(messages, tools):
    return gpt.chat.completions.create(model="gpt-5", messages=messages, tools=tools)
'''

AGENT_PY = '''import itertools

import anthropic
from langchain.agents import AgentExecutor
from openai import OpenAI

from bot.llm import ask, ask_gpt

client = anthropic.Anthropic()
oai = OpenAI()
TOOLS = [{"name": "search", "description": "Search the notes", "input_schema": {"type": "object"}}]


def run_tool(block):
    return {"type": "tool_result", "tool_use_id": block.id, "content": "found"}


# ---- dangerous: only the model's answer ends the loop, and each round is a paid call
def agent_until_done(messages):
    while True:
        resp = client.messages.create(model="claude-haiku-5-5", max_tokens=1024, messages=messages, tools=TOOLS)
        messages.append({"role": "assistant", "content": resp.content})
        if resp.stop_reason != "tool_use":
            return resp
        results = [run_tool(b) for b in resp.content if b.type == "tool_use"]
        messages.append({"role": "user", "content": results})


def agent_while_tools(messages):
    resp = client.messages.create(model="claude-haiku-5-5", max_tokens=1024, messages=messages, tools=TOOLS)
    while resp.stop_reason == "tool_use":
        messages.append({"role": "assistant", "content": resp.content})
        messages.append({"role": "user", "content": [run_tool(b) for b in resp.content if b.type == "tool_use"]})
        resp = client.messages.create(model="claude-haiku-5-5", max_tokens=1024, messages=messages, tools=TOOLS)
    return resp


def agent_flag(messages):
    done = False
    while not done:
        out = oai.chat.completions.create(model="gpt-5", messages=messages, tools=TOOLS)
        choice = out.choices[0]
        messages.append(choice.message)
        done = choice.finish_reason == "stop"
    return messages


def agent_continue(messages):
    while True:
        out = oai.chat.completions.create(model="gpt-5", messages=messages, tools=TOOLS)
        msg = out.choices[0].message
        if msg.tool_calls:
            messages.append(msg)
            continue
        return msg.content


def agent_helper(messages):
    while True:
        resp = ask(messages)
        if resp.stop_reason == "end_turn":
            break
        messages.append({"role": "assistant", "content": resp.content})
    return messages


def agent_counted_forever(messages):
    for step in itertools.count():
        out = ask_gpt(messages, TOOLS)
        if not out.choices[0].message.tool_calls:
            return out, step
        messages.append(out.choices[0].message)


def agent_again(messages):
    resp = client.messages.create(model="claude-haiku-5-5", max_tokens=1024, messages=messages, tools=TOOLS)
    if resp.stop_reason != "tool_use":
        return resp
    messages.append({"role": "assistant", "content": resp.content})
    return agent_again(messages)


def agent_counter_unread(messages):
    turns = 0
    while True:
        turns += 1
        resp = client.messages.create(model="claude-haiku-5-5", max_tokens=1024, messages=messages, tools=TOOLS)
        if resp.stop_reason == "end_turn":
            return resp, turns
        messages.append({"role": "assistant", "content": resp.content})


def make_executor(agent, tools):
    return AgentExecutor(agent=agent, tools=tools, max_iterations=None)
'''

SAFE_PY = '''import time

import anthropic
import click
import ollama
from langchain.agents import AgentExecutor
from openai import OpenAI

from bot.llm import ask

client = anthropic.Anthropic()
oai = OpenAI()
TOOLS = []
MAX_STEPS = 8
BUDGET = 50_000


# ---- safe twins: the same loops with a count of rounds, a clock, a budget, or a person who says yes to each round
def agent_steps(messages):
    for _ in range(MAX_STEPS):
        resp = client.messages.create(model="claude-haiku-5-5", max_tokens=1024, messages=messages, tools=TOOLS)
        if resp.stop_reason != "tool_use":
            return resp
        messages.append({"role": "assistant", "content": resp.content})
    return None


def agent_test_counts(messages):
    steps = 0
    resp = client.messages.create(model="claude-haiku-5-5", max_tokens=1024, messages=messages, tools=TOOLS)
    while resp.stop_reason == "tool_use" and steps < MAX_STEPS:
        steps += 1
        messages.append({"role": "assistant", "content": resp.content})
        resp = client.messages.create(model="claude-haiku-5-5", max_tokens=1024, messages=messages, tools=TOOLS)
    return resp


def agent_counter(messages):
    turns = 0
    while True:
        turns = turns + 1
        if turns > MAX_STEPS:
            raise RuntimeError("too many rounds")
        out = oai.chat.completions.create(model="gpt-5", messages=messages, tools=TOOLS)
        if out.choices[0].finish_reason == "stop":
            return out


def agent_clock(messages):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        resp = ask(messages)
        if resp.stop_reason == "end_turn":
            return resp
    return None


def agent_budget(messages):
    spent = 0
    while True:
        resp = client.messages.create(model="claude-haiku-5-5", max_tokens=1024, messages=messages, tools=TOOLS)
        spent += resp.usage.input_tokens + resp.usage.output_tokens
        if resp.stop_reason == "end_turn" or spent > BUDGET:
            return resp


def agent_asks(messages):
    while True:
        resp = client.messages.create(model="claude-haiku-5-5", max_tokens=1024, messages=messages, tools=TOOLS)
        if resp.stop_reason != "tool_use":
            return resp
        if not click.confirm("Run the tools the model asked for?"):
            return None
        messages.append({"role": "assistant", "content": resp.content})


def agent_again_capped(messages, depth=0):
    if depth >= MAX_STEPS:
        return None
    resp = client.messages.create(model="claude-haiku-5-5", max_tokens=1024, messages=messages, tools=TOOLS)
    if resp.stop_reason != "tool_use":
        return resp
    messages.append({"role": "assistant", "content": resp.content})
    return agent_again_capped(messages, depth + 1)


def make_executor(agent, tools):
    return AgentExecutor(agent=agent, tools=tools)


def make_executor_timed(agent, tools):
    return AgentExecutor(agent=agent, tools=tools, max_iterations=None, max_execution_time=120)


# ---- look-alikes: nothing is paid for each round, or the model's answer does not decide when the loop ends
def local_agent(messages):
    while True:
        out = ollama.chat(model="llama3", messages=messages)
        if "DONE" in out["message"]["content"]:
            return out
        messages.append(out["message"])


def summarize_all(queue):
    while True:
        job = queue.get()
        if job is None:
            break
        ask([{"role": "user", "content": job}])


def ask_until_answered(messages):
    while True:
        try:
            return client.messages.create(model="claude-haiku-5-5", max_tokens=1024, messages=messages)
        except anthropic.RateLimitError:
            time.sleep(1)


def handle_blocks(messages):
    resp = client.messages.create(model="claude-haiku-5-5", max_tokens=1024, messages=messages, tools=TOOLS)
    blocks = list(resp.content)
    while blocks:
        block = blocks.pop()
        if block.type == "tool_use":
            messages.append(block)
    return resp


class Messages:
    def create(self, text):
        return {"text": text, "done": text == "bye"}


class Room:
    def __init__(self):
        self.messages = Messages()


def chat_room(lines):
    room = Room()
    while True:
        said = room.messages.create(lines.pop())
        if said["done"]:
            return said
'''

AGENT_TS = '''import OpenAI from "openai";
import Anthropic from "@anthropic-ai/sdk";
import { generateText, hasToolCall, stepCountIs, tool } from "ai";

const openai = new OpenAI();
const anthropic = new Anthropic();
const MAX_STEPS = 8;

// ---- dangerous: only the model's answer ends the loop, and each round is a paid call
export async function loopUntilDone(messages: any[]) {
  while (true) {
    const res = await openai.chat.completions.create({ model: "gpt-5", messages, tools: [] });
    const msg = res.choices[0].message;
    if (!msg.tool_calls) break;
    messages.push(msg);
  }
  return messages;
}

export async function loopForever(messages: any[]) {
  for (;;) {
    const res = await openai.chat.completions.create({ model: "gpt-5", messages });
    if (res.choices[0].finish_reason === "stop") return res;
    messages.push(res.choices[0].message);
  }
}

export async function loopDoWhile(messages: any[]) {
  let res;
  do {
    res = await anthropic.messages.create({ model: "claude-haiku-5-5", max_tokens: 1024, messages });
    messages.push({ role: "assistant", content: res.content });
  } while (res.stop_reason === "tool_use");
  return res;
}

export async function again(messages: any[]): Promise<any> {
  const res = await anthropic.messages.create({ model: "claude-haiku-5-5", max_tokens: 1024, messages });
  if (res.stop_reason !== "tool_use") return res;
  messages.push({ role: "assistant", content: res.content });
  return again(messages);
}

export async function sdkUntilTool(prompt: string) {
  return generateText({ model: "openai/gpt-5", prompt, tools: { done: tool({}) }, stopWhen: hasToolCall("done") });
}

export async function sdkInfinite(prompt: string) {
  return generateText({ model: "openai/gpt-5", prompt, tools: {}, maxSteps: Infinity });
}

// ---- safe twins
export async function loopCapped(messages: any[]) {
  for (let i = 0; i < MAX_STEPS; i++) {
    const res = await openai.chat.completions.create({ model: "gpt-5", messages });
    if (!res.choices[0].message.tool_calls) return res;
    messages.push(res.choices[0].message);
  }
  return null;
}

export async function loopCounted(messages: any[]) {
  let steps = 0;
  while (steps++ < MAX_STEPS) {
    const res = await openai.chat.completions.create({ model: "gpt-5", messages });
    if (res.choices[0].finish_reason === "stop") return res;
  }
  return null;
}

export async function loopClock(messages: any[]) {
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    const res = await anthropic.messages.create({ model: "claude-haiku-5-5", max_tokens: 1024, messages });
    if (res.stop_reason === "end_turn") return res;
  }
  return null;
}

export async function againCapped(messages: any[], depth = 0): Promise<any> {
  if (depth > MAX_STEPS) return null;
  const res = await anthropic.messages.create({ model: "claude-haiku-5-5", max_tokens: 1024, messages });
  if (res.stop_reason !== "tool_use") return res;
  return againCapped(messages, depth + 1);
}

export async function sdkCapped(prompt: string) {
  return generateText({ model: "openai/gpt-5", prompt, tools: {}, stopWhen: [hasToolCall("done"), stepCountIs(10)] });
}

export async function sdkSteps(prompt: string) {
  return generateText({ model: "openai/gpt-5", prompt, tools: {}, maxSteps: 5 });
}

// ---- a look-alike: a chat object of the project's own, no model
const room = { messages: { create: async (m: any[]) => ({ done: m.length > 3 }) } };

export async function roomLoop(messages: any[]) {
  while (true) {
    const said = await room.messages.create(messages);
    if (said.done) return said;
  }
}
'''

PACKAGE_JSON = '{"name": "web", "dependencies": {"openai": "5.0.0", "@anthropic-ai/sdk": "0.60.0", "ai": "5.0.0"}}\n'

FILES = {"bot/__init__.py": "", "bot/llm.py": LLM_PY, "bot/agent.py": AGENT_PY, "bot/safe.py": SAFE_PY,
         "web/agent.ts": AGENT_TS, "web/package.json": PACKAGE_JSON}


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


def _scan(tmp_path):
    return scan(build_graph(_write(tmp_path, FILES)))


def test_a_loop_that_only_the_models_answer_ends(tmp_path):
    """Dangerous: `while True` with a `return` or `break` under a condition on the model's answer, a `while` whose own
    test reads it, a flag set from it, a `continue` while the model asks for a tool, the paid call made by a helper of
    another file, `itertools.count()`, a counter that is counted and never read, a function that calls itself again
    while the model asks for tools; TypeScript's `while (true)`, `for (;;)`, `do … while` and a function that calls
    itself; and a library's own loop with its limit switched off. Safe twins: a fixed number of rounds, a counter read
    in the loop's test or where it ends, a clock, a budget in tokens, a person who says yes to each round, a depth
    the function counts, the library's limit kept or a time limit set. Look-alikes: a model on this computer, a loop
    a queue ends, a call tried again after it failed, the model asked once before the loop, a chat object of the
    project's own."""
    sec = _scan(tmp_path)
    found = sorted((f["file"], f["line"]) for f in sec["findings"] if f["rule"] == RULE)
    trues = [i + 1 for i, x in enumerate(AGENT_PY.split("\n")) if x.strip() == "while True:"]
    assert len(trues) == 4      # agent_until_done, agent_continue, agent_helper, agent_counter_unread
    expected = [("bot/agent.py", n) for n in trues]
    expected += [("bot/agent.py", _at(AGENT_PY, line)) for line in (
        'while resp.stop_reason == "tool_use":',
        "while not done:",
        "for step in itertools.count():",
        "return agent_again(messages)",
        "return AgentExecutor(agent=agent, tools=tools, max_iterations=None)")]
    expected += [("web/agent.ts", _at(AGENT_TS, line)) for line in (
        "for (;;) {",
        "do {",
        "return again(messages);",
        'return generateText({ model: "openai/gpt-5", prompt, tools: { done: tool({}) }, stopWhen: hasToolCall("done") });',
        'return generateText({ model: "openai/gpt-5", prompt, tools: {}, maxSteps: Infinity });')]
    ts_lines = AGENT_TS.split("\n")
    ts_trues = [i + 1 for i, x in enumerate(ts_lines) if x.strip() == "while (true) {"]
    assert len(ts_trues) == 2   # loopUntilDone, and the look-alike roomLoop
    expected.append(("web/agent.ts", ts_trues[0]))
    assert found == sorted(expected)
    assert not [f for f in sec["findings"] if f["rule"] == RULE and f["file"] == "bot/safe.py"]


def test_what_the_finding_says_and_the_record(tmp_path):
    """The finding names each round's paid call and the condition on the model's answer that ends the loop; it is a
    heuristic (`tool_confidence: LOW`), ranked medium, CWE 834 (excessive iteration). The flow step's record counts
    the paid calls, the loops that make one each round and end on the model's answer, those that a count, a clock or
    a budget ends, those where a person says yes to each round, and the library settings with their limit off."""
    sec = _scan(tmp_path)
    mine = {(f["file"], f["line"]): f for f in sec["findings"] if f["rule"] == RULE}
    f = mine[("bot/agent.py", _at(AGENT_PY, "while resp.stop_reason == \"tool_use\":"))]
    assert f["tool"] == "lantern-flow"
    assert f["tool_severity"] == "MEDIUM" and f["tool_confidence"] == "LOW" and f["cwe"] == 834
    assert f["rank"] == "medium"
    loop = f["agent_loop"]
    assert loop["kind"] == "loop"
    creates = [i + 1 for i, x in enumerate(AGENT_PY.split("\n"))
               if x.strip().startswith("resp = client.messages.create(")]
    assert len(creates) == 5    # the third is the one inside agent_while_tools' loop
    assert loop["paid"] == [{"file": "bot/agent.py", "line": creates[2], "what": "client.messages.create()"}]
    assert loop["ends"] == [{"line": f["line"], "what": "resp.stop_reason"}]
    assert "only the model's answer" in f["title"]
    helper = mine[("bot/agent.py", _at(AGENT_PY, "resp = ask(messages)") - 1)]
    assert helper["agent_loop"]["paid"] == [{"file": "bot/agent.py", "line": _at(AGENT_PY, "resp = ask(messages)"),
                                             "what": "ask()", "through": "bot/llm.py:%d" % _at(
                                                 LLM_PY, 'return claude.messages.create(model="claude-haiku-5-5", '
                                                         'max_tokens=1024, messages=messages)')}]
    itself = mine[("bot/agent.py", _at(AGENT_PY, "return agent_again(messages)"))]
    assert itself["agent_loop"]["kind"] == "itself" and "calls itself" in itself["title"]
    setting = mine[("bot/agent.py", _at(AGENT_PY, "return AgentExecutor(agent=agent, tools=tools, "
                                                   "max_iterations=None)"))]
    assert setting["agent_loop"]["kind"] == "setting" and "max_iterations=None" in setting["more_info"]
    # the story and the case: a kind of their own, the paid call and the condition that ends the rounds as facts,
    # and a limit kept outside the code as what Lantern does not know
    assert f["scenario"]["kind"] == "agent-loop" and f["headline"] == (
        "An AI agent may keep calling a paid AI model with no limit"), (f["scenario"]["kind"], f.get("headline"))
    assert "resp.stop_reason" in f["scenario"]["basis"], f["scenario"]["basis"]
    assert "heuristic" in f["scenario"]["harm"], f["scenario"]["harm"]
    case = f["case"]
    assert case["claim"].startswith(f["title"].rstrip(".")) and "outside the code" in case["claim"], case["claim"]
    assert {"fact": "A paid model call is made in each round: `client.messages.create()` at bot/agent.py:%d"
                    % creates[2], "from": "data flow"} in case["evidence"], case["evidence"]
    assert {"fact": "What ends the rounds reads the model's answer: `resp.stop_reason` on line %d" % f["line"],
            "from": "code"} in case["evidence"], case["evidence"]
    met = {c["need"]: c["met"] for c in case["conditions"]}
    assert met["Each round makes a paid call to the model"] is True, met
    assert met["Only the model's answer ends the rounds"] is True, met
    assert met["Nothing outside the code stops it (a spending limit set with the provider, a time limit on the "
               "request)"] is None, met
    assert any("calls itself again" in s for s in itself["scenario"]["steps"]), itself["scenario"]["steps"]
    helped = {e["fact"] for e in helper["case"]["evidence"]}
    assert "A paid model call is made in each round: `ask()` at bot/agent.py:%d, which reaches the model call at " \
           "bot/llm.py:%d" % (_at(AGENT_PY, "resp = ask(messages)"), _at(LLM_PY, 'return claude.messages.create('
                                                                      'model="claude-haiku-5-5", max_tokens=1024, '
                                                                      'messages=messages)')) in helped, helped
    off = {c["need"]: c["met"] for c in setting["case"]["conditions"]}
    assert off["The agent's own limit on its rounds is switched off"] is True, off
    assert setting["scenario"]["kind"] == "agent-loop" and any(
        "switched off" in s for s in setting["scenario"]["steps"]), setting["scenario"]["steps"]
    rec = next(r for r in sec["tools"] if r["tool"] == "lantern-flow")
    # paid calls written in the code: 7 in bot/agent.py, 2 in bot/llm.py, 9 in bot/safe.py (Ollama runs on this
    # computer and is not one), 12 in web/agent.ts
    assert rec["scope"]["agent_loops"] == {"paid_calls": 30, "loops": 22, "capped": 9, "asked": 1,
                                           "settings_off": 3, "findings": 15}


def test_a_project_with_no_paid_call_has_no_record(tmp_path):
    """No paid model call, no agent loop: the record says nothing about it, and a loop of the project's own that ends
    on what a function hands back is no finding."""
    sec = scan(build_graph(_write(tmp_path, {"app/__init__.py": "", "app/loop.py": '''def step(state):
    return {"done": state["n"] > 3, "n": state["n"] + 1}


def run(state):
    while True:
        state = step(state)
        if state["done"]:
            return state
'''})))
    assert not [f for f in sec["findings"] if f["rule"] == RULE]
    rec = next(r for r in sec["tools"] if r["tool"] == "lantern-flow")
    assert "agent_loops" not in (rec.get("scope") or {})
