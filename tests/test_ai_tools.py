"""The AI-app pack, second version (roadmap of 2026-11-14, stage 5): a tool handed to a model that runs what the model
puts into it as a command, a query or code, or changes or removes the file it names (`LA-UNSAFE-MCP-TOOL`).

A model chooses a tool's arguments, and whoever can put words into what the model reads (a message, a web page, a
file, another tool's answer) can choose them through it. A tool that runs any command, any query or any code it is
given, or writes or removes any file, hands that choice on, unless it keeps to what it is for (a list of the code's
own, a folder it cannot leave, values passed as parameters) or a person approves each call. The data-flow step takes
the parameters of a function a library is told is a tool (an MCP server's, LangChain's, OpenAI's Agents SDK's,
Pydantic AI's, the AI SDK's) as what the model put into it, and follows them like what a request sent.

Each dangerous tool stands beside twins that must stay quiet and look-alikes that are no tool at all. Nothing here is
run, and no model is asked.
"""
from lantern.engine import build_graph
from lantern.security import scan

RULE = "LA-UNSAFE-MCP-TOOL"

SERVER_PY = '''import os
import shutil
import sqlite3
import subprocess
from pathlib import Path

import click
from mcp.server.fastmcp import Context, FastMCP

from srv.helpers import careful_clear, clear

mcp = FastMCP("files")
db = sqlite3.connect("notes.db")
ROOT = Path("/srv/notes").resolve()
ALLOWED = {"status", "log", "diff"}


# ---- dangerous: what the model puts into the tool is run, asked of the database, or changes or removes a file
@mcp.tool()
def run_command(command: str) -> str:
    """Run a shell command."""
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def query(sql: str) -> list:
    """Run SQL against the notes database."""
    return db.execute(sql).fetchall()


@mcp.tool
def delete_file(path: str) -> str:
    os.remove(path)
    return "removed"


@mcp.tool(name="save")
def save_note(name: str, text: str) -> str:
    with open(name, "w") as f:
        f.write(text)
    return "saved"


@mcp.tool()
def wipe(folder: str) -> str:
    return clear(folder)


@mcp.tool()
def wipe_cache(name: str) -> str:
    return clear("/tmp/cache/" + name)


@mcp.tool()
def calc(expression: str) -> str:
    return str(eval(expression))


@mcp.tool()
def run_after(command: str) -> str:
    out = subprocess.run(command, shell=True, capture_output=True, text=True).stdout
    click.confirm("Did that look right?")
    return out


def remove_tree(folder: str) -> str:
    shutil.rmtree(folder)
    return "removed"


mcp.add_tool(remove_tree)


# ---- safe twins: only read, a value handed to the database, a folder of the code's own, the code's own list, a
# program the code names, a person asked first, what it is given written into a file of the code's own
@mcp.tool()
def read_note(name: str) -> str:
    return open(os.path.join(ROOT, name)).read()


@mcp.tool()
def note_by_id(note_id: int) -> list:
    return db.execute("select body from notes where id = ?", (note_id,)).fetchall()


@mcp.tool()
def find(term: str) -> list:
    return db.execute("select body from notes where body like ?", ("%" + term + "%",)).fetchall()


@mcp.tool()
def remove_note(name: str) -> str:
    target = (ROOT / name).resolve()
    if not target.is_relative_to(ROOT):
        raise ValueError("outside the notes folder")
    target.unlink()
    return "removed"


@mcp.tool()
def git(sub: str) -> str:
    if sub not in ALLOWED:
        raise ValueError("not allowed")
    return subprocess.run("git " + sub, shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def git_log(term: str) -> str:
    return subprocess.run(["git", "log", "--grep", term], capture_output=True, text=True).stdout


@mcp.tool()
async def run_approved(command: str, ctx: Context) -> str:
    answer = await ctx.elicit(f"Run {command}?", response_type=bool)
    if answer.action != "accept" or not answer.data:
        return "not run"
    return subprocess.run(command, shell=True, text=True).stdout


@mcp.tool()
def purge(folder: str) -> str:
    return careful_clear(folder)


@mcp.tool()
def jot(note: str) -> str:
    (ROOT / "jotted.txt").write_text(note)
    return "kept"


@mcp.tool()
def log_line(line: str) -> str:
    with open("notes.log", "a") as f:
        f.write(line)
    return "logged"


# ---- look-alikes: functions of the code that no model is handed
def admin_run(command):
    return subprocess.run(command, shell=True).returncode


class Toolbox:
    def tool(self, f):
        return f


box = Toolbox()


@box.tool
def local_run(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True).stdout
'''

HELPERS_PY = '''import shutil

import click


def clear(folder):
    shutil.rmtree(folder)
    return "cleared"


def careful_clear(folder):
    if not click.confirm(f"Remove everything under {folder}?"):
        return "kept"
    shutil.rmtree(folder, ignore_errors=True)
    return "cleared"
'''

APP_PY = '''from fastmcp import FastMCP

mcp = FastMCP("notes")
'''

MORE_PY = '''import os

from srv.app import mcp


@mcp.tool()
def shell_more(command: str) -> str:
    return os.popen(command).read()
'''

AGENTS_PY = '''import sqlite3
import subprocess

from agents import function_tool
from langchain_core.tools import tool
from mcp.server.lowlevel import Server
from pydantic_ai import Agent, RunContext

db = sqlite3.connect("notes.db")
low = Server("low")
agent = Agent("openai:gpt-4o")


@tool
def shell(command: str) -> str:
    """Run a shell command."""
    return subprocess.check_output(command, shell=True, text=True)


@tool("lookup")
def lookup(word: str) -> str:
    """Look a word up in the dictionary."""
    return subprocess.check_output(["dict", word], text=True)


@function_tool
def forget(title: str) -> str:
    db.execute(f"delete from notes where title = '{title}'")
    return "forgotten"


@function_tool(needs_approval=True)
def forget_approved(title: str) -> str:
    db.execute(f"delete from notes where title = '{title}' and kept = 0")
    return "forgotten"


@agent.tool_plain
def run_plain(command: str) -> str:
    return subprocess.getoutput(command)


@agent.tool
def run_with(ctx: RunContext[str], command: str) -> str:
    return subprocess.getoutput(command + " --quiet")


@low.call_tool()
async def call(name: str, arguments: dict) -> list:
    if name == "exec":
        subprocess.Popen(arguments["command"], shell=True)
    return []
'''

SERVER_TS = '''import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { tool } from "ai";
import { exec, execFile, execSync } from "child_process";
import fs from "fs";
import path from "path";
import { z } from "zod";

const ROOT = path.resolve("notes");
const server = new McpServer({ name: "files", version: "1.0.0" });

// ---- dangerous
server.tool("run", { command: z.string() }, async ({ command }) => {
  exec(command);
  return { content: [] };
});

server.registerTool("remove", { inputSchema: { target: z.string() }, annotations: { destructiveHint: true } },
  async ({ target }) => {
    fs.rmSync(target, { recursive: true });
    return { content: [] };
  });

async function writeNote({ file, text }: { file: string; text: string }) {
  fs.writeFileSync(file, text);
  return { content: [] };
}
server.tool("write", { file: z.string(), text: z.string() }, writeNote);

export const shellTool = tool({
  description: "Run a shell command",
  inputSchema: z.object({ command: z.string() }),
  execute: async ({ command }) => execSync(command).toString(),
});

export const unconfirmed = tool({
  description: "Approval written and switched off",
  inputSchema: z.object({ command: z.string() }),
  needsApproval: false,
  execute: async ({ command }) => execSync(command, { stdio: "pipe" }).toString(),
});

const low = new Server({ name: "low", version: "1.0.0" }, { capabilities: { tools: {} } });
low.setRequestHandler(CallToolRequestSchema, async (request) => {
  const args = request.params.arguments ?? {};
  execSync(String(args.command));
  return { content: [] };
});

// ---- safe twins
server.tool("read", { file: z.string() }, async ({ file }) => {
  return { content: [{ type: "text", text: fs.readFileSync(file, "utf8") }] };
});

server.tool("removeNote", { name: z.string() }, async ({ name }) => {
  const full = path.resolve(ROOT, name);
  if (!full.startsWith(ROOT + path.sep)) throw new Error("outside the notes folder");
  fs.rmSync(full);
  return { content: [] };
});

server.tool("log", { term: z.string() }, async ({ term }) => {
  execFile("git", ["log", "--grep", term]);
  return { content: [] };
});

server.tool("jot", { text: z.string() }, async ({ text }) => {
  fs.appendFileSync(path.join(ROOT, "jotted.txt"), text);
  return { content: [] };
});

export const confirmedShell = tool({
  description: "Run a shell command once a person said yes",
  inputSchema: z.object({ command: z.string() }),
  needsApproval: true,
  execute: async ({ command }) => execSync(command, { encoding: "utf8" }),
});

// ---- look-alike: a registry of the project's own
class Toolbelt {
  tool(name: string, fn: (a: { command: string }) => unknown) {
    return fn;
  }
}
const belt = new Toolbelt();
belt.tool("run", async ({ command }) => exec(command));
'''

LC_TS = '''import { tool } from "@langchain/core/tools";
import { execSync } from "child_process";
import { z } from "zod";

export const shell = tool(async ({ command }) => execSync(command).toString(), {
  name: "shell",
  description: "Run a shell command",
  schema: z.object({ command: z.string() }),
});
'''

FILES = {"srv/__init__.py": "", "srv/server.py": SERVER_PY, "srv/helpers.py": HELPERS_PY, "srv/app.py": APP_PY,
         "srv/more_tools.py": MORE_PY, "srv/agents_tools.py": AGENTS_PY,
         "web/package.json": '{"dependencies": {"@modelcontextprotocol/sdk": "^1.20.0", "ai": "^5.0.0", '
                             '"@langchain/core": "^0.3.0", "zod": "^3.25.0"}}',
         "web/src/server.ts": SERVER_TS, "web/src/lc.ts": LC_TS}


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


def test_a_tool_that_runs_what_the_model_puts_into_it(tmp_path):
    """Dangerous: tools of an MCP server (Python's FastMCP as `@mcp.tool`, `@mcp.tool()`, `@mcp.tool(name=...)`,
    `mcp.add_tool(f)` and from a server made in another file; the low-level server's `@server.call_tool()`;
    TypeScript's `server.tool`, `server.registerTool`, a handler named by its function, and the low-level
    `setRequestHandler(CallToolRequestSchema, ...)`), LangChain's `@tool` and `tool(...)`, OpenAI's Agents SDK's
    `@function_tool`, Pydantic AI's `@agent.tool` and `@agent.tool_plain`, and the AI SDK's `tool({ execute })`, each
    running what it is given as a shell command, a query, code, or the file it writes or removes, also in a helper of
    another file. An MCP annotation (`destructiveHint`) asks nobody, an approval flag written `false` is none, and a
    person asked after the command ran is no gate. Safe twins: a tool that only reads a file, hands the value to the
    database as a parameter, keeps a path inside a folder of the code's own, checks the value against the code's own
    list, hands it to a program the code names, asks a person first (an MCP elicitation, a confirm in the helper
    before the action, the library's approval flag), or writes what it is given into a file the code names. Look-alikes: a function of the code no model is handed, and a
    registry of the project's own with a method called `tool`."""
    sec = scan(build_graph(_write(tmp_path, FILES)))
    found = sorted((f["file"], f["line"]) for f in sec["findings"] if f["rule"] == RULE)
    expected = [("srv/server.py", _at(SERVER_PY, line)) for line in (
        "return subprocess.run(command, shell=True, capture_output=True, text=True).stdout",
        "return db.execute(sql).fetchall()",
        "os.remove(path)",
        'with open(name, "w") as f:',
        "return str(eval(expression))",
        "out = subprocess.run(command, shell=True, capture_output=True, text=True).stdout",
        "shutil.rmtree(folder)")]
    expected += [("srv/helpers.py", _at(HELPERS_PY, "shutil.rmtree(folder)")),
                 ("srv/more_tools.py", _at(MORE_PY, "return os.popen(command).read()"))]
    expected += [("srv/agents_tools.py", _at(AGENTS_PY, line)) for line in (
        "return subprocess.check_output(command, shell=True, text=True)",
        "db.execute(f\"delete from notes where title = '{title}'\")",
        "return subprocess.getoutput(command)",
        'return subprocess.getoutput(command + " --quiet")',
        'subprocess.Popen(arguments["command"], shell=True)')]
    expected += [("web/src/server.ts", _at(SERVER_TS, line)) for line in (
        "exec(command);",
        "fs.rmSync(target, { recursive: true });",
        "fs.writeFileSync(file, text);",
        "execute: async ({ command }) => execSync(command).toString(),",
        'execute: async ({ command }) => execSync(command, { stdio: "pipe" }).toString(),',
        "execSync(String(args.command));")]
    expected += [("web/src/lc.ts", _at(LC_TS, "export const shell = tool(async ({ command }) => "
                                              "execSync(command).toString(), {"))]
    assert found == sorted(expected), found
    rec = next(r for r in sec["tools"] if r["tool"] == "lantern-flow")
    assert rec["scope"]["flows"] == 0, rec["scope"]        # what a request sent: here none of it reaches an action
    assert "model_text" not in rec["scope"], rec["scope"]
    # 39 tools; 28 flows: 22 to the 21 findings (two tools reach the helper's `rmtree`), 4 where a person is asked
    # first (an elicitation, a confirm in the helper, two approval flags), 2 to a file that is only read; what is
    # written into a file the code names is no flow to a file's place
    assert rec["scope"]["tool_text"] == {"tools": 39, "flows": 28, "findings": 21, "approval_asked": 4,
                                         "reads_only": 2, "on_model_findings": 0}, rec["scope"]
    by = {(f["file"], f["line"]): f for f in sec["findings"] if f["rule"] == RULE}
    one = by[("srv/server.py", _at(SERVER_PY, "return subprocess.run(command, shell=True, capture_output=True, "
                                              "text=True).stdout"))]
    assert one["tool"] == "lantern-flow" and one["tool_confidence"] == "LOW" and one["cwe"] == 78, one
    assert one["title"] == "A tool handed to the model uses what it is given as a shell command", one["title"]
    assert one["rank"] == "high" and one["input"] is None, (one["rank"], one.get("input"))
    fl = one["flow"]
    assert fl["origin"] == "tool" and fl["class"] == "shell" and fl["count"] == 1, fl
    assert (fl["source"]["file"], fl["source"]["line"]) == (
        "srv/server.py", _at(SERVER_PY, "def run_command(command: str) -> str:")), fl["source"]
    assert "`command`" in fl["source"]["what"] and "`run_command`" in fl["source"]["what"], fl["source"]
    assert "Heuristic" in one["more_info"] and "approve" in one["more_info"], one["more_info"]
    assert any(e["fact"].startswith("What the model puts into the tool was followed to this line")
               for e in one["case"]["evidence"]), one["case"]["evidence"]
    # the helper of another file that two tools hand a folder to: one finding, both tools on it
    helper = by[("srv/helpers.py", _at(HELPERS_PY, "shutil.rmtree(folder)"))]
    assert helper["flow"]["count"] == 2 and helper["flow"]["source"]["file"] == "srv/server.py", helper["flow"]
    assert helper["title"] == ("A tool handed to the model uses what it is given as the path of a file it writes or "
                               "removes"), helper["title"]
    assert helper["cwe"] == 22, helper["cwe"]
    assert by[("srv/server.py", _at(SERVER_PY, "return db.execute(sql).fetchall()"))]["cwe"] == 89
    assert by[("srv/server.py", _at(SERVER_PY, "return str(eval(expression))"))]["cwe"] == 94
    # the TypeScript server's own tool, handed the model's arguments as one object taken apart
    ts = by[("web/src/server.ts", _at(SERVER_TS, "exec(command);"))]
    assert ts["flow"]["origin"] == "tool" and ts["flow"]["source"]["file"] == "web/src/server.ts", ts["flow"]
    assert "`run`" in ts["flow"]["source"]["what"], ts["flow"]["source"]
    # the low-level servers' one handler is handed every call of every tool: no tool's name is said for it
    for file, text, line in (("srv/agents_tools.py", AGENTS_PY, 'subprocess.Popen(arguments["command"], shell=True)'),
                             ("web/src/server.ts", SERVER_TS, "execSync(String(args.command));")):
        what = by[(file, _at(text, line))]["flow"]["source"]["what"]
        assert "a call of any tool of the server" in what and "the tool `" not in what, what


def test_what_a_tool_is_handed_is_not_taken_for_what_a_request_sent(tmp_path):
    """What the model puts into a tool is followed to the actions this rule names, and to no other rule's: the file a
    tool only reads is not "a path the request chose" (LT-PATH), a row it picks by number is not "a record picked by
    an id from the request" (LT-AUTHZ-OWNER), and the low-level MCP handler's parameter called `request` is the
    model's call of a tool, not a request a visitor sent to a route. Those are not claimed, so they are said nowhere,
    and no finding of another tool carries a tool's flow."""
    sec = scan(build_graph(_write(tmp_path, FILES)))
    from_flows = sorted((f["rule"], f["file"], f["line"]) for f in sec["findings"]
                        if f["rule"].startswith("LT-") and f["file"].startswith(("srv/", "web/")))
    assert from_flows == [], from_flows
    shell = [f for f in sec["findings"] if f.get("flow") and f["rule"] != RULE]
    assert all((f["flow"].get("origin") or "server") != "tool" for f in shell), \
        [(f["rule"], f["file"], f["line"]) for f in shell]


# ---- tools written as classes of a library's tool class, and functions handed to an agent in a list
AGENTBASE_PY = '''from langchain_core.tools import BaseTool


class GuardedTool(BaseTool):
    """A base for the project's own tools."""
'''

CLASSES_PY = '''import subprocess
from typing import Optional

from crewai.tools import BaseTool as CrewTool
from langchain_core.callbacks import CallbackManagerForToolRun
from langchain_core.tools import BaseTool
from smolagents import Tool

from srv.agentbase import GuardedTool


class ShellTool(BaseTool):
    name: str = "shell"
    description: str = "Run a shell command"

    def _run(self, command: str, run_manager: Optional[CallbackManagerForToolRun] = None) -> str:
        return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

    async def _arun(self, command: str) -> str:
        return subprocess.getoutput(command)

    def describe(self, command: str) -> str:
        return subprocess.getoutput("man " + command)


class CrewShell(CrewTool):
    name: str = "crew_shell"
    description: str = "Run a command"

    def _run(self, command: str) -> str:
        return subprocess.check_output(command, shell=True, text=True)


class SmolShell(Tool):
    name = "smol_shell"
    description = "Run a command"
    inputs = {"command": {"type": "string", "description": "the command"}}
    output_type = "string"

    def forward(self, command: str):
        return subprocess.getoutput("set -e; " + command)


class LoudShell(GuardedTool):
    name: str = "loud"

    def _run(self, command: str) -> str:
        return subprocess.getoutput(command + " | tee loud.log")


# ---- safe twin: the folder is handed to a program the code names
class ListTool(BaseTool):
    name: str = "list"
    description: str = "List a folder"

    def _run(self, folder: str) -> str:
        return subprocess.run(["ls", "--", folder], capture_output=True, text=True).stdout


# ---- look-alike: a class of the project's own with a method called `_run`
class Runner:
    def _run(self, command: str) -> str:
        return subprocess.getoutput("echo " + command)
'''

GRAPH_PY = '''import subprocess

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import ToolNode, create_react_agent


def run_listed(command: str) -> str:
    """Run a command."""
    return subprocess.getoutput(command)


def run_noded(command: str) -> str:
    return subprocess.getoutput(command + " &")


def run_bound(command: str) -> str:
    return subprocess.getoutput(command + " 2>&1")


def listed_only(word: str) -> str:
    """Look a word up."""
    return subprocess.run(["dict", word], capture_output=True, text=True).stdout


def not_handed(command: str) -> str:
    return subprocess.getoutput("nice " + command)


def build():
    tools = [run_listed, listed_only]
    agent = create_react_agent(ChatOpenAI(model="gpt-4o"), tools)
    node = ToolNode([run_noded])
    llm = ChatOpenAI(model="gpt-4o")
    bound = llm.bind_tools([run_bound])
    return agent, node, bound
'''

SDK_TS = '''import { generateText, streamText } from "ai";
import { openai } from "@ai-sdk/openai";
import { execFileSync, execSync } from "child_process";
import { z } from "zod";

export async function ask(prompt: string) {
  return generateText({
    model: openai("gpt-4o"),
    prompt,
    tools: {
      run: {
        description: "Run a command",
        inputSchema: z.object({ command: z.string() }),
        execute: async ({ command }) => execSync(command).toString(),
      },
      list: {
        description: "List a folder",
        inputSchema: z.object({ folder: z.string() }),
        execute: async ({ folder }) => execFileSync("ls", ["--", folder]).toString(),
      },
    },
  });
}

const kit = {
  shell: {
    description: "Run a command",
    inputSchema: z.object({ command: z.string() }),
    execute: async ({ command }: { command: string }) => execSync(command, { stdio: "pipe" }).toString(),
  },
};

export function stream(prompt: string) {
  return streamText({ model: openai("gpt-4o"), prompt, tools: kit });
}

// look-alike: an object of the same shape that no model is handed
const plain = {
  shell: { execute: async ({ command }: { command: string }) => execSync(command + " --dry-run").toString() },
};
export const keep = plain;
'''

MORE_FILES = {"srv/__init__.py": "", "srv/agentbase.py": AGENTBASE_PY, "srv/classes.py": CLASSES_PY,
              "srv/graph.py": GRAPH_PY,
              "web/package.json": '{"dependencies": {"ai": "^5.0.0", "@ai-sdk/openai": "^2.0.0", "zod": "^3.25.0"}}',
              "web/src/sdk.ts": SDK_TS}


def test_tools_written_as_classes_and_handed_over_in_lists(tmp_path):
    """Dangerous: a class made from LangChain's `BaseTool` (its `_run` and `_arun`), also through a class of the
    project's own in another file, CrewAI's `BaseTool` imported under another name and smolagents' `Tool` (its
    `forward`); functions handed to LangGraph's `create_react_agent` in a list kept under a name, to its `ToolNode`
    and to a chat model's `bind_tools`; the AI SDK's tools written as plain objects in `generateText` and in an object
    kept under a name and handed to `streamText`. Safe twins: a folder handed to a program the code names. Look-alikes:
    a method of such a class that a call of the tool does not run, a class of the project's own with a `_run`, a
    function no agent is handed, and an object of the same shape that no model is handed."""
    sec = scan(build_graph(_write(tmp_path, MORE_FILES)))
    found = sorted((f["file"], f["line"]) for f in sec["findings"] if f["rule"] == RULE)
    expected = [("srv/classes.py", _at(CLASSES_PY, line)) for line in (
        "return subprocess.run(command, shell=True, capture_output=True, text=True).stdout",
        "return subprocess.getoutput(command)",
        "return subprocess.check_output(command, shell=True, text=True)",
        'return subprocess.getoutput("set -e; " + command)',
        'return subprocess.getoutput(command + " | tee loud.log")')]
    expected += [("srv/graph.py", _at(GRAPH_PY, line)) for line in (
        "return subprocess.getoutput(command)",
        'return subprocess.getoutput(command + " &")',
        'return subprocess.getoutput(command + " 2>&1")')]
    expected += [("web/src/sdk.ts", _at(SDK_TS, line)) for line in (
        "execute: async ({ command }) => execSync(command).toString(),",
        'execute: async ({ command }: { command: string }) => execSync(command, { stdio: "pipe" }).toString(),')]
    assert found == sorted(expected), found
    rec = next(r for r in sec["tools"] if r["tool"] == "lantern-flow")
    # 13 tools: ShellTool's two methods, CrewShell, SmolShell, LoudShell, ListTool; four functions handed in lists;
    # three objects of the AI SDK. 10 flows, one to each finding
    assert rec["scope"]["tool_text"] == {"tools": 13, "flows": 10, "findings": 10, "approval_asked": 0,
                                         "reads_only": 0, "on_model_findings": 0}, rec["scope"]
    by = {(f["file"], f["line"]): f for f in sec["findings"] if f["rule"] == RULE}
    for file, text, line, name in (
            ("srv/classes.py", CLASSES_PY, "return subprocess.run(command, shell=True, capture_output=True, "
                                           "text=True).stdout", "ShellTool"),
            ("srv/classes.py", CLASSES_PY, 'return subprocess.getoutput(command + " | tee loud.log")', "LoudShell"),
            ("srv/graph.py", GRAPH_PY, "return subprocess.getoutput(command)", "run_listed"),
            ("web/src/sdk.ts", SDK_TS, "execute: async ({ command }) => execSync(command).toString(),", "run"),
            ("web/src/sdk.ts", SDK_TS, 'execute: async ({ command }: { command: string }) => execSync(command, '
                                       '{ stdio: "pipe" }).toString(),', "shell")):
        what = by[(file, _at(text, line))]["flow"]["source"]["what"]
        assert f"the tool `{name}`" in what and "`command`" in what, what


# ---- the MCP library's newer names (its Python `MCPServer` and its TypeScript package `@modelcontextprotocol/server`),
# a server made inside a function, and a function handed the server with its class written
NEWER_PY = """import os
import sqlite3
import subprocess

from mcp.server import MCPServer
from mcp.server.mcpserver import MCPServer as NotesServer

app = MCPServer("plain")


@app.tool()
def erase(path: str) -> str:
    os.remove(path)
    return "erased"


@app.tool()
def peek(path: str) -> str:
    with open(path) as f:
        return f.read()


def serve(folder: str) -> NotesServer:
    server = NotesServer("notes")

    @server.tool()
    def run(command: str) -> str:
        return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

    @server.tool(name="search")
    def search(term: str) -> list:
        db = sqlite3.connect("notes.db")
        return db.execute("select title from notes where body like ?", (f"%{term}%",)).fetchall()

    def drop(title: str) -> str:
        db = sqlite3.connect("notes.db")
        db.execute(f"delete from notes where title = '{title}'")
        return "gone"

    server.add_tool(drop)
    return server


def register(server: NotesServer) -> None:
    @server.tool()
    def shell(command: str) -> str:
        return subprocess.getoutput(command)

    @server.tool()
    def status() -> str:
        return subprocess.getoutput("git status")
"""

LOOKALIKE_PY = """import subprocess

from mcp.server.mcpserver import MCPServer

server = MCPServer("top")


class Registry:
    def tool(self):
        return lambda f: f


def build():
    server = Registry()

    @server.tool()
    def run_local(command: str) -> str:
        return subprocess.getoutput(command)

    return run_local


def attach(server):
    @server.tool()
    def run_any(command: str) -> str:
        return subprocess.getoutput(command + " --dry-run")

    return run_any
"""

NEWER_TS = """import { McpServer, Server } from "@modelcontextprotocol/server";
import { execSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";

const ROOT = path.resolve("/srv/files");

export function createServer(): McpServer {
  const server = new McpServer({ name: "files", version: "1.0.0" });
  server.registerTool("run", { description: "Run a command" }, async ({ command }) => {
    return { content: [{ type: "text", text: execSync(command).toString() }] };
  });
  server.registerTool("save", { description: "Save a note" }, async ({ name, text }) => {
    const target = path.resolve(ROOT, name);
    if (!target.startsWith(ROOT + path.sep)) throw new Error("outside the files folder");
    fs.writeFileSync(target, text);
    return { content: [{ type: "text", text: "saved" }] };
  });
  return server;
}

export const registerWipe = (server: McpServer) => {
  server.registerTool("wipe", { description: "Remove a folder" }, async ({ folder }) => {
    fs.rmSync(folder, { recursive: true });
    return { content: [] };
  });
};

export function lowLevel() {
  const low = new Server({ name: "low", version: "1.0.0" }, { capabilities: { tools: {} } });
  low.setRequestHandler("tools/call", async (request, ctx) => {
    const args = request.params.arguments ?? {};
    execSync(String(args.command));
    return { content: [] };
  });
  low.setRequestHandler("prompts/get", async (request) => {
    execSync("echo " + String(request.params.name).length);
    return { messages: [] };
  });
  return low;
}
"""

NEWER_FILES = {"srv/__init__.py": "", "srv/newer.py": NEWER_PY, "srv/lookalike.py": LOOKALIKE_PY,
               "web/package.json": '{"dependencies": {"@modelcontextprotocol/server": "^2.0.0"}}',
               "web/src/newer.ts": NEWER_TS}


def test_the_mcp_librarys_newer_names_and_a_server_made_inside_a_function(tmp_path):
    """The MCP library's newer names: its Python server class `MCPServer` (imported from `mcp.server` or
    `mcp.server.mcpserver`, also under another name) and its TypeScript package `@modelcontextprotocol/server`
    (`McpServer.registerTool`; the low-level `Server`, whose handler for `"tools/call"` is handed every call). A
    server is also found where a function makes it (`server = MCPServer(...)` in `serve()`, tools written inside the
    function with `@server.tool()` or handed to `server.add_tool(f)`) and where a function is handed it with its class
    written (`def register(server: MCPServer)`, `(server: McpServer) =>`). Dangerous: a tool that runs a command, a
    query built with the value, a file removed or written at a path the model names. Safe twins: a tool that only
    reads a file, hands the value to the database as a parameter, runs a command the code fixes, or keeps the path
    inside a folder of the code's own; the low-level server's handler of another kind of request. Look-alikes: a
    function's own `server` that is a registry of the project's (it hides the file's MCP server of that name) and a
    function handed a `server` whose class is not written (Lantern cannot tell whose it is: no tool)."""
    sec = scan(build_graph(_write(tmp_path, NEWER_FILES)))
    found = sorted((f["file"], f["line"]) for f in sec["findings"] if f["rule"] == RULE)
    expected = [("srv/newer.py", _at(NEWER_PY, line)) for line in (
        "os.remove(path)",
        "return subprocess.run(command, shell=True, capture_output=True, text=True).stdout",
        "db.execute(f\"delete from notes where title = '{title}'\")",
        "return subprocess.getoutput(command)")]
    expected += [("web/src/newer.ts", _at(NEWER_TS, line)) for line in (
        'return { content: [{ type: "text", text: execSync(command).toString() }] };',
        "fs.rmSync(folder, { recursive: true });",
        "execSync(String(args.command));")]
    assert found == sorted(expected), found
    rec = next(r for r in sec["tools"] if r["tool"] == "lantern-flow")
    # Python: erase, peek, run, search, drop, shell, status; TypeScript: run, save, wipe, the low-level handler
    assert rec["scope"]["tool_text"]["tools"] == 11, rec["scope"]
    assert rec["scope"]["tool_text"]["findings"] == 7 and rec["scope"]["tool_text"]["reads_only"] == 1, rec["scope"]
    by = {(f["file"], f["line"]): f for f in sec["findings"] if f["rule"] == RULE}
    for line, name in (("return subprocess.run(command, shell=True, capture_output=True, text=True).stdout", "run"),
                       ("return subprocess.getoutput(command)", "shell")):
        what = by[("srv/newer.py", _at(NEWER_PY, line))]["flow"]["source"]["what"]
        assert f"the tool `{name}`" in what and "`command`" in what, what
    low = by[("web/src/newer.ts", _at(NEWER_TS, "execSync(String(args.command));"))]["flow"]["source"]["what"]
    assert "a call of any tool of the server" in low, low
