"""Three-Lens explanations with mechanical anchor validation, plus a scenario.

Lens 1 (technical), Lens 2 (everyday, no jargon, one example, one analogy from a single
"metaphor world" per repo), Lens 3 (the everyday text again, where each plain phrase is pinned
1:1 to a technical term, symbol or line range), and a Scenario: a short story of one named person
using the app so that this code runs (and, per finding, meeting the finding). Scenarios follow the
Lens 2 rules (no code identifiers) and may only name pages and routes the context shows; a scenario
that breaks those rules is removed, never shown, and the viewer falls back to the deterministic
scenario `scenarios.py` builds for every finding.

The model only explains facts the graph and scanners already established. Every Lens 3 pair has
an anchor that is checked against the graph and the source; explanations that fail are retried
once with the errors, then stored as `validated: false` and flagged in the viewer.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from .graph import Graph, Node
from .providers import AllowanceExhausted, Provider, ProviderError

PROMPT_VERSION = "lens-v4"

# Technical vocabulary a Lens 3 "term" anchor may use even if it doesn't appear verbatim in the code.
GLOSSARY = {
    "function", "method", "class", "object", "instance", "constructor", "argument", "parameter",
    "return value", "exception", "raise", "loop", "recursion", "callback", "decorator", "module",
    "import", "inheritance", "subclass", "override", "attribute", "dictionary", "list", "string",
    "integer", "boolean", "none", "iterator", "generator", "coroutine", "async", "await", "thread",
    "lock", "mutex", "queue", "cache", "hash", "hash function", "encryption", "jwt", "token", "http",
    "http request", "http response", "status code", "route", "endpoint", "api", "json",
    "serialization", "database", "sql", "query", "sql injection", "transaction", "connection",
    "cursor", "file handle", "path", "environment variable", "config", "logging", "subprocess",
    "shell", "shell injection", "command injection", "socket", "timeout", "retry", "regex",
    "validation", "authentication", "authorization", "session", "cookie", "password hash", "salt",
    "md5", "sha256", "bcrypt", "argon2", "cli", "command-line argument", "test", "assertion",
    "side effect", "state", "global variable", "scope", "closure", "lambda", "type hint",
    # web and app vocabulary the explanations keep reaching for
    "sanitization", "sanitize", "escaping", "escape", "input validation", "xss", "cross-site scripting",
    "html", "dom", "render", "rendering", "component", "props", "hook", "event handler", "click handler",
    "fetch", "request", "response", "url", "header", "headers", "payload", "form", "button", "page",
    "redirect", "command", "process", "secret", "api key", "credential", "credentials", "login", "logout",
    "user", "record", "row", "table", "schema", "backup", "archive", "parameter binding", "placeholder",
    "injection", "hard-coded", "hardcoded", "plaintext", "entry point", "main", "startup",
    # web / full stack
    "component", "react component", "hook", "props", "render", "jsx", "event handler", "click handler",
    "fetch", "promise", "api route", "api call", "mutation", "form", "form submission", "page", "router",
    "frontend", "backend", "server", "browser", "cors", "xss", "cross-site scripting", "local storage",
    "environment variable", "row level security", "middleware", "dependency injection", "rest api",
    "http method", "get request", "post request", "put request", "delete request", "url", "query string",
}

SYSTEM = """You explain code to people learning to understand software they built with AI help.
You write three lenses for ONE code unit, grounded ONLY in the context provided. Never invent
functions, files or behavior that the context does not show. If something is unknown, say so.

LENS 1 - TECHNICAL: precise, for an engineer. What it does, inputs, outputs, side effects, errors,
and its role in the call path. Name only functions that appear in the CODE, CALLS, CALLED BY or
ALLOWED SYMBOLS; never a function the context does not show.
LENS 2 - EVERYDAY: zero jargon and no code identifiers. Include one concrete example ("if someone
types...") and one analogy drawn ONLY from the metaphor world given. Short sentences.
LENS 3 - MAPPED: rewrite the Lens 2 explanation as `text`, then list `pairs`. Each pair maps one
plain phrase that appears VERBATIM in `text` to the exact technical thing it stands for. Every pair
needs an anchor:
  {"type":"symbol","id":"<an id from ALLOWED SYMBOLS; external calls like ext:... are symbols too>"}
  {"type":"lines","start":N,"end":M}   (within the unit's line range)
  {"type":"term","term":"<a whole word or name that appears in the CODE lines shown, or a standard CS term>"}
A `term` must be visible in this unit's own CODE lines. For anything that lives in another function
or file (a callee, a caller, a library), anchor with its symbol id instead.
Before you answer, check every pair: find its `plain` inside `text` with an exact search. If it is
not there, change `plain` to words that are, or drop the pair.
Use exactly 4 or 5 pairs covering the main ideas. Plain phrases must be short (1-6 words) and distinct.

SCENARIO: one short story (2 to 4 sentences) of a named person using the app so that this unit
runs: what they do (a page they open, a button they press, what they type), what this code then
does, and what they see. Plain words, no code identifiers. Name only pages and routes listed under
ENTRY POINT, REACHED FROM or MAKES HTTP REQUESTS; if none is listed, tell it from the point of view
of whoever calls this code.

If SECURITY FINDINGS are listed, add `findings` explaining each one in lens1 and lens2 terms,
including why it matters and the safest fix in one sentence, and a `scenario`: 2 to 4 plain
sentences in which a named tester (for example "Maria, a tester") meets this finding through the
page or route shown, what goes wrong, and what the fix changes. Do not judge whether a finding is a
false positive.

Rarely, this unit's own CODE lines are not enough to explain it honestly (the body is cut off, or it
is empty). Then do not guess: return lens1 for what is visible and `"undetermined": "<one sentence
saying what is missing>"` instead of lens2 and lens3. Callees whose bodies you cannot see are NOT a
reason: their one-line summaries under CALLS are what you explain them by. An honest "cannot tell"
beats an invented explanation, but a visible body always gets lens2 and lens3.

Respond with ONLY a json object (valid JSON), no markdown fences:
{"lens1":{"summary":str,"inputs":[str],"outputs":str,"side_effects":[str],"errors":[str],"role":str},
 "undetermined": str (only instead of lens2 and lens3, see above),
 "lens2":{"text":str,"example":str,"analogy":str},
 "lens3":{"text":str,"pairs":[{"plain":str,"technical":str,"anchor":{...}}]},
 "scenario":{"who":str,"story":str},
 "findings":[{"id":str,"lens1":str,"lens2":str,"fix":str,"scenario":str}]}"""

METAPHOR_SYSTEM = """Pick ONE everyday setting to use as a consistent metaphor world for explaining
this whole codebase to a non-programmer (examples: a restaurant kitchen, a hotel, a post office,
a library, an airport, a factory line). Choose the one whose roles best match what the code does.
Respond with ONLY json: {"world": str, "why": str, "roles": {"<code concept>": "<metaphor role>"}}"""


# --------------------------------------------------------------------------------------------
# Context
# --------------------------------------------------------------------------------------------

@dataclass
class Context:
    node: Node
    source: str
    allowed_symbols: dict[str, str]          # id -> display name
    line_range: tuple[int, int]
    findings: list[dict] = field(default_factory=list)
    callers: list[str] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)
    callee_summaries: dict[str, str] = field(default_factory=dict)
    metaphor: str = "a restaurant"
    reached_from: list[str] = field(default_factory=list)   # node ids from a page/route to this unit (the map's path)
    places: set[str] = field(default_factory=set)            # pages, routes and HTTP calls the prompt shows

    def hash(self) -> str:
        h = hashlib.sha256()
        h.update(json.dumps([self.node.fingerprint, sorted(self.callees), sorted(self.callers),
                             sorted(f["id"] for f in self.findings), self.metaphor, self.reached_from]).encode())
        return h.hexdigest()[:12]


def _term_in_code(term: str, code_lower: str) -> bool:
    """A term anchors only if it is a real name or phrase in the code: at least 3 characters with a letter, found as
    whole words (so "a", "1", or "|" can't anchor anything)."""
    if len(term) < 3 or not re.search(r"[^\W\d_]", term):
        return False
    return re.search(r"(?<![\w])" + re.escape(term) + r"(?![\w])", code_lower) is not None


def read_source(repo: Path, node: Node, max_lines: int = 160) -> str:
    try:
        lines = (repo / node.file).read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, TypeError):
        return ""
    start, end = (node.start_line or 1), (node.end_line or node.start_line or 1)
    chunk = lines[start - 1:end]
    if len(chunk) > max_lines:
        chunk = chunk[:max_lines] + [f"# ... {len(chunk) - max_lines} more lines truncated"]
    return "\n".join(f"{start + i:>5} | {ln}" for i, ln in enumerate(chunk))


def build_context(g: Graph, nid: str, findings: list[dict], done: dict[str, dict], metaphor: str,
                  reach: dict[str, dict] | None = None) -> Context:
    n = g.nodes[nid]
    repo = Path(g.repo_root)
    callees = [e.dst for e in g.callees(nid)]
    callers = [e.src for e in g.callers(nid)]
    allowed = {nid: n.qualname}
    for x in callees + callers + ([n.parent] if n.parent else []):
        if x in g.nodes:
            allowed[x] = g.nodes[x].qualname
    summaries = {c: done[c]["lens1"]["summary"] for c in callees if c in done and done[c].get("lens1")}
    mine = [f for f in findings if f.get("node") == nid]
    # The path from a page or route to this unit, for the scenario: a finding's own path first, else the map's.
    f_path = next((f.get("ui_path") or (f.get("reachable") or {}).get("path") for f in mine
                   if f.get("ui_path") or f.get("reachable")), None)
    path = [x for x in (f_path or ((reach or {}).get(nid) or {}).get("path") or []) if x in g.nodes]
    places = {str(g.nodes[x].entry.get("detail") or "") for x in path + [nid] if g.nodes[x].entry}
    places |= {str(e.detail or "") for x in path + [nid] for e in g.callees(x) if (e.via or "").startswith("http-")}
    places |= {str(e.detail or "") for e in g.callers(nid) if (e.via or "").startswith("http-")}
    return Context(node=n, source=read_source(repo, n), allowed_symbols=allowed,
                   line_range=(n.start_line or 1, n.end_line or n.start_line or 1),
                   findings=mine, callers=callers, callees=callees, callee_summaries=summaries, metaphor=metaphor,
                   reached_from=path if len(path) > 1 else [], places={p for p in places if p})


def render_prompt(ctx: Context, g: Graph) -> str:
    n = ctx.node
    lang = ("TypeScript/JavaScript" if (n.file or "").endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"))
            else "Go" if (n.file or "").endswith(".go") else "Rust" if (n.file or "").endswith(".rs")
            else "Java" if (n.file or "").endswith(".java") else "Kotlin" if (n.file or "").endswith(".kt")
            else "Swift" if (n.file or "").endswith(".swift") else "Dart" if (n.file or "").endswith(".dart")
            else "Python")
    parts = [
        f"METAPHOR WORLD: {ctx.metaphor}",
        f"LANGUAGE: {lang}",
        f"UNIT: {n.qualname}  ({n.kind}, {n.file} lines {ctx.line_range[0]}-{ctx.line_range[1]})",
        f"SIGNATURE: {n.signature or ''}",
    ]
    if n.entry:
        parts.append(f"ENTRY POINT: {n.entry['kind']} - {n.entry.get('detail', '')}")
    if n.docstring:
        parts.append(f"DOCSTRING: {n.docstring}")
    if ctx.reached_from:
        hops = []
        for a, b in zip(ctx.reached_from, ctx.reached_from[1:] + [None]):
            na = g.nodes[a]
            label = f"{na.entry['kind']} {na.entry.get('detail', '')}".strip() if na.entry else na.qualname
            e = next((e for e in g.callees(a) if e.dst == b), None) if b else None
            hops.append(label + (f" ({e.detail})" if e and e.detail else ""))
        parts.append("REACHED FROM (from the map, for the scenario): " + " -> ".join(hops))
    parts.append("SOURCE:\n" + (ctx.source or "(source unavailable)"))
    if ctx.callers:
        parts.append("CALLED BY: " + ", ".join(g.nodes[c].qualname for c in ctx.callers[:10] if c in g.nodes))
    http = [e for e in g.callees(n.id) if (e.via or "").startswith("http-")]
    if http:
        parts.append("MAKES HTTP REQUESTS (frontend to backend):\n" + "\n".join(
            f"  - {e.detail} -> handled by {g.nodes[e.dst].qualname if e.dst in g.nodes else e.dst[4:]}" for e in http))
    served = [e for e in g.callers(n.id) if (e.via or "").startswith("http-")]
    if served:
        parts.append("CALLED OVER HTTP BY THE FRONTEND FROM: " + ", ".join(
            g.nodes[e.src].qualname for e in served[:8] if e.src in g.nodes))
    if ctx.callees:
        lines = []
        for c in ctx.callees[:20]:
            if c not in g.nodes:
                continue
            s = ctx.callee_summaries.get(c)
            lines.append(f"  - {g.nodes[c].qualname}" + (f": {s}" if s else ""))
        parts.append("CALLS:\n" + "\n".join(lines))
    parts.append("ALLOWED SYMBOLS (for symbol anchors):\n" +
                 "\n".join(f"  {k}" for k in ctx.allowed_symbols))
    if ctx.findings:
        parts.append("SECURITY FINDINGS (from scanners, already verified as present):\n" + "\n".join(
            f"  - id={f['id']} [{f['rank']}] {f['rule']}: {f['title']} (line {f['line']})" +
            (f"; reachable via {' -> '.join(g.nodes[p].qualname for p in f['reachable']['path'] if p in g.nodes)}"
             if f.get("reachable") else "") for f in ctx.findings) +
            "\nYour `findings` array must have exactly these entries, with these ids copied as-is: " +
            json.dumps([{"id": f["id"], "lens1": "...", "lens2": "...", "fix": "..."} for f in ctx.findings]))
    return "\n\n".join(parts)


# --------------------------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------------------------

_IDENT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


def _code_identifiers(ctx: Context) -> set[str]:
    """Identifiers that look like code (snake_case, CamelCase, dotted) and so don't belong in Lens 2."""
    out = set()
    for q in ctx.allowed_symbols.values():
        for part in re.split(r"[./:]+", q):
            if "_" in part.strip("_") or (part[:1].isupper() and any(c.isupper() for c in part[1:])):
                out.add(part)
    return out


_NAME_RE = re.compile(r"\b(?:[A-Za-z_][\w]*\.)+[A-Za-z_]\w*\b|\b[a-z]+_[a-z_\d]+\b|\b[a-z]+[A-Z]\w+\b|\b[A-Za-z_]\w*(?=\()")
_NAME_SKIP = {"e.g", "i.e", "vs", "etc"}


def _unknown_names_in_lens1(l1: dict, ctx: Context) -> list[str]:
    """Code-looking names in Lens 1 (dotted, snake_case, camelCase, or called with parentheses) that appear nowhere
    in the unit's own code, its allowed symbols (callers, callees, parent), or the glossary."""
    blob = " ".join(str(l1.get(k, "")) for k in ("summary", "role", "outputs")) + " " + " ".join(
        str(x) for k in ("inputs", "side_effects", "errors") for x in (l1.get(k) or []) if isinstance(l1.get(k), list))
    # Everything the model was shown counts as context: this unit's code, the names of its callers, callees and
    # parent, the one-line summaries of its callees (which legitimately mention what those call), and its file.
    known = " ".join([ctx.source, ctx.node.file or "", *ctx.allowed_symbols.values(),
                      *ctx.callee_summaries.values()]).lower()
    out = []
    for m in _NAME_RE.finditer(blob):
        name = re.sub(r"^(?:self|this|cls)\.", "", m.group(0).strip("."))
        low = name.lower()
        if low in _NAME_SKIP or low in GLOSSARY or len(name) < 3:
            continue
        if re.search(r"\.(?:py|js|jsx|ts|tsx|json|db|sqlite|txt|md|html|css|yml|yaml|toml|env|csv|tgz|gz|zip)$", low):
            continue   # a file name, not a function
        last = low.rsplit(".", 1)[-1]
        if last in known or low in known:   # the whole dotted name, or its last segment, is in the code or map
            continue
        if re.search(r"(?<![\w])" + re.escape(last) + r"(?![\w])", known):
            continue
        out.append(name)
    return sorted(set(out))


_PLACE_RE = re.compile(r"(?<![\w.])/[\w\-{}:\[\]]+(?:/[\w\-{}:\[\]]+)*")


def _scenario_problem(story: str, ctx: Context) -> str | None:
    """Why a scenario cannot be shown, or None. Lens 2 rules (no code identifiers), and every page or route it names
    (`/admin`, `/users/42`) must start like one the prompt showed: a scenario walks through the app the map knows."""
    story = story.strip()
    if len(story) < 30 or " " not in story:
        return "scenario is too short to be a story"
    leaked = sorted(i for i in _code_identifiers(ctx) if re.search(rf"\b{re.escape(i)}\b", story))
    if leaked:
        return "scenario must not use code identifiers: " + ", ".join(leaked[:5])
    known = [p.split()[-1].lower() for p in ctx.places if p.split()]
    for m in _PLACE_RE.finditer(story):
        tok = m.group(0).lower().rstrip(".")
        first = "/" + tok.strip("/").split("/")[0]
        if not any(tok in k or k.startswith(first) for k in known):
            return f"scenario names a page or route the map does not show: {m.group(0)}"
    return None


def check_scenarios(rec: dict, ctx: Context) -> None:
    """Scenarios are extra: one that breaks the rules is removed (and kept under `dropped_scenarios` for the record),
    never shown and never a reason to reject the lenses. The viewer then shows the deterministic scenario."""
    dropped = []
    sc = rec.get("scenario")
    if sc is not None:
        story = sc.get("story") if isinstance(sc, dict) else sc
        why = _scenario_problem(story, ctx) if isinstance(story, str) else "scenario has no story"
        if why or rec.get("undetermined") and not isinstance(rec.get("lens2"), dict):
            dropped.append({"scenario": sc, "reason": why or "no plain-words lenses to go with it"})
            rec.pop("scenario", None)
        else:
            rec["scenario"] = {"who": str(sc.get("who") or "")[:80] if isinstance(sc, dict) else "", "story": story.strip()}
    for f in rec.get("findings") or []:
        if isinstance(f, dict) and "scenario" in f:
            why = _scenario_problem(f["scenario"], ctx) if isinstance(f["scenario"], str) else "scenario is not text"
            if why:
                dropped.append({"finding": f.get("id"), "scenario": f.pop("scenario"), "reason": why})
    if dropped:
        rec["dropped_scenarios"] = (rec.get("dropped_scenarios") or []) + dropped


def validate(rec: dict, ctx: Context) -> list[str]:
    errs: list[str] = []
    if not isinstance(rec, dict):
        return ["response is not a JSON object"]
    check_scenarios(rec, ctx)
    l1, l2, l3 = rec.get("lens1"), rec.get("lens2"), rec.get("lens3")
    if not isinstance(l1, dict) or not str(l1.get("summary", "")).strip():
        errs.append("lens1.summary is missing")
    else:
        # Read-back (HELM's round trip, the light form): every code name Lens 1 mentions must exist in this
        # unit's code or among its callers, callees and parent. A technical lens that names a function the
        # context does not show is describing code that is not there.
        unknown = _unknown_names_in_lens1(l1, ctx)
        if unknown:
            errs.append("lens1 names code that is not in this function or its callers/callees: " + ", ".join(unknown[:5]))
    und = rec.get("undetermined")
    if isinstance(und, str) and und.strip() and not isinstance(l2, dict) and not isinstance(l3, dict):
        if len(und.strip()) < 25 or " " not in und.strip():
            errs.append("undetermined needs a real one-sentence reason (what is missing), or lens2 and lens3")
            return errs
        # The model declined to explain in plain words rather than guess. Lens 1 still had to pass.
        rec["findings"] = [f for f in rec.get("findings") or [] if isinstance(f, dict) and f.get("id") in {x["id"] for x in ctx.findings}]
        missing = {f["id"] for f in ctx.findings} - {f.get("id") for f in rec["findings"]}
        if missing:
            errs.append(f"findings not explained: {', '.join(sorted(missing))}")
        return errs
    if not isinstance(l2, dict) or not str(l2.get("text", "")).strip():
        errs.append("lens2.text is missing")
    else:
        for k in ("example", "analogy"):
            if not str(l2.get(k, "")).strip():
                errs.append(f"lens2.{k} is missing")
        blob = " ".join(str(l2.get(k, "")) for k in ("text", "example", "analogy"))
        leaked = sorted(i for i in _code_identifiers(ctx) if re.search(rf"\b{re.escape(i)}\b", blob))
        if leaked:
            errs.append(f"lens2 must not use code identifiers: {', '.join(leaked[:5])}")
    if not isinstance(l3, dict):
        errs.append("lens3 is missing")
        return errs
    text, pairs = str(l3.get("text", "")), l3.get("pairs")
    if not text.strip():
        errs.append("lens3.text is missing")
    if not isinstance(pairs, list) or len(pairs) < 3:
        errs.append("lens3.pairs needs at least 3 pairs")
        return errs
    code_lower = re.sub(r"(?m)^\s*\d+ \| ", "", ctx.source).lower()   # without the line-number gutter
    seen_plain = set()
    for i, p in enumerate(pairs):
        tag = f"lens3.pairs[{i}]"
        if not isinstance(p, dict):
            errs.append(f"{tag} is not an object")
            continue
        plain, tech, anc = str(p.get("plain", "")).strip(), str(p.get("technical", "")).strip(), p.get("anchor")
        if not plain or not tech:
            errs.append(f"{tag} needs both plain and technical")
            continue
        if plain.lower() not in text.lower():
            errs.append(f"{tag}.plain '{plain}' does not appear verbatim in lens3.text")
        if plain.lower() in seen_plain:
            errs.append(f"{tag}.plain '{plain}' is duplicated")
        seen_plain.add(plain.lower())
        if not isinstance(anc, dict):
            errs.append(f"{tag} has no anchor")
            continue
        t = anc.get("type")
        if t == "symbol":
            if isinstance(anc.get("id"), str):
                anc["id"] = anc["id"].split()[0] if anc["id"].split() else anc["id"]   # "id  (name)" copied from a listing
            if anc.get("id") not in ctx.allowed_symbols:
                errs.append(f"{tag} anchors to unknown symbol '{anc.get('id')}'")
        elif t == "lines":
            try:
                s, e = int(anc.get("start")), int(anc.get("end", anc.get("start")))
            except (TypeError, ValueError):
                errs.append(f"{tag} has non-numeric line anchor")
                continue
            lo, hi = ctx.line_range
            if not (lo <= s <= e <= hi):
                errs.append(f"{tag} line anchor {s}-{e} is outside {lo}-{hi}")
        elif t == "term":
            term = str(anc.get("term", "")).strip().lower()
            if term not in GLOSSARY and not _term_in_code(term, code_lower):
                errs.append(f"{tag} term '{anc.get('term')}' is neither a word or name in the code (3+ characters, "
                            "with a letter) nor a standard term")
        else:
            errs.append(f"{tag} has unknown anchor type '{t}'")
    fids = {f["id"] for f in ctx.findings}
    # A findings entry whose id is not one the scanners reported is a finding the model made up. Models never
    # create findings, so the entry is removed before anything reaches a reader; it is kept under
    # `dropped_findings` so the run can count how often a model tried.
    kept, dropped = [], []
    for f in rec.get("findings") or []:
        (kept if isinstance(f, dict) and f.get("id") in fids else dropped).append(f)
    if dropped:
        rec["findings"], rec["dropped_findings"] = kept, dropped
    missing = fids - {f.get("id") for f in rec.get("findings") or [] if isinstance(f, dict)}
    if missing:
        errs.append(f"findings not explained: {', '.join(sorted(missing))}")
    return errs


def parse_json(text: str) -> dict | None:
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                return None
    return None


# --------------------------------------------------------------------------------------------
# Selection, ordering, caching
# --------------------------------------------------------------------------------------------

def select_nodes(g: Graph, depth: int = 3, include_tests: bool = False, limit: int | None = None,
                 only: list[str] | None = None) -> list[str]:
    """Entry points plus their callees up to `depth`, ordered bottom-up (callees first)."""
    if only:
        chosen = [next((c for c in (o, f"py:{o}", f"js:{o}") if c in g.nodes), o) for o in only]
        chosen = [c for c in chosen if c in g.nodes]
    else:
        adj: dict[str, list[str]] = {}
        for e in g.call_edges():
            adj.setdefault(e.src, []).append(e.dst)
        dist: dict[str, int] = {}
        q = deque()
        for n in g.entry_points():
            if include_tests or n.entry["kind"] != "test":
                dist[n.id] = 0
                q.append(n.id)
        while q:
            cur = q.popleft()
            if dist[cur] >= depth:
                continue
            for nxt in adj.get(cur, []):
                if nxt not in dist and nxt in g.nodes and g.nodes[nxt].kind == "callable":
                    dist[nxt] = dist[cur] + 1
                    q.append(nxt)
        chosen = [n for n in dist if g.nodes.get(n) and g.nodes[n].kind in ("callable", "module")]
    # bottom-up: post-order DFS over call edges restricted to chosen nodes
    chosen_set, order, seen = set(chosen), [], set()
    adj2: dict[str, list[str]] = {}
    for e in g.call_edges():
        if e.src in chosen_set and e.dst in chosen_set:
            adj2.setdefault(e.src, []).append(e.dst)

    def dfs(u: str):
        stack = [(u, iter(adj2.get(u, [])))]
        seen.add(u)
        while stack:
            node, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                order.append(node)
                stack.pop()
            elif nxt not in seen:
                seen.add(nxt)
                stack.append((nxt, iter(adj2.get(nxt, []))))

    for c in sorted(chosen):
        if c not in seen:
            dfs(c)
    return order[:limit] if limit else order


def estimate(g: Graph, nids: list[str], findings: list[dict]) -> dict:
    repo = Path(g.repo_root)
    inp = 0
    for nid in nids:
        ctx = build_context(g, nid, findings, {}, "x")
        inp += (len(SYSTEM) + len(render_prompt(ctx, g))) // 4 + 150
    out = 1100 * len(nids)
    return {"nodes": len(nids), "input_tokens": inp, "output_tokens": out,
            "note": "Estimate only (about 4 characters per token). Retries can add up to 2x."}


class Cache:
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)

    def key(self, ctx: Context, model: str) -> str:
        raw = f"{ctx.node.fingerprint}|{ctx.hash()}|{model}|{PROMPT_VERSION}"
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    def get(self, k: str) -> dict | None:
        p = self.root / f"{k}.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    def put(self, k: str, rec: dict) -> None:
        (self.root / f"{k}.json").write_text(json.dumps(rec, indent=1), encoding="utf-8")


# --------------------------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------------------------

def choose_metaphor(provider: Provider, g: Graph) -> dict:
    entries = [f"{n.entry['kind']}: {n.entry.get('detail', '')} -> {n.qualname}" for n in g.entry_points()
               if n.entry["kind"] != "test"][:25]
    mods = sorted({n.qualname for n in g.nodes.values() if n.kind == "module"})[:40]
    user = "ENTRY POINTS:\n" + "\n".join(entries) + "\n\nMODULES:\n" + "\n".join(mods)
    try:
        rec = parse_json(provider.complete(METAPHOR_SYSTEM, user, max_tokens=400)) or {}
    except AllowanceExhausted:
        raise
    except ProviderError:
        rec = {}
    if not isinstance(rec.get("world"), str) or not rec["world"].strip():
        rec = {"world": "a restaurant", "why": "default", "roles": {}}
    return rec


REPAIR_SYSTEM = """You fix one part of an answer you gave before. Return ONLY a json object. Follow the
instructions exactly; change nothing that was not asked about."""

_PAIR_ERR = re.compile(r"^lens3\.pairs\[(\d+)\]")


def _repairable(errors: list[str]) -> bool:
    """Only pair-level problems: the rest of the answer passed, so a small targeted fix beats a full retry."""
    return bool(errors) and all(_PAIR_ERR.match(e) or e.startswith("lens3.pairs needs") for e in errors)


def repair_pairs(provider: Provider, ctx: Context, rec: dict, errors: list[str]) -> dict | None:
    """HELM's RPM Gate has PROCEED, REPAIR and REFUSE. This is REPAIR: send back only the failing pairs with their
    reasons and the text they must be copied from; keep every pair that passed."""
    l3 = rec.get("lens3") or {}
    bad = sorted({int(m.group(1)) for e in errors for m in [_PAIR_ERR.match(e)] if m})
    user = ("TEXT (every pair's \"plain\" must be copied from here letter for letter, apostrophes included; "
            "do not reword it):\n" + str(l3.get("text", "")) +
            "\n\nPAIRS:\n" + json.dumps(l3.get("pairs") or [], ensure_ascii=False) +
            "\n\nPROBLEMS:\n- " + "\n- ".join(errors) +
            "\n\nALLOWED SYMBOLS:\n" + "\n".join(ctx.allowed_symbols) +
            f"\n\nLINE RANGE: {ctx.line_range[0]}-{ctx.line_range[1]}" +
            f"\n\nFix only pairs {bad} (or drop them), keep the others exactly as they are, keep at least 3 pairs, "
            "and return ONLY {\"pairs\": [...]} as json.")
    try:
        fixed = parse_json(provider.complete(REPAIR_SYSTEM, user, max_tokens=900))
    except AllowanceExhausted:
        raise
    except ProviderError:
        return None
    if not isinstance(fixed, dict) or not isinstance(fixed.get("pairs"), list):
        return None
    out = json.loads(json.dumps(rec))
    out["lens3"]["pairs"] = fixed["pairs"]
    return out


def drop_bad_pairs(rec: dict, errors: list[str], ctx: Context) -> dict | None:
    """Last resort after a failed REPAIR: a pair that cannot be anchored or highlighted is removed, not shown.

    Deterministic, never adds anything: the text and every other pair stay as the model wrote them. Only when
    every error names a pair and at least 3 pairs survive; the removed pairs are kept in `dropped_pairs` for the
    record. Mirrors how model-invented findings are handled (dropped and counted, never displayed)."""
    bad = {int(m.group(1)) for e in errors for m in [_PAIR_ERR.match(e)] if m}
    if not bad or len(bad) != len(errors):
        return None
    pairs = (rec.get("lens3") or {}).get("pairs") or []
    keep = [p for i, p in enumerate(pairs) if i not in bad]
    if len(keep) < 3:
        return None
    out = json.loads(json.dumps(rec))
    out["lens3"]["pairs"] = keep
    out["dropped_pairs"] = [{"pair": pairs[i], "reason": e} for i, e in zip(sorted(bad), errors)]
    return out if not validate(out, ctx) else None


def explain_node(provider: Provider, g: Graph, ctx: Context, retries: int = 1) -> dict:
    user = render_prompt(ctx, g)
    errors: list[str] = []
    rec: dict | None = None
    repaired = False
    for attempt in range(retries + 1):
        if attempt and rec is not None and _repairable(errors) and not repaired:
            fixed = repair_pairs(provider, ctx, rec, errors)      # REPAIR: cheap, targeted
            repaired = True
            if fixed is not None:
                e2 = validate(fixed, ctx)
                if not e2:
                    rec, errors = fixed, []
                    break
                dropped = drop_bad_pairs(fixed, e2, ctx)
                if dropped is not None:
                    rec, errors = dropped, []
                    break
                rec, errors = fixed, e2
                continue
        prompt = user if not errors else (
            user + "\n\nYOUR PREVIOUS ANSWER FAILED VALIDATION. Fix exactly these problems and "
                   "return the full JSON again:\n- " + "\n- ".join(errors))
        try:
            raw = provider.complete(SYSTEM, prompt, max_tokens=2500)
        except AllowanceExhausted:
            raise
        except ProviderError as e:
            return {"error": str(e), "validated": False, "attempts": attempt + 1}
        rec = parse_json(raw)
        errors = validate(rec, ctx) if rec is not None else ["response was not valid JSON"]
        if not errors:
            break
    if errors and isinstance(rec, dict) and attempt == retries:      # out of tries: the same last resort
        dropped = drop_bad_pairs(rec, errors, ctx)
        if dropped is not None:
            rec, errors = dropped, []
    rec = rec if isinstance(rec, dict) else {}
    rec.update({"node_id": ctx.node.id, "code_hash": ctx.node.fingerprint, "model": provider.label,
                "prompt_version": PROMPT_VERSION, "metaphor_world": ctx.metaphor,
                "validated": not errors, "validation_errors": errors, "attempts": attempt + 1,
                "repaired": repaired and not errors})
    if rec.get("undetermined") and not errors:
        rec["undetermined"] = str(rec["undetermined"])[:300]
    return rec


def run(g: Graph, provider: Provider, findings: list[dict], cache_dir: Path, nids: list[str],
        metaphor: str | None = None, progress=None, fresh: bool = False) -> dict:
    cache = Cache(cache_dir)
    done: dict[str, dict] = {}
    from .security import reachability
    reach = reachability(g, kinds={"page", "main"})   # pages first: a scenario starts where a visitor starts
    for k, v in reachability(g).items():
        reach.setdefault(k, v)
    stats = {"generated": 0, "cached": 0, "validated": 0, "failed": 0, "first_try": 0, "repaired": 0,
             "pairs_dropped": 0, "undetermined": 0, "invented_findings": 0, "scenarios_dropped": 0, "stopped": None}
    # the same model gives the same cache entries whether billed to the allowance or your own key
    model_id = getattr(provider, "cache_model", provider.label)
    try:
        world = {"world": metaphor, "why": "chosen by user", "roles": {}} if metaphor else choose_metaphor(provider, g)
    except AllowanceExhausted as e:
        stats["stopped"] = str(e)
        world = {"world": "a restaurant", "why": "default", "roles": {}}
        nids = []
    for i, nid in enumerate(nids):
        ctx = build_context(g, nid, findings, done, world["world"], reach)
        k = cache.key(ctx, model_id)
        rec = None if fresh else cache.get(k)   # fresh: 'Re-explain' asks the model again and overwrites the cache
        if rec is not None:
            stats["cached"] += 1
        else:
            try:
                rec = explain_node(provider, g, ctx)
            except AllowanceExhausted as e:
                stats["stopped"] = str(e)   # keep everything finished so far
                break
            stats["generated"] += 1
            if "error" not in rec:
                cache.put(k, rec)
        done[nid] = rec
        stats["invented_findings"] += len(rec.get("dropped_findings") or [])
        stats["repaired"] += 1 if rec.get("repaired") else 0
        stats["pairs_dropped"] += len(rec.get("dropped_pairs") or [])
        stats["scenarios_dropped"] += len(rec.get("dropped_scenarios") or [])
        stats["undetermined"] += 1 if rec.get("undetermined") and rec.get("validated") else 0   # rejected ones are failures
        if rec.get("validated"):
            stats["validated"] += 1
            if rec.get("attempts") == 1:
                stats["first_try"] += 1
        else:
            stats["failed"] += 1
        if progress:
            progress(i + 1, len(nids), nid, rec)
    stats["usage"] = {"input_tokens": provider.usage.input_tokens, "output_tokens": provider.usage.output_tokens}
    stats["model"] = provider.label
    return {"metaphor": world, "explanations": done, "stats": stats}
