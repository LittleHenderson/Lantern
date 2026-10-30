"""Three-Lens explanations with mechanical anchor validation.

Lens 1 (technical), Lens 2 (everyday, no jargon, one example, one analogy from a single
"metaphor world" per repo), Lens 3 (the everyday text again, where each plain phrase is pinned
1:1 to a technical term, symbol or line range).

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
from .providers import Provider, ProviderError

PROMPT_VERSION = "lens-v1"

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
and its role in the call path.
LENS 2 - EVERYDAY: zero jargon and no code identifiers. Include one concrete example ("if someone
types...") and one analogy drawn ONLY from the metaphor world given. Short sentences.
LENS 3 - MAPPED: rewrite the Lens 2 explanation as `text`, then list `pairs`. Each pair maps one
plain phrase that appears VERBATIM in `text` to the exact technical thing it stands for. Every pair
needs an anchor:
  {"type":"symbol","id":"<an id from ALLOWED SYMBOLS>"}
  {"type":"lines","start":N,"end":M}   (within the unit's line range)
  {"type":"term","term":"<a technical term that appears in the source, or a standard CS term>"}
Use 4-8 pairs covering the main ideas. Plain phrases must be short (1-6 words) and distinct.

If SECURITY FINDINGS are listed, add `findings` explaining each one in lens1 and lens2 terms,
including why it matters and the safest fix in one sentence. Do not judge whether a finding is a
false positive.

Respond with ONLY a JSON object, no markdown fences:
{"lens1":{"summary":str,"inputs":[str],"outputs":str,"side_effects":[str],"errors":[str],"role":str},
 "lens2":{"text":str,"example":str,"analogy":str},
 "lens3":{"text":str,"pairs":[{"plain":str,"technical":str,"anchor":{...}}]},
 "findings":[{"id":str,"lens1":str,"lens2":str,"fix":str}]}"""

METAPHOR_SYSTEM = """Pick ONE everyday setting to use as a consistent metaphor world for explaining
this whole codebase to a non-programmer (examples: a restaurant kitchen, a hotel, a post office,
a library, an airport, a factory line). Choose the one whose roles best match what the code does.
Respond with ONLY JSON: {"world": str, "why": str, "roles": {"<code concept>": "<metaphor role>"}}"""


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

    def hash(self) -> str:
        h = hashlib.sha256()
        h.update(json.dumps([self.node.fingerprint, sorted(self.callees), sorted(self.callers),
                             sorted(f["id"] for f in self.findings), self.metaphor]).encode())
        return h.hexdigest()[:12]


def read_source(repo: Path, node: Node, max_lines: int = 160) -> str:
    try:
        lines = (repo / node.file).read_text(errors="replace").splitlines()
    except (OSError, TypeError):
        return ""
    start, end = (node.start_line or 1), (node.end_line or node.start_line or 1)
    chunk = lines[start - 1:end]
    if len(chunk) > max_lines:
        chunk = chunk[:max_lines] + [f"# ... {len(chunk) - max_lines} more lines truncated"]
    return "\n".join(f"{start + i:>5} | {ln}" for i, ln in enumerate(chunk))


def build_context(g: Graph, nid: str, findings: list[dict], done: dict[str, dict], metaphor: str) -> Context:
    n = g.nodes[nid]
    repo = Path(g.repo_root)
    callees = [e.dst for e in g.callees(nid)]
    callers = [e.src for e in g.callers(nid)]
    allowed = {nid: n.qualname}
    for x in callees + callers + ([n.parent] if n.parent else []):
        if x in g.nodes:
            allowed[x] = g.nodes[x].qualname
    summaries = {c: done[c]["lens1"]["summary"] for c in callees if c in done and done[c].get("lens1")}
    return Context(node=n, source=read_source(repo, n), allowed_symbols=allowed,
                   line_range=(n.start_line or 1, n.end_line or n.start_line or 1),
                   findings=[f for f in findings if f.get("node") == nid],
                   callers=callers, callees=callees, callee_summaries=summaries, metaphor=metaphor)


def render_prompt(ctx: Context, g: Graph) -> str:
    n = ctx.node
    lang = "TypeScript/JavaScript" if (n.file or "").endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")) else "Python"
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
                 "\n".join(f"  {k}  ({v})" for k, v in ctx.allowed_symbols.items()))
    if ctx.findings:
        parts.append("SECURITY FINDINGS (from scanners, already verified as present):\n" + "\n".join(
            f"  - id={f['id']} [{f['rank']}] {f['rule']}: {f['title']} (line {f['line']})" +
            (f"; reachable via {' -> '.join(g.nodes[p].qualname for p in f['reachable']['path'] if p in g.nodes)}"
             if f.get("reachable") else "") for f in ctx.findings))
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


def validate(rec: dict, ctx: Context) -> list[str]:
    errs: list[str] = []
    if not isinstance(rec, dict):
        return ["response is not a JSON object"]
    l1, l2, l3 = rec.get("lens1"), rec.get("lens2"), rec.get("lens3")
    if not isinstance(l1, dict) or not str(l1.get("summary", "")).strip():
        errs.append("lens1.summary is missing")
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
    src_lower = ctx.source.lower()
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
            if not term or (term not in src_lower and term not in GLOSSARY):
                errs.append(f"{tag} term '{anc.get('term')}' is neither in the source nor a standard term")
        else:
            errs.append(f"{tag} has unknown anchor type '{t}'")
    fids = {f["id"] for f in ctx.findings}
    for f in rec.get("findings") or []:
        if isinstance(f, dict) and f.get("id") not in fids:
            errs.append(f"findings entry references unknown finding id '{f.get('id')}'")
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
        return json.loads(p.read_text()) if p.exists() else None

    def put(self, k: str, rec: dict) -> None:
        (self.root / f"{k}.json").write_text(json.dumps(rec, indent=1))


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
    except ProviderError:
        rec = {}
    if not isinstance(rec.get("world"), str) or not rec["world"].strip():
        rec = {"world": "a restaurant", "why": "default", "roles": {}}
    return rec


def explain_node(provider: Provider, g: Graph, ctx: Context, retries: int = 1) -> dict:
    user = render_prompt(ctx, g)
    errors: list[str] = []
    rec: dict | None = None
    for attempt in range(retries + 1):
        prompt = user if not errors else (
            user + "\n\nYOUR PREVIOUS ANSWER FAILED VALIDATION. Fix exactly these problems and "
                   "return the full JSON again:\n- " + "\n- ".join(errors))
        try:
            raw = provider.complete(SYSTEM, prompt, max_tokens=2500)
        except ProviderError as e:
            return {"error": str(e), "validated": False, "attempts": attempt + 1}
        rec = parse_json(raw)
        errors = validate(rec, ctx) if rec is not None else ["response was not valid JSON"]
        if not errors:
            break
    rec = rec if isinstance(rec, dict) else {}
    rec.update({"node_id": ctx.node.id, "code_hash": ctx.node.fingerprint, "model": provider.label,
                "prompt_version": PROMPT_VERSION, "metaphor_world": ctx.metaphor,
                "validated": not errors, "validation_errors": errors, "attempts": attempt + 1})
    return rec


def run(g: Graph, provider: Provider, findings: list[dict], cache_dir: Path, nids: list[str],
        metaphor: str | None = None, progress=None) -> dict:
    cache = Cache(cache_dir)
    world = {"world": metaphor, "why": "chosen by user", "roles": {}} if metaphor else choose_metaphor(provider, g)
    done: dict[str, dict] = {}
    stats = {"generated": 0, "cached": 0, "validated": 0, "failed": 0, "first_try": 0}
    for i, nid in enumerate(nids):
        ctx = build_context(g, nid, findings, done, world["world"])
        k = cache.key(ctx, provider.label)
        rec = cache.get(k)
        if rec is not None:
            stats["cached"] += 1
        else:
            rec = explain_node(provider, g, ctx)
            stats["generated"] += 1
            if "error" not in rec:
                cache.put(k, rec)
        done[nid] = rec
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
