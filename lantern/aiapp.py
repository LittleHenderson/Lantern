"""AI-app pack: what an app that calls models, vector stores and other paid services needs checked.

Everything here is deterministic pattern work on the graph and the source, like the rest of the scanners.

  * `find_calls(g)`   — every call into a model, embedding, vector-store or other pay-per-use API (Stripe, email,
                        SMS), pinned to the function that makes it. The viewer marks those functions and the paths
                        that reach them ("click → route → model call"). Stored in `security["ai"]`.
  * `LA-WALLET-DRAIN` — a route that reaches a paid call with no login check and no rate limiting anywhere in the
                        app: one script in a loop spends the owner's money. HIGH when neither protection is visible,
                        MEDIUM when only rate limiting is missing. Heuristic (`tool_confidence: LOW`): it reuses the
                        login check's name-based reading and the rate-limit library search.
  * `LA-MODEL-OUTPUT-TO-TOOL` — inside one function, text the model wrote is later run as a shell command, SQL,
                        `eval`, or fetched as a URL. HIGH: a prompt injection becomes code execution.
  * `LA-PROMPT-FROM-INPUT` — visitor text goes straight into a model call in a function that also has tool-like
                        sinks. LOW, informational: normal for a chat app, but the system prompt and tools must
                        assume the text is hostile.
  * `LA-NOTEBOOK-SECRET` — an API key or token written into a notebook's code cell or left in a saved output.
                        Notebooks are shared and committed far more often than people remember. HIGH (category
                        `secret`, so it ranks critical like any other leaked secret).

Nothing here changes a finding another scanner made, and none of it needs the network.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import manifest
from .python_frontend import project_text
from .graph import Graph

# kind, provider, pattern. Kinds: model | embedding | vector | image | speech | payment | email | sms
CALL_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("model", "OpenAI", re.compile(r"\.chat\.completions\.create\(|\.responses\.create\(|openai\.ChatCompletion|\.completions\.create\(|"
                                   r"\bgenerateText\(|\bstreamText\(|\bgenerateObject\(|\bstreamObject\(")),
    ("model", "Anthropic", re.compile(r"\.messages\.create\(|\.messages\.stream\(|anthropic\.(?:Anthropic|messages)")),
    ("model", "Google", re.compile(r"\.generate_content\(|\.generateContent\(|GenerativeModel\(|genai\.Client\(|\bai\.models\.generate")),
    ("model", "Mistral", re.compile(r"\bmistral(?:ai)?\.|\.chat\.complete\(")),
    ("model", "Cohere", re.compile(r"\bcohere\.|\bco\.(?:chat|generate)\(")),
    ("model", "Groq", re.compile(r"\bGroq\(|\bgroq\.")),
    ("model", "Replicate", re.compile(r"\breplicate\.(?:run|predictions)")),
    ("model", "Hugging Face", re.compile(r"InferenceClient\(|api-inference\.huggingface\.co|\.text_generation\(")),
    ("model", "Ollama", re.compile(r"\bollama\.(?:chat|generate)\(|localhost:11434")),
    ("model", "LangChain", re.compile(r"\bChat(?:OpenAI|Anthropic|GoogleGenerativeAI|Groq|Mistral|Cohere|Ollama|VertexAI|Bedrock)\(|"
                                      r"\bLLMChain\(|\bcreate_react_agent\(|\bAgentExecutor\(|\binitialize_agent\(")),
    ("model", "LlamaIndex", re.compile(r"\bVectorStoreIndex\b|\.as_query_engine\(|\.as_chat_engine\(")),
    ("model", "AWS Bedrock", re.compile(r"\binvoke_model\(|bedrock-runtime|BedrockRuntimeClient")),
    ("model", "Azure OpenAI", re.compile(r"\bAzureOpenAI\(|\.openai\.azure\.com")),
    ("embedding", "embeddings", re.compile(r"\.embeddings\.create\(|\bembed(?:Many|_documents|_query|Query)?\(|\bembed_content\(|\bembedContent\(")),
    ("image", "image generation", re.compile(r"\.images\.generate\(|\bgenerateImage\(|stability\.ai|\bdall-e|\bdalle")),
    ("speech", "speech", re.compile(r"\.audio\.(?:speech|transcriptions|translations)\.create\(|elevenlabs|deepgram")),
    ("vector", "Pinecone", re.compile(r"\bPinecone\(|\bpinecone\.|\.upsert\(\s*vectors|index\.query\(")),
    ("vector", "Chroma", re.compile(r"\bchromadb\b|\bChromaClient\(|\.get_or_create_collection\(")),
    ("vector", "Weaviate", re.compile(r"\bweaviate\b")),
    ("vector", "Qdrant", re.compile(r"\bQdrantClient\(|\bqdrant\b")),
    ("vector", "pgvector / Supabase", re.compile(r"\bpgvector\b|<->|\.rpc\(\s*['\"]match_\w+['\"]|vector\(\d+\)")),
    ("vector", "FAISS", re.compile(r"\bfaiss\b")),
    ("vector", "Milvus", re.compile(r"\bpymilvus\b|\bMilvusClient\(")),
    ("payment", "Stripe", re.compile(r"\bstripe\.(?:checkout|paymentIntents|PaymentIntent|charges|Charge|subscriptions|Subscription|customers|Customer)\b|"
                                     r"\bStripe\(")),
    ("email", "email", re.compile(r"\bresend\.emails\.send\(|\bsgMail\.send\(|\bsendgrid\b|\bmailgun\b|\bpostmark\b|\bses\.send_email\(|\bSESClient\b|"
                                  r"\bsmtplib\.SMTP\(|\bnodemailer\b|\bsendEmail\(|\bsend_mail\(|\bEmailMessage\(")),
    ("sms", "SMS", re.compile(r"\btwilio\b|\bmessages\.create\(\s*(?:to|body)=|\bvonage\b|\bnexmo\b")),
]
PAID_KINDS = {"model", "embedding", "image", "speech", "payment", "email", "sms"}
WORDS = {"model": "model call", "embedding": "embedding call", "image": "image generation", "speech": "speech API",
         "vector": "vector store", "payment": "payment API", "email": "email sending", "sms": "SMS sending"}

# text a model wrote, as it is usually read out of a response
MODEL_OUTPUT = re.compile(r"\.choices\[\d\]\.message\.content|\.choices\[\d\]\.text|\.output_text\b|\.content\[\d\]\.text|"
                          r"\bresponse\.text\b|\bresult\.text\b|\.message\.content\b|\.generations\[|\.candidates\[|"
                          r"\bcompletion\.(?:content|text)\b|\.text\(\)|\btext\s*}\s*=\s*await\s+(?:generateText|streamText)")
# where that text must never go unchecked
SINKS = [
    ("a shell command", re.compile(r"\bsubprocess\.(?:run|call|Popen|check_output)\(|\bos\.system\(|\bos\.popen\(|\bexecSync?\(|\bspawn(?:Sync)?\(|"
                                   r"\bexec\.Command\(|Command::new\(|Runtime\.getRuntime\(\)\.exec\(|new\s+ProcessBuilder\(")),
    ("a database query", re.compile(r"\.(?:execute|executemany|executescript|query|raw|executeQuery|executeUpdate|QueryRow|Exec|sqlx::query)\(|"
                                    r"\bsqlx::query\(|\bprisma\.\$(?:queryRaw|executeRaw)Unsafe\(")),
    ("code (eval / exec)", re.compile(r"(?<![\w.$])eval\(|(?<![\w.$])exec\(|\bnew\s+Function\(|\bFunction\(")),
    ("a web request", re.compile(r"\brequests\.(?:get|post|put|delete|request)\(|\bfetch\(|\baxios(?:\.\w+)?\(|\bhttpx\.(?:get|post)\(|"
                                 r"\burllib\.request\.urlopen\(|\bhttp\.(?:Get|Post)\(|reqwest::get\(")),
    ("a file path", re.compile(r"\bopen\(|\bfs\.(?:readFileSync|writeFileSync|readFile|writeFile|unlink|rm)\(|\bos\.remove\(|\bshutil\.")),
]
VISITOR_INPUT = re.compile(r"\b(?:request|req)\.(?:json|body|args|form|query|params|get_json|data)\b|\bsearchParams\b|\bformData\b|"
                           r"\bmessages?\b.*\brequest\b|\bawait\s+(?:req|request)\.(?:json|text|formData)\(\)|\bctx\.(?:body|query|params)\b|"
                           r"\br\.(?:PathValue|FormValue|Body)\b|\bc\.(?:Param|Query|PostForm|BindJSON)\(|Json\(\w+\)|\.getParameter\(")
MAX_LINE = 2000   # longer lines are minified bundles (jquery.min.js): vendored code, and quadratic for STRING_RE
STRING_RE = re.compile(r"(['\"`])(?:\\.|(?!\1).)*\1")

KEY_PATTERNS = [
    ("OpenAI key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Stripe key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[abp]-[0-9A-Za-z-]{20,}\b")),
    ("Replicate token", re.compile(r"\br8_[A-Za-z0-9]{30,}\b")),
    ("API key assigned in code", re.compile(r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['\"][A-Za-z0-9_\-./+]{16,}['\"]")),
    ("API key set in the environment from code", re.compile(r"(?i)os\.environ\[['\"][A-Z0-9_]*(?:KEY|TOKEN|SECRET)[A-Z0-9_]*['\"]\]\s*=\s*['\"][^'\"]{8,}['\"]")),
]
PLACEHOLDER = re.compile(r"(?i)your[_-]?|xxx|example|placeholder|<[^>]+>|\.\.\.|changeme|dummy|test_key|1234567890")


def _lines(repo: Path, rel: str, cache: dict[str, list[str]]) -> list[str]:
    if rel not in cache:
        try:
            cache[rel] = project_text(repo / rel, repo).splitlines()
        except OSError:
            cache[rel] = []
    return cache[rel]


def _comment(line: str) -> bool:
    s = line.lstrip()
    return s.startswith(("#", "//", "*", "/*", "--", "'''", '"""'))


def find_calls(g: Graph, cache: dict[str, list[str]] | None = None) -> list[dict]:
    """Every paid-API or vector-store call, pinned to the callable whose lines hold it."""
    repo = Path(g.repo_root)
    cache = cache if cache is not None else {}
    out: list[dict] = []
    seen: set[tuple[str, int, str]] = set()
    callables = [n for n in g.nodes.values() if n.kind == "callable" and n.file and n.start_line]
    callables.sort(key=lambda n: (n.file, n.start_line, -(n.end_line or n.start_line)))
    by_file: dict[str, list] = {}
    for n in callables:
        by_file.setdefault(n.file, []).append(n)
    for rel, nodes in by_file.items():
        lines = _lines(repo, rel, cache)
        for i, raw in enumerate(lines, 1):
            if _comment(raw) or len(raw) > MAX_LINE:
                continue
            code = STRING_RE.sub("''", raw) if "'" in raw or '"' in raw else raw
            for kind, provider, rx in CALL_PATTERNS:
                if not (rx.search(code) or (kind == "vector" and rx.search(raw))):
                    continue
                # the innermost callable holding this line
                owner = None
                for n in nodes:
                    if n.start_line <= i <= (n.end_line or n.start_line):
                        if owner is None or (n.end_line or n.start_line) - n.start_line <= (owner.end_line or owner.start_line) - owner.start_line:
                            owner = n
                key = (rel, i, kind)
                if key in seen:
                    continue
                seen.add(key)
                out.append({"node": owner.id if owner else None, "file": rel, "line": i, "kind": kind, "provider": provider,
                            "snippet": raw.strip()[:160]})
                break
    return out


def _rate_limited(g: Graph, cache: dict[str, list[str]]) -> bool:
    from .protections import RATE_LIMIT_LIBS, _deps_text
    from .readiness import Repo
    repo = Repo(Path(g.repo_root))
    return bool(RATE_LIMIT_LIBS.search(_deps_text(repo)) or repo.grep(RATE_LIMIT_LIBS, limit=1))


def wallet_drain(g: Graph, calls: list[dict], cache: dict[str, list[str]]) -> list[dict]:
    from .websec import _finding, call_adjacency, login_check
    paid_nodes = {c["node"]: c for c in calls if c["node"] and c["kind"] in PAID_KINDS}
    if not paid_nodes:
        return []
    limited = _rate_limited(g, cache)
    adj = call_adjacency(g)
    out = []
    # which routes reach which paid calls (walk forward from each route)
    routes = [n for n in g.entry_points() if (n.entry or {}).get("kind") == "route"]
    for r in routes:
        seen, frontier, hit = {r.id}, [r.id], []
        while frontier:
            nxt = []
            for u in frontier:
                for v in adj.get(u, []):
                    if v in seen:
                        continue
                    seen.add(v)
                    if v in paid_nodes:
                        hit.append(paid_nodes[v])
                    nxt.append(v)
            frontier = nxt
        if r.id in paid_nodes:
            hit.insert(0, paid_nodes[r.id])
        if not hit:
            continue
        text = "\n".join(_lines(Path(g.repo_root), r.file, cache)) if r.file else None
        sign = login_check(g, r, adj, text)
        logged_in = bool(sign and sign[0] == "strong")
        if logged_in and limited:
            continue
        kinds = sorted({WORDS[h["kind"]] for h in hit})
        what = ", ".join(kinds)
        detail = r.entry.get("detail") or r.qualname
        if not logged_in and not limited:
            sev, title = "HIGH", f"{detail} spends money ({what}) and anyone can call it as often as they like"
            why = ("No login check was found on this route and no rate-limiting library or setting anywhere in the app. "
                   "A single script in a loop can run up the bill until the key's limit or the card's limit is hit.")
        elif not logged_in:
            sev, title = "MEDIUM", f"{detail} spends money ({what}) without a login check"
            why = "Rate limiting exists somewhere in the app, but the route itself does not check who is calling."
        else:
            sev, title = "MEDIUM", f"{detail} spends money ({what}) with no rate limit"
            why = "Callers must log in, but nothing limits how often one account can call it."
        out.append(_finding(
            "LA-WALLET-DRAIN", title, sev, r.file, r.start_line, category="code", conf="LOW", cwe=770,
            fixed_rank="high" if sev == "HIGH" else "medium",
            more=why + " Fix: require a signed-in user, add a per-user and per-IP rate limit (slowapi, express-rate-limit, "
                 "@upstash/ratelimit), set `max_tokens`, and put a spend limit on the provider's dashboard. Heuristic: "
                 "Lantern reads names, not meaning, for both checks. Paid calls reached: " +
                 "; ".join(f"{h['provider']} ({h['file']}:{h['line']})" for h in hit[:4]),
            snippet=detail))
    return out


def model_output_sinks(g: Graph, calls: list[dict], cache: dict[str, list[str]]) -> list[dict]:
    from .websec import _finding
    out = []
    repo = Path(g.repo_root)
    model_nodes = {c["node"] for c in calls if c["node"] and c["kind"] == "model"}
    for nid in sorted(model_nodes):
        n = g.nodes[nid]
        lines = _lines(repo, n.file, cache)
        lo, hi = n.start_line, min(n.end_line or n.start_line, len(lines))
        tainted: dict[str, int] = {}
        input_line = None
        for i in range(lo, hi + 1):
            raw = lines[i - 1]
            if _comment(raw) or len(raw) > MAX_LINE:
                continue
            code = STRING_RE.sub("''", raw)
            if input_line is None and VISITOR_INPUT.search(code):
                input_line = i
            m = re.match(r"\s*(?:(?:const|let|var|val)\s+)?(?:\{\s*)?([A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?\s*(?:\}\s*)?(?::?=)\s*(.+)$", code)
            if m and (MODEL_OUTPUT.search(m.group(2)) or any(t for t in tainted if re.search(rf"(?<![\w$.]){re.escape(t)}(?![\w$])", m.group(2)))):
                tainted[m.group(1)] = i
                continue
            if not tainted:
                continue
            for what, rx in SINKS:
                if rx.search(code) and any(re.search(rf"(?<![\w$.]){re.escape(t)}(?![\w$])", code) for t in tainted):
                    name = next(t for t in tainted if re.search(rf"(?<![\w$.]){re.escape(t)}(?![\w$])", code))
                    out.append(_finding(
                        "LA-MODEL-OUTPUT-TO-TOOL", f"Text the model wrote is used as {what}", "HIGH", n.file, i,
                        category="code", conf="LOW", cwe=94,
                        more=(f"`{name}` is set from a model response on line {tainted[name]} and used as {what} on line {i}. "
                              "Anything a visitor can put in the prompt can steer that text (prompt injection). Validate it "
                              "against an allow-list, or never let model text reach this call: pass structured fields the "
                              "code chooses, not the text. Heuristic: assignments followed inside this function only."),
                        snippet=raw.strip()[:200]))
                    break
        if input_line is not None and any(rx.search(STRING_RE.sub("''", lines[i - 1])) for i in range(lo, hi + 1) if len(lines[i - 1]) <= MAX_LINE for _w, rx in SINKS):
            call_line = next((c["line"] for c in calls if c["node"] == nid and c["kind"] == "model"), lo)
            out.append(_finding(
                "LA-PROMPT-FROM-INPUT", "Visitor text goes into a model call in a function that also runs tools", "LOW",
                n.file, call_line, category="code", conf="LOW", cwe=74,
                more=(f"Line {input_line} reads visitor input and this function also calls a command, query, web or file "
                      "API. Treat everything the visitor sends as hostile: keep secrets out of the system prompt, "
                      "restrict what tools can do, and never let the model's text choose a target by itself."),
                snippet=lines[call_line - 1].strip()[:200] if 0 < call_line <= len(lines) else ""))
    return out


def _said(value) -> str:
    """The text of a notebook cell or output: one text, or a list of lines. The file comes with the project, so
    whatever else is there is read as the text it would print as: a key written inside it is still a key."""
    if isinstance(value, list):
        return "".join(x if isinstance(x, str) else str(x) for x in value)
    return value if isinstance(value, str) else str(value or "")


def notebooks(repo: Path) -> tuple[list[dict], list[dict]]:
    """Secrets in .ipynb code cells and saved outputs. Returns (findings, notebook summaries)."""
    from .python_frontend import SKIP_DIRS
    from .websec import _finding
    out, books = [], []
    for p in sorted(repo.rglob("*.ipynb")):
        rel = p.relative_to(repo).as_posix()
        if any(part in SKIP_DIRS or part.startswith(".") for part in rel.split("/")[:-1]):
            continue
        try:
            nb = manifest.parse_json(project_text(p, repo))
        except OSError:
            continue
        cells = nb.get("cells") if isinstance(nb, dict) else None
        if not isinstance(cells, list):
            continue
        code_cells, ai_kinds, hits = 0, set(), 0
        for ci, cell in enumerate(cells, 1):
            if not isinstance(cell, dict):
                continue
            text = _said(cell.get("source"))
            if cell.get("cell_type") == "code":
                code_cells += 1
                for kind, _prov, rx in CALL_PATTERNS:
                    if rx.search(text):
                        ai_kinds.add(kind)
            outputs = []
            for o in manifest.tables(cell.get("outputs")):
                outputs.append(_said(o.get("text") or manifest.table(o.get("data")).get("text/plain")))
            for where, blob in (("code cell", text), ("saved output", "\n".join(outputs))):
                found = next(((label, m) for label, rx in KEY_PATTERNS for m in rx.finditer(blob)
                              if not PLACEHOLDER.search(m.group(0))), None)
                if found is None:
                    continue                                   # one finding per cell and place is enough
                label, m = found
                hits += 1
                line = blob.count("\n", 0, m.start()) + 1
                out.append(_finding(
                    "LA-NOTEBOOK-SECRET", f"{label} in a notebook {where} (cell {ci})", "HIGH", rel, line,
                    category="secret", conf="HIGH", cwe=798,
                    more=("Notebooks are committed and shared with their outputs. Revoke this key, load keys from "
                          "the environment (`os.environ[...]`) and clear outputs before committing "
                          "(`jupyter nbconvert --clear-output`)."),
                    snippet=m.group(0)[:6] + "…"))
        books.append({"file": rel, "code_cells": code_cells, "ai": sorted(ai_kinds), "secrets": hits})
    return out, books


def scan_ai(g: Graph) -> tuple[list[dict], dict]:
    """Findings plus the summary the viewer shows: calls by node, kinds present, notebooks."""
    cache: dict[str, list[str]] = {}
    calls = find_calls(g, cache)
    findings = wallet_drain(g, calls, cache) + model_output_sinks(g, calls, cache)
    nb_findings, books = notebooks(Path(g.repo_root))
    findings += nb_findings
    by_node: dict[str, list[dict]] = {}
    for c in calls:
        if c["node"]:
            by_node.setdefault(c["node"], []).append({"kind": c["kind"], "provider": c["provider"], "line": c["line"]})
    summary = {"calls": calls, "by_node": by_node, "kinds": sorted({c["kind"] for c in calls}),
               "providers": sorted({c["provider"] for c in calls}), "notebooks": books,
               "is_ai_app": any(c["kind"] in ("model", "embedding", "vector") for c in calls)}
    return findings, summary
