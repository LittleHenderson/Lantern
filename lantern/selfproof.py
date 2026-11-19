"""Proof that something happened, written by the side whose word it is (2026-11-19). Two heuristics, each
`tool_confidence: LOW` and ranked medium; they read a file's own text and run nothing.

**`LW-CALLER-SAYS-DONE`** (`caller_says_done(g)`; `read_py(text)` and `read_js(lines)` are the reading of one
function): a function marks something as paid, settled, confirmed, verified or approved (a `status` set to such a
word, a flag such as `paid` set true, SQL that sets them), and the only proof it holds is a value the caller handed
it whose name says it is the proof of an outside event (a provider's transaction id, a payment intent, a receipt,
a confirmation number), and that value is only stored or looked at for being there: nothing hands it to anything
that could ask the provider whether it is real (Stripe's `retrieve`, a bank's status call, a function of the
project named for checking). Whoever can call the function marks the thing done with a made-up value. Written after
another review tool named that shape in a project Lantern was measured on (a withdrawal marked settled from a
provider's id the caller sent), from examples of Lantern's own.

**`LW-SELF-WRITTEN-PROOF`** (`self_written(g)`; `writer_sets(text)` and `verifiers(text)` are the reading of one
file): a list of the kinds of record that a side the program trusts less (a runner, a worker, a client, an agent, a
child process, a plugin) may write, and a function named for checking (`verify`, `certify`, `attest`, `approve`,
`validate`, `confirm`) that asks for at least two of those very kinds, one of them a record of something that
happened outside (sent, response, receipt, capture, observation, result). What that side writes then proves that
side did its work: a receipt it made up is as good as a real one. Written after the same review named that shape
(a worker that may write every record its own certification asks for), from examples of Lantern's own.

Neither knows who the caller is, nor whether something outside the code checks the value: they say "check".
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from .graph import Graph, outside
from .localweb import NOT_THE_APP
from .python_frontend import project_text
from .websec import JS_EXTS, _finding, code_only

CALLER_RULE = "LW-CALLER-SAYS-DONE"
WRITER_RULE = "LW-SELF-WRITTEN-PROOF"
MOST_FILE = 400_000
MOST_BODY = 40_000
MOST_LINE = 2_000
FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)
WORD = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")

DONE = {"paid", "settled", "succeeded", "confirmed", "verified", "approved", "fulfilled", "captured", "completed",
        "complete", "delivered", "cleared"}
NOT_DONE = {"pending", "un", "not", "failed", "failure", "awaiting", "requested", "requires", "partially", "partial",
            "cancelled", "canceled", "rejected", "expired", "refunded"}
STATE_WORDS = {"status", "state", "stage", "phase"}
FLAG_DONE = {"paid", "settled", "confirmed", "verified", "approved", "captured", "fulfilled", "cleared"}
# the proof of an outside event: a provider's or a bank's id, a receipt, a confirmation
PROOF_WORDS = {"provider", "external", "tx", "txn", "transaction", "receipt", "confirmation", "intent", "charge",
               "proof", "reference", "stripe", "paypal", "bank", "processor", "gateway", "capture", "settlement"}
PROOF_ENDS = {"id", "ids", "ref", "reference", "number", "no", "code", "hash", "receipt", "proof", "token"}
# what a value may be handed to and still be "only stored or looked at"
NEUTRAL = {"execute", "executemany", "update", "update_one", "update_many", "save", "add", "insert", "insert_one",
           "create", "upsert", "set", "commit", "str", "int", "len", "bool", "strip", "lower", "upper", "format",
           "append", "info", "debug", "warning", "warn", "error", "exception", "log", "print", "dict", "tuple", "list",
           "isinstance", "Decimal", "need", "require", "assert_", "dumps", "json", "jsonify", "eq", "where", "data",
           "String", "Number", "trim", "toString", "toLowerCase", "toUpperCase", "set_", "put", "replace", "filter",
           "filter_by", "get", "pop", "text", "values", "update_status", "mark", "write", "send", "status",
           "updateOne", "updateMany", "findOneAndUpdate", "findByIdAndUpdate", "insertOne", "set_status", "run"}
# a helper of the project's own whose name says it only writes something down
NEUTRAL_WORDS = {"audit", "log", "logs", "record", "journal", "emit", "event", "events", "store", "persist", "save",
                 "insert", "write", "append", "notify", "history", "ledger", "trail"}
LOOKS_UP = re.compile(r"(?i)retrieve|verify|lookup|look_up|fetch(?!one|all|many|_?row)|reconcile|capture|confirm_with|status_of|"
                      r"check_\w*(?:payment|status|transaction|transfer|charge)|get_\w*(?:payment|transaction|charge|"
                      r"transfer|status|receipt)")
WEBHOOK = re.compile(r"(?i)webhook|hook")
SQL_DONE = re.compile(r"(?is)\bupdate\b.{0,200}?\bset\b.{0,300}?\b(\w{0,30}(?:status|state|paid|settled|verified|"
                      r"confirmed))\s*=\s*(?:'([^']{1,40})'|\"([^\"]{1,40})\"|(true|1)\b)")

# the lower-trust side and the record kinds it may write
WRITER_ROLE = {"runner", "worker", "client", "agent", "child", "sandbox", "guest", "plugin", "remote", "untrusted",
               "caller", "subprocess", "external", "tenant", "device", "sensor", "bot"}
WRITER_SET = {"kinds", "types", "events", "records", "receipts", "allowed", "allowlist", "whitelist", "writable",
              "messages", "ops", "appends"}
TRUSTED_ROLE = {"controller", "supervisor", "server", "parent", "host", "trusted", "observer", "orchestrator",
                "coordinator", "verifier", "monitor"}
CHECKER = re.compile(r"(?i)^_*(?:verify|certify|attest|approve|validate|confirm|accept|check|admit|promote)")
HAPPENED = {"sent", "response", "receipt", "receipts", "capture", "captured", "observation", "observed", "result",
            "results", "done", "completed", "complete", "delivered", "executed", "ran", "inference", "acknowledged",
            "ack", "proof", "outcome", "evidence"}


def _words(name: str) -> list[str]:
    return [w.lower() for w in WORD.findall(name or "")]


def _is_done_word(text: str) -> bool:
    words = set(_words(text.replace("-", "_")))
    return bool(words & DONE) and not words & NOT_DONE


def _is_proof_name(name: str) -> bool:
    words = _words(name)
    if not words:
        return False
    return bool(set(words) & PROOF_WORDS) and (words[-1] in PROOF_ENDS or words[-1] in {"receipt", "proof"})


def _text(node) -> str:
    try:
        return ast.unparse(node)
    except Exception:       # a tree Python cannot write back: nothing is read from it
        return ""


def _own_parts(fn):
    stack = list(reversed(fn.body))
    while stack:
        node = stack.pop()
        if isinstance(node, (*FUNCS, ast.Lambda, ast.ClassDef)):
            continue
        yield node
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _name_of(func) -> str:
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


# --- LW-CALLER-SAYS-DONE, Python ------------------------------------------------------------------------------------

def _done_lines(fn, parts) -> list[tuple[int, str]]:
    """Where the function marks something done, with the words that say so."""
    out = []
    strings: dict[str, str] = {}
    for node in parts:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            strings.update({t.id: node.value.value for t in node.targets if isinstance(t, ast.Name)})
    for node in parts:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            for t in targets:
                key = t.attr if isinstance(t, ast.Attribute) else \
                    t.slice.value if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) and \
                    isinstance(t.slice.value, str) else ""
                if not key:
                    continue
                if _said_done(key, value):
                    out.append((node.lineno, f"{key} = {_text(value)[:40]}"))
        elif isinstance(node, ast.Call):
            for k in node.keywords:
                if k.arg and _said_done(k.arg, k.value):
                    out.append((node.lineno, f"{k.arg}={_text(k.value)[:40]}"))
            for a in node.args:
                text = a.value if isinstance(a, ast.Constant) and isinstance(a.value, str) else \
                    strings.get(a.id, "") if isinstance(a, ast.Name) else ""
                m = SQL_DONE.search(text) if text else None
                if m and _sql_done(m):
                    out.append((node.lineno, f"SET {m.group(1)} = {m.group(2) or m.group(3) or m.group(4)}"))
        elif isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                # a table written out is a document, a flag in it marks no record: only a state word counts there
                if isinstance(k, ast.Constant) and isinstance(k.value, str) and \
                        set(_words(k.value)) & STATE_WORDS and _said_done(k.value, v):
                    out.append((node.lineno, f"{k.value}: {_text(v)[:40]}"))
    return sorted(set(out))


def _said_done(key: str, value) -> bool:
    words = set(_words(key))
    if words & STATE_WORDS and isinstance(value, ast.Constant) and isinstance(value.value, str):
        return _is_done_word(value.value)
    if isinstance(value, ast.Constant) and value.value is True:
        return bool(words & FLAG_DONE) and not words & NOT_DONE
    if isinstance(value, ast.Attribute) and words & STATE_WORDS:      # Status.PAID
        return _is_done_word(value.attr)
    return False


def _sql_done(m) -> bool:
    column, said = m.group(1), m.group(2) or m.group(3) or m.group(4) or ""
    if said.lower() in ("true", "1"):
        return bool(set(_words(column)) & FLAG_DONE)
    return bool(set(_words(column)) & STATE_WORDS) and _is_done_word(said)


def _proofs(fn, parts) -> dict[str, int]:
    """The caller's proofs: parameters, and values taken out of what the caller sent, named like one."""
    found: dict[str, int] = {}
    args = fn.args
    params = [a.arg for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]]
    for p in params:
        if _is_proof_name(p):
            found[p] = fn.lineno
    holders = {p for p in params if p not in ("self", "cls")}
    for node in parts:
        # body["provider_tx_id"], body.get("payment_intent"), request.json["receipt"]
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and \
                isinstance(node.slice.value, str) and _is_proof_name(node.slice.value) and _from_caller(node.value, holders):
            found.setdefault(_text(node), node.lineno)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" and \
                node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str) and \
                _is_proof_name(node.args[0].value) and _from_caller(node.func.value, holders):
            found.setdefault(_text(node), node.lineno)
        elif isinstance(node, ast.Attribute) and _is_proof_name(node.attr) and isinstance(node.value, ast.Name) and \
                node.value.id in holders:
            found.setdefault(_text(node), node.lineno)                  # body.payment_intent_id (a form's model)
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and \
                _is_proof_name(node.targets[0].id) and _from_caller(node.value, holders):
            found.setdefault(node.targets[0].id, node.lineno)
    return found


def _from_caller(node, holders: set[str]) -> bool:
    text = _text(node)
    if re.match(r"(?:request|req|flask\.request)\b", text) or re.search(r"\b(?:get_json|json|form|args|values|"
                                                                        r"query_params|POST|GET|data)\b", text):
        return True
    root = node
    while isinstance(root, (ast.Attribute, ast.Subscript, ast.Call)):
        root = root.func if isinstance(root, ast.Call) else root.value
    return isinstance(root, ast.Name) and root.id in holders


def _handed_on(parts, proof: str) -> str:
    """The name of a call the proof is handed to that is not only a store or a look; '' when there is none."""
    for node in parts:
        if not isinstance(node, ast.Call):
            continue
        name = _name_of(node.func)
        if name in NEUTRAL or name.endswith(("Error", "Exception")) or set(_words(name)) & NEUTRAL_WORDS:
            continue
        for a in [*node.args, *(k.value for k in node.keywords)]:
            if any(_text(sub) == proof for sub in ast.walk(a)):
                return name or _text(node.func)[:40]
    return ""


def read_py(text: str) -> list[dict]:
    tree = ast.parse(text)
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, FUNCS) or WEBHOOK.search(fn.name):
            continue
        parts = list(_own_parts(fn))
        done = _done_lines(fn, parts)
        if not done:
            continue
        if any(isinstance(c, ast.Call) and LOOKS_UP.search(_text(c.func)) for c in parts):
            continue
        proofs = _proofs(fn, parts)
        if not proofs:
            continue
        used = {}
        for proof in proofs:
            if not any(_text(n) == proof for n in parts if isinstance(n, (ast.Name, ast.Attribute, ast.Subscript,
                                                                         ast.Call))):
                continue                    # a parameter the function never reads
            if _handed_on(parts, proof):
                used = {}
                break
            used[proof] = proofs[proof]
        if not used:
            continue
        line, said = done[0]
        out.append({"line": line, "function": fn.name, "said": said, "proof": sorted(used)[0][:60]})
    return out


# --- LW-CALLER-SAYS-DONE, JavaScript and TypeScript (one function's own lines) -----------------------------------

JS_DONE = [re.compile(r"(?i)(?<![\w$])(?:status|state|paymentStatus|payment_status|stage)\s*[:=]\s*['\"`]([\w-]{2,40})"
                      r"['\"`]"),
           re.compile(r"(?<![\w$])(?:is)?(?:Paid|paid|Settled|settled|Verified|verified|Confirmed|confirmed|Approved|"
                      r"approved|Captured|captured)\s*[:=]\s*true\b")]
JS_SOURCE = re.compile(r"(?<![\w$])(?:req|request)\s*\.\s*(?:body|query|params)|await\s+(?:req|request)\s*\.\s*"
                       r"(?:json|formData)\s*\(|(?<![\w$])(?:body|input|searchParams|formData|payload)(?![\w$])")
JS_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
JS_CALL = re.compile(r"([A-Za-z_$][\w$.]*)\s*\(([^()]*)\)")


def read_js(code: list[str], raw: list[str]) -> dict | None:
    joined = "\n".join(code)
    if len(joined) > MOST_BODY:
        return None
    done = None
    for i, line in enumerate(code):
        for rx in JS_DONE:
            # the strings are blanked in `code`: read the raw line where its key stands in code, not in a remark
            m = next((m for m in rx.finditer(raw[i]) if line[m.start():m.start() + 3] == raw[i][m.start():m.start() + 3]),
                     None)
            if m and (rx is JS_DONE[1] or _is_done_word(m.group(1))):
                done = (i, m.group(0)[:60])
                break
        if done:
            break
        m = SQL_DONE.search(raw[i]) if raw[i] else None
        if m and _sql_done(m):
            done = (i, f"SET {m.group(1)} = {m.group(2) or m.group(3) or m.group(4)}")
            break
    if not done:
        return None
    if any(LOOKS_UP.search(name) for line in code for name, _ in JS_CALL.findall(line)):
        return None
    proofs = []
    for line in code:
        if not JS_SOURCE.search(line):
            continue
        for name in JS_IDENT.findall(line):
            if _is_proof_name(name) and name not in proofs:
                proofs.append(name)
    if not proofs:
        return None
    for proof in proofs:
        for line in code:
            for name, args in JS_CALL.findall(line):
                last = name.rsplit(".", 1)[-1]
                if last in NEUTRAL or last.endswith(("Error", "Exception")) or last in ("json", "formData") or \
                        set(_words(last)) & NEUTRAL_WORDS:
                    continue
                if re.search(rf"(?<![\w$]){re.escape(proof)}(?![\w$])", args):
                    return None
    return {"line": done[0], "said": done[1], "proof": proofs[0]}


def caller_says_done(g: Graph) -> list[dict]:
    """Functions that mark something done on the caller's word alone (see the note above). Heuristic."""
    by_file: dict[str, list] = {}
    for nid, n in g.nodes.items():
        if n.file and not outside(nid):
            by_file.setdefault(n.file, []).append(n)
    out = []
    for file in sorted(by_file):
        js = file.endswith(tuple(JS_EXTS) + (".mts", ".cts"))
        if not (js or file.endswith(".py")) or NOT_THE_APP.search(file) or WEBHOOK.search(file):
            continue
        try:
            text = project_text(Path(g.repo_root) / file, g.repo_root, MOST_FILE + 1)
        except OSError:
            continue
        if len(text) > MOST_FILE or not re.search(r"(?i)paid|settled|succeeded|confirmed|verified|approved|"
                                                  r"fulfilled|captured|completed|delivered|cleared", text):
            continue
        raw = text.splitlines()
        if js:
            out += _js_file(g, file, text, raw, by_file[file])
            continue
        try:
            found = read_py(text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue
        for c in found:
            out.append(_caller_finding(file, c["line"], c["function"], c["said"], c["proof"], raw))
    return out


def _js_file(g, file, text, raw, nodes) -> list[dict]:
    out = []
    code = [line if len(line) <= MOST_LINE else "" for line in code_only(text, True).splitlines()]
    code += [""] * (len(raw) - len(code))
    raw = [line if len(line) <= MOST_LINE else "" for line in raw]
    spans = sorted({(n.start_line, n.end_line or n.start_line) for n in nodes if n.kind == "callable" and n.start_line})
    told: set[int] = set()
    for n in sorted((n for n in nodes if n.kind == "callable" and n.start_line),
                    key=lambda n: ((n.end_line or n.start_line) - n.start_line, n.start_line)):
        a, b = n.start_line, min(n.end_line or n.start_line, len(raw))
        if b - a < 2 or WEBHOOK.search(n.name or ""):
            continue
        own_code, own_raw = code[a - 1:b], raw[a - 1:b]
        for s, e in spans:
            if (s, e) != (a, b) and a <= s and e <= b:
                for i in range(s - a, e - a + 1):
                    own_code[i] = own_raw[i] = ""
        got = read_js(own_code, own_raw)
        if not got or a + got["line"] in told:
            continue
        told.add(a + got["line"])
        out.append(_caller_finding(file, a + got["line"], n.name, got["said"], got["proof"], raw))
    return out


def _caller_finding(file, line, function, said, proof, raw) -> dict:
    f = _finding(
        CALLER_RULE, f"`{function}` marks it done ({said}) on the caller's word alone",
        "MEDIUM", file, line, category="code", conf="LOW", cwe=345, fixed_rank="medium",
        more=("Heuristic: read from this function's own lines. This line marks something as done (paid, settled, "
              f"confirmed, verified or approved), and the only proof the function holds is `{proof}`, a value the "
              "caller handed it that is named like the proof of an outside event (a provider's or a bank's id, a "
              "receipt). The value is only stored or looked at for being there: nothing hands it to anything that "
              "could ask the provider whether it is real. Whoever can call this marks the thing done with a "
              "made-up value. Fix: ask the provider for that id (its status, its amount, that it belongs to this "
              "record) before marking it done, or let only the provider's signed message mark it. If the caller is "
              "the provider itself, checked elsewhere, or a person whose word is the record, this is no problem."),
        snippet=raw[line - 1].strip() if 0 < line <= len(raw) else "")
    f["caller_proof"] = {"value": proof, "marks": said}
    return f


# --- LW-SELF-WRITTEN-PROOF ------------------------------------------------------------------------------------------

def _strings(value) -> set[str] | None:
    if isinstance(value, ast.Call) and _name_of(value.func) in ("frozenset", "set", "tuple", "list") and value.args:
        value = value.args[0]
    if not isinstance(value, (ast.Set, ast.List, ast.Tuple)):
        return None
    got = {e.value for e in value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return got if len(got) == len(value.elts) and len(got) >= 2 else None


def writer_sets(text: str, roles: set[str] = WRITER_ROLE) -> dict[str, tuple[int, set[str]]]:
    """The lists of record kinds a lower-trust side may write: name -> (line, kinds). With `roles=TRUSTED_ROLE`, the
    lists of the side the program trusts (a controller, a supervisor)."""
    out = {}
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                name = t.id if isinstance(t, ast.Name) else t.attr if isinstance(t, ast.Attribute) else ""
                words = set(_words(name))
                if not (words & roles and words & WRITER_SET) or (roles is not WRITER_ROLE and words & WRITER_ROLE) \
                        or node.value is None:
                    continue
                kinds = _strings(node.value)
                if kinds:
                    out[name] = (node.lineno, kinds)
    return out


def verifiers(text: str) -> list[tuple[str, int, set[str]]]:
    """Functions named for checking, with the text constants they ask for: (name, line, constants)."""
    out = []
    for fn in ast.walk(ast.parse(text)):
        if isinstance(fn, FUNCS) and CHECKER.search(fn.name):
            asked = {n.value for n in _own_parts(fn) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
            out.append((fn.name, fn.lineno, asked))
    return out


def self_written(g: Graph) -> list[dict]:
    """Checks that ask for what the checked side itself may write (see the note above). Heuristic."""
    files = sorted({n.file for nid, n in g.nodes.items() if n.file and n.file.endswith(".py") and not outside(nid)})
    texts = {}
    sets: dict[str, tuple[str, int, set[str]]] = {}
    trusted: set[str] = set()
    for file in files:
        if NOT_THE_APP.search(file):
            continue
        try:
            text = project_text(Path(g.repo_root) / file, g.repo_root, MOST_FILE + 1)
        except OSError:
            continue
        if len(text) > MOST_FILE:
            continue
        texts[file] = text
        if re.search(r"(?i)(?:controller|supervisor|server|parent|host|trusted|observer|orchestrator|coordinator|"
                     r"verifier|monitor)\w*_(?:kinds|types|events|records|receipts|allowed|allowlist|whitelist|"
                     r"writable|messages|ops|appends)", text):
            try:
                for _line, kinds in writer_sets(text, TRUSTED_ROLE).values():
                    trusted |= kinds
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                pass
        if not re.search(r"(?i)(?:runner|worker|client|agent|child|sandbox|guest|plugin|remote|untrusted|caller|"
                         r"subprocess|external|tenant|device|sensor|bot)\w*_(?:kinds|types|events|records|receipts|"
                         r"allowed|allowlist|whitelist|writable|messages|ops|appends)", text):
            continue
        try:
            for name, (line, kinds) in writer_sets(text).items():
                sets[name] = (file, line, kinds)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue
    if not sets:
        return []
    out = []
    for file, text in texts.items():
        if not CHECKER.search(text) and not re.search(r"(?i)def\s+_*(?:verify|certify|attest|approve|validate|"
                                                      r"confirm|accept|check|admit|promote)", text):
            continue
        try:
            found = verifiers(text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue
        raw = text.splitlines()
        for fname, line, asked in found:
            for set_name, (set_file, set_line, kinds) in sorted(sets.items()):
                theirs = sorted(asked & kinds)
                happened = [k for k in theirs if set(_words(k)) & HAPPENED]
                if len(theirs) < 2 or not happened or asked & (trusted - kinds):
                    continue                             # also asks for a record the trusted side writes
                others = sorted(k for k in asked - kinds if re.fullmatch(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+", k))
                f = _finding(
                    WRITER_RULE, f"`{fname}` checks records that `{set_name}` lets the checked side write itself",
                    "MEDIUM", file, line, category="code", conf="LOW", cwe=345, fixed_rank="medium",
                    more=("Heuristic: read from the names and the text constants of the code. This function is named "
                          f"for checking, and it asks for {len(theirs)} kinds of record that `{set_name}` "
                          f"({set_file}:{set_line}) lets a side the program trusts less write itself: "
                          f"{', '.join(theirs[:6])}. {happened[0]} says something happened outside; written by the "
                          "side whose work is being checked, it proves only that this side said so, and a record it "
                          "made up passes as well as a real one. "
                          + (f"It also asks for {', '.join(others[:4])}, which that list does not name: if the "
                             "trusted side writes those from what it saw itself, the risk is smaller. " if others
                             else "") +
                          "Fix: have the trusted side observe the event itself (its own socket, its own clock, the "
                          "provider's own answer) and write that record, and check against it. Lantern reads names "
                          "only; it does not know who really writes each record."),
                    snippet=raw[line - 1].strip() if 0 < line <= len(raw) else "")
                f["self_proof"] = {"writer": set_name, "where": f"{set_file}:{set_line}", "kinds": theirs,
                                   "also": others[:10]}
                out.append(f)
                break
    return out
