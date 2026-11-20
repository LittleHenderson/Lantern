"""Money or an order sent out before the program writes down that it is sending it (2026-11-19). One heuristic,
`tool_confidence: LOW` and ranked medium; it reads a Python file's own text and runs nothing.

`LW-EFFECT-BEFORE-RECORD` (`effect_first(g)`; `read(text)` is the reading of one file): in one function, a call that
asks another service to move money or to place an order (a withdrawal, a payout, a transfer, a refund, an order to
a broker: `client.withdraw(...)`, `stripe.Payout.create(...)`, `broker.place_order(...)`) comes before the first line
that writes anything down (a database write, a `commit()`, a `save()`, an `INSERT` or `UPDATE`), and the function
does write it down after. Where the program stops between the two (a crash, a deploy, a time limit, a database
that is not there for a moment), the money has moved or the order stands and nothing of this program says so: the
next try sends it again, and the books do not match the account. Written after another review tool named that
shape in a project Lantern was measured on (a bank withdrawal sent, and the row that records it written after it),
from examples of Lantern's own.

It says nothing where something is written down before the call (the intent, a "pending" row), where the call is
handed a key that makes a second send the same as the first (`idempotency_key`, `client_order_id`, ...), and where
the function writes nothing at all (it may be written elsewhere, which is not followed). A call of the project's own
method (`self.withdraw()`) is not the other service's. It does not know what the other service does with a second
call: it says "check".
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from .graph import Graph, outside
from .localweb import NOT_THE_APP
from .python_frontend import project_text
from .websec import _finding

RULE = "LW-EFFECT-BEFORE-RECORD"
MOST_FILE = 400_000
EFFECT = re.compile(r"(?i)^(?:withdraw\w*|\w*_withdraw\w*|payout\w*|\w*_payout|send_payout|transfer_funds|send_money|"
                    r"send_funds|wire_\w+|disburse\w*|place_\w*order|submit_\w*order|send_\w*order|order_send|"
                    r"create_\w*order|execute_trade|place_trade|open_position|close_position|buy_market|sell_market)$")
EFFECT_CHAIN = re.compile(r"(?i)\b(?:Payout|Transfer|Refund|payouts|transfers|refunds|withdrawals)\.create$")
IDEMPOTENT = re.compile(r"(?i)idempoten|client_?order_?id|client_?oid|dedup|request_?id|idem_?key")
RECORD_ATTRS = {"commit", "save", "add", "add_all", "insert", "insert_one", "insert_many", "bulk_create", "put_item",
                "update", "update_one", "update_many", "create", "execute", "executemany", "record", "append",
                "upsert", "write"}
STORE_WORDS = {"db", "session", "conn", "connection", "cursor", "cur", "repo", "repository", "store", "ledger",
               "journal", "objects", "table", "collection", "prisma", "tx", "txn", "database", "dao", "orm"}
SQL_WRITE = re.compile(r"(?is)^\s*(?:insert\s+into|update\s+\w|replace\s+into|upsert)")


def _words(name: str) -> set[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name or "")
    return {w.lower() for w in re.split(r"[^A-Za-z0-9]+", spaced) if w}


def _text(node) -> str:
    try:
        return ast.unparse(node)
    except Exception:       # a tree Python cannot write back: nothing is read from it
        return ""


def _own_parts(fn):
    """The parts of a function, not those of a function written inside it."""
    stack = list(reversed(fn.body))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        yield node
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _sql_texts(fn) -> dict[str, str]:
    out = {}
    for node in _own_parts(fn):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            out.update({t.id: node.value.value for t in node.targets if isinstance(t, ast.Name)})
    return out


def _is_effect(call: ast.Call) -> str:
    if not isinstance(call.func, ast.Attribute):
        return ""
    whole = _text(call.func)
    if isinstance(call.func.value, ast.Name) and call.func.value.id in ("self", "cls"):
        return ""           # the project's own method, not the other service's
    if EFFECT.match(call.func.attr) or EFFECT_CHAIN.search(whole):
        return whole
    return ""


def _is_record(call: ast.Call, sql: dict[str, str]) -> bool:
    if not isinstance(call.func, ast.Attribute):
        return False
    attr = call.func.attr
    if attr not in RECORD_ATTRS:
        return False
    if attr in ("execute", "executemany"):
        first = call.args[0] if call.args else None
        text = first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else \
            sql.get(first.id, "") if isinstance(first, ast.Name) else ""
        if not text and isinstance(first, ast.Call):        # text(...) of SQLAlchemy
            inner = first.args[0] if first.args else None
            text = inner.value if isinstance(inner, ast.Constant) and isinstance(inner.value, str) else ""
        return bool(SQL_WRITE.match(text))
    if attr in ("commit", "save"):
        return True
    return bool(_words(_text(call.func.value)) & STORE_WORDS)


def read(text: str) -> list[dict]:
    tree = ast.parse(text)
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        calls = sorted((c for c in _own_parts(fn) if isinstance(c, ast.Call)), key=lambda c: (c.lineno, c.col_offset))
        effects = [(c, w) for c in calls for w in [_is_effect(c)] if w]
        if not effects:
            continue
        sql = _sql_texts(fn)
        records = [c for c in calls if _is_record(c, sql)]
        call, what = effects[0]
        # a key handed to the send itself, or a function of its own for it (`dedup(...)`); a request's id handed to
        # some other call is no key of the send (2026-11-19: `verify(owner_request_id=...)` before a withdrawal kept
        # the first version quiet about a project's withdrawal sent before its row)
        if any(IDEMPOTENT.search(_text(k)) for c, _ in effects for k in [*c.args, *c.keywords]) or \
                any(IDEMPOTENT.search(_text(c.func)) for c in calls):
            continue
        before = [r for r in records if (r.lineno, r.col_offset) < (call.lineno, call.col_offset)]
        after = [r for r in records if (r.lineno, r.col_offset) > (call.end_lineno or call.lineno, 0)]
        if before or not after:
            continue
        out.append({"line": call.lineno, "function": fn.name, "effect": what[:80], "record": after[0].lineno})
    return out


def effect_first(g: Graph) -> list[dict]:
    files = sorted({n.file for nid, n in g.nodes.items() if n.file and n.file.endswith(".py") and not outside(nid)})
    out = []
    for file in files:
        if NOT_THE_APP.search(file):
            continue
        try:
            text = project_text(Path(g.repo_root) / file, g.repo_root, MOST_FILE + 1)
        except OSError:
            continue
        if len(text) > MOST_FILE or not re.search(r"(?i)withdraw|payout|transfer|refund|order|trade|position|wire_|"
                                                  r"disburse|send_money|send_funds", text):
            continue
        try:
            found = read(text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue
        raw = text.splitlines()
        for c in found:
            f = _finding(
                RULE, f"`{c['function']}` sends `{c['effect']}` before anything of it is written down",
                "MEDIUM", file, c["line"], category="code", conf="LOW", cwe=696, fixed_rank="medium",
                more=("Heuristic: read from this function's own lines. This line asks another service to move money "
                      f"or to place an order, and the first line that writes anything down comes after it (line "
                      f"{c['record']}). Where the program stops between the two (a crash, a deploy, a time limit, a "
                      "database that is not there for a moment), the money has moved or the order stands and nothing "
                      "here says so: the next try sends it again, and the books do not match the account. Fix: write "
                      "the intent down first (a row that says \"sending\", committed), send with a key that makes a "
                      "second send the same as the first (an idempotency key, a client order id), and mark the row "
                      "done after. If the service is asked with such a key elsewhere, this is no problem."),
                snippet=raw[c["line"] - 1].strip() if 0 < c["line"] <= len(raw) else "")
            f["effect"] = {"call": c["effect"], "recorded_at": c["record"]}
            out.append(f)
    return out
