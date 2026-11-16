"""A first behaviour plan, written from the code (roadmap of 2026-11-14, stage 4): `lantern behave --init`.

`lantern behave` starts an app in the sandbox and asks it the requests of a plan (`lantern-behaviour.json`,
docs/behaviour.md). Until now a person wrote that plan by hand. `draft(repo)` writes a first one from what the map
and the code's own text show, and runs nothing of the project:

* the app: a FastAPI app made at the top of a file (`app = FastAPI()`) or by a function (`create_app`), with the
  folder it is started in;
* its settings: the variables the code reads for its database (handed a file in the sandbox's own data folder),
  for a secret (handed one made for the run) and for a folder it writes to;
* two people, alice and bob: the request that makes an account, and the request that signs in and answers with a
  token;
* one case for each route (`refuse`): a visitor who is not signed in must be turned away, beside alice, who may.
  Where the route names one row (`/notes/{note_id}`) the row is made by alice first, and bob must be turned away
  as well;
* limits and repeats: wrong passwords at the sign-in, a route that reaches a paid service (`limit`), a route that
  moves money or points (`once`), a route that reads an idempotency key (`retry`).

Everything is read from names and shapes, like the login check and the limits view it builds on: a heuristic. So
the plan says what it is unsure of (`notes.review`: a page whose code shows no login check, a value Lantern made
up for a field whose meaning it cannot tell) and what it left out, with the reason (`notes.left_out`). A person
reads it once, corrects it, and keeps it with the code. Nothing here decides anything: the cases are judged by
`behave.judge` from what the app did when it was run.

Read, never run: the files are parsed with Python's own `ast`, bounded in size and number; a file Python cannot
parse is passed by. The plan holds only what `behave.check` accepts, and a text taken from the code (a path, a
field's name) goes into it as data."""
from __future__ import annotations

import ast
import json
import os
import re
import warnings
from pathlib import Path

from . import __version__
from . import results
from .behave import PLAN_NAME, PlanError, _request_ok, check as plan_ok, scene
from .graph import Graph, outside
from .localweb import NOT_THE_APP
from .python_frontend import inside_repo, project_text

MOST_FILE = 400_000          # characters of a file that are read
MOST_FILES = 4_000           # Python files of a project that are read
MOST_CHECKS = 300            # checks a first plan holds
MOST_DEPTH = 4               # a body's tables inside tables
TRIES = 10                   # tries before the one that must be refused as too many, where the code names no number
MOST_TRIES = 100
FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)
MAKERS = frozenset({"FastAPI"})
MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
PEOPLE = ("alice", "bob")
OWNER, OTHER = PEOPLE

PARAM = re.compile(r"\{(\w+)(?::\w+)?\}")
IDENT = re.compile(r"[A-Za-z_]\w*\Z")
WORDS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")     # the words of a name: `DB_PATH`, `accessToken`
LOGIN_WORDS = frozenset({"login", "signin", "token", "session", "sessions", "auth", "authenticate", "authorize"})
SIGNUP_WORDS = frozenset({"signup", "register", "registration", "users", "user", "accounts", "account"})
PASSWORD = frozenset({"password", "passwd", "pwd", "passphrase"})
PAY_WORDS = frozenset({"pay", "payment", "payments", "charge", "charges", "checkout", "transfer", "transfers", "purchase",
                       "purchases", "redeem", "withdraw", "withdrawal", "refund", "refunds", "donate", "donation",
                       "topup", "deposit", "buy", "spend"})
FREE_TEXT = frozenset({"text", "title", "body", "content", "message", "description", "note", "comment", "subject",
                       "label", "summary", "caption", "instructions", "details", "bio", "about"})
ASKED = frozenset({"q", "query", "search", "term", "keyword", "keywords", "filter"})
NUMBERS = frozenset({"amount", "quantity", "qty", "count", "price", "total", "servings", "number", "value", "size",
                     "limit", "offset", "page", "rating", "score", "age", "points", "credits"})
WHO_NAMES = frozenset({"username", "user", "login", "handle", "nickname", "nick", "name", "fullname", "firstname",
                       "lastname", "displayname", "team", "teamname", "org", "organisation", "organization", "company",
                       "workspace"})
PASSED_BY = frozenset({"Request", "Response", "BackgroundTasks", "WebSocket", "HTTPConnection", "SecurityScopes"})
DB_WORDS = frozenset({"db", "database", "sqlite", "sqlalchemy"})
SECRET_WORDS = frozenset({"secret", "key", "token", "salt", "password", "passphrase", "signing", "jwt"})
NOT_A_SECRET = frozenset({"expire", "expires", "expiry", "expiration", "minutes", "seconds", "hours", "days", "ttl",
                          "algorithm", "alg", "url", "uri", "header", "name", "length", "rounds", "prefix", "type",
                          "file", "path", "public", "id", "max", "min", "lifetime"})
FOLDER_WORDS = frozenset({"dir", "folder", "uploads", "media", "storage"})
QUIET = frozenset({"audit", "log", "logs", "attempt", "attempts", "ratelimit", "ratelimits", "throttle", "throttles"})
TABLE = re.compile(r"\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?[\"'`\[]?(\w+)", re.I)
READS = re.compile(r"\bselect\b[\s\S]{0,300}?\bfrom\b|\.query\(|\.execute\(|\.objects\b|\.find(?:_one|_many|_all)?\(|"
                   r"\.fetch(?:one|all|many|val|row)?\(|\.scalars?\(|\.get_or_404\(", re.I)
LIMIT_NAME = re.compile(r"(?i)limit|throttl")
PER = re.compile(r"\s*(\d{1,6})\s*(?:/|per\b)")
# where a paid service is asked, for the services that have one address: a case that tries it is not called a fault
PAID_HOSTS = {"OpenAI": "api.openai.com", "Anthropic": "api.anthropic.com", "Mistral": "api.mistral.ai",
              "Cohere": "api.cohere.com", "Groq": "api.groq.com", "Replicate": "api.replicate.com",
              "Stripe": "api.stripe.com"}
WRONG_PASSWORD = "not-the-pass-phrase-0"      # nosec B105: a made-up wrong password for a throw-away account of a test run


class _Cannot(Exception):
    """No request can be made for a route; the message is the reason, as a part of a sentence."""


def _words(name: str) -> list[str]:
    return [w.lower() for w in WORDS.findall(name.replace("_", " ").replace("-", " "))]


def _last(node) -> str:
    """`c` for the names `c` and `a.b.c`, "" for anything else."""
    if isinstance(node, ast.Attribute):
        return node.attr
    return node.id if isinstance(node, ast.Name) else ""


def _text(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _dotted(node) -> str:
    """`a.b.c` for a name with its attributes (the first 12 of them), "" for anything else."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute) and len(parts) < 12:
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _own(fn):
    """Every part of a function that is its own: not what a function or class written inside it holds."""
    todo = list(fn.body)
    while todo:
        node = todo.pop()
        yield node
        if not isinstance(node, FUNCS + (ast.Lambda, ast.ClassDef)):
            todo.extend(ast.iter_child_nodes(node))


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "route"


def _singular(word: str) -> str:
    word = re.sub(r"\W+", "_", word).strip("_").lower() or "row"
    if word.endswith("ies") and len(word) > 4:
        return word[:-3] + "y"
    return word[:-1] if word.endswith("s") and not word.endswith("ss") and len(word) > 2 else word


# ----------------------------------------------------------------------------------------------- annotations
class _Kind:
    """What an annotation says: its last name (`str`, `NoteIn`, `list`), what stands in its brackets, what
    `Annotated[...]` carries beside the type, and whether None is allowed."""

    def __init__(self, name: str = "", args=(), marks=(), optional: bool = False):
        self.name, self.args, self.marks, self.optional = name, list(args), list(marks), optional


def _kind(node, depth: int = 0) -> _Kind:
    if node is None or depth > 6:
        return _Kind()
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str) and IDENT.match(node.value.strip()):
            return _Kind(node.value.strip())
        return _Kind("None" if node.value is None else "")
    if isinstance(node, (ast.Name, ast.Attribute)):
        return _Kind(_last(node))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        sides = [_kind(node.left, depth + 1), _kind(node.right, depth + 1)]
        real = [k for k in sides if k.name != "None"]
        if real:
            real[0].optional = real[0].optional or len(real) < len(sides)
            return real[0]
        return _Kind()
    if isinstance(node, ast.Subscript):
        head = _last(node.value)
        inner = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
        if head == "Annotated" and inner:
            k = _kind(inner[0], depth + 1)
            k.marks = k.marks + [m for m in inner[1:] if isinstance(m, ast.Call)]
            return k
        if head == "Optional" and inner:
            k = _kind(inner[0], depth + 1)
            k.optional = True
            return k
        if head == "Union":
            kinds = [_kind(i, depth + 1) for i in inner]
            real = [k for k in kinds if k.name != "None"]
            if real:
                real[0].optional = real[0].optional or len(real) < len(kinds)
                return real[0]
            return _Kind()
        return _Kind(head, inner)
    return _Kind()


class _Field:
    """One value a request carries: a field of a body, a form field, a value in the address."""

    def __init__(self, name: str, ann=None, required: bool = True, limits: dict | None = None):
        self.name, self.ann, self.required, self.limits = name, ann, required, limits or {}


def _limits(call) -> dict:
    """The bounds a `Field(...)`, `Query(...)` or `Form(...)` names, where they are written as numbers."""
    out = {}
    for kw in getattr(call, "keywords", None) or []:
        if kw.arg in ("min_length", "max_length", "ge", "gt", "le", "lt") and isinstance(kw.value, ast.Constant) \
                and isinstance(kw.value.value, (int, float)) and not isinstance(kw.value.value, bool):
            out[kw.arg] = kw.value.value
        elif kw.arg in ("pattern", "regex"):
            out["pattern"] = True
    return out


def _needed(call) -> bool:
    """Whether a `Field(...)` and its like leave the value without a default."""
    if call.args:
        return isinstance(call.args[0], ast.Constant) and call.args[0].value is Ellipsis
    return not any(kw.arg in ("default", "default_factory") for kw in call.keywords)


# --------------------------------------------------------------------------------------------------- the code
class _Code:
    """The project's Python files as trees, read once, with what the plan is made from: the classes that are a
    body's shape (`models`), the lists of allowed words (`enums`), the variables the code reads (`settings`)."""

    def __init__(self, g: Graph):
        self.repo = Path(g.repo_root)
        self.trees: dict[str, ast.Module] = {}
        self.texts: dict[str, list[str]] = {}
        files = sorted({n.file for nid, n in g.nodes.items() if n.file and n.file.endswith(".py") and not outside(nid)})
        for file in files[:MOST_FILES]:
            if NOT_THE_APP.search(file):
                continue
            try:
                text = project_text(self.repo / file, self.repo, MOST_FILE + 1)
            except OSError:
                continue
            if len(text) > MOST_FILE:
                continue
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    self.trees[file] = ast.parse(text)
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                continue
            self.texts[file] = text.splitlines()
        self.classes: dict[str, tuple[str, ast.ClassDef]] = {}
        for file, tree in self.trees.items():
            for node in tree.body:
                if isinstance(node, ast.ClassDef):
                    self.classes.setdefault(node.name, (file, node))
        self.models = self._family({"BaseModel", "SQLModel"})
        self.settings_classes = self._family({"BaseSettings"})
        self.enums = self._family({"Enum", "IntEnum", "StrEnum"})

    def _family(self, roots: set) -> set:
        """The project's classes that are built on one of `roots`, directly or through another of them."""
        found: set = set()
        grew = True
        while grew:
            grew = False
            for name, (_file, cls) in self.classes.items():
                if name not in found and any(_last(b) in roots or _last(b) in found for b in cls.bases):
                    found.add(name)
                    grew = True
        return found

    def fields(self, model: str, seen=()) -> list[_Field]:
        """A model's fields, a parent's first; a name written again further down takes the earlier one's place."""
        if model not in self.classes or model in seen:
            return []
        _file, cls = self.classes[model]
        out: dict[str, _Field] = {}
        for base in cls.bases:
            if _last(base) in self.models:
                for f in self.fields(_last(base), tuple(seen) + (model,)):
                    out[f.name] = f
        for node in cls.body:
            if not isinstance(node, ast.AnnAssign) or not isinstance(node.target, ast.Name):
                continue
            name = node.target.id
            if name.startswith("_") or name == "model_config" or _kind(node.annotation).name == "ClassVar":
                continue
            kind = _kind(node.annotation)
            limits, required = {}, node.value is None
            for mark in kind.marks:
                limits.update(_limits(mark))
            if isinstance(node.value, ast.Call) and _last(node.value.func) == "Field":
                limits.update(_limits(node.value))
                required = _needed(node.value)
            out[name] = _Field(name, node.annotation, required, limits)
        return list(out.values())

    def first_word(self, enum: str):
        """The first value of a list of allowed words (`class Role(str, Enum)`), None when none is written out."""
        for node in self.classes[enum][1].body:
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                return node.value.value
        return None

    def function(self, file: str, name: str, line: int | None):
        """The function of a file that the map knows under `name` at `line` (a decorator's line counts as its own)."""
        tree = self.trees.get(file)
        if tree is None:
            return None
        best = None
        for node in ast.walk(tree):
            if isinstance(node, FUNCS) and node.name == name:
                top = min([d.lineno for d in node.decorator_list] + [node.lineno])
                if line is None or top <= line <= (node.end_lineno or node.lineno):
                    return node
                best = best or node
        return best

    def lines(self, file: str, first: int | None, last: int | None) -> str:
        rows = self.texts.get(file) or []
        return "\n".join(rows[max((first or 1) - 1, 0):last or first or 0])


# ------------------------------------------------------------------------------------------------- the values
def _value(field: _Field, who: str | None, code: _Code, unsure: list, depth: int = 0):
    """A value for one field, from its type and its name. A value whose meaning Lantern cannot tell (a text under
    a name it does not know) is still made, and the field's name is added to `unsure`. _Cannot when none can be."""
    kind = _kind(field.ann)
    name, lim = field.name, field.limits
    for mark in kind.marks:
        lim = {**_limits(mark), **lim}
    words = set(_words(name)) | {name.lower().replace("_", "")}
    person = who or "somebody"
    t = kind.name
    if t == "Literal" and kind.args:
        first = kind.args[0]
        if isinstance(first, ast.Constant):
            return first.value
        raise _Cannot(f"the value of `{name}` is one of a list Lantern could not read")
    if t in code.enums:
        word = code.first_word(t)
        if word is None:
            raise _Cannot(f"the value of `{name}` is one of a list Lantern could not read")
        return word
    if t in code.models:
        if depth >= MOST_DEPTH:
            raise _Cannot(f"the body is nested too deep at `{name}`")
        return {f.name: _value(f, who, code, unsure, depth + 1) for f in code.fields(t) if f.required}
    if t in ("list", "List", "set", "Set", "frozenset", "tuple", "Tuple", "Sequence", "Iterable"):
        if lim.get("min_length"):
            raise _Cannot(f"`{name}` needs a list that is not empty")
        return []
    if t in ("dict", "Dict", "Mapping", "Any", "object"):
        return {}
    if t == "bool":
        return True
    if t in ("int", "float", "Decimal", "PositiveInt", "NonNegativeInt", "PositiveFloat", "conint", "confloat"):
        n = 1
        if "gt" in lim:
            n = int(lim["gt"]) + 1
        elif "ge" in lim:
            n = max(n, int(lim["ge"])) if lim["ge"] > 1 else n
        if "lt" in lim and n >= lim["lt"]:
            n = int(lim["lt"]) - 1
        elif "le" in lim and n > lim["le"]:
            n = int(lim["le"])
        if not words & NUMBERS and not name.lower().endswith(("_id", "id")):
            pass                                  # a plain number under any name is a value like another
        if name.lower() == "id" or name.lower().endswith("_id") or name in ("to", "recipient", "owner"):
            unsure.append(name)                   # the number of another row: Lantern cannot know one that is there
        return float(n) if t in ("float", "PositiveFloat", "confloat") else n
    if t in ("EmailStr", "NameEmail"):
        text = f"{person}@example.test"
    elif t in ("HttpUrl", "AnyUrl", "AnyHttpUrl", "Url"):
        text = "https://example.test/"
    elif t == "UUID" or t.startswith("UUID"):
        return "00000000-0000-4000-8000-000000000001"
    elif t == "datetime":
        return "2026-01-01T12:00:00"
    elif t == "date":
        return "2026-01-01"
    elif t in ("str", "SecretStr", "constr", "", "None"):
        if lim.get("pattern"):
            unsure.append(name)
        if words & {"email", "mail"}:
            text = f"{person}@example.test"
        elif words & PASSWORD or words & {"confirm", "confirmation"} and words & {"pass", "password"}:
            text = f"{person.title()}-pass-phrase-1"
        elif words & WHO_NAMES:
            text = person
        elif words & {"url", "link", "website", "href", "uri"}:
            text = "https://example.test/"
        elif words & {"phone", "mobile", "tel"}:
            text = "+15550100"
        elif words & FREE_TEXT:
            text = f"kept by {person}" if who else "written by a check of Lantern"
        elif words & ASKED:
            text = "kept"
        else:
            text = "text"
            unsure.append(name)
    else:
        raise _Cannot(f"`{name}` is of a kind Lantern cannot make a value for (`{t[:40]}`)")
    if isinstance(lim.get("min_length"), (int, float)) and len(text) < lim["min_length"] <= 2000:
        text += "x" * (int(lim["min_length"]) - len(text))
    if isinstance(lim.get("max_length"), (int, float)) and len(text) > lim["max_length"] >= 1:
        text = text[:int(lim["max_length"])]
    return text


# ------------------------------------------------------------------------------------------------- the routes
class _Route:
    """One route of the app as the plan needs it: its verb and path, and what its handler asks for."""

    def __init__(self, node, fn, code: _Code):
        self.node, self.fn, self.code = node, fn, code
        self.detail = (node.entry or {}).get("detail") or ""
        verb, _, path = self.detail.partition(" ")
        self.verb = verb.split("/")[0].upper()
        self.path = path.split("?")[0] or "/"
        self.params = PARAM.findall(self.path)
        self.query: list[_Field] = []
        self.form: list[_Field] = []
        self.body: list[tuple[str, str]] = []           # (the parameter's name, the model's name)
        self.loose: list[_Field] = []                   # values of a body that are parameters themselves (`Body(...)`)
        self.headers: list[str] = []                    # headers it cannot do without, other than the sign-in's
        self.idem: str | None = None                    # the header an idempotency key is read from
        self.raw = self.file = self.plain_body = False
        self.why_not: str | None = None
        self._read()

    def _read(self) -> None:
        fn = self.fn
        args = fn.args
        named = list(args.posonlyargs) + list(args.args)
        defaults = [None] * (len(named) - len(args.defaults)) + list(args.defaults)
        pairs = list(zip(named, defaults)) + list(zip(args.kwonlyargs, args.kw_defaults))
        asks_request = False
        for arg, default in pairs:
            name = arg.arg
            if name in ("self", "cls"):
                continue
            kind = _kind(arg.annotation)
            calls = list(kind.marks) + ([default] if isinstance(default, ast.Call) else [])
            how = next((_last(c.func) for c in calls if _last(c.func) in
                        ("Depends", "Security", "Header", "Cookie", "Form", "File", "Body", "Query", "Path")), "")
            call = next((c for c in calls if _last(c.func) == how), None)
            has_default = default is not None and not (isinstance(default, ast.Constant) and default.value is Ellipsis)
            required = _needed(call) if call is not None and how not in ("Depends", "Security") else not has_default
            if call is None and kind.marks:
                required = not has_default
            limits = _limits(call) if call is not None else {}
            field = _Field(name, arg.annotation, required, limits)
            if kind.name == "OAuth2PasswordRequestForm":
                self.form = [_Field("username"), _Field("password")]
            elif how in ("Depends", "Security"):
                continue
            elif kind.name in PASSED_BY:
                asks_request = asks_request or kind.name == "Request"
            elif name in self.params or how == "Path":
                continue
            elif how == "Header":
                alias = next((_text(kw.value) for kw in call.keywords if kw.arg == "alias"), None)
                header = alias or name.replace("_", "-")
                if "idempot" in header.lower():
                    self.idem = "-".join(w.capitalize() for w in header.split("-"))
                elif header.lower() != "authorization" and required:
                    self.headers.append(header)
            elif how == "Cookie":
                if required:
                    self.headers.append("Cookie")
            elif how == "File" or kind.name in ("UploadFile", "bytes"):
                self.file = self.file or required
            elif how == "Form":
                self.form.append(field)
            elif how == "Body":
                if kind.name in self.code.models:
                    self.body.append((name, kind.name))
                else:
                    self.loose.append(field)
            elif kind.name in self.code.models and how != "Query":
                self.body.append((name, kind.name))
            elif kind.name in ("dict", "Dict") and not how:
                self.plain_body = True
            else:
                self.query.append(field)
        if asks_request:
            for node in _own(fn):
                if isinstance(node, ast.Attribute) and node.attr in ("json", "body", "form", "stream"):
                    self.raw = True

    def words(self) -> set:
        return {w for seg in self.path.split("/") if not seg.startswith("{") for w in _words(seg)} \
            | {seg.lower().replace("-", "").replace("_", "") for seg in self.path.split("/") if seg and not seg.startswith("{")}

    def all_fields(self) -> list[_Field]:
        out = list(self.form) + list(self.loose)
        for _name, model in self.body:
            out += self.code.fields(model)
        return out

    def has_password(self) -> bool:
        return any(set(_words(f.name)) & PASSWORD for f in self.all_fields())

    def request(self, who: str | None, unsure: list, path: str | None = None, values: dict | None = None) -> dict:
        """The request a person makes of this route, with a value for everything it cannot do without. `values`
        are values given by name (a sign-in's e-mail and password are the sign-up's). _Cannot with the reason."""
        if self.file:
            raise _Cannot("it takes an uploaded file")
        if self.headers:
            raise _Cannot(f"it needs the header {self.headers[0][:40]}, which Lantern cannot fill in")
        if self.raw and self.verb != "GET":
            raise _Cannot("its code reads the request's body itself, so Lantern cannot see what it expects")
        given = values or {}

        def made(f: _Field):
            return given[f.name] if f.name in given else _value(f, who, self.code, unsure)

        req: dict = {"method": self.verb, "path": path or self.path}
        query = {f.name: made(f) for f in self.query if f.required}
        if query:
            req["query"] = query
        if self.form:
            if self.body or self.loose:
                raise _Cannot("it takes a form and a body together")
            pairs = {f.name: made(f) for f in self.form if f.required}
            req["text"] = "&".join(f"{_quote(k)}={_quote(v)}" for k, v in pairs.items())
            req["headers"] = {"Content-Type": "application/x-www-form-urlencoded"}
        elif self.body or self.loose:
            parts = {}
            for name, model in self.body:
                parts[name] = {f.name: made(f) for f in self.code.fields(model) if f.required}
            if len(self.body) == 1 and not self.loose:
                req["json"] = parts[self.body[0][0]]
            else:
                parts.update({f.name: made(f) for f in self.loose if f.required})
                req["json"] = parts
        elif self.plain_body:
            req["json"] = {}
        return req

    def answer_keys(self) -> list[str]:
        """The names in the table this route answers with, where the code writes it out: a `return {...}`, a
        `JSONResponse({...})`, or the fields of the model named as its answer."""
        keys: list[str] = []

        def take(node) -> None:
            if isinstance(node, ast.Call) and _last(node.func) in ("JSONResponse", "ORJSONResponse", "jsonable_encoder"):
                node = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == "content"), None)
            if isinstance(node, ast.Dict):
                for k in node.keys:
                    if _text(k) and _text(k) not in keys:
                        keys.append(_text(k))
            elif isinstance(node, ast.Call) and _last(node.func) in self.code.models:
                for f in self.code.fields(_last(node.func)):
                    if f.name not in keys:
                        keys.append(f.name)

        for node in _own(self.fn):
            if isinstance(node, ast.Return) and node.value is not None:
                take(node.value)
        models = [_kind(self.fn.returns).name] if self.fn.returns is not None else []
        for deco in self.fn.decorator_list:
            if isinstance(deco, ast.Call):
                models += [_kind(kw.value).name for kw in deco.keywords if kw.arg == "response_model"]
        for model in models:
            if model in self.code.models:
                for f in self.code.fields(model):
                    if f.name not in keys:
                        keys.append(f.name)
        return keys

    def limit_written(self) -> int | None:
        """The number of requests a limit written on the route itself allows (`@limiter.limit("5/minute")`)."""
        for deco in self.fn.decorator_list:
            if isinstance(deco, ast.Call) and LIMIT_NAME.search(_dotted(deco.func)):
                for arg in list(deco.args) + [kw.value for kw in deco.keywords]:
                    m = PER.match(_text(arg) or "")
                    if m:
                        return int(m.group(1))
        return None


def _quote(value) -> str:
    from urllib.parse import quote
    return quote(str(value), safe="")


# ---------------------------------------------------------------------------------------------- app, settings
def _module(code: _Code, file: str) -> tuple[str, str]:
    """(the folder the app is started in, the dotted name its file is loaded by)."""
    parts = file[:-3].split("/")
    tree = code.trees[file]
    need = max((n.level for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)), default=0)
    at = len(parts) - 1                      # how many folders lie above the file
    cut = at
    while cut > 0:
        folder = "/".join(parts[:cut])
        package = inside_repo(code.repo / folder / "__init__.py", code.repo)
        if not package and at - cut >= need:
            break
        cut -= 1
    return "/".join(parts[:cut]), ".".join(parts[cut:])


def _apps(code: _Code) -> list[dict]:
    """Every place a FastAPI app is made: at the top of a file, or in a function that hands it back."""
    found = []
    for file, tree in code.trees.items():
        for node in tree.body:
            value = getattr(node, "value", None)
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(value, ast.Call) \
                    and _last(value.func) in MAKERS:
                target = node.targets[0] if isinstance(node, ast.Assign) else node.target
                if isinstance(target, ast.Name):
                    found.append({"file": file, "line": node.lineno, "name": target.id, "factory": False})
            elif isinstance(node, FUNCS) and not node.args.args and not node.args.kwonlyargs:
                makes = any(isinstance(n, ast.Call) and _last(n.func) in MAKERS for n in _own(node))
                if makes and any(isinstance(n, ast.Return) and n.value is not None for n in _own(node)):
                    found.append({"file": file, "line": node.lineno, "name": node.name, "factory": True})
    usual = ("main.py", "app.py", "asgi.py", "server.py", "api.py")
    found.sort(key=lambda a: (a["factory"], a["file"].rsplit("/", 1)[-1] not in usual, a["file"].count("/"), a["file"]))
    return found


def _settings(code: _Code) -> dict:
    """The variables the code reads from its surroundings: name -> {default, required, file, line}."""
    seen: dict[str, dict] = {}

    def note(name, default, required, file, line) -> None:
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,80}", name):
            return
        row = seen.setdefault(name, {"default": default, "required": required, "file": file, "line": line})
        if row["default"] is None and default is not None:
            row["default"] = default
        row["required"] = row["required"] and required and row["default"] is None

    for file, tree in code.trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and node.args and _text(node.args[0]) is not None:
                f = node.func
                env_get = isinstance(f, ast.Attribute) and f.attr == "get" and _last(f.value) == "environ"
                if env_get or _last(f) == "getenv" or (_last(f) == "config" and _text(node.args[0]).isupper()):
                    default = node.args[1] if len(node.args) > 1 else next(
                        (kw.value for kw in node.keywords if kw.arg == "default"), None)
                    value = default.value if isinstance(default, ast.Constant) else None
                    note(_text(node.args[0]), value, default is None, file, node.lineno)
            elif isinstance(node, ast.Subscript) and _last(node.value) == "environ" and _text(node.slice) is not None:
                note(_text(node.slice), None, True, file, node.lineno)
    for name in sorted(code.settings_classes):
        file, cls = code.classes[name]
        prefix = ""
        for node in ast.walk(cls):
            if isinstance(node, ast.keyword) and node.arg == "env_prefix" and _text(node.value) is not None:
                prefix = _text(node.value)
            elif isinstance(node, ast.Assign) and any(_last(t) == "env_prefix" for t in node.targets) \
                    and _text(node.value) is not None:
                prefix = _text(node.value)
        for node in cls.body:
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and not node.target.id.startswith("_") \
                    and node.target.id != "model_config":
                value = node.value.value if isinstance(node.value, ast.Constant) else None
                note((prefix + node.target.id).upper(), value, node.value is None, file, node.lineno)
    return seen


def _written_database(code: _Code) -> tuple[str, int] | None:
    """Where the code opens a database at a place written in the code itself (`sqlite3.connect("notes.db")`)."""
    for file, tree in code.trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and node.args and _text(node.args[0]) is not None \
                    and _last(node.func) in ("connect", "create_engine", "create_async_engine"):
                where = _text(node.args[0])
                if where != ":memory:" and (where.startswith("sqlite") or where.endswith((".db", ".sqlite", ".sqlite3"))):
                    return file, node.lineno
    return None


def _env(code: _Code, notes: list) -> tuple[dict, dict, bool]:
    """(what the plan hands the app as settings, the plan's `state`, whether a database's place was found)."""
    env: dict[str, str] = {}
    state: dict[str, list] = {}
    have_db = False
    for name, row in sorted(_settings(code).items()):
        words = set(_words(name))
        default = row["default"] if isinstance(row["default"], str) else ""
        looks_db = bool(words & DB_WORDS) or default.startswith("sqlite") or default.endswith((".db", ".sqlite", ".sqlite3"))
        if looks_db and not words & {"wait", "timeout", "pool", "echo", "name", "user", "password", "host", "port"}:
            if have_db:
                continue
            scheme = default.split(":", 1)[0] if "://" in default else ""
            if words & {"url", "uri", "dsn"} or scheme:
                if scheme and not scheme.startswith("sqlite"):
                    notes.append(f"The app's setting {name} names a database of another kind by default "
                                 f"({scheme[:30]}). The sandbox holds SQLite only, so the plan hands the app a SQLite "
                                 "file; an app that cannot run on SQLite will read \"not run\".")
                    scheme = "sqlite"
                env[name] = f"{scheme or 'sqlite'}:///" + "{data}/app.db"
            else:
                env[name] = "{data}/app.db"
            state["sqlite"] = ["{data}/app.db"]
            have_db = True
        elif words & SECRET_WORDS and not words & NOT_A_SECRET and not isinstance(row["default"], (int, float)):
            env[name] = "{secret}"
        elif words & FOLDER_WORDS and not words & {"max", "size", "url"}:
            folder = "{data}/" + (_slug(name) or "files")
            env[name] = folder
            state.setdefault("folders", []).append(folder)
        elif row["required"]:
            notes.append(f"The app reads the setting {name} ({row['file']}:{row['line']}) and has no value for it "
                         "of its own. The plan does not set it: if the app does not start, put a value under "
                         "\"app\" > \"env\".")
    return env, state, have_db


def _quiet_tables(code: _Code) -> list[str]:
    """Tables named for keeping a record of what was tried (an audit log, a count of wrong passwords): they may
    change when a request is refused, and that is no fault."""
    names: set = set()
    for tree in code.trees.values():
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) < 20_000:
                names.update(TABLE.findall(node.value))
            elif isinstance(node, ast.Assign) and any(_last(t) == "__tablename__" for t in node.targets) \
                    and _text(node.value):
                names.add(_text(node.value))
    return sorted(n for n in names if set(_words(n)) & QUIET or n.lower().replace("_", "") in QUIET)


# --------------------------------------------------------------------------------------------------- the plan
def _token_key(keys: list[str]) -> str | None:
    if "access_token" in keys:
        return "access_token"
    return next((k for k in keys if "token" in k.lower() or k.lower() == "jwt"), None)


def _doors(routes: list[_Route], logins: dict) -> tuple[_Route | None, _Route | None]:
    """(the route that makes an account, the route that signs in), as far as their names and shapes show."""
    posts = [r for r in routes if r.verb == "POST" and not r.params and r.has_password()]
    sign_in = [r for r in posts if _token_key(r.answer_keys())]
    sign_in.sort(key=lambda r: (not r.words() & LOGIN_WORDS, bool(r.words() & SIGNUP_WORDS), len(r.all_fields()), r.path))
    login = sign_in[0] if sign_in and (sign_in[0].words() & LOGIN_WORDS or len(sign_in) == 1) else None

    def sureness(r: _Route) -> tuple:
        unsure: list = []
        try:
            r.request(OWNER, unsure)
        except _Cannot:
            return (2, 0, 0, r.path)
        return (1 if unsure else 0, not r.words() & SIGNUP_WORDS, len(r.all_fields()), r.path)

    makers = [r for r in posts if r is not login and (logins.get(r.node.id) or {}).get("login") != "shown"
              and not r.words() & LOGIN_WORDS]
    makers.sort(key=sureness)
    signup = makers[0] if makers and sureness(makers[0])[0] < 2 else None
    if login is None and signup is not None and _token_key(signup.answer_keys()):
        login = signup                       # the account's own answer carries the token
    return signup, login


def _sign_in_values(login: _Route, made: dict, who: str) -> dict:
    """The sign-in's fields from what the account was made with: the same names, and `username` for an e-mail."""
    out = {}
    for f in login.all_fields():
        words = set(_words(f.name))
        if f.name in made:
            out[f.name] = made[f.name]
        elif words & PASSWORD:
            out[f.name] = next((v for k, v in made.items() if set(_words(k)) & PASSWORD), f"{who.title()}-pass-phrase-1")
        elif words & {"username", "email", "login", "user", "name"}:
            for near in ("email", "username", "name", "login"):
                hit = next((v for k, v in made.items() if near in _words(k)), None)
                if hit is not None:
                    out[f.name] = hit
                    break
    return out


def _flat(req: dict) -> dict:
    """The named values of a request, whichever way it carries them."""
    if isinstance(req.get("json"), dict):
        return dict(req["json"])
    if "text" in req:
        from urllib.parse import parse_qsl
        return dict(parse_qsl(req["text"]))
    return {}


def _reads_rows(route: _Route, g: Graph, adj: dict, code: _Code) -> bool:
    """Whether the handler, or a function of the project it calls, reads what the app keeps: by its words."""
    n = route.node
    texts = [code.lines(n.file, n.start_line, n.end_line)]
    for callee in adj.get(n.id, [])[:40]:
        c = g.nodes.get(callee)
        if c is not None and c.file in code.texts and not outside(callee):
            texts.append(code.lines(c.file, c.start_line, c.end_line))
    return any(READS.search(t) for t in texts)


def _paid(g: Graph, routes: list[_Route], adj: dict) -> dict:
    """route id -> the paid calls it reaches (`aiapp.find_calls`), walking the map forward from the route."""
    from .aiapp import PAID_KINDS, find_calls
    try:
        calls = find_calls(g)
    except (OSError, ValueError):
        return {}
    paid = {c["node"]: c for c in calls if c.get("node") and c.get("kind") in PAID_KINDS}
    out: dict = {}
    if not paid:
        return out
    for r in routes:
        seen, todo, hit = {r.node.id}, [r.node.id], []
        while todo and len(seen) < 5000:
            u = todo.pop()
            if u in paid:
                hit.append(paid[u])
            for v in adj.get(u, []):
                if v not in seen:
                    seen.add(v)
                    todo.append(v)
        if hit:
            out[r.node.id] = hit
    return out


def draft(repo, g: Graph | None = None) -> dict:
    """A first plan for the project at `repo`, from its map and its code. The answer holds `plan` (None when none
    can be written, with `why_not`), `review` (the cases a person should look at first, each with the reason),
    `left_out` (routes with no case, each with the reason), `notes` (what to know before the first run) and
    `cases` (how many requests the plan comes to)."""
    from . import engine
    from .websec import call_adjacency, route_logins
    repo = Path(repo).resolve()
    out: dict = {"plan": None, "why_not": None, "review": [], "left_out": [], "notes": [], "cases": 0}
    if g is None:
        g = engine.build_graph(repo)
    code = _Code(g)
    apps = _apps(code)
    if not apps:
        out["why_not"] = ("Lantern writes a first plan for a FastAPI app (the kind `lantern behave` starts), and found "
                          "none made in this project's code. For another kind of app the plan is written by hand: "
                          "docs/behaviour.md")
        return out
    app = apps[0]
    cwd, module = _module(code, app["file"])
    plan: dict = {"app": {"asgi": f"{module}:{app['name']}"}}
    if app["factory"]:
        plan["app"]["factory"] = True
    if cwd:
        plan["app"]["cwd"] = cwd
    notes = out["notes"]
    if len(apps) > 1:
        notes.append(f"More than one app is made in the code. The plan starts the one in {app['file']} (line "
                     f"{app['line']}); the others: " + ", ".join(f"{a['file']}:{a['line']}" for a in apps[1:6]) + ".")
    env, state, have_db = _env(code, notes)
    if env:
        plan["app"]["env"] = env
    if state:
        plan["state"] = state
    if not have_db:
        at = _written_database(code)
        if at:
            notes.insert(0, f"The app opens its database at a place written in the code ({at[0]}:{at[1]}). In the "
                            "sandbox the app can write only into the data folder it is handed, and only there is a "
                            "change seen. Let the app read the place from a setting (an environment variable) and "
                            "write this plan again; until then the cases will read \"not run\" or undecided.")
        else:
            notes.insert(0, "Lantern could not see where the app keeps its data (no setting for a database's place "
                            "was found). Without one under \"state\", a request that was refused and changed "
                            "something anyway does not show, and a request that changes data reads undecided.")

    def lines_for(file: str) -> list[str]:
        return code.texts.get(file) or []

    logins = {r["node"]: r for r in route_logins(g, lines_for)}
    routes = []
    for n in g.entry_points():
        if (n.entry or {}).get("kind") != "route" or not n.id.startswith("py:") or n.file not in code.trees:
            continue
        if n.id not in logins or " " not in ((n.entry or {}).get("detail") or ""):
            continue
        fn = code.function(n.file, n.name, n.start_line)
        if fn is not None:
            routes.append(_Route(n, fn, code))
    routes.sort(key=lambda r: (r.node.file or "", r.node.start_line or 0))
    signup, login = _doors(routes, logins)
    if signup is None or login is None:
        missing = "a request that makes an account" if signup is None else "a sign-in that answers with a token"
        out["why_not"] = (f"Lantern found the app ({app['file']}), but not {missing}: a POST route that takes a "
                          "password" + (" and answers with a table that holds a token" if signup is not None else "")
                          + ". Without two people to tell apart no case can be written. The plan is then written by "
                          "hand: docs/behaviour.md")
        return out

    # ---- the people: an account each, and a sign-in
    seed, made = [], {}
    signup_keys = [k for k in signup.answer_keys() if IDENT.match(k)]
    token_key = _token_key(login.answer_keys())
    try:
        for who in PEOPLE:
            _request_ok(signup.request(who, []), "the account")
            if login is not signup:
                made_with = _flat(signup.request(who, []))
                _request_ok(login.request(who, [], values=_sign_in_values(login, made_with, who)), "the sign-in")
    except (_Cannot, PlanError) as e:
        out["why_not"] = (f"Lantern found the app ({app['file']}) and its sign-in, but cannot write the requests that "
                          f"make an account and sign in ({e}). The plan is then written by hand: docs/behaviour.md")
        return out
    for who in PEOPLE:
        unsure: list = []
        req = signup.request(who, unsure)
        made[who] = _flat(req)
        save = {f"{who}_{k}": f"json:{k}" for k in signup_keys if k != token_key or login is not signup}
        if login is signup:
            save[f"{who}_token"] = f"json:{token_key}"
        step = {"request": req}
        if save:
            step["save"] = save
        seed.append(step)
        if unsure and who == OWNER:
            notes.append(f"The request that makes an account ({signup.detail}) carries a value Lantern made up for "
                         + ", ".join(f"`{u}`" for u in dict.fromkeys(unsure)) + ". If the app refuses it, the run "
                         "says that the plan's set-up failed at step 1: put a value the app accepts there.")
    if login is not signup:
        for who in PEOPLE:
            req = login.request(who, [], values=_sign_in_values(login, made[who], who))
            seed.append({"request": req, "save": {f"{who}_token": f"json:{token_key}"}})
    plan["people"] = {who: {"token": "{" + who + "_token}"} for who in PEOPLE}
    plan["seed"] = seed
    quiet = _quiet_tables(code)
    if quiet:
        plan["quiet_tables"] = quiet
        notes.append("These tables may change when a request is refused (they are named for keeping a record of "
                     "what was tried): " + ", ".join(quiet) + ". Take one out of \"quiet_tables\" if that is not so.")

    # ---- one case for each route
    adj = call_adjacency(g)
    by_path = {(r.verb, r.path.rstrip("/") or "/"): r for r in routes}
    checks: list[dict] = []
    ids: set = set()

    def new_id(text: str) -> str:
        base, n = _slug(text)[:60], 1
        name = base
        while name in ids:
            n += 1
            name = f"{base}-{n}"
        ids.add(name)
        return name

    def left(route: _Route, why: str) -> None:
        out["left_out"].append({"route": route.detail, "where": f"{route.node.file}:{route.node.start_line}", "why": why})

    def row_for(route: _Route) -> tuple[str, list, str | None]:
        """(the path with alice's row in it, the steps that make the row, the text the row holds)."""
        if len(route.params) != 1:
            raise _Cannot("its address names more than one row, and Lantern makes one")
        param = route.params[0]
        head = route.path.split("{", 1)[0].rstrip("/")
        maker = by_path.get(("POST", head or "/"))
        if maker is None or maker.params:
            raise _Cannot(f"Lantern found no request that makes a row for it (a POST to {head or '/'})")
        thing = _singular(head.rsplit("/", 1)[-1])
        keys = maker.answer_keys()
        key = next((k for k in ("id", param, f"{thing}_id") if k in keys), None)
        if key is None or not IDENT.match(key):
            raise _Cannot(f"the answer of POST {head} does not show the new row's number in a way Lantern can read")
        filled = PARAM.sub(lambda m: "{" + (f"{OWNER}_{key}" if maker is signup else f"{OWNER}_{thing}") + "}", route.path)
        if maker is signup:
            return filled, [], None
        if maker is login or (logins.get(maker.node.id) or {}).get("login") != "shown":
            raise _Cannot(f"the request that makes a row for it (POST {head}) does not ask who is calling, so the "
                          "row would be nobody's")
        unsure: list = []
        try:
            req = maker.request(OWNER, unsure)
        except _Cannot as e:
            raise _Cannot(f"Lantern cannot write the request that makes a row for it (POST {head}): {e}") from None
        if unsure:
            raise _Cannot(f"the request that makes a row for it (POST {head}) needs a value Lantern cannot make up "
                          f"(`{unsure[0]}`)")
        marker = next((v for v in _flat(req).values() if isinstance(v, str) and v.startswith("kept by ")), None)
        return filled, [{"request": req, "as": OWNER, "save": {f"{OWNER}_{thing}": f"json:{key}"}}], marker

    for route in routes:
        if len(checks) >= MOST_CHECKS:
            left(route, f"a first plan holds {MOST_CHECKS} checks at most")
            continue
        if route is signup or route is login:
            continue
        seen = logins[route.node.id]
        if route.verb not in MUTATING | {"GET"}:
            continue
        if seen["public"]:
            left(route, "its address is one made to be open (a sign-in, a webhook, a health page)")
            continue
        shown = seen["login"] == "shown"
        changes = route.verb in MUTATING
        if not changes and not shown and not route.params and not _reads_rows(route, g, adj, code):
            left(route, "it changes nothing, its code shows no login check and reads nothing the app keeps: it "
                        "looks like a page for everyone")
            continue
        try:
            path, arrange, marker = (route.path, [], None)
            if route.params:
                path, arrange, marker = row_for(route)
            unsure = []
            req = route.request(None, unsure, path=path)
        except _Cannot as e:
            left(route, str(e))
            continue
        try:
            _request_ok(req, "")
        except PlanError:
            left(route, "its address is not one a plan can hold")
            continue
        who = [OTHER, "nobody"] if route.params else ["nobody"]
        c: dict = {"id": new_id(f"{route.verb} {route.path}"), "kind": "refuse", "request": req, "who": who,
                   "allowed": [OWNER]}
        if route.params:
            c["about"] = (f"{route.detail} is asked for a row that {OWNER} made: {OTHER}, who is signed in as "
                          f"somebody else, and a visitor who is not signed in must both be turned away.")
            out["review"].append({"check": c["id"], "why": f"If the rows behind {route.path} are shared between "
                                  f"people by design, take \"{OTHER}\" out of this case's \"who\"."})
        elif changes:
            c["about"] = (f"{route.detail} changes what the app keeps: a visitor who is not signed in must be turned "
                          "away, and nothing may change when they are.")
        else:
            c["about"] = f"{route.detail} is for people who are signed in: a visitor who is not must be turned away."
        if arrange:
            c["arrange"] = arrange
        if marker and route.verb == "GET":
            c["must_not_say"] = [marker]
        if not shown:
            out["review"].append({"check": c["id"], "why": f"The code of {route.detail} shows no check of who is "
                                  "calling" + (", and it reads what the app keeps" if not changes else "") + ". If it "
                                  "is meant for everyone, take this case out; if not, this case will read \"let in\"."})
        if unsure:
            out["review"].append({"check": c["id"], "why": "Lantern made up a value for "
                                  + ", ".join(f"`{u}`" for u in dict.fromkeys(unsure)) + ". If the app refuses it from "
                                  f"{OWNER} too, the case reads undecided: put a value the app accepts."})
        checks.append(c)

    # ---- limits and repeats
    wrong = dict(_sign_in_values(login, made[OWNER], OWNER))
    for f in login.all_fields():
        if set(_words(f.name)) & PASSWORD:
            wrong[f.name] = WRONG_PASSWORD
    if login is not signup:
        times = min(login.limit_written() or TRIES, MOST_TRIES)
        checks.append({"id": new_id(f"limit {login.verb} {login.path}"), "kind": "limit", "times": times,
                       "request": login.request(OWNER, [], values=wrong),
                       "about": (f"Wrong passwords at {login.detail}: after {times} tries the next one must be turned "
                                 "away as too many (status 429 or 423), also after a restart and on a second copy of "
                                 "the app.")})
        if not login.limit_written():
            out["review"].append({"check": checks[-1]["id"], "why": f"Lantern tries {times} wrong passwords. If the "
                                  "app allows more before it locks, raise \"times\"."})
    paid = _paid(g, routes, adj)
    for route in routes:
        if route is signup or route is login or len(checks) >= MOST_CHECKS or route.params:
            continue
        hit = paid.get(route.node.id) or []
        pays = bool(route.words() & PAY_WORDS) or any(h.get("kind") == "payment" for h in hit)
        if not hit and not pays and not route.idem:
            continue
        signed = logins[route.node.id]["login"] == "shown"
        try:
            unsure = []
            req = route.request(None, unsure)
            _request_ok(req, "")
        except (_Cannot, PlanError):
            continue                         # the route is on the list of what was left out already, with the reason
        who = {"who": OWNER} if signed else {}
        made_up = ("Lantern made up a value for " + ", ".join(f"`{u}`" for u in dict.fromkeys(unsure))
                   + ": put one the app accepts. ") if unsure else ""
        if hit:
            times = min(route.limit_written() or TRIES, MOST_TRIES)
            hosts = sorted({PAID_HOSTS[h["provider"]] for h in hit if h.get("provider") in PAID_HOSTS})
            c = {"id": new_id(f"limit {route.verb} {route.path}"), "kind": "limit", "times": times, "request": req, **who,
                 "about": (f"{route.detail} reaches a paid service: after {times} requests the next one must be turned "
                           "away as too many (status 429 or 423).")}
            if hosts:
                c["may_reach"] = hosts
            checks.append(c)
            out["review"].append({"check": c["id"], "why": made_up + "The sandbox has no network, so each try fails "
                                  "where the app sets out for the paid service; the case shows only whether the app "
                                  "starts turning requests away."
                                  + ("" if hosts else " Put the address the service is asked at under \"may_reach\", "
                                     "or each try reads as a reach for an outside address.")})
        if pays and route.verb in MUTATING:
            c = {"id": new_id(f"once {route.verb} {route.path}"), "kind": "once", "request": req, **who,
                 "about": (f"Two requests to {route.detail} at the same moment must end like two requests one after "
                           "the other.")}
            checks.append(c)
            if unsure:
                out["review"].append({"check": c["id"], "why": made_up.strip()})
        if route.idem and route.verb in MUTATING:
            again = dict(req, headers={**(req.get("headers") or {}), route.idem: "lantern-check-1"})
            c = {"id": new_id(f"retry {route.verb} {route.path}"), "kind": "retry", "request": again, **who,
                 "about": (f"{route.detail} sent again with the same {route.idem} must not be carried out twice.")}
            checks.append(c)
            if unsure:
                out["review"].append({"check": c["id"], "why": made_up.strip()})
    if not checks:
        out["why_not"] = ("Lantern found the app and its sign-in, but no route it could write a case for. What was "
                          "left out, and why, is listed.")
        return out
    plan["checks"] = checks
    used = set(re.findall(r"\{(\w+)\}", json.dumps([plan["people"], checks, seed[len(PEOPLE):]])))
    for step in seed:
        keep = {name: where for name, where in (step.get("save") or {}).items() if name in used}
        step.pop("save", None)
        if keep:
            step["save"] = keep
    plan["notes"] = {"made_by": f"lantern behave --init (Lantern {__version__}), from reading the code. Read it once, "
                                "correct it, and keep it with the code: docs/behaviour.md",
                     "read_first": list(notes), "review": out["review"], "left_out": out["left_out"]}
    try:
        plan_ok(plan)
        out["cases"] = len(scene(plan)[1])
    except PlanError as e:
        out["why_not"] = f"the plan Lantern drafted is not one it can run ({e}); nothing was written"
        return out
    out["plan"] = plan
    return out


def write(repo, force: bool = False, g: Graph | None = None) -> dict:
    """`draft`, written as the project's `lantern-behaviour.json`. A plan that is there already is left alone
    unless `force`. The answer is `draft`'s, with `written` (the file's path, or None) and `exists`."""
    repo = Path(repo).resolve()
    target = repo / PLAN_NAME
    made = draft(repo, g)
    made["written"], made["exists"] = None, os.path.lexists(target)
    if made["plan"] is None:
        return made
    if made["exists"] and not force:
        made["why_not"] = (f"the project has a {PLAN_NAME} already, and it was left as it is (--force writes the new "
                           "one over it)")
        return made
    results.write(target, json.dumps(made["plan"], indent=1, ensure_ascii=False) + "\n", where="the project folder")
    made["written"] = str(target)
    return made
