"""`LW-CLIENT-ENV-SECRET`: a setting every visitor's browser gets, whose value is a secret (roadmap of 2026-11-14,
stage 5).

A setting whose name starts with `NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `PUBLIC_` and the like is copied into the
JavaScript every visitor downloads. `websec.exposed_secrets` (`LW-PUBLIC-SECRET`) reads the name. This reads what
the setting is given, where the name says nothing:

* an address that carries a password (`https://user:password@host`, a database's address),
* a key of a shape only servers hold (a payment service's secret key, a code host's token),
* the value of another setting whose name is a secret's (`NEXT_PUBLIC_PAY: process.env.STRIPE_SECRET_KEY`,
  `- VITE_PAY=${STRIPE_SECRET_KEY}`, `${{ secrets.SUPABASE_SERVICE_ROLE_KEY }}`).

It reads lines of the files that give settings their values (settings files, compose files, workflows, a host's
settings file, Dockerfiles, JavaScript); it runs nothing and looks nothing up. The value is never repeated: a
finding names the setting and says why. A heuristic: whether the file feeds the build that visitors get, and
whether the value is a secret after all, is not known from a line.
"""
from __future__ import annotations

import re
from pathlib import Path

from .aiapp import PLACEHOLDER
from .localweb import NOT_THE_APP
from .security import SECRET_PATTERNS
from .websec import JS_EXTS, PUBLIC_PREFIX, SAFE_NAMES, SECRET_WORD, _files, _finding
from .python_frontend import project_text

RULE = "LW-CLIENT-ENV-SECRET"
MOST_FILE = 2_000_000       # characters of a file that are read
MOST_LINE = 2_000           # a longer line is passed by
MOST_FOUND = 200            # findings of one project

_NAME = rf"(?<![A-Za-z0-9_])({PUBLIC_PREFIX}[A-Z0-9_]*[A-Z0-9])"
_Q = "[\"'`]?"
# How each kind of file gives a setting its value: the name, then everything after the sign that gives it.
GIVES = {
    "env": [re.compile(rf"^\s*(?:export\s+|set\s+)?{_NAME}\s*=(.*)$")],
    "yaml": [re.compile(rf"^\s*(?:-\s*)?{_Q}{_NAME}{_Q}\s*[:=](.*)$")],
    "toml": [re.compile(rf"^\s*{_Q}{_NAME}{_Q}\s*=(.*)$")],
    "json": [re.compile(rf"\"{_NAME}\"\s*:\s*(\"(?:[^\"\\]|\\.)*\")")],
    "docker": [re.compile(rf"^\s*(?:ARG|ENV)\s+{_NAME}(?:=|\s+)(.*)$", re.I)],
    "js": [re.compile(rf"(?:^|[{{,(\s]){_Q}(?:[A-Za-z_$][\w$]*\.)*{_NAME}{_Q}\s*:(?!:)(.*)$"),
           re.compile(rf"(?:process\.env|import\.meta\.env|\benv)\s*\.\s*{_NAME}\s*=(?!=)(.*)$")],
}
COMMENT = {"env": ("#",), "yaml": ("#",), "toml": ("#",), "docker": ("#",), "json": (), "js": ("//", "/*", "*")}
DOCKER_NAMES = ("Dockerfile", "Containerfile")
SHELL_EXTS = {".sh", ".bash", ".zsh", ".env"}
READ_EXTS = JS_EXTS | SHELL_EXTS | {".yml", ".yaml", ".toml", ".json", ".dockerfile"}

# another setting, written the ways these files write one
_ID = r"([A-Za-z_][A-Za-z0-9_]*)"
REFERENCE = re.compile(
    rf"\$\{{\{{\s*(?:secrets|env|vars)\.{_ID}\s*\}}\}}"                       # ${{ secrets.NAME }}
    rf"|\$\{{(?:process\.env\.|import\.meta\.env\.|env\.)?{_ID}(?::?[-+?=][^}}]*)?\}}"     # ${NAME}, ${NAME:-x}
    rf"|\${_ID}"                                                              # $NAME
    rf"|(?:process\.env|import\.meta\.env|\benv)\s*\.\s*{_ID}"                # process.env.NAME
    rf"|(?:process\.env|import\.meta\.env|\benv)\s*\[\s*[\"']{_ID}[\"']\s*\]")
WRAPPED = re.compile(r"^(?:JSON\.stringify|String)\s*\((.*)\)$", re.S)
DEFAULTED = re.compile(r"^(.*?)\s*(?:\|\||\?\?)\s*(?:\"[^\"]*\"|'[^']*'|``)$", re.S)
ADDRESS = re.compile(r"(?<![A-Za-z0-9+.-])([a-z][a-z0-9+.-]{1,20})://([^\s/@:?#\"'`]*):([^\s/@?#\"'`]+)@"
                     r"(\[[0-9A-Fa-f:.]+\]|[^\s/:?#\"'`@]+)")
THIS_COMPUTER = re.compile(r"(?i)^(?:localhost|.*\.localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1?\]|"
                           r"host\.docker\.internal)$")
NO_PASSWORD = re.compile(r"(?i)^(?:(?:my|the|db|your)?[_-]?(?:password|passwd|pass|pwd|pw|secret|token|apikey|"
                         r"api[_-]?key|key)\d*|\*+|x+|\.+|_+|-+|[\[{<(%].*)$")
OWN_KEYS = [
    ("stripe-test-key", re.compile(r"\b[sr]k_test_[A-Za-z0-9]{20,}\b")),
    ("stripe-restricted-key", re.compile(r"\brk_live_[A-Za-z0-9]{20,}\b")),
    ("stripe-webhook-secret", re.compile(r"\bwhsec_[A-Za-z0-9]{20,}\b")),
    ("sendgrid-key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b")),
]
KEY_WORDS = {
    "aws-access-key": "a cloud account's access key", "private-key": "a private key",
    "github-token": "a code host's token", "slack-token": "a chat service's token",
    "stripe-live-key": "a payment service's secret key", "stripe-test-key": "a payment service's secret test key",
    "stripe-restricted-key": "a payment service's restricted key",
    "stripe-webhook-secret": "the secret a payment service signs its messages with",
    "anthropic-key": "a model provider's key", "openai-key": "a model provider's key",
    "sendgrid-key": "a mail service's key",
}
PREFIXES = "NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_, NUXT_PUBLIC_, GATSBY_, PUBLIC_ or VUE_APP_"


def kind_of(name: str) -> str | None:
    """How a file of this name gives settings their values, or None for a file that is not read."""
    low = name.lower()
    if name.startswith(".env") or low.endswith((".env", ".sh", ".bash", ".zsh")):
        return "env"
    if name.startswith(DOCKER_NAMES) or low.endswith(".dockerfile"):
        return "docker"
    for ending, kind in ((".yml", "yaml"), (".yaml", "yaml"), (".toml", "toml"), (".json", "json")):
        if low.endswith(ending):
            return kind
    return "js" if Path(name).suffix in JS_EXTS else None


def _secret_name(name: str) -> bool:
    """A name that says its value is a secret, by the words `LW-PUBLIC-SECRET` reads, and that is no setting for
    the browser itself."""
    return bool(re.fullmatch(SECRET_WORD, name)) and not SAFE_NAMES.search(name) and not re.match(PUBLIC_PREFIX, name)


def _referred(text: str) -> str | None:
    """The setting `text` is, when it is exactly another setting and nothing else."""
    m = REFERENCE.fullmatch(text)
    return next((x for x in m.groups() if x), None) if m else None


def _bare(value: str, kind: str = "env") -> str:
    """The value as written: without the quotes around it, what follows it on the line, and a remark at its end."""
    v = value.strip()
    if v[:1] in "\"'`":
        end = 1
        while end < len(v) and v[end] != v[0]:
            end += 2 if v[end] == "\\" else 1
        return v[1:end]
    if kind == "js":                        # up to the end of this entry or statement: `a: f(x), b: 2 }`
        depth = 0
        for i, c in enumerate(v):
            depth += (c in "([") - (c in ")]")
            if depth < 0 or (depth == 0 and c in ",;}"):
                return v[:i].strip()
        return v
    if kind != "json":
        v = re.split(r"\s+#", v, maxsplit=1)[0]
    return v.strip().rstrip(",;").strip()


def why(value: str) -> dict | None:
    """Why this value is a secret, or None: `{"why": "from-secret", "from"}` (it is another setting, whose name is
    a secret's), `{"why": "address-with-password"[, "from"]}` (an address with a password that is no placeholder,
    not the user's own name, and not for this computer; `from` when the password is another setting) or
    `{"why": "key", "kind"}` (a key of a shape only servers hold)."""
    v = value.strip()
    if not v or len(v) > MOST_LINE:
        return None
    inner = v
    for _ in range(3):                                  # String(JSON.stringify(x)) || "", a few layers at most
        m = WRAPPED.match(inner) or DEFAULTED.match(inner)
        if not m:
            break
        inner = m.group(1).strip()
    inner = re.sub(r"\s+as\s+string$|!$", "", inner).strip()
    name = _referred(inner)
    if name:
        return {"why": "from-secret", "from": name} if _secret_name(name) else None
    plain = re.sub(r"\$\{\{\s*(?:secrets|env|vars)\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}", r"${\1}", v)
    for m in ADDRESS.finditer(plain):
        user, password, host = m.group(2), m.group(3), m.group(4)
        if THIS_COMPUTER.match(host) or PLACEHOLDER.search(user + " " + host):
            continue
        name = _referred(password)
        if name:
            return {"why": "address-with-password", "from": name}
        if NO_PASSWORD.match(password) or PLACEHOLDER.search(password) or password.lower() == user.lower():
            continue
        return {"why": "address-with-password"}
    if not PLACEHOLDER.search(v):
        for kind, pattern in list(SECRET_PATTERNS) + OWN_KEYS:
            if pattern.search(v):
                return {"why": "key", "kind": kind}
    return None


def read(name: str, text: str) -> list[dict]:
    """The settings for the browser that the file `name` gives a secret value: `[{"line", "name", "why", ...}]`,
    one for each setting, on the first such line."""
    kind = kind_of(name)
    if kind is None:
        return []
    out, seen = [], set()
    for i, line in enumerate(text.split("\n"), 1):
        if len(line) > MOST_LINE or "_" not in line:
            continue
        if line.lstrip().startswith(COMMENT[kind]) and COMMENT[kind]:
            continue
        for pattern in GIVES[kind]:
            for m in pattern.finditer(line):
                setting, value = m.group(1), _bare(m.group(2), kind)
                got = None if setting in seen else why(value)
                if got:
                    seen.add(setting)
                    out.append({"line": i, "name": setting, **got})
    return out


def _where(name: str) -> tuple[str, str]:
    """Who gets a setting of this name, for a title and as a sentence."""
    if name.startswith("EXPO_PUBLIC_"):
        return ("which is built into the app every user installs",
                "Settings whose names start with EXPO_PUBLIC_ are copied into the app that every user installs, "
                "where anyone can read them.")
    return ("which every visitor's browser gets",
            f"Settings whose names start with {PREFIXES} are copied into the JavaScript every visitor downloads.")


def _words(found: dict) -> tuple[str, str, str]:
    """Title, what was read, and what to do, for one setting."""
    name, src = found["name"], found.get("from")
    where = _where(name)[0]
    if found["why"] == "from-secret":
        return (f"{name}, {where}, is given the value of the secret setting {src}",
                f"This line gives {name} the value of the setting {src}, whose name says it is a secret.",
                f"Read {src} in server code only, and give the page what it needs through a route of your own.")
    if found["why"] == "key":
        what = KEY_WORDS.get(found.get("kind"), "a key for servers only")
        return (f"{name}, {where}, holds {what} (a key for servers only)",
                f"The value on this line has the shape of {what}.",
                "Keep the key in a setting only the server reads, and replace it with a new one: this one was in "
                "the repository and in every copy that was handed out.")
    carried = f"the password from the setting {src}" if src else "a password"
    return (f"The address in {name}, {where}, carries {carried}",
            "The value on this line is an address of the form scheme://user:password@host"
            + (f", and its password is the setting {src}." if src else "."),
            "Give the page an address with no password in it, keep the password in a setting only the server reads, "
            "and change the password: the old one was in every copy that was handed out.")


def also_public(found: dict) -> str:
    """One sentence for another rule's finding on the same line (a key the secret scan lists): where the key goes."""
    return (f"This line gives the key to the setting {found['name']}, {_where(found['name'])[0]}: taking it out of "
            "the repository is not enough, the key has to be replaced with a new one.")


def public_values(repo: Path, said=()) -> list[dict]:
    """LW-CLIENT-ENV-SECRET: one finding for each setting of each file. `said`: the `(file, name)` pairs another
    rule already names (`LW-PUBLIC-SECRET`, which reads the name), not named a second time."""
    repo, said, out = Path(repo), set(said), []
    for p in _files(repo, READ_EXTS, names=(".env",) + DOCKER_NAMES):
        rel = p.relative_to(repo).as_posix()
        if NOT_THE_APP.search(rel) or kind_of(p.name) is None:
            continue
        try:
            text = project_text(p, repo, MOST_FILE + 1)
        except OSError:
            continue
        if len(text) > MOST_FILE or "_" not in text:
            continue
        for found in read(p.name, text):
            if (rel, found["name"]) in said:
                continue
            title, seen, do = _words(found)
            strong = found["why"] != "from-secret"
            out.append({**_finding(
                RULE, title, "HIGH" if strong else "MEDIUM", rel, found["line"], category="exposure", conf="LOW",
                cwe=200, fixed_rank="high" if strong else "medium",
                more=(f"Heuristic: read from this one line; nothing was run and nothing looked up. "
                      f"{_where(found['name'])[1]} {seen} Lantern does not repeat the value. {do} This is as "
                      "intended only where the value is no secret after all (an account made for everyone, a key "
                      "the service means for pages) or where this file gives its values to no build that people "
                      "get; neither can be read from a line."),
                snippet=found["name"]), "public": {k: v for k, v in found.items() if k != "line"}})
            if len(out) >= MOST_FOUND:
                return out
    return out
