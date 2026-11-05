"""React Native and Expo apps: screens and links from the JS/TS map, Expo's app.json, and `LN-*` checks.

A React Native app is a folder whose `package.json` depends on `react-native` or `expo`. Its folder becomes a phone root
(`meta["rn"]["roots"]`), so its components are on the Screen and App lanes; native `android/` and `ios/` folders, when
the project has them, are read by `android.py` and `ios.py` as usual.

`add_entries` (after the JS reader and the bridge):
  * Screens: components given to React Navigation (`<Stack.Screen name="Note" component={NoteScreen} />`,
    `component={Screens.NoteScreen}`) and Expo Router files (`app/**` default exports, not `_layout` or `+api`) → `page`,
    detail `NoteScreen screen · NoteScreen`.
  * Links: a screen listed in React Navigation's `linking` config, or any Expo Router screen when the app has a URL
    `scheme`, can be opened by a link → `route`, detail `LINK NoteScreen screen (other apps and web pages can open it) ·
    NoteScreen`; what a `Linking.addEventListener("url", …)` / `Linking.getInitialURL()` handler calls → `route`.
    `route.params`, `useLocalSearchParams()`, `Linking.parse()` count as request data.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .graph import Graph

SKIP = re.compile(r"(^|/)(node_modules|build|dist|\.expo|tests?|fixtures|__tests__)/")
NAV_SCREEN = re.compile(r"<\s*[\w.]*Screen\b[^>]*?\bcomponent\s*=\s*\{\s*(?:[\w$]+\.)?([\w$]+)\s*\}", re.S)
LINKING_CFG = re.compile(r"\blinking\s*[:=]\s*\{|\bconst\s+linking\b|LinkingOptions")
LINK_HANDLER = re.compile(r"Linking\.(?:addEventListener\s*\(\s*['\"]url['\"]|getInitialURL\s*\(\)|useURL\s*\()|"
                          r"\buseURL\s*\(\)")
NAVIGATOR = re.compile(r"(Navigator|Stack|Tabs|Drawer|Routes?)$")
ROUTER_FILE = re.compile(r"(^|/)app/(?!.*(?:_layout|\+api|\+html|\+not-found)\.)[^/].*\.(?:tsx|jsx|ts|js)$")


def find_projects(repo: Path) -> list[dict]:
    out = []
    for p in sorted(repo.rglob("package.json")):
        rel = p.relative_to(repo).as_posix()
        if SKIP.search(rel):
            continue
        try:
            pkg = json.loads(p.read_text(encoding="utf-8", errors="replace")[:500_000])
        except (OSError, ValueError):
            continue
        deps = {**(pkg.get("dependencies") or {}), **(pkg.get("devDependencies") or {})} if isinstance(pkg, dict) else {}
        if not isinstance(deps, dict) or not ({"react-native", "expo"} & set(deps)):
            continue
        root = rel.rpartition("/")[0]
        root = root + "/" if root else ""
        cfg, cfg_file = {}, None
        aj = p.parent / "app.json"
        if aj.is_file():
            try:
                data = json.loads(aj.read_text(encoding="utf-8", errors="replace")[:500_000])
                cfg = data.get("expo", data) if isinstance(data, dict) else {}
                cfg_file = root + "app.json"
            except (OSError, ValueError):
                pass
        out.append({"root": root, "expo": "expo" in deps, "router": "expo-router" in deps, "config": cfg,
                    "config_file": cfg_file})
    return out


def _in(file: str | None, roots: list[str]) -> bool:
    return bool(file) and any(file.startswith(r) for r in roots)


def _handler_spans(text: str) -> list[tuple[int, int]]:
    """Line spans (1-based, in `text`) of each Linking listener call and the callback or `.then` chain it carries."""
    out = []
    for m in LINK_HANDLER.finditer(text):
        start = text.count("\n", 0, m.start()) + 1
        depth, j = 0, m.start()
        opened = False
        while j < len(text):
            c = text[j]
            if c in "({[":
                depth += 1
                opened = True
            elif c in ")}]":
                depth -= 1
                if depth < 0:
                    break
            elif opened and depth == 0 and c in ";\n" and not re.match(r"\s*\.", text[j + 1:j + 40]):
                break
            j += 1
        out.append((start, text.count("\n", 0, j) + 1))
    return out


def add_entries(g: Graph, repo: str | Path) -> dict:
    repo = Path(repo)
    projects = find_projects(repo)
    if not projects:
        return {}
    roots = [p["root"] for p in projects]
    g.meta.setdefault("platform", "react-native")
    by_name: dict[str, list] = {}
    for n in g.nodes.values():
        if n.kind == "callable" and n.id.startswith("js:") and _in(n.file, roots) and "." not in n.id.split("::")[-1]:
            by_name.setdefault(n.name, []).append(n)
    texts: dict[str, str] = {}

    def text(file: str) -> str:
        if file not in texts:
            try:
                texts[file] = (repo / file).read_text(encoding="utf-8", errors="replace")
            except OSError:
                texts[file] = ""
        return texts[file]

    files = sorted({n.file for n in g.nodes.values() if n.id.startswith("js:") and _in(n.file, roots) and n.file})
    linked_names: set[str] = set()
    screens: set[str] = set()
    for f in files:
        t = text(f)
        for m in NAV_SCREEN.finditer(t):
            screens.add(m.group(1))
        if LINKING_CFG.search(t):
            for m in re.finditer(r"\bscreens\s*:\s*\{([^}]*)\}", t):
                linked_names.update(re.findall(r"([A-Z][\w$]*)\s*:", m.group(1)))
    added = 0
    scheme = any(isinstance(p["config"].get("scheme"), (str, list)) for p in projects)
    router_roots = [p["root"] for p in projects if p["router"]]
    for name in sorted(screens):
        if NAVIGATOR.search(name):                      # a nested navigator, not a screen
            continue
        for n in by_name.get(name, []):
            if n.entry and n.entry.get("kind") == "test":
                continue
            # React Navigation's linking config names routes, not components: `Note: "note/:id"` → NoteScreen
            open_by_link = any(name == ln or name in (ln + "Screen", ln + "Page") for ln in linked_names)
            n.entry = ({"kind": "route", "detail": f"LINK {name} screen (other apps and web pages can open it) · {name}"}
                       if open_by_link else {"kind": "page", "detail": f"{name} screen · {name}"})
            added += 1
    for f in files:                                     # Expo Router: each file under app/ is a screen
        if not any(f.startswith(r) for r in router_roots) or not ROUTER_FILE.search(f[len(next(
                r for r in router_roots if f.startswith(r))):]):
            continue
        m = re.search(r"export\s+default\s+(?:async\s+)?function\s+([\w$]+)|export\s+default\s+([\w$]+)\s*;?\s*$",
                      text(f), re.M)
        name = (m.group(1) or m.group(2)) if m else None
        node = next((n for n in by_name.get(name or "", []) if n.file == f), None)
        if node is None or (node.entry and node.entry.get("kind") == "test"):
            continue
        path = "/" + re.sub(r"(^|/)index$", "", re.sub(r"\.(tsx|jsx|ts|js)$", "", f.split("app/", 1)[1]))
        path = re.sub(r"/\([^)]*\)", "", path) or "/"
        node.entry = ({"kind": "route", "detail": f"LINK {name} screen (other apps and web pages can open it) · {path}"}
                      if scheme else {"kind": "page", "detail": f"{name} screen · {path}"})
        added += 1
    # Linking handlers: what a listener's callback calls, or what is handed the URL it read
    for n in list(g.nodes.values()):
        if n.kind != "callable" or not n.id.startswith("js:") or not _in(n.file, roots):
            continue
        first = n.start_line or 1
        body = "\n".join(text(n.file).splitlines()[first - 1:n.end_line or first])
        spans = [(a + first - 1, b + first - 1) for a, b in _handler_spans(body)]
        if not spans:
            continue
        url_vars = set(re.findall(r"(?:const|let|var)\s+([\w$]+)\s*=\s*(?:await\s+)?(?:Linking\.)?(?:getInitialURL|useURL)"
                                  r"\s*\(", body))
        lines = text(n.file).splitlines()
        for e in g.call_edges():
            if e.src != n.id:
                continue
            inside = any(a <= ln <= b for ln in e.lines for a, b in spans)
            gets_url = any(ln <= len(lines) and re.search(r"\(\s*[^)]*\b(" + "|".join(map(re.escape, url_vars)) + r")\b",
                                                         lines[ln - 1]) for ln in e.lines) if url_vars else False
            if not (inside or gets_url):
                continue
            t = g.nodes.get(e.dst)
            if t is None or t.kind != "callable" or not t.id.startswith("js:") or (t.entry and t.entry.get("kind")
                                                                                   in ("page", "route", "test")):
                continue
            if re.match(r"use[A-Z]|set[A-Z]", t.name):            # React hooks and state setters
                continue
            t.entry = {"kind": "route", "detail": f"LINK {t.name} handles links (other apps and web pages can open it)"
                                                  f" · {t.name}"}
            added += 1
    g.meta["rn"] = {"roots": roots, "entries": added, "apps": [{"root": p["root"], "expo": p["expo"],
                                                                 "router": p["router"], "config": p["config_file"]}
                                                                for p in projects]}
    return g.meta["rn"]


# ------------------------------------------------------------------------------------------------ findings

PERMS = {   # Android permission (as Expo writes it) -> (plain words, code that would use it)
    "CAMERA": ("camera", r"expo-camera|react-native-vision-camera|launchCamera|ImagePicker\.launchCameraAsync|"
                         r"expo-image-picker|BarCodeScanner"),
    "RECORD_AUDIO": ("microphone", r"expo-av|Audio\.Recording|react-native-audio|expo-audio|Voice\.start"),
    "ACCESS_FINE_LOCATION": ("exact location", r"expo-location|Geolocation|react-native-geolocation|watchPosition"),
    "ACCESS_COARSE_LOCATION": ("rough location", r"expo-location|Geolocation|react-native-geolocation"),
    "ACCESS_BACKGROUND_LOCATION": ("location while the app is closed", r"startLocationUpdatesAsync|TaskManager"),
    "READ_CONTACTS": ("read contacts", r"expo-contacts|react-native-contacts"),
    "READ_CALENDAR": ("read the calendar", r"expo-calendar"),
    "SEND_SMS": ("send text messages", r"expo-sms|SendSMS"),
    "READ_SMS": ("read text messages", r"react-native-get-sms|SmsAndroid"),
    "BODY_SENSORS": ("body sensors", r"expo-sensors|Pedometer"),
    "READ_EXTERNAL_STORAGE": ("shared files and photos", r"expo-media-library|MediaLibrary|expo-image-picker|"
                                                         r"expo-document-picker|react-native-fs"),
    "READ_MEDIA_IMAGES": ("photos", r"expo-media-library|MediaLibrary|expo-image-picker"),
}
SENSITIVE_WORDS = r"(?i:password|passwd|passcode|token|secret|api_?key|ssn|credit|card_?number|cvv|\bpin\b|otp)"
CODE_RULES = [   # (id, pattern, severity, title, cwe, tool confidence, rank)
    ("LN-ASYNC-SECRET", re.compile(r"AsyncStorage\.(?:setItem|multiSet)\s*\(\s*['\"`][^'\"`]*" + SENSITIVE_WORDS +
                                   r"|\bMMKV\b[^\n]*\.set\s*\(\s*['\"`][^'\"`]*" + SENSITIVE_WORDS),
     "MEDIUM", "Keeps a password or token in AsyncStorage (plain text on the phone); use expo-secure-store or "
               "react-native-keychain", 312, "LOW", "medium"),
    ("LN-LOG-SENSITIVE", re.compile(r"\bconsole\.(?:log|info|warn|debug)\s*\((?=[^\n]*" + SENSITIVE_WORDS + ")"),
     "MEDIUM", "Writes a password or token to the device log", 532, "LOW", "medium"),
    ("LN-SQL-CONCAT", re.compile(r"\b(?:executeSql|execAsync|runAsync|getAllAsync|getFirstAsync|exec)\s*\(\s*"
                                 r"(?:`[^`]*\$\{|['\"][^'\"\n]*['\"]\s*\+)", re.I), "HIGH",
     "Builds a database query from variables (SQL injection risk); pass values as ? parameters", 89, "HIGH", None),
    ("LN-WEBVIEW-ANY", re.compile(r"originWhitelist\s*=\s*\{\s*\[\s*['\"]\*['\"]\s*\]\s*\}"), "LOW",
     "A web view in the app will open any site", 749, "HIGH", "low"),
    ("LN-WEBVIEW-FILE", re.compile(r"allowFileAccess(?:FromFileURLs)?\s*=\s*\{\s*true\s*\}|"
                                   r"allowUniversalAccessFromFileURLs\s*=\s*\{\s*true\s*\}"), "MEDIUM",
     "A web view in the app may read the app's files", 200, "HIGH", "medium"),
    ("LN-CLEARTEXT-URL", re.compile(r"['\"`]http://(?!localhost|127\.0\.0\.1|10\.0\.2\.2|0\.0\.0\.0)[^'\"`\s]+['\"`]"),
     "LOW", "Talks to a server over plain http", 319, "HIGH", "low"),
]
TEST_PATH = re.compile(r"(^|/)(__tests__|tests?|e2e)/|\.(test|spec)\.[jt]sx?$")


def _f(rule, title, sev, file, line, cwe=None, conf="HIGH", category="config", snippet="", rank=None):
    from .websec import _finding
    f = _finding(rule, title, sev, file, line, category=category, conf=conf, cwe=cwe, snippet=snippet,
                 fixed_rank=rank)
    f["platform"] = "react-native"
    return f


def _line_of(text: str, needle: str) -> int:
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else 1


def config_findings(repo: Path, proj: dict, code: str) -> tuple[list[dict], list[dict]]:
    out: list[dict] = []
    perms: list[dict] = []
    cfg, file = proj["config"], proj["config_file"]
    if not file or not isinstance(cfg, dict):
        return out, perms
    text = (repo / file).read_text(encoding="utf-8", errors="replace")
    schemes = cfg.get("scheme")
    for s in ([schemes] if isinstance(schemes, str) else schemes if isinstance(schemes, list) else []):
        if isinstance(s, str) and s:
            ln = _line_of(text, f'"{s}"')
            out.append(_f("LN-URL-SCHEME", f"Links that start with {s}:// open your app, and any app can send them",
                          "LOW", file, ln, cwe=939, conf="LOW", rank="low", snippet=text.splitlines()[ln - 1].strip()))
    android = cfg.get("android") if isinstance(cfg.get("android"), dict) else {}
    if android.get("allowBackup") is not False and proj["expo"]:
        ln = _line_of(text, '"android"')
        out.append(_f("LN-BACKUP", "App data goes into Android backups (Expo's default allowBackup is true)", "LOW",
                      file, ln, cwe=530, conf="LOW", rank="low", snippet=""))
    ios = cfg.get("ios") if isinstance(cfg.get("ios"), dict) else {}
    ats = ((ios.get("infoPlist") or {}).get("NSAppTransportSecurity") or {}) if isinstance(ios.get("infoPlist"), dict) else {}
    if isinstance(ats, dict) and ats.get("NSAllowsArbitraryLoads") is True:
        ln = _line_of(text, "NSAllowsArbitraryLoads")
        out.append(_f("LN-ATS-OFF", "App Transport Security is off: the iPhone app may load anything over plain http",
                      "MEDIUM", file, ln, cwe=319, rank="medium", snippet=text.splitlines()[ln - 1].strip()))
    for p in android.get("permissions") or []:
        if not isinstance(p, str):
            continue
        short = p.rsplit(".", 1)[-1]
        ln = _line_of(text, f'"{p}"')
        words, rx = PERMS.get(short, (None, None))
        used = None if rx is None else bool(re.search(rx, code))
        perms.append({"name": short, "line": ln, "sensitive": bool(words), "words": words or "", "used": used})
        if used is False:
            out.append(_f("LN-UNUSED-PERMISSION", f"The app asks for {words} ({short}) but no code that uses it was "
                                                  "found", "LOW", file, ln, cwe=250, conf="LOW", rank="low",
                          snippet=text.splitlines()[ln - 1].strip()))
    return out, perms


def code_findings(files: list[tuple[str, str]]) -> list[dict]:
    out = []
    for rel, text in files:
        if TEST_PATH.search(rel):
            continue
        lines = text.splitlines()
        for rule, rx, sev, title, cwe, conf, rank in CODE_RULES:
            for m in rx.finditer(text):
                ln = text.count("\n", 0, m.start()) + 1
                src = lines[ln - 1] if ln <= len(lines) else ""
                if src.lstrip().startswith(("//", "*", "/*")):
                    continue
                out.append(_f(rule, title, sev, rel, ln, cwe=cwe, conf=conf, category="code", snippet=src.strip(),
                              rank=rank))
    return out


def scan(g: Graph) -> tuple[list[dict], dict | None]:
    from .websec import _files
    repo = Path(g.repo_root)
    projects = find_projects(repo)
    if not projects:
        return [], None
    roots = [p["root"] for p in projects]
    files = [(p.relative_to(repo).as_posix(), p.read_text(encoding="utf-8", errors="replace"))
             for p in _files(repo, {".js", ".jsx", ".ts", ".tsx"})]
    files = [(r, t) for r, t in files if _in(r, roots)]
    out = code_findings(files)
    summary = {"platform": "react-native", "modules": []}
    for proj in projects:
        code = "\n".join(t for r, t in files if r.startswith(proj["root"]))
        pkg = (repo / (proj["root"] + "package.json")).read_text(encoding="utf-8", errors="replace")
        found, perms = config_findings(repo, proj, code + "\n" + pkg)
        out += found
        cfg = proj["config"] if isinstance(proj["config"], dict) else {}
        summary["modules"].append({
            "root": proj["root"], "manifest": proj["config_file"] or proj["root"] + "package.json",
            "package": ((cfg.get("android") or {}).get("package") if isinstance(cfg.get("android"), dict) else None)
            or cfg.get("slug"),
            "permissions": perms,
            "components": [{"kind": "link", "name": f["title"].split("://")[0].rsplit(" ", 1)[-1] + "://",
                            "exported": True, "launcher": False, "permission": None, "line": f["line"]}
                           for f in found if f["rule"] == "LN-URL-SCHEME"],
        })
    return out, summary
