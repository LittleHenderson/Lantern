"""Flutter apps: screens and links from the Dart map, and `LF-*` checks over Dart code.

A Flutter project is a folder whose `pubspec.yaml` depends on the `flutter` SDK. Its folder becomes a phone root
(`meta["flutter"]["roots"]`), so its Dart code is on the Screen and App lanes; its `android/` and `ios/` folders are read
by `android.py` and `ios.py` as usual (manifest, Info.plist, Gradle, entitlements).

`add_entries` (after the Dart reader):
  * Screens: widgets a route opens (`MaterialPageRoute`/`CupertinoPageRoute`/`PageRouteBuilder`, `routes: {…}`,
    `GoRoute`, `Navigator.push…`, `home:`, `showModalBottomSheet`, `showDialog`) and widgets named `…Screen`/`…Page` →
    their `build` (a StatefulWidget's State `build`) is a `page`, detail `NoteScreen screen · build`. Rows and other
    pieces (`…Tile`, `…Card`, `…Item`, …) are skipped.
  * Links: what a `uriLinkStream`/`AppLinks().uriLinkStream`/`getInitialLink`/`getInitialUri` listener calls (the
    uni_links and app_links packages) → `route`, detail `LINK <Class> handles links (other apps and web pages can open it) · <fn>`.
    `Uri.queryParameters`, `pathParameters`, `uri.path`, `getInitialLink()` count as request data.
"""

from __future__ import annotations

import re
from pathlib import Path

from .graph import Graph

SKIP = re.compile(r"(^|/)(build|\.dart_tool|tests?|fixtures|example)/")
OPENS = re.compile(r"\b(MaterialPageRoute|CupertinoPageRoute|PageRouteBuilder|GoRoute|ShellRoute|routes\s*:|home\s*:|"
                   r"Navigator\.\w*push\w*|showModalBottomSheet|showDialog|showCupertinoModalPopup|AutoRoute|"
                   r"GetPage|onGenerateRoute)\b")
PIECE = re.compile(r"(Tile|Card|Item|Row|Cell|Button|Icon|Badge|Avatar|Chip|Header|Footer|Label|Image|Field|Bar|"
                   r"Indicator|Divider|Section|Widget)$")
LINK_LISTEN = re.compile(r"(uriLinkStream|linkStream|getInitialLink|getInitialUri|getInitialAppLink|"
                         r"getLatestAppLink|onAppLink)\b[^\n{]*?(\{|=>)")


def find_projects(repo: Path) -> list[str]:
    roots = []
    for p in sorted(repo.rglob("pubspec.yaml")):
        rel = p.relative_to(repo).as_posix()
        if SKIP.search(rel) or "/.symlinks/" in rel:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")[:200_000]
        except OSError:
            continue
        if re.search(r"^\s*flutter\s*:\s*\n\s+sdk\s*:\s*flutter", text, re.M):
            root = rel.rpartition("/")[0]
            roots.append(root + "/" if root else "")
    return roots


def _in(file: str | None, roots: list[str]) -> bool:
    return bool(file) and any(file.startswith(r) for r in roots)


def _closure_spans(text: str) -> list[tuple[int, int]]:
    out = []
    for m in LINK_LISTEN.finditer(text):
        start = text.count("\n", 0, m.start()) + 1
        if m.group(2) == "=>":
            out.append((start, start + 2))
            continue
        depth = 0
        for j in range(m.end() - 1, len(text)):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    out.append((start, text.count("\n", 0, j) + 1))
                    break
    return out


def add_entries(g: Graph, repo: str | Path) -> dict:
    repo = Path(repo)
    roots = find_projects(repo)
    if not roots:
        return {}
    g.meta.setdefault("platform", "android" if g.meta.get("android") else "ios" if g.meta.get("ios") else "flutter")
    texts: dict[str, list[str]] = {}

    def lines(file: str) -> list[str]:
        if file not in texts:
            try:
                texts[file] = (repo / file).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                texts[file] = []
        return texts[file]

    added = 0
    for e in g.call_edges():
        if e.via != "flutter-build" or not e.dst.startswith("dt:"):
            continue
        src, dst = g.nodes.get(e.src), g.nodes.get(e.dst)
        if src is None or dst is None or not _in(dst.file, roots) or (dst.entry and dst.entry.get("kind") == "test"):
            continue
        widget = _widget_name(g, dst)
        near = " ".join(" ".join(lines(src.file)[max(0, ln - 4):ln]) for ln in e.lines)
        if PIECE.search(widget) and not re.search(r"(Screen|Page)$", widget):
            continue
        if OPENS.search(near) or re.search(r"(Screen|Page|View)$", widget) and OPENS.search(near or ""):
            dst.entry = {"kind": "page", "detail": f"{widget} screen · build"}
            added += 1
    for n in g.nodes.values():                          # widgets named …Screen / …Page, even when opened indirectly
        if n.kind == "callable" and n.name == "build" and n.id.startswith("dt:") and not n.entry \
                and _in(n.file, roots) and re.search(r"(Screen|Page)$", _widget_name(g, n)):
            n.entry = {"kind": "page", "detail": f"{_widget_name(g, n)} screen · build"}
            added += 1
    # links
    for n in list(g.nodes.values()):
        if n.kind != "callable" or not n.id.startswith("dt:") or not _in(n.file, roots):
            continue
        body = lines(n.file)[(n.start_line or 1) - 1:n.end_line or n.start_line or 1]
        spans = [(a + (n.start_line or 1) - 1, b + (n.start_line or 1) - 1) for a, b in _closure_spans("\n".join(body))]
        if not spans:
            continue
        for e in g.call_edges():
            if e.src != n.id or not any(a <= ln <= b for ln in e.lines for a, b in spans):
                continue
            t = g.nodes.get(e.dst)
            if t is None or t.kind != "callable" or not t.id.startswith("dt:") or e.via == "flutter-build" \
                    or t.name == "new":
                continue
            owner = g.nodes[t.parent].name if t.parent in g.nodes and g.nodes[t.parent].kind == "class" else t.name
            t.entry = {"kind": "route", "detail": f"LINK {owner} handles links (other apps and web pages can open it)"
                                                  f" · {t.name}"}
            added += 1
    g.meta["flutter"] = {"roots": roots, "entries": added}
    return g.meta["flutter"]


def _widget_name(g: Graph, build) -> str:
    """`dt:_NoteState@lib/note.dart.build` → NoteScreen (the widget whose State it is), else the class name."""
    cls = g.nodes.get(build.parent or "")
    if cls is None:
        return build.name
    m = re.search(r"\(state of (\w+)\)", cls.signature or "")
    return m.group(1) if m else cls.name


# ------------------------------------------------------------------------------------------------ findings

SENSITIVE_WORDS = r"(?i:password|passwd|passcode|token|secret|api_?key|ssn|credit|card_?number|cvv|\bpin\b|otp)"
CODE_RULES = [   # (id, pattern, severity, title, cwe, tool confidence, rank)
    ("LF-LOG-SENSITIVE", re.compile(r"\b(?:print|debugPrint|log|logger\.\w+|developer\.log)\s*\((?=[^\n]*" +
                                    SENSITIVE_WORDS + ")"),
     "MEDIUM", "Writes a password or token to the device log", 532, "LOW", "medium"),
    ("LF-PREFS-SECRET", re.compile(r"\.\s*set(?:String|StringList)\s*\(\s*['\"][^'\"]*" + SENSITIVE_WORDS),
     "MEDIUM", "Keeps a password or token in SharedPreferences (plain text on the phone); use flutter_secure_storage",
     312, "LOW", "medium"),
    ("LF-TLS-OFF", re.compile(r"badCertificateCallback\s*=\s*\([^)]*\)\s*(?:=>\s*true|\{\s*return\s+true)"), "HIGH",
     "Accepts any HTTPS certificate (anyone on the same Wi-Fi can read and change the traffic)", 295, "HIGH", "high"),
    ("LF-SQL-CONCAT", re.compile(r"\b(?:rawQuery|rawInsert|rawUpdate|rawDelete|execute)\s*\(\s*(?:\"[^\"\n]*\$\{?[A-Za-z_]|"
                                 r"'[^'\n]*\$\{?[A-Za-z_]|\"[^\"\n]*\"\s*\+|'[^'\n]*'\s*\+|[A-Za-z_]\w*\s*\+\s*['\"])"),
     "HIGH",
     "Builds a database query from variables (SQL injection risk); pass values in the arguments list instead", 89,
     "HIGH", None),
    ("LF-WEBVIEW-JS", re.compile(r"JavaScriptMode\.unrestricted|javascriptMode\s*:\s*JavascriptMode\.unrestricted"),
     "LOW", "A web view in the app runs JavaScript", 749, "HIGH", "low"),
    ("LF-WEBVIEW-BRIDGE", re.compile(r"addJavaScriptChannel\s*\(|javascriptChannels\s*:"), "LOW",
     "Pages in a web view can call into your app's code", 749, "LOW", "low"),
    ("LF-CLEARTEXT-URL", re.compile(r"['\"]http://(?!localhost|127\.0\.0\.1|10\.0\.2\.2|0\.0\.0\.0)[^'\"\s]+['\"]"),
     "LOW", "Talks to a server over plain http", 319, "HIGH", "low"),
    ("LF-WEAK-HASH", re.compile(r"\b(?:md5|sha1)\.convert\s*\("), "MEDIUM", "Uses a weak hash (MD5/SHA-1)", 328,
     "HIGH", None),
]
TEST_PATH = re.compile(r"(^|/)(test|integration_test|test_driver)/|_test\.dart$")


def code_findings(files: list[tuple[str, str]]) -> list[dict]:
    from .websec import _finding
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
                f = _finding(rule, title, sev, rel, ln, category="code", conf=conf, cwe=cwe, snippet=src.strip(),
                             fixed_rank=rank)
                f["platform"] = "flutter"
                out.append(f)
    return out


def scan(g: Graph) -> list[dict]:
    from .websec import _files
    repo = Path(g.repo_root)
    roots = (g.meta.get("flutter") or {}).get("roots")
    files = [(p.relative_to(repo).as_posix(), p.read_text(encoding="utf-8", errors="replace"))
             for p in _files(repo, {".dart"})]
    if not roots:
        files = [(r, t) for r, t in files if "package:flutter/" in t]
    return code_findings(files)
