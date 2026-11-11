""".NET apps: MAUI / Xamarin phone screens and links from the C# map, and `LC-*` checks over C# code.

A phone project is a `.csproj` with `<UseMaui>true</UseMaui>`, a `net…-android`/`net…-ios` target framework, or a
Xamarin.Forms / Microsoft.Maui library. Its folder becomes a phone root (`meta["maui"]["roots"]`, lanes Screen/App);
its `Platforms/Android/AndroidManifest.xml` and `Platforms/iOS/Info.plist` are read by `android.py` and `ios.py`.

`add_entries` (after the C# reader):
  * Screens: classes that extend a page type (`ContentPage`, `TabbedPage`, `FlyoutPage`, `Shell`, …, or any repo class
    that does): their constructor, `OnAppearing`/`OnNavigatedTo` and event handlers (`(object sender, …EventArgs e)`)
    → `page`, detail `MainPage screen · OnSearchClicked`. `[RelayCommand]` methods of a view model are what the page's
    buttons run: `page` with the page's name (`MainViewModel` → `MainPage`) when that page exists.
  * Links: `OnAppLinkRequestReceived` (MAUI/Xamarin.Forms app links) and an Android activity with an `[IntentFilter]`
    that has a `DataScheme` (its `OnCreate`/`OnNewIntent`), and the repo functions they call with the link →
    `route`, detail `LINK App handles links (other apps and web pages can open it) · OnAppLinkRequestReceived`.

`scan`: `LC-*` line rules over `.cs` (and `Html.Raw` in `.cshtml`/`.razor`; passwords in `appsettings*.json`
connection strings). Rules that only make sense on a phone (Preferences secrets, the device log) run inside the phone
roots only.
"""

from __future__ import annotations

import re
from pathlib import Path

from .graph import Graph
from .python_frontend import project_text

SKIP = re.compile(r"(^|/)(bin|obj|packages|\.vs|node_modules)/")
PROJECT_SKIP = re.compile(r"(^|/)(bin|obj|packages|\.vs|node_modules|tests?|fixtures)/")   # samples inside a repo
PAGE_TYPES = {"ContentPage", "TabbedPage", "FlyoutPage", "MasterDetailPage", "NavigationPage", "CarouselPage", "Shell",
              "Page", "PopupPage", "Popup"}
LIFECYCLE = {"OnAppearing", "OnDisappearing", "OnNavigatedTo", "OnNavigatedFrom", "OnBackButtonPressed"}
HANDLER_SIG = re.compile(r"\(\s*object\??\s+\w+\s*,\s*\w*EventArgs\b")


def find_projects(repo: Path) -> list[str]:
    roots = []
    for p in sorted(repo.rglob("*.csproj")):
        rel = p.relative_to(repo).as_posix()
        if PROJECT_SKIP.search(rel):
            continue
        try:
            text = project_text(p, repo, 200_000)
        except OSError:
            continue
        if re.search(r"<UseMaui>\s*true\s*</UseMaui>", text, re.I) or \
                re.search(r"<TargetFrameworks?>[^<]*\bnet[\d.]+-(?:android|ios|maccatalyst)", text) or \
                re.search(r"Include=\"(?:Xamarin\.Forms|Xamarin\.Essentials|Microsoft\.Maui\.Controls)\"", text) or \
                re.search(r"Sdk=\"Xamarin\.|MonoAndroid|Xamarin\.iOS", text):
            root = rel.rpartition("/")[0]
            roots.append(root + "/" if root else "")
    return roots


def _in(file: str | None, roots: list[str]) -> bool:
    return file is not None and any(file.startswith(r) for r in roots)


def _supers(sig: str) -> list[str]:
    m = re.search(r":\s*(.+)$", sig or "")
    return [x.strip().split("<")[0].split(".")[-1] for x in m.group(1).split(",")] if m else []


def add_entries(g: Graph, repo: str | Path) -> dict:
    repo = Path(repo)
    roots = find_projects(repo)
    if not roots:
        return {}
    inside = all(_in(r, roots) for k in ("android", "ios") for r in (g.meta.get(k) or {}).get("roots") or [])
    if g.meta.get("platform") in (None, "android", "ios") and inside:   # Platforms/Android is MAUI's own folder
        g.meta["platform"] = "maui"
    classes = {n.id: n for n in g.nodes.values() if n.kind == "class" and n.id.startswith("cs:") and _in(n.file, roots)}
    by_name = {}
    for n in classes.values():
        by_name.setdefault(n.name, []).append(n)

    def is_page(c, seen=()) -> bool:
        for s in _supers(c.signature or ""):
            if s in PAGE_TYPES:
                return True
            for k in by_name.get(s, []):
                if k.id not in seen and is_page(k, seen + (c.id,)):
                    return True
        return False

    pages = {cid for cid, c in classes.items() if is_page(c)}
    page_names = {classes[cid].name for cid in pages}
    texts: dict[str, list[str]] = {}

    def lines(file: str) -> list[str]:
        if file not in texts:
            try:
                texts[file] = project_text(repo / file, repo).splitlines()
            except OSError:
                texts[file] = []
        return texts[file]

    added = 0
    for n in g.nodes.values():
        if n.kind != "callable" or n.parent not in classes or (n.entry and n.entry.get("kind") == "test"):
            continue
        cls = classes[n.parent]
        if n.parent in pages and (n.name == cls.name or n.name in LIFECYCLE or HANDLER_SIG.search(n.signature or "")):
            n.entry = {"kind": "page", "detail": f"{cls.name} screen · {n.name}"}
            added += 1
        elif cls.name.endswith("ViewModel") and n.start_line:
            above = " ".join(lines(n.file)[max(0, n.start_line - 3):n.start_line])
            if re.search(r"\[\s*(?:RelayCommand|ICommand)\b", above) or re.search(r"\[\s*RelayCommand", n.signature or ""):
                page = cls.name[:-len("ViewModel")] + "Page"
                screen = page if page in page_names else cls.name
                n.entry = {"kind": "page", "detail": f"{screen} screen · {n.name}"}
                added += 1
    # links
    link_fns = []
    for n in g.nodes.values():
        if n.kind != "callable" or n.parent not in classes:
            continue
        cls = classes[n.parent]
        if n.name == "OnAppLinkRequestReceived":
            link_fns.append(n)
        elif n.name in ("OnCreate", "OnNewIntent") and cls.start_line:
            head = "\n".join(lines(cls.file)[max(0, cls.start_line - 6):cls.start_line])
            if re.search(r"\[IntentFilter\b[^\]]*DataScheme", head, re.S):
                link_fns.append(n)
    for n in link_fns:
        owner = classes[n.parent].name
        n.entry = {"kind": "route", "detail": f"LINK {owner} handles links (other apps and web pages can open it)"
                                              f" · {n.name}"}
        added += 1
        for e in g.call_edges():   # the repo functions handed the link
            if e.src != n.id:
                continue
            t = g.nodes.get(e.dst)
            if t is None or t.kind != "callable" or not t.id.startswith("cs:") or t.entry or t.name == n.name:
                continue
            call = " ".join(lines(n.file)[ln - 1] for ln in e.lines if 0 < ln <= len(lines(n.file)))
            if re.search(r"\(\s*[^)]*\b(?:uri|url|link|intent|Intent)\b", call):
                towner = g.nodes[t.parent].name if t.parent in g.nodes and g.nodes[t.parent].kind == "class" else t.name
                t.entry = {"kind": "route", "detail": f"LINK {towner} handles links (other apps and web pages can open it)"
                                                      f" · {t.name}"}
                added += 1
    g.meta["maui"] = {"roots": roots, "entries": added}
    return g.meta["maui"]


# ------------------------------------------------------------------------------------------------ findings

SENSITIVE = r"(?i:password|passwd|passcode|token|secret|api_?key|ssn|credit|card_?number|cvv|\bpin\b|otp)"
SQL_CALL = (r"(?:new\s+(?:Sql|Npgsql|MySql|Sqlite|SQLite|OleDb|Odbc)Command|\.CommandText\s*=|FromSqlRaw|ExecuteSqlRaw(?:Async)?|"
            r"SqlQueryRaw|\.(?:Query|QueryAsync|QueryFirst\w*|QuerySingle\w*|Execute|ExecuteAsync|ExecuteScalar\w*|"
            r"DeferredQuery)(?:<[^>\n]*>)?)")
SQL_VALUE = (r"\s*\(?\s*(?:\$@?\"[^\"\n]*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^\"\n]*\{|@?\$\"[^\"\n]*\b(?:SELECT|"
             r"INSERT|UPDATE|DELETE|WHERE|FROM)\b[^\"\n]*\{|\"[^\"\n]*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^\"\n]*\"\s*\+|"
             r"string\.Format\s*\(\s*\"[^\"\n]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b)")
CODE_RULES = [   # (id, pattern, severity, title, cwe, tool confidence, rank, phone only)
    ("LC-SQL-CONCAT", re.compile(SQL_CALL + SQL_VALUE, re.I), "HIGH",
     "Builds a database query from variables (SQL injection risk); pass values as parameters instead", 89, "HIGH",
     None, False),
    ("LC-EXEC-CONCAT", re.compile(r"\bProcess\.Start\s*\([^;\n]*(?:\+|\$\")|\bArguments\s*=\s*(?:\$\"[^\"\n]*\{|[^;\n]*\+)"),
     "HIGH", "Starts a program with text built from variables (command injection risk)", 78, "HIGH", None, False),
    ("LC-TLS-OFF", re.compile(r"(?:ServerCertificateCustomValidationCallback|ServerCertificateValidationCallback|"
                              r"RemoteCertificateValidationCallback)\s*\+?=\s*(?:\([^)]*\)|\w+|delegate\s*(?:\([^)]*\))?)\s*"
                              r"(?:=>\s*true\b|\{\s*return\s+true\s*;)|DangerousAcceptAnyServerCertificateValidator"),
     "HIGH", "Accepts any HTTPS certificate (anyone on the same network can read and change the traffic)", 295, "HIGH",
     "high", False),
    ("LC-WEAK-HASH", re.compile(r"\b(?:MD5|SHA1)\.(?:Create|HashData)\s*\(|new\s+(?:MD5CryptoServiceProvider|SHA1Managed|"
                                r"SHA1CryptoServiceProvider)\b"), "MEDIUM", "Uses a weak hash (MD5/SHA-1)", 328, "HIGH",
     None, False),
    ("LC-DESERIALIZE", re.compile(r"new\s+(?:BinaryFormatter|NetDataContractSerializer|LosFormatter|SoapFormatter|"
                                  r"ObjectStateFormatter)\s*\(|TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)"),
     "MEDIUM", "Reads objects whose type the data chooses (untrusted data can run code)", 502, "HIGH", None, False),
    ("LC-CORS-ALL", re.compile(r"\.AllowAnyOrigin\s*\(\s*\)|\.WithOrigins\s*\(\s*\"\*\"\s*\)"), "MEDIUM",
     "Allows any website to call this API (CORS *)", 942, "HIGH", None, False),
    ("LC-HTML-RAW", re.compile(r"@?Html\.Raw\s*\((?!\s*\"[^\"]*\"\s*\))|\(MarkupString\)\s*(?!\")"), "MEDIUM",
     "Puts text into the page as HTML without escaping it (cross-site scripting risk)", 79, "LOW", None, False),
    ("LC-LOG-SENSITIVE", re.compile(r"\b(?:Console\.Write(?:Line)?|Debug\.Write(?:Line)?|Trace\.Write(?:Line)?|"
                                    r"_?[lL]ogger\.Log\w*|Log\.(?:Debug|Info|Information|Warning|Error|Verbose|D|I|W|E))\s*"
                                    r"\((?=[^\n]*\{?\s*\w*" + SENSITIVE + r")"),
     "MEDIUM", "Writes a password or token to the phone's log", 532, "LOW", "medium", True),
    ("LC-PREFS-SECRET", re.compile(r"\bPreferences(?:\.Default)?\.Set\s*\(\s*\"[^\"]*" + SENSITIVE), "MEDIUM",
     "Keeps a password or token in Preferences (plain text on the phone); use SecureStorage", 312, "LOW", "medium",
     True),
    ("LC-CLEARTEXT-URL", re.compile(r"\"http://(?!localhost|127\.0\.0\.1|10\.0\.2\.2|0\.0\.0\.0|schemas\.|www\.w3\.org)"
                                    r"[^\"\s]+\""), "LOW", "Talks to a server over plain http", 319, "HIGH", "low", False),
    ("LC-CONN-PASSWORD", re.compile(r"(?i)\"[^\"\n]*(?:Server|Data Source|Host)\s*=[^\"\n]*(?:Password|Pwd)\s*=\s*"
                                    r"(?![\"{;]|\$)[^;\"\s]{3,}"), "MEDIUM",
     "A database password is written in the code; read it from configuration or a secret store", 798, "HIGH", None,
     False),
]
JSON_PASSWORD = re.compile(r"(?i)\"[^\"\n]*(?:Server|Data Source|Host)\s*=[^\"\n]*(?:Password|Pwd)\s*=\s*(?![\"{;$])[^;\"\s]{3,}")
TEST_PATH = re.compile(r"(^|/)(tests?|[^/]*\.Tests?|[^/]*Tests)/|Tests?\.cs$")


def code_findings(files: list[tuple[str, str]], roots: list[str]) -> list[dict]:
    from .websec import _finding
    out = []
    for rel, text in files:
        if TEST_PATH.search(rel) or SKIP.search(rel):
            continue
        lines = text.splitlines()
        if rel.endswith(".json"):
            for m in JSON_PASSWORD.finditer(text):
                ln = text.count("\n", 0, m.start()) + 1
                out.append(_finding("LC-CONN-PASSWORD", "A database password is written in the app's settings file; "
                                    "keep it in user secrets or the host's secret store", "MEDIUM", rel, ln,
                                    category="code", conf="HIGH", cwe=798, snippet="(connection string with a password)"))
            continue
        phone = _in(rel, roots)
        for rule, rx, sev, title, cwe, conf, rank, phone_only in CODE_RULES:
            if phone_only and not phone:
                continue
            if rel.endswith((".cshtml", ".razor")) and rule != "LC-HTML-RAW":
                continue
            for m in rx.finditer(text):
                ln = text.count("\n", 0, m.start()) + 1
                src = lines[ln - 1] if ln <= len(lines) else ""
                if src.lstrip().startswith(("//", "*", "/*")):
                    continue
                f = _finding(rule, title, sev, rel, ln, category="code", conf=conf, cwe=cwe,
                             snippet=src.strip() if rule != "LC-CONN-PASSWORD" else "(connection string with a password)",
                             fixed_rank=rank)
                if phone:
                    f["platform"] = "maui"
                out.append(f)
    return out


def scan(g: Graph) -> list[dict]:
    from .websec import _files
    repo = Path(g.repo_root)
    roots = (g.meta.get("maui") or {}).get("roots") or []
    files = [(p.relative_to(repo).as_posix(), project_text(p, repo))
             for p in _files(repo, {".cs", ".cshtml", ".razor"})]
    files += [(p.relative_to(repo).as_posix(), project_text(p, repo))
              for p in _files(repo, {".json"}) if re.match(r"appsettings[\w.]*\.json$", p.name)]
    return code_findings(files, roots)
