"""iOS apps: screens and links from the Swift map, Info.plist / entitlements / Xcode settings, and `LI-*` checks.

An iOS app is found from an Xcode project built for the iPhone (`SDKROOT = iphoneos` or `IPHONEOS_DEPLOYMENT_TARGET` in
`project.pbxproj`) or an `Info.plist` with iPhone keys. Its folder becomes a phone root (`meta["ios"]["roots"]`), so the
lanes say Screen and App the way they do for Android.

`add_entries` (after the Swift reader):
  * UIKit screens: lifecycle methods (`viewDidLoad`, `viewWillAppear`, …) and `@IBAction`s of a `UIViewController`
    family class → `page`, detail `SettingsViewController screen · viewDidLoad`.
  * SwiftUI screens: the view the app's `WindowGroup` draws, views opened by `NavigationLink`, `sheet`,
    `fullScreenCover`, `navigationDestination`, `popover` or a `TabView`, and views named `…Screen` → their `body` is a
    `page`, detail `EntryView screen · body`.
  * Links other apps and web pages can send: the functions an `.onOpenURL { }` / `.onContinueUserActivity { }` closure
    calls, and `application(_:open:…)`, `scene(_:openURLContexts:)`, `scene(_:continue:)` → `route`, detail
    `LINK DeepLink handles links (other apps and web pages can open it) · handle`. What a link carries
    (`url.queryItems`, `URLComponents`) is request data.

Plists are read with the same expat reader as Android manifests (entity declarations refused, line numbers kept).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .android import XEl, _read, parse_xml
from .graph import Graph
from .python_frontend import inside_repo

SKIP = re.compile(r"(^|/)(Pods|Carthage|DerivedData|build|\.build|SourcePackages|node_modules|tests?|fixtures|"
                  r"[^/]*Tests|[^/]*UITests)/")
IOS_EXTS = {".swift", ".m", ".mm"}
IOS_PLIST_KEYS = ("LSRequiresIPhoneOS", "UILaunchStoryboardName", "UILaunchScreen", "UIApplicationSceneManifest",
                  "UISupportedInterfaceOrientations", "UIRequiredDeviceCapabilities", "UIMainStoryboardFile")
VC_BASES = {"UIViewController", "UITableViewController", "UICollectionViewController", "UINavigationController",
            "UITabBarController", "UIPageViewController", "UISplitViewController", "UIHostingController",
            "UIAlertController", "UISearchController", "UIDocumentViewController", "AVPlayerViewController"}
VC_METHODS = {"viewDidLoad", "viewWillAppear", "viewDidAppear", "loadView", "viewWillDisappear", "viewDidDisappear",
              "viewWillLayoutSubviews", "viewDidLayoutSubviews"}
OPENS_SCREEN = re.compile(r"\b(NavigationLink|sheet|fullScreenCover|navigationDestination|popover|TabView|tabItem|"
                          r"WindowGroup|present|pushViewController)\b")
PIECE = re.compile(r"(Cell|Row|Item|Button|Label|Badge|Icon|Header|Footer|Image|Avatar|Chip|Tile)$")   # parts of a screen
LINK_CLOSURE = re.compile(r"\.(onOpenURL|onContinueUserActivity)\s*(\([^)]*\))?\s*\{")
LINK_METHOD = re.compile(r"func\s+(application|scene)\s*\(\s*_\s+\w+\s*:\s*\w+\s*,\s*(open\s+url|openURLContexts|"
                         r"continue\s+userActivity)")


@dataclass
class App:
    root: str                      # "" = the repo itself, else "path/"
    plist: str | None = None
    plist_root: XEl | None = None
    pbxproj: str | None = None
    entitlements: list[str] = field(default_factory=list)
    bundle_id: str | None = None
    min_ios: str | None = None
    keys: dict[str, tuple] = field(default_factory=dict)     # top-level Info.plist key -> (value element, line)
    build_keys: dict[str, tuple[str, int]] = field(default_factory=dict)   # INFOPLIST_KEY_* from the Xcode project


def plist_dict(el: XEl | None) -> dict[str, tuple[XEl, int]]:
    """A plist <dict> as {key: (value element, line of the key)}."""
    out: dict[str, tuple[XEl, int]] = {}
    if el is None:
        return out
    kids = el.children
    for i, k in enumerate(kids):
        if k.tag == "key" and i + 1 < len(kids):
            out[_text(k)] = (kids[i + 1], k.line)
    return out


def _text(el: XEl) -> str:
    return getattr(el, "text", "") or ""


def _parse_plist(text: str) -> XEl | None:
    """`parse_xml` keeps no text; plists are small, so the text of each element is filled from a second pass."""
    root = parse_xml(text)
    if root is None:
        return None
    # The reader does not collect character data: read it with a tiny expat pass of our own (same refusals).
    from xml.parsers import expat
    p = expat.ParserCreate()
    stack: list[list[str]] = []
    texts: list[str] = []

    def start(_tag, _attrs):
        stack.append([])

    def end(_tag):
        texts.append("".join(stack.pop()).strip())

    def data(s):
        if stack:
            stack[-1].append(s)

    def refuse(*_a):
        raise ValueError("entities refused")

    p.StartElementHandler, p.EndElementHandler, p.CharacterDataHandler = start, end, data
    p.EntityDeclHandler = refuse
    p.ExternalEntityRefHandler = refuse
    p.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        p.Parse(text, True)
    except (expat.ExpatError, ValueError, RecursionError):
        return None
    # `texts` is in end-tag order: a post-order walk of the same tree visits elements in the same order.
    order: list[XEl] = []

    def post(el: XEl):
        for c in el.children:
            post(c)
        order.append(el)

    post(root)
    if len(order) != len(texts):
        return None
    for el, t in zip(order, texts):
        el.text = t if not el.children else ""          # type: ignore[attr-defined]
    return root


def _top_dict(root: XEl | None) -> XEl | None:
    if root is None:
        return None
    return next((c for c in root.children if c.tag == "dict"), None) if root.tag == "plist" else \
        (root if root.tag == "dict" else None)


def _true(el: XEl | None) -> bool:
    return el is not None and (el.tag == "true" or (el.tag == "string" and _text(el).upper() in ("YES", "TRUE")))


def find_apps(repo: Path) -> list[App]:
    apps: dict[str, App] = {}
    for proj in sorted(repo.rglob("project.pbxproj")):
        rel = proj.relative_to(repo).as_posix()
        if SKIP.search(rel) or ".xcodeproj/" not in rel:
            continue
        text = _read(proj, repo)
        if not re.search(r"SDKROOT\s*=\s*iphoneos|IPHONEOS_DEPLOYMENT_TARGET\s*=", text):
            continue
        root = rel.split(".xcodeproj/")[0].rpartition("/")[0]
        root = root + "/" if root else ""
        app = apps.setdefault(root, App(root=root))
        app.pbxproj = rel
        m = re.findall(r"IPHONEOS_DEPLOYMENT_TARGET\s*=\s*([\d.]+)", text)
        if m:
            app.min_ios = min(m, key=lambda v: [int(x) for x in v.split(".") if x.isdigit()])
        b = re.search(r"PRODUCT_BUNDLE_IDENTIFIER\s*=\s*\"?([\w.\-$()]+)", text)
        app.bundle_id = app.bundle_id or (b.group(1) if b else None)
        for km in re.finditer(r"INFOPLIST_KEY_(\w+)\s*=\s*(\"[^\"\n]*\"|[^;\n]*);", text):
            app.build_keys.setdefault(km.group(1), (km.group(2).strip('"'), text.count("\n", 0, km.start()) + 1))
    for pl in sorted(repo.rglob("Info.plist")):
        rel = pl.relative_to(repo).as_posix()
        if SKIP.search(rel) or ".xcodeproj/" in rel or ".framework/" in rel or ".bundle/" in rel:
            continue
        if not inside_repo(pl, repo):
            # A link out of the project, or a pipe, is no settings file of the app: it is not read, so it is not named
            # either. (Before Python 3.12 a look for an exact name finds a link only when something is at its end;
            # naming what was found made the results tell whether a path outside the project exists.)
            continue
        root_el = _parse_plist(_read(pl, repo))
        d = plist_dict(_top_dict(root_el))
        root = next((r for r in sorted(apps, key=len, reverse=True) if rel.startswith(r)), None)
        if root is None:
            if not any(k in d for k in IOS_PLIST_KEYS):
                continue
            parent = rel.rpartition("/")[0].rpartition("/")[0]
            root = parent + "/" if parent else ""
            apps[root] = App(root=root)
        app = apps[root]
        if app.plist is None or "CFBundleIdentifier" in d:
            app.plist, app.plist_root, app.keys = rel, root_el, d
            bid = d.get("CFBundleIdentifier")
            if bid and "$(" not in _text(bid[0]):
                app.bundle_id = _text(bid[0])
    for ent in sorted(repo.rglob("*.entitlements")):
        rel = ent.relative_to(repo).as_posix()
        if SKIP.search(rel) or not inside_repo(ent, repo):
            continue
        root = next((r for r in sorted(apps, key=len, reverse=True) if rel.startswith(r)), None)
        if root is not None:
            apps[root].entitlements.append(rel)
    return list(apps.values())


# ------------------------------------------------------------------------------------------------ entries

def _supers(sig: str) -> list[str]:
    return [s.strip() for s in sig.split(":", 1)[1].split(",")] if ":" in (sig or "") else []


def _family(g: Graph, cid: str, depth: int = 0) -> str | None:
    n = g.nodes.get(cid)
    if n is None or depth > 6:
        return None
    for s in _supers(n.signature or ""):
        if s in VC_BASES:
            return "controller"
        if s == "View":
            return "view"
        if s == "App":
            return "app"
        if f"sw:{s}" in g.nodes and f"sw:{s}" != cid:
            fam = _family(g, f"sw:{s}", depth + 1)
            if fam:
                return fam
    return None


def _in(file: str | None, roots: list[str]) -> bool:
    return bool(file) and any(file.startswith(r) for r in roots)


def _closure_lines(text: str, rx: re.Pattern) -> list[tuple[int, int]]:
    """Line ranges of the `{ … }` closures that start where `rx` matches."""
    out = []
    for m in rx.finditer(text):
        i, depth = m.end() - 1, 0
        for j in range(i, len(text)):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    out.append((text.count("\n", 0, m.start()) + 1, text.count("\n", 0, j) + 1))
                    break
    return out


def add_entries(g: Graph, repo: str | Path) -> dict:
    repo = Path(repo)
    apps = find_apps(repo)
    if not apps:
        return {}
    roots = [a.root for a in apps]
    g.meta.setdefault("platform", "ios")
    sources: dict[str, str] = {}

    def src(file: str) -> str:
        if file not in sources:
            sources[file] = _read(repo / file, repo)
        return sources[file]

    children: dict[str, list] = {}
    for n in g.nodes.values():
        if n.kind == "callable" and n.parent and n.id.startswith("sw:"):
            children.setdefault(n.parent, []).append(n)
    added = 0
    fams = {n.id: _family(g, n.id) for n in g.nodes.values() if n.kind == "class" and n.id.startswith("sw:")
            and _in(n.file, roots)}
    # SwiftUI views another screen opens: the line that draws them names a navigation call
    opened: set[str] = set()
    for e in g.call_edges():
        if e.via != "swiftui-body" or not e.dst.startswith("sw:"):
            continue
        s = g.nodes.get(e.src)
        lines = src(s.file).splitlines() if s and s.file else []
        near = " ".join(" ".join(lines[max(0, ln - 3):ln]) for ln in e.lines)
        parent = g.nodes[e.src].parent if e.src in g.nodes else None
        view = e.dst[3:].rsplit(".", 1)[0].rsplit(".", 1)[-1]          # sw:EntryView.body -> EntryView
        dest = re.findall(r"destination:\s*(\w+)", near)
        if PIECE.search(view) or (dest and view not in dest):         # a row inside the link, not where it goes
            continue
        if OPENS_SCREEN.search(near) or fams.get(parent or "") == "app":
            opened.add(e.dst)
    for cid, fam in fams.items():
        cls = g.nodes[cid]
        for meth in children.get(cid, []):
            if meth.entry and meth.entry.get("kind") != "main":
                continue
            if fam == "controller" and (meth.name in VC_METHODS or "@IBAction" in (meth.decorators or [])):
                meth.entry = {"kind": "page", "detail": f"{cls.name} screen · {meth.name}"}
                added += 1
            elif fam == "view" and meth.name == "body" and (meth.id in opened or re.search(r"(Screen|Page)$", cls.name)):
                meth.entry = {"kind": "page", "detail": f"{cls.name} screen · body"}
                added += 1
    # links: closures of .onOpenURL / .onContinueUserActivity, and the app/scene delegate methods
    for n in list(g.nodes.values()):
        if not n.id.startswith("sw:") or n.kind != "callable" or not _in(n.file, roots):
            continue
        text = src(n.file)
        lines = text.splitlines()
        body = "\n".join(lines[(n.start_line or 1) - 1:n.end_line or n.start_line or 1])
        if n.name in ("application", "scene") and LINK_METHOD.search(text):
            n.entry = {"kind": "route", "detail": f"LINK {g.nodes[n.parent].name if n.parent in g.nodes else n.name} "
                                                  f"handles links (other apps and web pages can open it) · {n.name}"}
            added += 1
        if not LINK_CLOSURE.search(body):
            continue
        spans = [(a + (n.start_line or 1) - 1, b + (n.start_line or 1) - 1) for a, b in _closure_lines(body, LINK_CLOSURE)]
        for e in g.call_edges():
            if e.src != n.id or not any(a <= ln <= b for ln in e.lines for a, b in spans):
                continue
            t = g.nodes.get(e.dst)
            if t is None or t.kind != "callable" or (t.entry and t.entry.get("kind") == "test"):
                continue
            owner = g.nodes[t.parent].name if t.parent in g.nodes and g.nodes[t.parent].kind == "class" else t.name
            t.entry = {"kind": "route", "detail": f"LINK {owner} handles links (other apps and web pages can open it)"
                                                  f" · {t.name}"}
            added += 1
    g.meta["ios"] = {"roots": roots, "apps": [{"root": a.root, "plist": a.plist, "project": a.pbxproj,
                                               "bundle_id": a.bundle_id, "min_ios": a.min_ios} for a in apps],
                     "entries": added}
    return g.meta["ios"]


# ------------------------------------------------------------------------------------------------ permissions

USAGE = {   # Info.plist key -> (plain words, code that would use it)
    "NSCameraUsageDescription": ("camera", r"AVCaptureDevice|AVCaptureSession|UIImagePickerController|\.camera\b|"
                                           r"DataScannerViewController|VNDocumentCamera"),
    "NSMicrophoneUsageDescription": ("microphone", r"AVAudioRecorder|AVAudioSession|requestRecordPermission|"
                                                   r"AVAudioEngine|SFSpeechRecognizer|AVCaptureDevice"),
    "NSLocationWhenInUseUsageDescription": ("location while the app is open", r"CLLocationManager|CLLocationUpdate|"
                                                                              r"LocationButton|MKUserLocation"),
    "NSLocationAlwaysAndWhenInUseUsageDescription": ("location even when the app is closed", r"CLLocationManager|"
                                                                                            r"requestAlwaysAuthorization"),
    "NSLocationAlwaysUsageDescription": ("location even when the app is closed", r"CLLocationManager"),
    "NSContactsUsageDescription": ("contacts", r"CNContactStore|CNContactPicker"),
    "NSPhotoLibraryUsageDescription": ("photo library", r"PHPhotoLibrary|PHPicker|PhotosPicker|UIImagePickerController|"
                                                        r"PHAsset"),
    "NSPhotoLibraryAddUsageDescription": ("save to photos", r"UIImageWriteToSavedPhotosAlbum|PHPhotoLibrary|"
                                                            r"PHAssetChangeRequest"),
    "NSCalendarsUsageDescription": ("calendar", r"EKEventStore"),
    "NSCalendarsFullAccessUsageDescription": ("calendar", r"EKEventStore"),
    "NSRemindersUsageDescription": ("reminders", r"EKEventStore"),
    "NSFaceIDUsageDescription": ("Face ID", r"LAContext|evaluatePolicy"),
    "NSBluetoothAlwaysUsageDescription": ("Bluetooth", r"CBCentralManager|CBPeripheralManager"),
    "NSMotionUsageDescription": ("motion and fitness", r"CMMotionManager|CMPedometer|CMMotionActivityManager"),
    "NSHealthShareUsageDescription": ("health data", r"HKHealthStore"),
    "NSHealthUpdateUsageDescription": ("change health data", r"HKHealthStore"),
    "NSSpeechRecognitionUsageDescription": ("speech recognition", r"SFSpeechRecognizer"),
    "NSUserTrackingUsageDescription": ("track you across other apps", r"ATTrackingManager"),
    "NSLocalNetworkUsageDescription": ("devices on the local network", r"NWBrowser|NWConnection|NetService|"
                                                                       r"NWListener|MCSession"),
    "NSHomeKitUsageDescription": ("home devices", r"HMHomeManager"),
    "NSAppleMusicUsageDescription": ("music library", r"MPMediaLibrary|MPMediaQuery|MusicKit"),
    "NFCReaderUsageDescription": ("NFC tags", r"NFCNDEFReaderSession|NFCTagReaderSession"),
}


def _usage_keys(app: App) -> list[tuple[str, int, str]]:
    """(key, line, file) of every usage description, from Info.plist and the Xcode project."""
    out = [(k, line, app.plist) for k, (_v, line) in app.keys.items() if k in USAGE]
    have = {k for k, *_ in out}
    out += [(k, line, app.pbxproj) for k, (_v, line) in app.build_keys.items() if k in USAGE and k not in have]
    return out


def permission_summary(app: App, code: str) -> list[dict]:
    out = []
    for key, line, _file in _usage_keys(app):
        words, rx = USAGE[key]
        out.append({"name": key, "line": line, "sensitive": True, "words": words, "used": bool(re.search(rx, code))})
    return out


# ------------------------------------------------------------------------------------------------ findings

def _f(rule, title, sev, file, line, cwe=None, conf="HIGH", category="config", snippet="", rank=None, more=None,
       pin=None):
    from .websec import _finding
    f = _finding(rule, title, sev, file, line, category=category, conf=conf, cwe=cwe, more=more, snippet=snippet,
                 fixed_rank=rank)
    f["platform"] = "ios"
    if pin:
        f["pin"] = pin
    return f


def _line(text: str, line: int) -> str:
    lines = text.splitlines()
    return lines[line - 1].strip() if 0 < line <= len(lines) else ""


KEY_VALUE = re.compile(r"AIza[0-9A-Za-z_\-]{35}|sk_live_[0-9A-Za-z]{16,}|xox[bp]-[0-9A-Za-z-]{20,}|"
                       r"(?:ghp|github_pat)_[0-9A-Za-z_]{30,}|AKIA[0-9A-Z]{16}")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def plist_findings(repo: Path, app: App) -> list[dict]:
    out: list[dict] = []
    if app.plist:
        text = _read(repo / app.plist, repo)
        d = app.keys
        ats = plist_dict(d["NSAppTransportSecurity"][0]) if "NSAppTransportSecurity" in d else {}
        if _true((ats.get("NSAllowsArbitraryLoads") or (None,))[0]):
            ln = ats["NSAllowsArbitraryLoads"][1]
            out.append(_f("LI-ATS-OFF", "App Transport Security is off: the app may load anything over plain http",
                          "MEDIUM", app.plist, ln, cwe=319, snippet=_line(text, ln), rank="medium"))
        elif _true((ats.get("NSAllowsArbitraryLoadsInWebContent") or (None,))[0]):
            ln = ats["NSAllowsArbitraryLoadsInWebContent"][1]
            out.append(_f("LI-ATS-OFF", "Web views in the app may load pages over plain http", "LOW", app.plist, ln,
                          cwe=319, snippet=_line(text, ln), rank="low"))
        for domain, (el, ln) in plist_dict((ats.get("NSExceptionDomains") or (None,))[0]).items():
            dd = plist_dict(el)
            if domain in LOCAL_HOSTS:
                continue
            if _true((dd.get("NSExceptionAllowsInsecureHTTPLoads") or dd.get("NSTemporaryExceptionAllowsInsecureHTTPLoads")
                      or (None,))[0]):
                out.append(_f("LI-ATS-OFF", f"Plain http is allowed to {domain}", "LOW", app.plist, ln, cwe=319,
                              snippet=_line(text, ln), rank="low"))
        for item in ((d.get("CFBundleURLTypes") or (None,))[0] or XEl("array", {}, 0)).children:
            for scheme_el in ((plist_dict(item).get("CFBundleURLSchemes") or (None,))[0] or XEl("array", {}, 0)).children:
                s = _text(scheme_el)
                if s and not s.startswith(("fb", "com.googleusercontent", "$(")):
                    out.append(_f("LI-URL-SCHEME", f"Links that start with {s}:// open your app, and any app can send "
                                                   "them", "LOW", app.plist, scheme_el.line, cwe=939,
                                  snippet=_line(text, scheme_el.line), rank="low", conf="LOW"))
        if _true((d.get("UIFileSharingEnabled") or (None,))[0]):
            ln = d["UIFileSharingEnabled"][1]
            out.append(_f("LI-FILE-SHARING", "The app's Documents folder is visible in Finder and the Files app",
                          "LOW", app.plist, ln, cwe=538, snippet=_line(text, ln), rank="low", conf="LOW"))
        for key, (el, ln) in d.items():
            val = _text(el)
            if el.tag == "string" and KEY_VALUE.search(val):
                out.append(_f("LI-PLIST-KEY", f"A service key is written in Info.plist ({key}); anyone who downloads "
                                              "the app can read it", "MEDIUM", app.plist, ln, cwe=798,
                              category="exposure", snippet="[redacted]", rank="medium", conf="LOW"))
    for ent in app.entitlements:
        if re.search(r"(?i)debug|dev", ent):
            continue
        text = _read(repo / ent, repo)
        d = plist_dict(_top_dict(_parse_plist(text)))
        if _true((d.get("get-task-allow") or (None,))[0]):
            ln = d["get-task-allow"][1]
            out.append(_f("LI-DEBUGGABLE", "The app's entitlements let a debugger attach (get-task-allow)", "MEDIUM",
                          ent, ln, cwe=489, snippet=_line(text, ln), rank="medium", conf="LOW"))
    if app.pbxproj and app.min_ios:
        try:
            major = int(app.min_ios.split(".")[0])
        except ValueError:
            major = 99
        if major < 15:
            text = _read(repo / app.pbxproj, repo)
            m = re.search(r"IPHONEOS_DEPLOYMENT_TARGET\s*=\s*" + re.escape(app.min_ios), text)
            ln = text.count("\n", 0, m.start()) + 1 if m else 1
            out.append(_f("LI-OLD-TARGET", f"The app still runs on iOS {app.min_ios}, which no longer gets security "
                                           "updates", "LOW", app.pbxproj, ln, cwe=1104, snippet=_line(text, ln),
                          rank="low"))
    return out


def unused_permission_findings(repo: Path, app: App, code: str) -> list[dict]:
    out = []
    for key, line, file in _usage_keys(app):
        words, rx = USAGE[key]
        if not re.search(rx, code):
            text = _read(repo / file, repo)
            out.append(_f("LI-UNUSED-PERMISSION", f"The app asks for {words} ({key}) but no code that uses it was "
                                                  "found", "LOW", file, line, cwe=250, snippet=_line(text, line),
                          rank="low", conf="LOW"))
    return out


SENSITIVE_WORDS = r"(?i:password|passwd|passcode|token|secret|api_?key|ssn|credit|card_?number|cvv|\bpin\b|otp)"
SWIFT_STR = r"\"[^\"\n]*"
CODE_RULES = [   # (id, pattern, severity, title, cwe, tool confidence, rank)
    ("LI-LOG-SENSITIVE", re.compile(r"\b(?:print|NSLog|debugPrint|os_log|(?:logger|log|Logger\(\))\s*\.\s*"
                                    r"(?:debug|info|notice|error|log))\s*\((?=[^\n]*" + SENSITIVE_WORDS + ")"),
     "MEDIUM", "Writes a password or token to the device log", 532, "LOW", "medium"),
    ("LI-DEFAULTS-SECRET", re.compile(r"UserDefaults[^\n]*\.set\s*\([^\n]*forKey:\s*\"[^\"]*" + SENSITIVE_WORDS +
                                      r"|@AppStorage\s*\(\s*\"[^\"]*" + SENSITIVE_WORDS),
     "MEDIUM", "Keeps a password or token in UserDefaults (plain text on the phone); use the Keychain", 312, "LOW",
     "medium"),
    ("LI-KEYCHAIN-ALWAYS", re.compile(r"\bkSecAttrAccessibleAlways(?:ThisDeviceOnly)?\b"), "MEDIUM",
     "Keychain items readable even while the phone is locked", 311, "HIGH", "medium"),
    ("LI-TLS-OFF", re.compile(r"\.useCredential\s*,\s*URLCredential\s*\(\s*trust:|allowsAnyHTTPSCertificate|"
                              r"setAllowsAnyHTTPSCertificate|ServerTrustManager\s*\([^\n]*DisabledTrustEvaluator|"
                              r"DisabledEvaluator\s*\("), "HIGH",
     "Accepts any HTTPS certificate (anyone on the same Wi-Fi can read and change the traffic)", 295, "HIGH",
     "high"),     # iOS calls the challenge handler itself, for every connection: no path in the map is needed
    ("LI-SQL-CONCAT", re.compile(r"\b(?:sqlite3_exec|sqlite3_prepare(?:_v2|_v3)?|executeQuery|executeUpdate|"
                                 r"execute\s*\(\s*sql:|db\.execute|db\.prepare|fetchAll\s*\(\s*\w+\s*,\s*sql:)\s*\(?"
                                 r"[^\n]*?" + SWIFT_STR + r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\"\n]*(?:\\\(|\"\s*\+)",
                                 re.I), "HIGH",
     "Builds a database query from variables (SQL injection risk); bind values with ? instead", 89, "HIGH", None),
    ("LI-WEAK-HASH", re.compile(r"\bInsecure\.(?:MD5|SHA1)\b|\bCC_(?:MD5|SHA1)\s*\("), "MEDIUM",
     "Uses a weak hash (MD5/SHA-1)", 328, "HIGH", None),
    ("LI-WEBVIEW-FILE", re.compile(r"allowFileAccessFromFileURLs|allowUniversalAccessFromFileURLs|"
                                   r"allowingReadAccessTo:\s*URL\s*\(\s*fileURLWithPath:\s*\"/\""), "MEDIUM",
     "A web view in the app may read the app's files", 200, "HIGH", "medium"),
    ("LI-WEBVIEW-BRIDGE", re.compile(r"\.add\s*\(\s*\w+\s*,\s*name:\s*\"|addScriptMessageHandler\s*\("), "LOW",
     "Pages in a web view can call into your app's code", 749, "LOW", "low"),
    ("LI-UIWEBVIEW", re.compile(r"\bUIWebView\b"), "LOW", "Uses UIWebView, which Apple no longer accepts", 1104,
     "HIGH", "low"),
    ("LI-CLEARTEXT-URL", re.compile(r"\"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|www\.apple\.com/DTDs|"
                                    r"schemas\.|www\.w3\.org)[^\"\s]+\""), "LOW",
     "Talks to a server over plain http", 319, "HIGH", "low"),
    ("LI-PASTEBOARD", re.compile(r"UIPasteboard\.general\.(?:string|setValue)\s*=?[^\n]*" + SENSITIVE_WORDS), "LOW",
     "Copies a password or token to the clipboard, which other apps can read", 200, "LOW", "low"),
]
TEST_PATH = re.compile(r"(^|/)[^/]*(Tests|UITests|Specs)/|(^|/)tests?/")


def code_findings(files: list[tuple[str, str]]) -> list[dict]:
    out = []
    for rel, text in files:
        if TEST_PATH.search(rel):
            continue
        lines = text.splitlines()
        for rule, rx, sev, title, cwe, conf, rank in CODE_RULES:
            if rule == "LI-TLS-OFF" and "SecTrustEvaluate" in text:
                continue                             # the certificate is checked before it is accepted
            for m in rx.finditer(text):
                ln = text.count("\n", 0, m.start()) + 1
                src = lines[ln - 1] if ln <= len(lines) else ""
                if src.lstrip().startswith(("//", "*", "/*")):
                    continue
                out.append(_f(rule, title, sev, rel, ln, cwe=cwe, conf=conf, category="code", snippet=src.strip(),
                              rank=rank))
    return out


def scan(g: Graph) -> tuple[list[dict], dict | None]:
    """All iOS findings and the "On the phone" summary (None when the repo has no iOS app)."""
    from .websec import _files
    repo = Path(g.repo_root)
    apps = find_apps(repo)
    files = [(p.relative_to(repo).as_posix(), _read(p, repo)) for p in _files(repo, IOS_EXTS)]
    if not apps:
        files = [(r, t) for r, t in files if re.search(r"^\s*import\s+(UIKit|SwiftUI)\b", t, re.M)]
        return code_findings(files), None
    out = []
    summary = {"platform": "ios", "modules": []}
    for app in apps:
        code = "\n".join(t for r, t in files if r.startswith(app.root))
        out += plist_findings(repo, app)
        out += unused_permission_findings(repo, app, code)
        schemes = [f for f in out if f["rule"] == "LI-URL-SCHEME" and f["file"] == app.plist]
        summary["modules"].append({
            "root": app.root, "manifest": app.plist or app.pbxproj, "package": app.bundle_id, "min_ios": app.min_ios,
            "permissions": permission_summary(app, code),
            "components": [{"kind": "link", "name": f["title"].split("://")[0].rsplit(" ", 1)[-1] + "://",
                            "exported": True, "launcher": False, "permission": None, "line": f["line"]}
                           for f in schemes],
        })
    out += code_findings(files)
    return out, summary
