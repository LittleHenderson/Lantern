"""Android apps: what the phone and other apps can reach, and the holes Android apps are known for.

Everything here is deterministic: the manifest (`AndroidManifest.xml`), the network security config, the Gradle
build files, and line patterns over Java and Kotlin source. Nothing is guessed by a model.

What it adds:

* **Entry points** (`add_entries`): Android starts an app through its components, not through `main()`. Activities and
  fragments are screens (`page`), a component another app can start is a `route` (its data comes from outside the
  app), background services, receivers, workers and the `Application` class are `main`. Only `on…` methods and the
  fixed lifecycle methods of each component become entries.
* **Findings** (`scan`), rule ids `LM-*`:

  LM-DEBUGGABLE          the app ships debuggable (anyone with a cable can read its data and run code as it)
  LM-BACKUP              app data goes into backups that can be copied off the phone
  LM-CLEARTEXT           plain-http traffic allowed (manifest or network security config)
  LM-USER-CERTS          trusts certificates the user installed (a proxy can read the HTTPS traffic)
  LM-EXPORTED            a component other apps can start or bind to, with no permission guarding it
  LM-UNUSED-PERMISSION   asks for a sensitive permission the code never seems to use (heuristic)
  LM-GOOGLE-KEY          Google API key written into the app (fine only when restricted to the app)
  LM-KEY-IN-APP          other key or password written into the app or its build file
  LM-SIGNING-SECRET      the signing key's password in the build file (critical when the key file is committed too)
  LM-RELEASE-DEBUGGABLE  release build type sets debuggable
  LM-RELEASE-DEBUG-KEY   release build signed with the debug key
  LM-NO-SHRINK           release build not shrunk/obfuscated (R8 off)
  LM-OLD-TARGET          targets an old Android version (old, less safe defaults)
  LM-DYNAMIC-VERSION     a library version ending in `+` (a different library on every build)
  LM-LOG-SENSITIVE       location, passwords, tokens or user ids written to the device log
  LM-WEBVIEW-*           WebView with JavaScript, a JavaScript bridge, file-URL access, or SSL errors ignored
  LM-WORLD-MODE          files created readable or writable by every app
  LM-EXTERNAL-STORAGE    files saved to shared storage other apps can read
  LM-PREFS-SECRET        a password or token saved in plain SharedPreferences
  LM-SQL-CONCAT          SQLite query built from variables (rawQuery/execSQL)
  LM-TLS-OFF             Kotlin trust-all certificate or hostname checks
  LM-CLEARTEXT-URL       http:// link in the code
  LM-IMPLICIT-BROADCAST  broadcast sent to any app that listens for its action

Checks that read meaning from names (permissions used, sensitive words in a log line) set `tool_confidence: LOW`, so
the viewer labels them heuristic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from xml.parsers import expat

from .graph import Graph
from .python_frontend import inside_repo, project_text

ANDROID_EXTS = {".java", ".kt"}
MAX_XML = 2_000_000

# ------------------------------------------------------------------------------------------------ XML


@dataclass
class XEl:
    tag: str
    attrs: dict[str, str]
    line: int
    children: list["XEl"] = field(default_factory=list)

    def get(self, name: str, default: str | None = None) -> str | None:
        """`get("exported")` reads `android:exported` (any prefix bound to the Android namespace is written android:)."""
        return self.attrs.get("android:" + name, self.attrs.get(name, default))

    def find(self, tag: str) -> list["XEl"]:
        return [c for c in self.children if c.tag == tag]

    def walk(self):
        yield self
        for c in self.children:
            yield from c.walk()


class _Refused(Exception):
    pass


def parse_xml(text: str) -> XEl | None:
    """A small expat reader that keeps line numbers. Entity declarations are refused (no billion laughs, no external
    entities); a file that does not parse returns None."""
    if len(text) > MAX_XML:
        return None
    p = expat.ParserCreate()
    stack: list[XEl] = []
    root: list[XEl] = []

    def start(tag, attrs):
        el = XEl(tag=tag, attrs=dict(attrs), line=p.CurrentLineNumber)
        if stack:
            stack[-1].children.append(el)
        else:
            root.append(el)
        stack.append(el)

    def end(_tag):
        stack.pop()

    def refuse(*_a):
        raise _Refused()

    p.StartElementHandler = start
    p.EndElementHandler = end
    p.EntityDeclHandler = refuse
    p.ExternalEntityRefHandler = refuse
    p.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        p.Parse(text, True)
    except (expat.ExpatError, _Refused, RecursionError):
        return None
    if not root:
        return None
    # Normalise the prefix bound to the Android namespace to "android:" (it is almost always that already).
    ns = {k[6:]: v for k, v in root[0].attrs.items() if k.startswith("xmlns:")}
    alias = next((k for k, v in ns.items() if v == "http://schemas.android.com/apk/res/android"), "android")
    if alias != "android":
        for el in root[0].walk():
            el.attrs = {("android:" + k[len(alias) + 1:] if k.startswith(alias + ":") else k): v for k, v in el.attrs.items()}
    return root[0]


# ------------------------------------------------------------------------------------------------ modules

COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")


@dataclass
class Component:
    tag: str
    name: str             # fully qualified class name
    line: int
    exported: bool
    explicit: bool        # android:exported written
    permission: str | None
    launcher: bool
    deep_link: bool
    actions: list[str]


@dataclass
class Module:
    root: str             # repo-relative module folder ("" = repo root), with a trailing "/" when not empty
    manifest: str
    package: str
    gradle: str | None
    gradle_text: str
    target_sdk: int | None
    min_sdk: int | None
    app: XEl | None
    app_class: str | None
    components: list[Component]
    permissions: list[tuple[str, int]]
    xml: XEl


def _read(p: Path, repo) -> str:
    """The text of a file of the project `repo`; nothing when it is none, cannot be read or is very large."""
    try:
        if not inside_repo(p, repo) or p.stat().st_size > MAX_XML:
            return ""
        return project_text(p, repo)
    except OSError:
        return ""


def _qualify(name: str, package: str) -> str:
    name = name.strip().replace("$", ".")
    if name.startswith("."):
        return package + name
    if "." not in name and package:
        return package + "." + name
    return name


def _sdk(text: str, key: str) -> int | None:
    m = re.search(rf"\b{key}(?:Version)?\s*(?:=|\(|\s)\s*(\d+)\b", text)
    return int(m.group(1)) if m else None


MANIFEST_RE = re.compile(r"(^|/)src/(main|release|prod\w*)/AndroidManifest\.xml$|(^|/)AndroidManifest\.xml$")


def find_modules(repo: Path) -> list[Module]:
    from .websec import _files
    out = []
    for p in sorted(_files(repo, names={"AndroidManifest.xml"})):
        if p.name != "AndroidManifest.xml":
            continue
        rel = p.relative_to(repo).as_posix()
        if re.search(r"(^|/)src/(debug|test|androidTest)\w*/|(^|/)(tests?|fixtures)/", rel) or not MANIFEST_RE.search(rel):
            continue
        variant = re.search(r"(^|/)src/([^/]+)/AndroidManifest\.xml$", rel)
        if variant and variant.group(2) != "main" and inside_repo(repo / rel.replace(f"src/{variant.group(2)}/", "src/main/"), repo):
            continue          # a build variant's manifest (profile, release, a flavor) is merged into main's
        xml = parse_xml(_read(p, repo))
        if xml is None or xml.tag != "manifest":
            continue
        m = re.match(r"(.*?)(?:src/[^/]+/)?AndroidManifest\.xml$", rel)
        root = m.group(1) if m else ""
        gradle = next((root + n for n in ("build.gradle.kts", "build.gradle") if inside_repo(repo / (root + n), repo)), None)
        gtext = _read(repo / gradle, repo) if gradle else ""
        package = xml.attrs.get("package") or ""
        if not package:
            gm = re.search(r"\bnamespace\s*=?\s*[\"']([\w.]+)[\"']", gtext) or \
                re.search(r"\bapplicationId\s*=?\s*[\"']([\w.]+)[\"']", gtext)
            package = gm.group(1) if gm else ""
        uses_sdk = next(iter(xml.find("uses-sdk")), None)
        target = _sdk(gtext, "targetSdk") or (int(uses_sdk.get("targetSdkVersion")) if uses_sdk is not None and
                                              (uses_sdk.get("targetSdkVersion") or "").isdigit() else None)
        min_sdk = _sdk(gtext, "minSdk") or (int(uses_sdk.get("minSdkVersion")) if uses_sdk is not None and
                                            (uses_sdk.get("minSdkVersion") or "").isdigit() else None)
        app = next(iter(xml.find("application")), None)
        comps = []
        for el in (app.children if app is not None else []):
            if el.tag not in COMPONENT_TAGS:
                continue
            name = el.get("name") or ""
            if el.tag == "activity-alias":
                name = el.get("targetActivity") or name
            if not name or name.startswith("@"):
                continue
            filters = el.find("intent-filter")
            actions = [a.get("name") or "" for f in filters for a in f.find("action")]
            cats = [c.get("name") or "" for f in filters for c in f.find("category")]
            schemes = [d.get("scheme") for f in filters for d in f.find("data") if d.get("scheme")]
            exp = el.get("exported")
            explicit = exp is not None
            if explicit:
                exported = exp.strip().lower() == "true"
            elif el.tag == "provider":
                exported = target is not None and target < 17
            else:
                exported = bool(filters)          # an intent filter used to export the component by default
            comps.append(Component(
                tag=el.tag, name=_qualify(name, package), line=el.line, exported=exported, explicit=explicit,
                permission=el.get("permission") or (el.get("readPermission") if el.tag == "provider" else None),
                launcher="android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in cats,
                deep_link=any(s for s in schemes) and "android.intent.category.BROWSABLE" in cats, actions=actions))
        perms = [((u.get("name") or ""), u.line) for u in xml.walk() if u.tag in ("uses-permission", "uses-permission-sdk-23")]
        app_class = _qualify(app.get("name"), package) if app is not None and app.get("name") else None
        out.append(Module(root=root, manifest=rel, package=package, gradle=gradle, gradle_text=gtext, target_sdk=target,
                          min_sdk=min_sdk, app=app, app_class=app_class, components=comps, permissions=perms, xml=xml))
    return out


# ------------------------------------------------------------------------------------------------ entries

ACTIVITY_BASES = {"Activity", "AppCompatActivity", "FragmentActivity", "ComponentActivity", "ListActivity",
                  "PreferenceActivity", "ActionBarActivity", "NativeActivity", "TabActivity"}
FRAGMENT_BASES = {"Fragment", "DialogFragment", "BottomSheetDialogFragment", "PreferenceFragmentCompat",
                  "ListFragment", "AppCompatDialogFragment", "PreferenceFragment"}
SERVICE_BASES = {"Service", "IntentService", "JobIntentService", "JobService", "LifecycleService",
                 "FirebaseMessagingService", "AccessibilityService", "NotificationListenerService",
                 "InputMethodService", "TileService", "WallpaperService", "MediaBrowserServiceCompat"}
RECEIVER_BASES = {"BroadcastReceiver", "AppWidgetProvider", "DeviceAdminReceiver"}
PROVIDER_BASES = {"ContentProvider", "FileProvider", "DocumentsProvider"}
APP_BASES = {"Application", "MultiDexApplication"}
WORKER_BASES = {"Worker", "CoroutineWorker", "ListenableWorker", "RxWorker"}
ALL_BASES = ACTIVITY_BASES | FRAGMENT_BASES | SERVICE_BASES | RECEIVER_BASES | PROVIDER_BASES | APP_BASES | WORKER_BASES
PROVIDER_METHODS = {"query", "insert", "update", "delete", "openFile", "call", "getType", "openAssetFile", "bulkInsert"}
WORKER_METHODS = {"doWork", "startWork", "createWork", "getForegroundInfo"}

EXTENDS_JAVA = re.compile(r"\bclass\s+([A-Za-z_]\w*)\b[^{;]*?\bextends\s+([\w.]+)")
EXTENDS_KT = re.compile(r"\bclass\s+([A-Za-z_]\w*)\b[^{=]*?:\s*([\w.]+)\s*\(")


def _family(base: str) -> str | None:
    for fam, names in (("activity", ACTIVITY_BASES), ("fragment", FRAGMENT_BASES), ("service", SERVICE_BASES),
                       ("receiver", RECEIVER_BASES), ("provider", PROVIDER_BASES), ("application", APP_BASES),
                       ("worker", WORKER_BASES)):
        if base in names:
            return fam
    return None


def class_families(g: Graph) -> dict[str, str]:
    """Class node id -> activity | fragment | service | receiver | provider | application | worker, following
    `extends` through the repo's own classes (BaseActivity → AppCompatActivity)."""
    supers: dict[str, str] = {}          # simple class name -> simple super name
    ids: dict[str, list[str]] = {}       # simple class name -> class node ids
    root = Path(g.repo_root)
    texts: dict[str, str] = {}
    for n in g.nodes.values():
        if n.kind != "class" or not n.file or Path(n.file).suffix not in ANDROID_EXTS:
            continue
        ids.setdefault(n.name, []).append(n.id)
        if n.file not in texts:
            texts[n.file] = _read(root / n.file, root)
            for rx in (EXTENDS_JAVA, EXTENDS_KT):
                for m in rx.finditer(texts[n.file]):
                    supers.setdefault(m.group(1), m.group(2).rsplit(".", 1)[-1])
    out: dict[str, str] = {}
    for name, nids in ids.items():
        cur, seen = name, set()
        fam = None
        while cur in supers and cur not in seen:
            seen.add(cur)
            cur = supers[cur]
            fam = _family(cur)
            if fam:
                break
        if fam:
            for i in nids:
                out[i] = fam
    return out


def _short(fqcn: str) -> str:
    return fqcn.rsplit(".", 1)[-1]


def add_entries(g: Graph, repo: str | Path) -> dict:
    """Mark the methods Android calls as entry points, set `meta["platform"]` and `meta["android"]`."""
    repo = Path(repo)
    mods = find_modules(repo)
    if not mods:
        return {}
    g.meta["platform"] = "android"
    by_qual = {n.qualname: n for n in g.nodes.values() if n.kind == "class"}
    fams = class_families(g)
    children: dict[str, list] = {}
    for n in g.nodes.values():
        if n.kind == "callable" and n.parent:
            children.setdefault(n.parent, []).append(n)
    comp_of: dict[str, Component] = {}
    for m in mods:
        for c in m.components:
            cn = by_qual.get(c.name)
            if cn is not None:
                comp_of[cn.id] = c
        if m.app_class and m.app_class in by_qual:
            fams.setdefault(by_qual[m.app_class].id, "application")
    for cid, c in comp_of.items():
        fams.setdefault(cid, {"activity": "activity", "activity-alias": "activity", "service": "service",
                              "receiver": "receiver", "provider": "provider"}[c.tag])
    added = 0
    for cid, fam in fams.items():
        cls = g.nodes.get(cid)
        if cls is None:
            continue
        comp = comp_of.get(cid)
        open_to_apps = bool(comp and comp.exported and not comp.permission and not comp.launcher)
        for meth in children.get(cid, []):
            if meth.entry and meth.entry.get("kind") != "main":
                continue
            name = meth.name
            hit = bool(re.match(r"on[A-Z]", name)) or (fam == "provider" and name in PROVIDER_METHODS) or \
                (fam == "worker" and name in WORKER_METHODS)
            if not hit:
                continue
            if open_to_apps:
                what = "screen (other apps and links can open it)" if fam in ("activity", "fragment") else \
                    f"{fam} (other apps can start it)"
                meth.entry = {"kind": "route", "detail": f"INTENT {cls.name} {what} · {name}"}
            elif fam in ("activity", "fragment"):
                where = " (app start)" if comp and comp.launcher else ""
                meth.entry = {"kind": "page", "detail": f"{cls.name} screen{where} · {name}"}
            elif fam == "application":
                meth.entry = {"kind": "main", "detail": f"app start ({cls.name}) · {name}"}
            else:
                meth.entry = {"kind": "main", "detail": f"Android starts {cls.name} ({fam}) · {name}"}
            added += 1
    g.meta["android"] = {
        "roots": [m.root for m in mods],
        "modules": [{"root": m.root, "manifest": m.manifest, "package": m.package, "min_sdk": m.min_sdk,
                     "target_sdk": m.target_sdk, "components": len(m.components),
                     "exported": sum(1 for c in m.components if c.exported and not c.launcher)} for m in mods],
        "entries": added,
    }
    return g.meta["android"]


def in_android(file: str | None, android: dict | None) -> bool:
    if not file or not android:
        return False
    return any(file.startswith(r) for r in android.get("roots") or [])


# ------------------------------------------------------------------------------------------------ permissions

# Permission -> (plain words, code that would use it). The code pattern is a heuristic: a match anywhere in the
# module's Java/Kotlin counts as "used".
SENSITIVE = {
    "ACCESS_FINE_LOCATION": ("exact location", r"Location(Manager|Services|Request|Callback|Listener)|FusedLocation|getLastKnownLocation|requestLocationUpdates|getCurrentLocation"),
    "ACCESS_COARSE_LOCATION": ("rough location", r"Location(Manager|Services|Request|Callback|Listener)|FusedLocation|getLastKnownLocation|requestLocationUpdates|getCurrentLocation"),
    "ACCESS_BACKGROUND_LOCATION": ("location while the app is closed", r"Location(Manager|Services|Request|Callback)|FusedLocation|requestLocationUpdates|Geofenc"),
    "SEND_SMS": ("send text messages (they can cost money)", r"SmsManager|sendTextMessage|sendMultipartTextMessage"),
    "READ_SMS": ("read text messages", r"Telephony\.Sms|content://sms|SmsMessage"),
    "RECEIVE_SMS": ("receive text messages", r"SMS_RECEIVED|SmsMessage|Telephony\.Sms"),
    "READ_CONTACTS": ("read contacts", r"ContactsContract"),
    "WRITE_CONTACTS": ("change contacts", r"ContactsContract"),
    "RECORD_AUDIO": ("microphone", r"MediaRecorder|AudioRecord|SpeechRecognizer|AudioSource"),
    "CAMERA": ("camera", r"\bCamera\b|camera2|CameraX|ProcessCameraProvider|CameraManager|ImageCapture|cameraProvider"),
    "READ_PHONE_STATE": ("phone number and call state", r"TelephonyManager|getDeviceId|getLine1Number|getImei|PhoneStateListener|TelephonyCallback"),
    "CALL_PHONE": ("make phone calls", r"ACTION_CALL\b|Intent\.ACTION_CALL|placeCall|TelecomManager"),
    "READ_CALL_LOG": ("call history", r"CallLog"),
    "WRITE_CALL_LOG": ("change call history", r"CallLog"),
    "READ_EXTERNAL_STORAGE": ("shared files and photos", r"getExternalStorage|Environment\.getExternal|MediaStore|ACTION_GET_CONTENT|ACTION_OPEN_DOCUMENT|getExternalFilesDir|contentResolver|getContentResolver"),
    "WRITE_EXTERNAL_STORAGE": ("write shared files", r"getExternalStorage|Environment\.getExternal|MediaStore|getExternalFilesDir|FileOutputStream"),
    "MANAGE_EXTERNAL_STORAGE": ("every file on the phone", r"getExternalStorage|Environment\.getExternal|MANAGE_ALL_FILES"),
    "READ_MEDIA_IMAGES": ("photos", r"MediaStore|ACTION_PICK|PickVisualMedia"),
    "READ_MEDIA_VIDEO": ("videos", r"MediaStore|ACTION_PICK|PickVisualMedia"),
    "READ_MEDIA_AUDIO": ("audio files", r"MediaStore"),
    "BODY_SENSORS": ("body sensors (heart rate)", r"SensorManager|Sensor\.TYPE_HEART"),
    "ACTIVITY_RECOGNITION": ("physical activity", r"ActivityRecognition|Sensor\.TYPE_STEP"),
    "GET_ACCOUNTS": ("accounts on the phone", r"AccountManager"),
    "SYSTEM_ALERT_WINDOW": ("draw over other apps", r"TYPE_APPLICATION_OVERLAY|TYPE_SYSTEM_ALERT|canDrawOverlays"),
    "REQUEST_INSTALL_PACKAGES": ("install other apps", r"application/vnd\.android\.package-archive|PackageInstaller|ACTION_INSTALL_PACKAGE"),
    "QUERY_ALL_PACKAGES": ("see every installed app", r"getInstalledPackages|getInstalledApplications|queryIntentActivities"),
    "READ_CALENDAR": ("read the calendar", r"CalendarContract"),
    "WRITE_CALENDAR": ("change the calendar", r"CalendarContract"),
    "BLUETOOTH_SCAN": ("find nearby Bluetooth devices", r"Bluetooth"),
    "NEARBY_WIFI_DEVICES": ("find nearby Wi-Fi devices", r"Wifi|WiFi"),
    "USE_FULL_SCREEN_INTENT": ("full-screen alerts", r"setFullScreenIntent"),
}


def permission_summary(mod: Module, code: str) -> list[dict]:
    out = []
    for name, line in mod.permissions:
        short = name.rsplit(".", 1)[-1]
        words, rx = SENSITIVE.get(short, (None, None))
        out.append({"name": short, "line": line, "sensitive": bool(words), "words": words or "",
                    "used": None if rx is None else bool(re.search(rx, code))})
    return out


# ------------------------------------------------------------------------------------------------ findings

def _f(rule, title, sev, file, line, cwe=None, conf="HIGH", category="config", snippet="", rank=None, more=None,
       pin=None):
    from .websec import _finding
    f = _finding(rule, title, sev, file, line, category=category, conf=conf, cwe=cwe, more=more, snippet=snippet,
                 fixed_rank=rank)
    f["platform"] = "android"
    if pin:
        f["pin"] = pin
    return f


def _line_text(text: str, line: int) -> str:
    lines = text.splitlines()
    return lines[line - 1].strip() if 0 < line <= len(lines) else ""


def _module_code(repo: Path, mod: Module, files: list[tuple[str, str]]) -> str:
    return "\n".join(t for rel, t in files if rel.startswith(mod.root))


# Intent actions an app component answers for the system or a platform library, not for other apps: home-screen
# widgets, boot and package events, push messages, media sessions. A user-facing action (VIEW, SEND, PICK, MAIN…) is
# something another app or a link can send with data inside, so it is not in this list.
USER_ACTIONS = re.compile(r"^android\.intent\.action\.(?:VIEW|SEND|SENDTO|SEND_MULTIPLE|PICK|GET_CONTENT|EDIT|INSERT|"
                          r"MAIN|SEARCH|WEB_SEARCH|PROCESS_TEXT|CREATE_SHORTCUT|OPEN_DOCUMENT|ATTACH_DATA|DIAL|CALL|"
                          r"INSERT_OR_EDIT|CREATE_DOCUMENT|SET_WALLPAPER|ASSIST|RUN|DELETE)$")
SYSTEM_ACTION_PREFIX = ("android.", "com.google.firebase.", "com.google.android.c2dm.", "com.google.android.gms.",
                        "com.android.", "com.htc.intent.action.", "androidx.", "com.sec.android.intent.action.")


def _system_action(action: str) -> bool:
    return action.startswith(SYSTEM_ACTION_PREFIX) and not USER_ACTIONS.match(action)


def manifest_findings(repo: Path, mod: Module, files: list[tuple[str, str]], g: Graph | None) -> list[dict]:
    out = []
    mtext = _read(repo / mod.manifest, repo)
    rel = mod.manifest
    app = mod.app
    code = _module_code(repo, mod, files)
    perms = permission_summary(mod, code)
    sensitive = [p for p in perms if p["sensitive"]]
    if app is not None:
        if (app.get("debuggable") or "").lower() == "true":
            out.append(_f("LM-DEBUGGABLE", "The app ships debuggable: anyone with a USB cable can read its private "
                          "data and run code as the app", "HIGH", rel, app.line, cwe=489, rank="high",
                          snippet=_line_text(mtext, app.line)))
        backup = (app.get("allowBackup") or "").lower()
        rules = app.get("fullBackupContent") or app.get("dataExtractionRules")
        if backup != "false" and not rules and (not mod.gradle or is_app_module(mod.gradle_text)):
            why = (" It can see " + ", ".join(p["words"] for p in sensitive[:3]) + ".") if sensitive else ""
            out.append(_f("LM-BACKUP", ("App data is copied into phone backups" if backup == "true" else
                                        "App data goes into phone backups by default (allowBackup is not set)") +
                          ", where it can be copied off the phone with adb or restored onto another device." + why,
                          "MEDIUM", rel, app.line, cwe=530, conf="HIGH" if backup == "true" else "LOW",
                          rank="medium" if sensitive else "low", snippet=_line_text(mtext, app.line)))
        if (app.get("usesCleartextTraffic") or "").lower() == "true":
            out.append(_f("LM-CLEARTEXT", "The app allows plain-http traffic (usesCleartextTraffic): anyone on the same "
                          "Wi-Fi can read or change it", "MEDIUM", rel, app.line, cwe=319, rank="medium",
                          snippet=_line_text(mtext, app.line)))
        elif mod.target_sdk is not None and mod.target_sdk < 28 and not app.get("networkSecurityConfig"):
            out.append(_f("LM-CLEARTEXT", f"Plain-http traffic is allowed: the app targets Android API {mod.target_sdk}, "
                          "where http is on unless a network security config turns it off", "MEDIUM", rel, app.line,
                          cwe=319, rank="low", conf="LOW", snippet=_line_text(mtext, app.line)))
        nsc = app.get("networkSecurityConfig")
        if nsc and nsc.startswith("@xml/"):
            out += network_config_findings(repo, mod, nsc[5:])
        for md in app.find("meta-data"):
            val = md.get("value") or ""
            if re.fullmatch(r"AIza[0-9A-Za-z_\-]{35}", val):
                out.append(_f("LM-GOOGLE-KEY", "A Google API key is written into the app. Anyone can unzip the app and "
                              "read it, so it must be restricted to this app's package and signature in Google Cloud",
                              "MEDIUM", rel, md.line, cwe=798, conf="LOW", rank="low", category="exposure",
                              snippet="[redacted]"))
    class_ids = {}
    if g is not None:
        class_ids = {n.qualname: n.id for n in g.nodes.values() if n.kind == "class"}
    for c in mod.components:
        if not c.exported or c.launcher or c.permission:
            continue
        kind_words = {"activity": "screen", "activity-alias": "screen", "service": "service",
                      "receiver": "broadcast receiver", "provider": "content provider"}[c.tag]
        sev, rank = {"provider": ("HIGH", "high"), "service": ("MEDIUM", "medium"),
                     "receiver": ("MEDIUM", "medium")}.get(c.tag, ("MEDIUM", "medium") if c.deep_link else ("LOW", "low"))
        system_only = bool(c.actions) and all(_system_action(a) for a in c.actions)
        if system_only:
            sev, rank = "LOW", "low"
        how = "" if c.explicit else " (exported by default because it has an intent filter; set android:exported)"
        if system_only:
            how = " (it answers the system: " + ", ".join(_short(a) for a in c.actions[:3]) + "; the system is the only sender that matters)"
        what = {"provider": "Other apps can read and change this content provider's data",
                "service": "Other apps can start or bind to this service",
                "receiver": "Other apps can send this receiver broadcasts",
                }.get(c.tag, "Any link can open this screen with data inside" if c.deep_link else
                      "Other apps can open this screen directly, skipping the screens before it")
        out.append(_f("LM-EXPORTED", f"{what}: {_short(c.name)} {kind_words}, no permission guards it{how}", sev, rel,
                      c.line, cwe=926, conf="LOW" if system_only or not c.explicit else "HIGH", rank=rank,
                      snippet=_line_text(mtext, c.line), pin=class_ids.get(c.name)))
    for p in perms:
        if p["sensitive"] and p["used"] is False:
            out.append(_f("LM-UNUSED-PERMISSION", f"Asks for {p['words']} ({p['name']}) but no code that uses it was found. "
                          "Users and store reviewers see every permission; drop the ones you do not need",
                          "LOW", rel, p["line"], cwe=250, conf="LOW", rank="low", snippet=_line_text(mtext, p["line"])))
    return out


def network_config_findings(repo: Path, mod: Module, name: str) -> list[dict]:
    out = []
    for res in ("src/main/res/xml/", "res/xml/"):
        rel = f"{mod.root}{res}{name}.xml"
        p = repo / rel
        if not inside_repo(p, repo):
            continue
        text = _read(p, repo)
        x = parse_xml(text)
        if x is None:
            return out
        for el in x.walk():
            if el.tag in ("base-config", "domain-config") and (el.attrs.get("cleartextTrafficPermitted") or "").lower() == "true":
                if el.tag == "base-config":
                    out.append(_f("LM-CLEARTEXT", "The network security config allows plain-http traffic to every "
                                  "server", "MEDIUM", rel, el.line, cwe=319, rank="medium",
                                  snippet=_line_text(text, el.line)))
                else:
                    out.append(_f("LM-CLEARTEXT", "The network security config allows plain-http traffic to some "
                                  "servers", "LOW", rel, el.line, cwe=319, rank="low",
                                  snippet=_line_text(text, el.line)))
        for parent in x.walk():
            if parent.tag == "debug-overrides":
                continue
            for anchors in parent.find("trust-anchors"):
                for cert in anchors.find("certificates"):
                    if (cert.attrs.get("src") or "") == "user":
                        out.append(_f("LM-USER-CERTS", "The app trusts certificates the phone's user installed, so a "
                                      "proxy on the phone can read its HTTPS traffic (keep this in debug-overrides only)",
                                      "MEDIUM", rel, cert.line, cwe=295, rank="medium",
                                      snippet=_line_text(text, cert.line)))
        return out
    return out


GRADLE_KEY = re.compile(r"buildConfigField\s*\(?\s*[\"']String[\"']\s*,\s*[\"']([A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD)[A-Z0-9_]*)[\"']\s*,\s*"
                        r"[\"']\\?\"([^\"'\\$]{12,})\\?\"[\"']", re.I)


APP_PLUGIN = re.compile(r"com\.android\.application|\bandroid\.application\b|\bapplicationId\b")


def is_app_module(gradle_text: str) -> bool:
    """An application module (the one that becomes the APK), not a library, test or benchmark module. A build file
    with no plugin line at all (an old project with everything in the root) counts as the app."""
    if APP_PLUGIN.search(gradle_text):
        return True
    return not re.search(r"\bplugins\s*\{|\bapply\s+plugin\b|\bid\s*\(?\s*[\"']", gradle_text)


def gradle_findings(repo: Path, mod: Module) -> list[dict]:
    if not mod.gradle:
        return []
    out = []
    t = mod.gradle_text
    rel = mod.gradle

    def ln(pos: int) -> int:
        return t.count("\n", 0, pos) + 1

    types = _block(t, "buildTypes")             # `release { }` also names a signing config: read the build type
    release = _block(types[1], "release") if types else None
    if release is not None:
        release = (types[0] + release[0], release[1])
    if release is not None:
        start, body = release
        if re.search(r"\b(?:is)?[Dd]ebuggable\s*=?\s*true\b", body):
            m = re.search(r"\b(?:is)?[Dd]ebuggable\s*=?\s*true\b", body)
            out.append(_f("LM-RELEASE-DEBUGGABLE", "The release build is debuggable: anyone with a USB cable can read "
                          "its private data and run code as the app", "HIGH", rel, ln(start + m.start()), cwe=489,
                          rank="high", snippet=_line_text(t, ln(start + m.start()))))
        m = re.search(r"signingConfig\s*=?\s*signingConfigs\.(?:getByName\(\s*\"debug\"\s*\)|debug)\b", body)
        if m:
            out.append(_f("LM-RELEASE-DEBUG-KEY", "The release build is signed with the debug key, which is the same "
                          "on every developer's computer", "MEDIUM", rel, ln(start + m.start()), cwe=321, rank="medium",
                          snippet=_line_text(t, ln(start + m.start()))))
        m = re.search(r"\b(?:is)?[Mm]inifyEnabled\s*=?\s*(\S+)", body)
        # only an app module ships an APK (a library's build type is not what users install); a value computed
        # at build time (`isMinifyEnabled = providers.gradleProperty(...)`) cannot be read here, so it is not reported
        if is_app_module(t) and (not m or m.group(1).rstrip(";,)").lower() == "false"):
            line = ln(start + m.start()) if m else ln(start)
            out.append(_f("LM-NO-SHRINK", "The release build is not shrunk or obfuscated (minifyEnabled is off), so "
                          "anyone can turn the app back into readable code, including its keys and server addresses",
                          "LOW", rel, line, cwe=656, rank="low", snippet=_line_text(t, line)))
    elif is_app_module(t):
        out.append(_f("LM-NO-SHRINK", "No release build type is set up, so the release build is not shrunk or "
                      "obfuscated: anyone can turn the app back into readable code", "LOW", rel, 1, cwe=656,
                      conf="LOW", rank="low", snippet=""))
    if mod.target_sdk is not None and mod.target_sdk < 34:
        m = re.search(r"\btargetSdk(?:Version)?\b", t)
        line = ln(m.start()) if m else 1
        out.append(_f("LM-OLD-TARGET", f"The app targets Android API {mod.target_sdk}. Phones run it with that "
                      "version's older, less safe defaults, and Google Play requires a recent target for updates",
                      "MEDIUM", rel, line, cwe=1104, rank="medium" if mod.target_sdk < 30 else "low",
                      snippet=_line_text(t, line)))
    for m in re.finditer(r"(?:implementation|api|compile|kapt|ksp|annotationProcessor)\s*\(?\s*[\"'][\w.\-]+:[\w.\-]+:"
                         r"([^\"'\s]*\+|latest\.\w+)[\"']", t):
        out.append(_f("LM-DYNAMIC-VERSION", "A library version ends in + so each build can pull a different, untested "
                      "version", "LOW", rel, ln(m.start()), cwe=1104, rank="low", snippet=_line_text(t, ln(m.start()))))
    keystore = any(inside_repo(p, repo) for p in (repo / mod.root).rglob("*")
                   if p.suffix in (".jks", ".keystore") and "debug" not in p.name and "build" not in p.relative_to(repo).parts)
    # `storePassword "s3cret"` / `storePassword = "s3cret"`; not `keystoreProperties['storePassword']` (Flutter's
    # template reads the password from key.properties) and never across lines
    for m in re.finditer(r"(?<![\"'\w])(storePassword|keyPassword)[ \t]*(?:=[ \t]*|[ \t]+|\([ \t]*)[\"']([^\"'$\n]{4,})[\"']", t):
        if m.group(2).lower() == "android":          # the well-known password of the debug key
            continue
        out.append(_f("LM-SIGNING-SECRET", f"The signing key's password ({m.group(1)}) is written in the build file"
                      + (" and the key file is in the repository too: anyone with the code can publish updates as you"
                         if keystore else ""), "HIGH", rel, ln(m.start()), cwe=798,
                      category="secret" if keystore else "exposure", rank=None if keystore else "high",
                      snippet="[redacted]"))
    for m in GRADLE_KEY.finditer(t):
        out.append(_f("LM-KEY-IN-APP", f"The build writes {m.group(1)} into the app; anyone can unzip the app and read it",
                      "MEDIUM", rel, ln(m.start()), cwe=798, conf="LOW", rank="medium", category="exposure",
                      snippet="[redacted]"))
    return out


def _block(t: str, name: str) -> tuple[int, str] | None:
    """The `{ ... }` body after `name {` / `getByName("name") {` / `create("name") {`, with its start offset."""
    m = re.search(rf"(?:\b{name}\s*\{{|getByName\(\s*\"{name}\"\s*\)\s*\{{|named\(\s*\"{name}\"\s*\)\s*\{{)", t)
    if not m:
        return None
    depth, i = 1, m.end()
    while i < len(t) and depth:
        depth += {"{": 1, "}": -1}.get(t[i], 0)
        i += 1
    return m.start(), t[m.start():i]


# Line rules over Java and Kotlin: id, regex, severity, title, cwe, confidence
SENSITIVE_WORDS = (r"(?i:\b(?:password|passwd|passcode|pin|otp|token|secret|api_?key|ssn|credit|card_?number|cvv)\b)|"
                   r"(?i:latitude|longitude)|\blat(?:Lng)?\b|\blng\b|\blon\b|LatLng|getUid\(|getEmail\(|getPhoneNumber\(|"
                   r"(?i:\blocation\b)\.|currentLocation|getLastKnownLocation")
CODE_RULES = [
    ("LM-LOG-SENSITIVE", re.compile(r"\b(?:Log\.[vdiwe]|Timber\.[vdiwe]|android\.util\.Log\.[vdiwe])\s*\((?=[^\n;]*(?:"
                                    + SENSITIVE_WORDS + r"))"), "MEDIUM",
     "Writes location, a password, token or user id to the device log, which other tools and crash reports can read", 532, "LOW"),
    ("LM-WEBVIEW-JS", re.compile(r"setJavaScriptEnabled\s*\(\s*true\s*\)|\bjavaScriptEnabled\s*=\s*true\b"), "LOW",
     "A WebView runs JavaScript; any page it loads can run code inside the app's screen", 79, "HIGH"),
    ("LM-WEBVIEW-BRIDGE", re.compile(r"\baddJavascriptInterface\s*\("), "MEDIUM",
     "A WebView gives web pages a bridge into the app's own code (addJavascriptInterface)", 749, "HIGH"),
    ("LM-WEBVIEW-FILE-URL", re.compile(r"setAllow(?:Universal|File)AccessFromFileURLs\s*\(\s*true\s*\)|"
                                       r"\ballow(?:Universal|File)AccessFromFileURLs\s*=\s*true\b"), "HIGH",
     "A WebView lets local files read other files or websites (file-URL access on)", 200, "HIGH"),
    ("LM-WEBVIEW-SSL", re.compile(r"\bhandler\s*[?!]?\.\s*proceed\s*\(\s*\)|\bsslErrorHandler\s*[?!]?\.\s*proceed\s*\(\s*\)"), "HIGH",
     "A WebView ignores HTTPS certificate errors (handler.proceed()), so a fake server is accepted", 295, "HIGH"),
    ("LM-WORLD-MODE", re.compile(r"\bMODE_WORLD_(?:READABLE|WRITEABLE)\b"), "HIGH",
     "Creates a file or setting every other app on the phone can read or change", 276, "HIGH"),
    ("LM-EXTERNAL-STORAGE", re.compile(r"\bgetExternalStorage(?:Public)?Directory\s*\(|\bEnvironment\.getExternalStorage(?:Public)?Directory\b"), "LOW",
     "Saves files to shared storage, where other apps can read them", 922, "HIGH"),
    ("LM-PREFS-SECRET", re.compile(r"\.\s*putString\s*\(\s*\"[^\"]*(?i:password|passwd|token|secret|api_?key|pin\b|otp)[^\"]*\""), "MEDIUM",
     "Saves a password or token in SharedPreferences as plain text (use EncryptedSharedPreferences or the Keystore)", 312, "LOW"),
    ("LM-SQL-CONCAT", re.compile(r"\b(?:rawQuery|execSQL|compileStatement)\s*\(\s*(?:\"[^\"]*\"\s*\+|[^\"\n,)]+\+\s*\"|"
                                 r"\"[^\"]*\$\{?\w|String\.format\()"), "HIGH",
     "Builds an SQLite query from variables (SQL injection risk); use ? placeholders", 89, "HIGH"),
    ("LM-TLS-OFF", re.compile(r"HostnameVerifier\s*\{\s*_\s*,\s*_\s*->\s*true\s*\}|hostnameVerifier\s*\{\s*_\s*,\s*_\s*->\s*true\s*\}|"
                              r"override\s+fun\s+checkServerTrusted\s*\([^)]*\)\s*(?:\{\s*\}|=\s*Unit)"), "MEDIUM",
     "Turns off HTTPS certificate checks", 295, "HIGH"),
    ("LM-CLEARTEXT-URL", re.compile(r"\"http://(?!localhost|127\.0\.0\.1|10\.0\.2\.2|0\.0\.0\.0|schemas\.android\.com|"
                                    r"www\.w3\.org|ns\.adobe\.com|xmlpull\.org|example\.)[^\"\s]+"), "LOW",
     "Uses a plain http:// address; anyone on the same network can read or change what travels over it", 319, "HIGH"),
    ("LM-IMPLICIT-BROADCAST", re.compile(r"\bsendBroadcast\s*\(\s*(?:new\s+)?Intent\s*\(\s*\"[^\"]+\"\s*\)\s*\)"), "LOW",
     "Sends a broadcast any app can listen for; set a package or a permission", 927, "HIGH"),
]
KOTLIN_ONLY = {"LM-TLS-OFF"}
# Problems whose harm does not grow with who can reach the line keep one rank (the rest are ranked by reachability)
CODE_RANK = {"LM-LOG-SENSITIVE": "medium", "LM-WEBVIEW-JS": "low", "LM-EXTERNAL-STORAGE": "low",
             "LM-PREFS-SECRET": "medium", "LM-CLEARTEXT-URL": "low", "LM-IMPLICIT-BROADCAST": "low",
             "LM-WORLD-MODE": "high"}
TEST_PATH = re.compile(r"(^|/)src/(test|androidTest|sharedTest)\w*/|(^|/)tests?/")


_STR = re.compile(r"\"(?:[^\"\\\n]|\\.)*\"")
_CONST = re.compile(r"^(?:[A-Za-z_]\w*\.)*[A-Z][A-Z0-9_]*$")   # UPPER_CASE names are constants by convention
_TEMPLATE = re.compile(r"\$\{?([A-Za-z_]\w*)\}?")


def only_constants(stmt: str) -> bool:
    """True when the query is glued together from string literals and UPPER_CASE constants only (table and column
    names such as `"DELETE FROM " + TABLE_NAME + " WHERE " + KEY_ID + "=?"`): no variable, so no injection. The
    statement is the flagged line plus the next few, up to the closing `)`; a variable anywhere in it keeps the
    finding."""
    m = re.search(r"\b(?:rawQuery|execSQL|compileStatement)\s*\(", stmt)
    if not m:
        return False
    rest = stmt[m.end():]
    end = rest.find(");")
    rest = rest if end < 0 else rest[:end]
    for name in _TEMPLATE.findall(rest):             # Kotlin "$TABLE" templates: constants only
        if not _CONST.match(name):
            return False
    rest = _TEMPLATE.sub("", rest)
    if "String.format(" in rest or "format(" in rest:
        return False
    # the first argument is the SQL; a second argument (bind values array) is fine, so stop at the first comma
    sql = _STR.sub("", rest).replace("\n", " ")
    first = sql.split(",")[0] if "," in sql else sql
    pieces = [x.strip(" ;)") for x in first.split("+")]
    pieces = [x for x in pieces if x]
    return all(_CONST.match(x) for x in pieces)


def code_findings(files: list[tuple[str, str]]) -> list[dict]:
    out = []
    for rel, text in files:
        if TEST_PATH.search(rel):
            continue
        lines = text.splitlines()
        ssl_file = "onReceivedSslError" in text
        for rule, rx, sev, title, cwe, conf in CODE_RULES:
            if rule in KOTLIN_ONLY and not rel.endswith(".kt"):
                continue
            if rule == "LM-WEBVIEW-SSL" and not ssl_file:
                continue
            for m in rx.finditer(text):
                ln = text.count("\n", 0, m.start()) + 1
                src = lines[ln - 1] if ln <= len(lines) else ""
                if src.lstrip().startswith(("//", "*", "/*")):
                    continue
                if rule == "LM-SQL-CONCAT" and only_constants("\n".join(lines[ln - 1:ln + 3])):
                    continue
                out.append(_f(rule, title, sev, rel, ln, cwe=cwe, conf=conf, category="code", snippet=src.strip(),
                              rank=CODE_RANK.get(rule)))
    return out


def scan(g: Graph) -> tuple[list[dict], dict | None]:
    """All Android findings, and the summary the viewer draws (`security["mobile"]`). (None when not an Android app.)"""
    from .websec import _files
    repo = Path(g.repo_root)
    mods = find_modules(repo)
    files = [(p.relative_to(repo).as_posix(), _read(p, repo)) for p in _files(repo, ANDROID_EXTS)]
    if not mods:
        # Java/Kotlin with no manifest (a library or a server): only the code rules that are Android-specific apply,
        # and only when the code uses Android at all.
        files = [(r, t) for r, t in files if re.search(r"^\s*import\s+android\.", t, re.M)]
        return code_findings(files), None
    out = []
    for mod in mods:
        out += manifest_findings(repo, mod, files, g)
        out += gradle_findings(repo, mod)
    out += code_findings(files)
    summary = {"platform": "android", "modules": []}
    for mod in mods:
        perms = permission_summary(mod, _module_code(repo, mod, files))
        summary["modules"].append({
            "root": mod.root, "manifest": mod.manifest, "package": mod.package,
            "min_sdk": mod.min_sdk, "target_sdk": mod.target_sdk,
            "permissions": perms,
            "components": [{"kind": c.tag, "name": _short(c.name), "exported": c.exported, "launcher": c.launcher,
                            "permission": c.permission, "line": c.line} for c in mod.components],
        })
    return out, summary
