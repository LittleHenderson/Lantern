"""iOS apps: the Swift reader (lantern/swift_frontend.py) and lantern/ios.py (screens, links, LI-* checks, readiness)."""

import json
from pathlib import Path

import pytest

from lantern import ios
from lantern.engine import build_graph
from lantern.readiness import assess
from lantern.security import scan

FIX = Path(__file__).parent / "fixtures"


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


@pytest.fixture(scope="module")
def journal():
    g = build_graph(FIX / "iosapp")
    sec = scan(g)
    return g, sec, assess(g, sec)


def edges(g):
    return {(e.src, e.dst): e for e in g.call_edges()}


def rules(sec):
    return {f["rule"] for f in sec["findings"]}


def by_rule(sec, rule):
    return [f for f in sec["findings"] if f["rule"] == rule]


def test_swift_is_mapped(journal):
    g, _, _ = journal
    sw = g.meta["languages"]["swift"]
    assert sw["files"] == 8 and sw["types"] >= 10
    assert g.nodes["sw:ContentView"].signature == "struct ContentView: View"
    assert g.nodes["sw:Uploader"].signature == "protocol Uploader"
    assert g.nodes["sw:String.trimmed"].parent == "sw:String"            # an extension of a library type
    assert g.nodes["sw:ContentView.body"].kind == "callable"             # SwiftUI's computed body is code


def test_calls_resolve_the_swift_ways(journal):
    g, _, _ = journal
    e = edges(g)
    assert e[("sw:ContentView.body", "sw:ContentView.reload")].via == "name"
    assert e[("sw:ContentView.body", "sw:ContentView.sync")].via == "callback"        # Button(action: sync)
    assert e[("sw:ContentView.reload", "sw:EntryStore.all")].via == "receiver-type"   # `let store: EntryStore`
    assert e[("sw:ContentView.sync", "sw:Sync.push")].via == "receiver-type"          # Sync.shared.push
    assert e[("sw:JournalApp.body", "sw:DeepLink.handle")].via == "assoc"             # a static func
    assert e[("sw:JournalTests.testAllIsEmpty", "sw:EntryStore.init")].via == "constructor"
    body = e[("sw:ContentView.body", "sw:EntryView.body")]                           # NavigationLink { EntryView() }
    assert body.via == "swiftui-body" and body.confidence == "inferred"
    assert any("UserDefaults.standard" in k for k in g.unresolved)                   # counted, not guessed


def test_protocol_calls_fan_out(tmp_path):
    _write(tmp_path, {"S/A.swift": "protocol Store { func load() }\nclass Disk: Store { func load() {} }\n"
                                   "class Mem: Store { func load() {} }\n"
                                   "class Repo { let s: Store\n init(s: Store) { self.s = s }\n func go() { s.load() } }\n"})
    g = build_graph(tmp_path)
    got = {(e.dst, e.confidence) for e in g.call_edges() if e.src == "sw:Repo.go"}
    assert got == {("sw:Disk.load", "possible"), ("sw:Mem.load", "possible")}


def test_screens_links_and_app_start(journal):
    g, _, _ = journal
    e = {n.id: n.entry for n in g.entry_points()}
    assert g.meta["platform"] == "ios" and g.meta["ios"]["apps"][0]["bundle_id"] == "com.example.journal"
    assert e["sw:JournalApp.body"] == {"kind": "main", "detail": "app start (JournalApp) · body"}
    assert e["sw:ContentView.body"]["detail"] == "ContentView screen · body"            # what WindowGroup draws
    assert e["sw:EntryView.body"]["kind"] == "page"                                    # opened by NavigationLink
    assert e["sw:SettingsViewController.viewDidLoad"]["detail"] == "SettingsViewController screen · viewDidLoad"
    assert e["sw:SettingsViewController.signIn"]["kind"] == "page"                     # an @IBAction
    assert e["sw:DeepLink.handle"]["kind"] == "route"                                  # called from .onOpenURL
    assert e["sw:DeepLink.handle"]["detail"].startswith("LINK DeepLink handles links")
    assert "sw:ContentView.reload" not in e
    assert g.nodes["sw:ContentView.body"].lane == "browser" and g.nodes["sw:EntryStore.entry"].lane == "frontend"


def test_a_link_reaching_a_query_is_critical(journal):
    _, sec, _ = journal
    f = by_rule(sec, "LI-SQL-CONCAT")[0]
    assert f["node"] == "sw:EntryStore.entry" and f["rank"] == "critical"
    assert f["reachable"]["entry"] == "sw:DeepLink.handle" and f["input"] == {"via": "parameter `id`"}
    assert f["headline"] == "Another app or a link can change what your app's database is asked"
    assert f["scenario"]["steps"][0].endswith("DeepLink handles it and reads data of their choosing.")
    assert f["scenario"]["steps"][1].startswith("In the link they send, they put:")


def test_every_planted_problem_is_found(journal):
    _, sec, _ = journal
    want = {"LI-SQL-CONCAT", "LI-DEFAULTS-SECRET", "LI-TLS-OFF", "LI-ATS-OFF", "LI-DEBUGGABLE", "LI-LOG-SENSITIVE",
            "LI-OLD-TARGET", "LI-CLEARTEXT-URL", "LI-URL-SCHEME", "LI-UNUSED-PERMISSION", "LI-FILE-SHARING"}
    assert want <= rules(sec), want - rules(sec)
    assert by_rule(sec, "LI-TLS-OFF")[0]["rank"] == "high"          # iOS calls the handler for every connection
    assert {f["snippet"] for f in by_rule(sec, "LI-UNUSED-PERMISSION")} == {
        "<key>NSCameraUsageDescription</key>", "<key>NSLocationWhenInUseUsageDescription</key>"}
    m = sec["mobile"]["modules"][0]
    assert sec["mobile"]["platform"] == "ios" and m["min_ios"] == "14.0"
    assert [c["name"] for c in m["components"]] == ["journal://"]
    assert {p["words"] for p in m["permissions"]} == {"camera", "location while the app is open"}


def test_ios_stories_say_iphone_things(journal):
    _, sec, _ = journal
    dbg = by_rule(sec, "LI-DEBUGGABLE")[0]
    assert dbg["headline"] == "A debugger can attach to the app"
    assert "Mac with Xcode" in dbg["scenario"]["steps"][0]
    assert "Android" not in json.dumps([f["scenario"] for f in sec["findings"]])


def test_readiness_grades_an_ios_app_as_one(journal):
    _, _, r = journal
    assert r["shape"] == "iOS app"
    checks = {c["id"]: c for cat in r["categories"] for c in cat["checks"]}
    assert checks["pkg-debuggable"]["status"] == "fail" and checks["pkg-ats"]["status"] == "fail"
    assert checks["pkg-target"]["status"] == "fail" and checks["obs-crash"]["status"] == "fail"
    assert checks["res-timeout"]["status"] == "fail" and checks["tests-exist"]["status"] == "pass"
    assert "pkg-docker" not in checks
    assert any("TestFlight" in a for a in r["advice"])


def test_a_clean_ios_app_has_nothing_to_report(tmp_path):
    _write(tmp_path, {
        "A.xcodeproj/project.pbxproj": "buildSettings = { IPHONEOS_DEPLOYMENT_TARGET = 17.0; SDKROOT = iphoneos; };\n",
        "A/Info.plist": '<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key>'
                        '<string>$(PRODUCT_BUNDLE_IDENTIFIER)</string></dict></plist>',
        "A/AApp.swift": "import SwiftUI\n@main\nstruct AApp: App { var body: some Scene { WindowGroup { HomeScreen() } } }\n",
        "A/HomeScreen.swift": "import SwiftUI\nstruct HomeScreen: View { var body: some View { Text(\"hi\") } }\n",
    })
    g = build_graph(tmp_path)
    sec = scan(g)
    assert [f["rule"] for f in sec["findings"] if f["rule"].startswith("LI-")] == []
    assert g.nodes["sw:HomeScreen.body"].entry["kind"] == "page"


def test_usage_keys_in_the_xcode_project_count(tmp_path):
    _write(tmp_path, {
        "A.xcodeproj/project.pbxproj": "IPHONEOS_DEPLOYMENT_TARGET = 17.0;\n"
                                       "INFOPLIST_KEY_NSMicrophoneUsageDescription = \"Record notes\";\n",
        "A/Rec.swift": "import AVFoundation\nfinal class Rec { let r = AVAudioRecorder() }\n",
    })
    sec = scan(build_graph(tmp_path))
    assert by_rule(sec, "LI-UNUSED-PERMISSION") == []
    assert sec["mobile"]["modules"][0]["permissions"][0]["used"] is True


def test_hostile_plists_are_refused_quietly(tmp_path):
    _write(tmp_path, {
        "A.xcodeproj/project.pbxproj": "IPHONEOS_DEPLOYMENT_TARGET = 17.0;\n",
        "A/Info.plist": '<?xml version="1.0"?><!DOCTYPE p [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]>'
                        '<plist><dict><key>NSAppTransportSecurity</key><string>&b;</string></dict></plist>',
        "A/Other.entitlements": "<plist><dict><key>get-task-allow</key>",
    })
    apps = ios.find_apps(tmp_path)
    assert len(apps) == 1 and apps[0].keys == {}
    sec = scan(build_graph(tmp_path))
    assert not by_rule(sec, "LI-ATS-OFF") and not by_rule(sec, "LI-DEBUGGABLE")


def test_a_key_in_info_plist_is_named_but_not_shown(tmp_path):
    key = "AIza" + "Sy" + "B" * 33
    _write(tmp_path, {
        "A.xcodeproj/project.pbxproj": "IPHONEOS_DEPLOYMENT_TARGET = 17.0;\n",
        "A/Info.plist": f'<plist><dict><key>MapsKey</key><string>{key}</string></dict></plist>',
    })
    sec = scan(build_graph(tmp_path))
    f = by_rule(sec, "LI-PLIST-KEY")[0]
    assert f["snippet"] == "[redacted]" and key not in json.dumps(sec)


def test_vapor_routes_are_entry_points(tmp_path):
    _write(tmp_path, {"Sources/App/routes.swift": (
        "import Vapor\n\nfunc routes(_ app: Application) throws {\n"
        "    let c = NoteController()\n"
        "    app.get(\"notes\", \":id\", use: c.show)\n}\n\n"
        "struct NoteController {\n    func show(req: Request) throws -> String {\n"
        "        let id = req.parameters.get(\"id\")!\n        return id\n    }\n}\n")})
    g = build_graph(tmp_path)
    assert "platform" not in g.meta                                  # a server, not a phone app
    assert g.nodes["sw:NoteController.show"].entry == {"kind": "route", "detail": "GET /notes/{id}"}
    assert g.nodes["sw:NoteController.show"].lane == "server"


def test_a_broken_swift_file_does_not_stop_the_map(tmp_path):
    _write(tmp_path, {"A/Bad.swift": "class Bad { func x( {\n", "A/Good.swift": "func ok() -> Int { 1 }\n"})
    g = build_graph(tmp_path)
    assert "sw:ok" in g.nodes
