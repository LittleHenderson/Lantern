"""Android apps (lantern/android.py): manifest entry points, LM-* rules, lanes, readiness and stories."""

import json
from pathlib import Path

import pytest

from lantern import android
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
def notes():
    g = build_graph(FIX / "androidapp")
    sec = scan(g)
    return g, sec, assess(g, sec)


def rules(sec):
    return {f["rule"] for f in sec["findings"]}


def by_rule(sec, rule):
    return [f for f in sec["findings"] if f["rule"] == rule]


def test_the_manifest_gives_the_app_its_entry_points(notes):
    g, _, _ = notes
    e = {n.id: n.entry for n in g.entry_points()}
    assert e["jv:com.example.notes.MainActivity.onCreate"]["kind"] == "page"
    assert "(app start)" in e["jv:com.example.notes.MainActivity.onCreate"]["detail"]
    assert e["jv:com.example.notes.SettingsActivity.onCreate"]["kind"] == "page"       # not exported: a screen
    assert e["jv:com.example.notes.ui.HomeFragment.onCreateView"]["kind"] == "page"    # found by `extends Fragment`
    # other apps can start these, so what they receive is outside input
    assert e["jv:com.example.notes.NoteActivity.onCreate"]["kind"] == "route"
    assert e["jv:com.example.notes.NoteActivity.onCreate"]["detail"].startswith("INTENT NoteActivity screen")
    assert e["jv:com.example.notes.NotesProvider.query"]["kind"] == "route"
    assert e["jv:com.example.notes.AlertService.onStartCommand"]["kind"] == "route"     # exported by its intent filter
    assert "jv:com.example.notes.NoteActivity.show" not in e                           # only on…/lifecycle methods
    assert g.meta["platform"] == "android"
    assert g.meta["android"]["modules"][0]["package"] == "com.example.notes"
    assert g.meta["android"]["modules"][0]["target_sdk"] == 29


def test_lanes_put_the_app_on_the_phone(notes):
    g, _, _ = notes
    assert g.nodes["jv:com.example.notes.MainActivity.onCreate"].lane == "browser"     # a screen
    assert g.nodes["jv:com.example.notes.NoteActivity.onCreate"].lane == "browser"     # a screen other apps can open
    assert g.nodes["jv:com.example.notes.NoteActivity.show"].lane == "frontend"        # the app, not a server
    assert g.nodes["jv:com.example.notes.NotesProvider.query"].lane == "frontend"


def test_every_planted_problem_is_found(notes):
    _, sec, _ = notes
    want = {"LM-BACKUP", "LM-CLEARTEXT", "LM-USER-CERTS", "LM-EXPORTED", "LM-UNUSED-PERMISSION",
            "LM-RELEASE-DEBUGGABLE", "LM-RELEASE-DEBUG-KEY", "LM-NO-SHRINK", "LM-OLD-TARGET", "LM-DYNAMIC-VERSION",
            "LM-LOG-SENSITIVE", "LM-WEBVIEW-JS", "LM-WEBVIEW-BRIDGE", "LM-WEBVIEW-FILE-URL", "LM-EXTERNAL-STORAGE",
            "LM-PREFS-SECRET", "LM-TLS-OFF", "LM-CLEARTEXT-URL", "LM-IMPLICIT-BROADCAST", "LV-SQL-CONCAT"}
    assert want <= rules(sec), want - rules(sec)
    assert sec["mobile"]["platform"] == "android"


def test_a_link_that_reaches_a_query_is_critical(notes):
    _, sec, _ = notes
    sql = [f for f in sec["findings"] if f["file"].endswith("NoteActivity.java") and f["rule"].endswith("SQL-CONCAT")]
    assert len(sql) == 1                                          # LV and LM do not both report one line
    f = sql[0]
    assert f["rank"] == "critical"
    assert f["reachable"]["kind"] == "route" and f["input"]
    assert f["headline"] == "Another app or a link can change what your app's database is asked"
    assert "installs a small app of their own" in f["scenario"]["steps"][0]


def test_exported_components_are_ranked_by_what_they_open(notes):
    _, sec, _ = notes
    ex = {"." + f["title"].split(": ", 1)[1].split()[0]: f for f in by_rule(sec, "LM-EXPORTED")}
    assert ex[".NotesProvider"]["rank"] == "high"                 # data other apps can read and change
    assert ex[".NoteActivity"]["rank"] == "medium"                # a deep link carries data in
    assert ex[".AlertService"]["rank"] == "medium"
    assert ex[".AlertService"]["tool_confidence"] == "LOW"        # exported only by default
    assert ex[".BootReceiver"]["rank"] == "low"                   # system broadcasts only
    assert ex[".NotesProvider"]["node"] == "jv:com.example.notes.NotesProvider"   # pinned to the class
    assert ".MainActivity" not in ex                              # the launcher is fine


def test_the_unused_permission_is_the_camera_only(notes):
    _, sec, _ = notes
    unused = by_rule(sec, "LM-UNUSED-PERMISSION")
    assert [f["snippet"] for f in unused] == ['<uses-permission android:name="android.permission.CAMERA" />']
    perms = {p["name"]: p for p in sec["mobile"]["modules"][0]["permissions"]}
    assert perms["SEND_SMS"]["used"] is True and perms["ACCESS_FINE_LOCATION"]["used"] is True
    assert perms["INTERNET"]["sensitive"] is False


def test_readiness_grades_an_android_app_as_one(notes):
    _, _, r = notes
    assert r["shape"] == "Android app"
    checks = {c["id"]: c for cat in r["categories"] for c in cat["checks"]}
    assert checks["tests-exist"]["status"] == "partial"           # Android Studio's sample test only
    assert "sample tests" in checks["tests-exist"]["evidence"]
    assert checks["pkg-debuggable"]["status"] == "fail"
    assert checks["pkg-shrink"]["status"] == "fail"
    assert checks["pkg-signing"]["status"] == "fail"
    assert checks["obs-crash"]["status"] == "fail"
    assert checks["obs-health"]["status"] == "skip"
    assert "pkg-docker" not in checks                             # no Dockerfile advice for a phone app
    assert any("Play" in a for a in r["advice"])


def test_a_clean_app_has_nothing_to_report(tmp_path):
    _write(tmp_path, {
        "app/build.gradle.kts": 'android {\n  namespace = "a.b"\n  defaultConfig { targetSdk = 35\n minSdk = 26 }\n'
                                '  buildTypes { getByName("release") { isMinifyEnabled = true } }\n}\n'
                                'dependencies {\n  implementation("androidx.core:core-ktx:1.13.1")\n}\n',
        "app/src/main/AndroidManifest.xml": '<manifest xmlns:a="http://schemas.android.com/apk/res/android">\n'
                                            '<application a:allowBackup="false">\n'
                                            '<activity a:name=".Main" a:exported="true"><intent-filter>'
                                            '<action a:name="android.intent.action.MAIN"/>'
                                            '<category a:name="android.intent.category.LAUNCHER"/></intent-filter></activity>\n'
                                            '<service a:name=".Sync" a:exported="false"/>\n'
                                            '</application></manifest>\n',
        "app/src/main/java/a/b/Main.java": "package a.b;\nimport android.app.Activity;\nimport android.os.Bundle;\n"
                                           "public class Main extends Activity {\n"
                                           "  protected void onCreate(Bundle b) { super.onCreate(b); }\n}\n",
    })
    g = build_graph(tmp_path)
    sec = scan(g)
    assert [f["rule"] for f in sec["findings"] if f["rule"].startswith("LM-")] == []
    assert g.nodes["jv:a.b.Main.onCreate"].entry["kind"] == "page"   # any prefix bound to the Android namespace


def test_signing_password_with_the_key_file_is_a_secret(tmp_path):
    pw = "s3cr" + "et-store"
    _write(tmp_path, {
        "app/build.gradle": "android {\n  signingConfigs {\n    release {\n      storeFile file('release.jks')\n"
                            f"      storePassword \"{pw}\"\n    }}\n" + "}\n",
        "app/release.jks": "not really a key",
        "app/src/main/AndroidManifest.xml": '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                                            'package="a.b"><application android:allowBackup="false"/></manifest>',
    })
    g = build_graph(tmp_path)
    sec = scan(g)
    f = by_rule(sec, "LM-SIGNING-SECRET")[0]
    assert f["category"] == "secret" and f["rank"] == "critical" and f["snippet"] == "[redacted]"
    r = assess(g, sec)
    checks = {c["id"]: c for cat in r["categories"] for c in cat["checks"]}
    assert checks["secrets-keystore"]["status"] == "fail"


def test_google_key_in_the_manifest_is_named_but_not_shown(tmp_path):
    key = "AIza" + "Sy" + "A" * 33
    _write(tmp_path, {
        "src/main/AndroidManifest.xml": '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a">'
                                        '<application android:allowBackup="false"><meta-data '
                                        f'android:name="com.google.android.geo.API_KEY" android:value="{key}"/>'
                                        '</application></manifest>',
    })
    sec = scan(build_graph(tmp_path))
    f = by_rule(sec, "LM-GOOGLE-KEY")[0]
    assert f["snippet"] == "[redacted]" and key not in json.dumps(sec)
    assert f["tool_confidence"] == "LOW"


def test_hostile_manifests_are_refused_quietly(tmp_path):
    _write(tmp_path, {
        "AndroidManifest.xml": '<?xml version="1.0"?><!DOCTYPE m [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]>'
                               '<manifest package="&b;"><application/></manifest>',
        "app/src/main/AndroidManifest.xml": "<manifest><application",
    })
    assert android.find_modules(tmp_path) == []
    g = build_graph(tmp_path)
    assert "platform" not in g.meta


def test_fixtures_inside_tests_do_not_make_a_repo_an_android_app(tmp_path):
    _write(tmp_path, {"tests/fixtures/app/src/main/AndroidManifest.xml":
                      '<manifest package="a"><application android:debuggable="true"/></manifest>',
                      "main.py": "print('hi')\n"})
    g = build_graph(tmp_path)
    assert "platform" not in g.meta


def test_network_config_cleartext_for_some_domains_is_low(tmp_path):
    _write(tmp_path, {
        "app/src/main/AndroidManifest.xml": '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                                            'package="a"><application android:allowBackup="false" '
                                            'android:networkSecurityConfig="@xml/nsc"/></manifest>',
        "app/src/main/res/xml/nsc.xml": '<network-security-config><domain-config cleartextTrafficPermitted="true">'
                                        '<domain>10.0.2.2</domain></domain-config><debug-overrides><trust-anchors>'
                                        '<certificates src="user"/></trust-anchors></debug-overrides>'
                                        '</network-security-config>',
    })
    sec = scan(build_graph(tmp_path))
    assert [f["rank"] for f in by_rule(sec, "LM-CLEARTEXT")] == ["low"]
    assert by_rule(sec, "LM-USER-CERTS") == []                   # user certificates in debug builds only: fine
