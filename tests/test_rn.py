"""React Native and Expo apps: lantern/rn.py (screens, links, app.json and LN-* checks) on top of the JS/TS reader."""

from pathlib import Path

import pytest

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
    g = build_graph(FIX / "rnapp")
    sec = scan(g)
    return g, sec, assess(g, sec)


def by_rule(sec, rule):
    return [f for f in sec["findings"] if f["rule"] == rule]


def test_screens_and_links(notes):
    g, _, _ = notes
    e = {n.id: n.entry for n in g.entry_points()}
    assert g.meta["platform"] == "react-native" and g.meta["rn"]["roots"] == [""]
    assert e["js:src/screens/HomeScreen::HomeScreen"] == {"kind": "page", "detail": "HomeScreen screen · HomeScreen"}
    # `Note: 'note/:id'` in the linking config: the Note screen can be opened by a link
    assert e["js:src/screens/NoteScreen::NoteScreen"]["detail"].startswith("LINK NoteScreen screen")
    # what the Linking listener's callback calls
    assert e["js:src/links/handleLink::handleLink"]["detail"].startswith("LINK handleLink handles links")
    assert "js:src/screens/NoteRow::NoteRow" not in e                      # a row, never given to a navigator
    assert "js:App::SettingsStack" not in e                                # a nested navigator, not a screen
    assert "js:src/links/ready::useIsReady" not in e                       # a hook called next to the listener
    assert g.nodes["js:src/screens/HomeScreen::HomeScreen"].lane == "browser"
    assert g.nodes["js:src/db/notes::findNote"].lane == "frontend"


def test_a_link_reaching_a_query_is_critical(notes):
    _, sec, _ = notes
    f = by_rule(sec, "LN-SQL-CONCAT")[0]
    assert f["node"] == "js:src/db/notes::findNote" and f["rank"] == "critical"
    assert f["reachable"]["entry"] == "js:src/links/handleLink::handleLink" and f["input"] == {"via": "parameter `id`"}
    assert f["headline"] == "Another app or a link can change what your app's database is asked"


def test_every_planted_problem_is_found(notes):
    _, sec, _ = notes
    rules = {f["rule"] for f in sec["findings"]}
    assert {"LN-SQL-CONCAT", "LN-ASYNC-SECRET", "LN-LOG-SENSITIVE", "LN-CLEARTEXT-URL", "LN-URL-SCHEME",
            "LN-BACKUP", "LN-ATS-OFF", "LN-UNUSED-PERMISSION"} <= rules
    assert {f["title"].split("(")[1].split(")")[0] for f in by_rule(sec, "LN-UNUSED-PERMISSION")} == \
        {"CAMERA", "READ_CONTACTS"}
    assert "expo-secure-store" in by_rule(sec, "LN-ASYNC-SECRET")[0]["title"]
    assert all(f["scenario"]["kind"] != "generic" for f in sec["findings"])
    mod = sec["mobile"]["modules"][0]
    assert sec["mobile"]["platform"] == "react-native" and mod["package"] == "com.example.pocketnotes"
    assert mod["components"][0]["name"] == "pocketnotes://"


def test_readiness_grades_it_as_a_react_native_app(notes):
    _, _, r = notes
    checks = {c["id"]: c for cat in r["categories"] for c in cat["checks"]}
    assert r["shape"] == "React Native app"
    assert checks["obs-crash"]["status"] == "fail" and checks["pkg-ats"]["status"] == "fail"
    assert checks["res-timeout"]["status"] == "fail" and checks["obs-health"]["status"] == "skip"
    assert any("expo-secure-store" in t for t in r["advice"])


def test_expo_router_files_are_screens_and_a_scheme_makes_them_links(tmp_path):
    _write(tmp_path, {
        "package.json": '{"dependencies": {"expo": "52", "expo-router": "4", "react-native": "0.76"}}',
        "app.json": '{"expo": {"scheme": "demo", "android": {"allowBackup": false}}}',
        "app/_layout.tsx": "export default function Layout() { return null; }\n",
        "app/(tabs)/index.tsx": "export default function Home() { return null; }\n",
        "app/note/[id].tsx": "export default function Note() { return null; }\n",
    })
    g = build_graph(tmp_path)
    e = {n.id: n.entry["detail"] for n in g.entry_points()}
    assert e["js:app/(tabs)/index::Home"] == "LINK Home screen (other apps and web pages can open it) · /"
    assert e["js:app/note/[id]::Note"].endswith("· /note/[id]")
    assert "js:app/_layout::Layout" not in e
    rules = {f["rule"] for f in scan(g)["findings"]}
    assert "LN-URL-SCHEME" in rules and "LN-BACKUP" not in rules


def test_a_handler_that_reads_the_first_link_is_a_link(tmp_path):
    _write(tmp_path, {
        "package.json": '{"dependencies": {"react-native": "0.76"}}',
        "App.js": "import { Linking } from 'react-native';\n"
                  "function track() {}\nfunction openUrl(u) { return u; }\n"
                  "export async function start() {\n  track();\n  const url = await Linking.getInitialURL();\n"
                  "  if (url) openUrl(url);\n}\n",
    })
    g = build_graph(tmp_path)
    e = {n.id: n.entry for n in g.entry_points()}
    assert e["js:App::openUrl"]["kind"] == "route" and "js:App::track" not in e


def test_a_plain_web_app_is_not_a_phone_app(tmp_path):
    _write(tmp_path, {"package.json": '{"dependencies": {"react": "18"}}', "src/a.js": "export function a() {}\n"})
    g = build_graph(tmp_path)
    assert "rn" not in g.meta and g.meta.get("platform") is None
