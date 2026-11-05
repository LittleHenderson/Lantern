"""Kotlin (lantern/kotlin_frontend.py): classes, objects, companions, calls, Android entries and Spring routes."""

from pathlib import Path

import pytest

from lantern.engine import build_graph
from lantern.security import scan

FIX = Path(__file__).parent / "fixtures"
P = "kt:com.example.trips."


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


@pytest.fixture(scope="module")
def trips():
    g = build_graph(FIX / "kotlinapp")
    return g, scan(g)


def edges(g):
    return {(e.src, e.dst): e for e in g.call_edges()}


def test_kotlin_is_mapped(trips):
    g, _ = trips
    kt = g.meta["languages"]["kotlin"]
    assert kt["files"] == 9 and kt["classes"] >= 10
    assert g.nodes[P + "data.TripRepository.make"].parent == P + "data.TripRepository"   # companion → the class
    assert g.nodes[P + "data.TripDatabase"].signature == "object TripDatabase"
    assert g.nodes[P + "data.Api"].signature == "interface Api"


def test_calls_resolve_the_kotlin_ways(trips):
    g, _ = trips
    e = edges(g)
    assert e[(P + "MainActivity.onCreate", P + "MainActivity.showList")].via == "name"
    assert e[(P + "TripsApp.onCreate", P + "data.TripDatabase.open")].via == "assoc"            # object
    assert e[(P + "ui.TripListFragment.onCreateView", P + "data.TripRepository.make")].via == "assoc"  # companion
    # `val repo = TripRepository.make()`: typed from the function's written return type
    assert e[(P + "ui.TripListFragment.onCreateView", P + "data.TripRepository.all")].via == "receiver-type"
    # `private val repo = TripRepository()`: a property typed by its constructor call
    assert e[(P + "TripActivity.show", P + "data.TripRepository.find")].via == "receiver-type"
    # `private val api: Api`: an interface, so one possible edge per class that implements it
    up = [e[k] for k in e if k[0] == P + "SyncService.onStartCommand" and k[1].endswith(".upload")]
    assert {x.dst for x in up} == {P + "data.HttpApi.upload", P + "data.FakeApi.upload"}
    assert {x.confidence for x in up} == {"possible"}
    assert e[(P + "data.Formatter.names", P + "data.Formatter.clean")].via == "callback"        # ::clean
    assert (P + "TripActivity.show", "ext:Log.d") in e                                          # library call
    assert any("supportFragmentManager" in k for k in g.unresolved)                             # counted, not guessed


def test_android_entries_attach_to_kotlin_classes(trips):
    g, _ = trips
    e = {n.id: n.entry for n in g.entry_points()}
    assert e[P + "MainActivity.onCreate"]["kind"] == "page"
    assert e[P + "ui.TripListFragment.onCreateView"]["kind"] == "page"
    assert e[P + "TripActivity.onCreate"]["kind"] == "route"           # a deep link: other apps and links open it
    assert e[P + "TripsApp.onCreate"]["kind"] == "main"
    assert e[P + "SyncService.onStartCommand"]["kind"] == "main"       # not exported: Android starts it
    assert e[P + "FormatterTest.namesAreTrimmed"]["kind"] == "test"
    assert g.nodes[P + "TripActivity.onCreate"].lane == "browser"
    assert g.nodes[P + "data.TripRepository.find"].lane == "frontend"


def test_a_deep_link_reaching_a_kotlin_query_is_critical(trips):
    _, sec = trips
    sql = [f for f in sec["findings"] if f["rule"].endswith("SQL-CONCAT")]
    assert len(sql) == 1
    f = sql[0]
    assert f["node"] == P + "data.TripRepository.find"
    assert f["rank"] == "critical" and f["input"] == {"via": "parameter `id`"}
    assert f["reachable"]["entry"] == P + "TripActivity.onCreate"
    assert f["headline"] == "Another app or a link can change what your app's database is asked"


def test_kotlin_parameters_and_locals_carry_input(tmp_path):
    _write(tmp_path, {
        "src/main/kotlin/a/Api.kt": (
            "package a\n\n"
            "import org.springframework.web.bind.annotation.*\n"
            "import org.springframework.jdbc.core.JdbcTemplate\n\n"
            "@RestController\n@RequestMapping(\"/api\")\n"
            "class Api(private val jdbc: JdbcTemplate) {\n"
            "    @GetMapping(\"/users\")\n"
            "    fun users(@RequestParam name: String, limit: Int = 10): Any {\n"
            "        val q = name.trim()\n"
            "        return jdbc.queryForList(\"SELECT * FROM users WHERE name = '$q'\")\n"
            "    }\n\n"
            "    @DeleteMapping(\"/users/{id}\")\n"
            "    fun remove(@PathVariable id: Long) {\n"
            "        Runtime.getRuntime().exec(\"rm -rf /data/$id\")\n"
            "    }\n"
            "}\n"),
    })
    g = build_graph(tmp_path)
    assert g.nodes["kt:a.Api.users"].entry == {"kind": "route", "detail": "GET /api/users"}
    assert g.nodes["kt:a.Api.remove"].entry["detail"] == "DELETE /api/users/{id}"
    sec = scan(g)
    by = {f["rule"]: f for f in sec["findings"]}
    assert by["LV-SQL-CONCAT"]["node"] == "kt:a.Api.users"
    assert "line 11 sets from parameter `name`" in by["LV-SQL-CONCAT"]["input"]["via"]
    assert by["LV-SQL-CONCAT"]["rank"] == "critical"
    assert by["LV-EXEC-CONCAT"]["input"] == {"via": "parameter `id`"}


def test_overloads_share_a_node_and_nested_classes_are_named(tmp_path):
    _write(tmp_path, {"a/Shapes.kt": (
        "package a\n\n"
        "class Outer {\n"
        "    class Inner {\n"
        "        fun area(x: Int): Int = x\n"
        "        fun area(x: Int, y: Int): Int = x * y\n"
        "    }\n"
        "    fun go() { val i = Inner(); i.area(2) }\n"
        "}\n\n"
        "fun main() { Outer().go() }\n")})
    g = build_graph(tmp_path)
    assert "(+1 overload)" in g.nodes["kt:a.Outer.Inner.area"].signature
    assert g.nodes["kt:a.main"].entry["kind"] == "main"
    e = edges(g)
    assert ("kt:a.Outer.go", "kt:a.Outer.Inner.area") in e


def test_a_broken_kotlin_file_does_not_stop_the_map(tmp_path):
    _write(tmp_path, {"a/Bad.kt": "package a\nclass Bad { fun x( {\n", "a/Good.kt": "package a\nfun ok() = 1\n"})
    g = build_graph(tmp_path)
    assert "kt:a.ok" in g.nodes


def test_compose_screens_are_screens(tmp_path):
    _write(tmp_path, {"app/src/main/AndroidManifest.xml": '<manifest xmlns:android="http://schemas.android.com/apk/res/android"'
                                                         ' package="a"><application android:allowBackup="false"/></manifest>',
                      "app/src/main/java/a/Home.kt": (
                          "package a\n\nimport androidx.compose.runtime.Composable\n\n"
                          "@Composable\nfun HomeScreen(onOpen: (String) -> Unit) {\n    Title()\n}\n\n"
                          "@Composable\nfun Title() {}\n")})
    g = build_graph(tmp_path)
    assert g.nodes["kt:a.HomeScreen"].entry == {"kind": "page", "detail": "Home screen (Compose) · HomeScreen"}
    assert g.nodes["kt:a.HomeScreen"].lane == "browser"
    assert g.nodes["kt:a.Title"].entry is None                     # a piece of a screen, not a screen
    assert ("kt:a.HomeScreen", "kt:a.Title") in edges(g)
