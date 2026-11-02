"""Java frontend: packages and classes, interfaces and inheritance, Spring / JAX-RS / Javalin routes, bridge, LV-* rules."""

from pathlib import Path

import pytest

from lantern.engine import build_graph
from lantern.security import scan

FIX = Path(__file__).parent / "fixtures"
PKG = "jv:com.example.notes"


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def edge(g, src, dst):
    return next((e for e in g.call_edges() if e.src == src and e.dst == dst), None)


def entries(g):
    return {n.id: n.entry for n in g.entry_points()}


@pytest.fixture(scope="module")
def javaapp():
    g = build_graph(FIX / "javaapp")
    return g, scan(g)


def test_java_is_a_language_of_its_own(javaapp):
    g, _ = javaapp
    assert set(g.meta["languages"]) == {"java", "typescript/javascript"}
    j = g.meta["languages"]["java"]
    assert j["packages"] == 4 and j["classes"] == 9 and j["routes"] == 3


def test_spring_routes_main_and_tests_are_entries(javaapp):
    g, _ = javaapp
    e = entries(g)
    assert e[f"{PKG}.web.NoteController.getNote"] == {"kind": "route", "detail": "GET /api/notes/{id}"}   # class prefix + method
    assert e[f"{PKG}.web.NoteController.createNote"]["detail"] == "POST /api/notes"                      # @PostMapping without a path
    assert e[f"{PKG}.web.NoteController.deleteNote"]["detail"] == "DELETE /api/notes/{id}"
    assert "server start" in e[f"{PKG}.NotesApplication.main"]["detail"]                                 # SpringApplication.run
    assert e[f"{PKG}.store.SqlNoteRepositoryTest.savesANote"]["kind"] == "test"


def test_calls_resolve_by_name_static_constructor_and_receiver_type(javaapp):
    g, _ = javaapp
    c = f"{PKG}.web.NoteController"
    assert edge(g, f"{c}.createNote", f"{c}.currentUser").via == "name"
    assert edge(g, f"{c}.createNote", f"{PKG}.web.Exporter.export").via == "static"
    assert edge(g, f"{c}.createNote", f"{PKG}.mail.SmtpMailer.send").via == "receiver-type"      # field initialised with new SmtpMailer()
    assert edge(g, f"{c}.createNote", f"{PKG}.store.Note.getText").via == "receiver-type"        # typed by save()'s return type
    assert edge(g, f"{PKG}.store.SqlNoteRepository.find", f"{PKG}.store.Note.Note").via == "constructor"
    t = f"{PKG}.store.SqlNoteRepositoryTest.savesANote"
    assert edge(g, t, f"{PKG}.store.SqlNoteRepository.save").confidence == "resolved"


def test_interface_calls_are_possible_edges_to_implementers(javaapp):
    g, _ = javaapp
    e = edge(g, f"{PKG}.web.NoteController.getNote", f"{PKG}.store.SqlNoteRepository.find")
    assert e.confidence == "possible" and e.via == "interface"


def test_untyped_receivers_are_counted_not_guessed(javaapp):
    g, _ = javaapp
    assert not any(k.startswith(("rs.", "st.")) for k in g.unresolved)    # try-resource and typed locals resolve to ext nodes
    assert "ext:ResultSet.next" in {e.dst for e in g.call_edges()}


def test_js_frontend_links_to_spring_routes(javaapp):
    g, _ = javaapp
    e = edge(g, "js:web/src/api::getNote", f"{PKG}.web.NoteController.getNote")
    assert e.via == "http-exact" and e.detail == "GET /api/notes/{}"


def test_java_rules_find_the_planted_problems(javaapp):
    _, sec = javaapp
    by = {f["rule"]: f for f in sec["findings"]}
    assert by["LV-SQL-CONCAT"]["reachable"]["entry"].endswith("getNote") and by["LV-SQL-CONCAT"]["rank"] == "critical"
    assert by["LV-SQL-CONCAT"]["input"]["via"] == "parameter `id`"                   # `String id`: the name, not the type
    assert by["LV-EXEC-CONCAT"]["reachable"]["entry"].endswith("createNote") and by["LV-EXEC-CONCAT"]["rank"] == "critical"
    assert by["LW-AUTH-MISSING"]["line"] == 36                             # deleteNote; createNote checks the session


def test_jaxrs_javalin_inheritance_nested_and_resttemplate(tmp_path):
    _write(tmp_path, {
        "build.gradle": 'dependencies { implementation "io.javalin:javalin:6.1.0" }\n',
        "src/main/java/app/Api.java": '''package app;

import javax.ws.rs.*;

@Path("/v1")
public class Api extends Base {
    @GET
    @Path("/items")
    public String items() { return load(); }

    @POST
    public String create() { return helper().run(); }

    static class Helper {
        String run() { return ""; }
    }

    Helper helper() { return new Helper(); }
}
''',
        "src/main/java/app/Base.java": '''package app;

public class Base {
    protected String load() { return ""; }
}
''',
        "src/main/java/app/Main.java": '''package app;

import io.javalin.Javalin;
import org.springframework.web.client.RestTemplate;

public class Main {
    static final String BASE = "https://api.example.com";

    public static void main(String[] args) {
        Javalin app = Javalin.create().start(7000);
        app.get("/health", Main::health);
        app.post("/sync", ctx -> sync());
    }

    static void health(Object ctx) {}

    static void sync() {
        RestTemplate t = new RestTemplate();
        t.getForObject(BASE + "/items/" + 1, String.class);
        t.postForObject("/local/items", null, String.class);
    }
}
''',
    })
    g = build_graph(tmp_path)
    e = entries(g)
    assert e["jv:app.Api.items"]["detail"] == "GET /v1/items"
    assert e["jv:app.Api.create"]["detail"] == "POST /v1"
    assert e["jv:app.Main.health"]["detail"] == "GET /health"
    assert "server start" in e["jv:app.Main.main"]["detail"]
    assert edge(g, "jv:app.Api.items", "jv:app.Base.load").via == "inherited"
    assert edge(g, "jv:app.Api.create", "jv:app.Api.Helper.run").via == "receiver-type"    # nested class via helper()'s return type
    calls = {(c["method"], c["path"], c["host"], c["prefix_unknown"]) for c in g.meta["http_calls"]}
    assert ("GET", "/items/{}", "api.example.com", False) in calls
    assert ("POST", "/local/items", None, False) in calls
