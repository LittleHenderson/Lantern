"""Go frontend: packages, methods, interfaces, routers, the bridge to a JS frontend, and the LG-* rules."""

from pathlib import Path

import pytest

from lantern.engine import build_graph
from lantern.security import scan

FIX = Path(__file__).parent / "fixtures"


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
def goapp():
    g = build_graph(FIX / "goapp")
    return g, scan(g)


def test_go_is_a_language_of_its_own(goapp):
    g, _ = goapp
    assert set(g.meta["languages"]) == {"go", "typescript/javascript"}
    assert g.meta["languages"]["go"]["packages"] == 2        # main and store (the test file is package store too)


def test_routes_main_and_tests_are_entries(goapp):
    g, _ = goapp
    e = entries(g)
    assert e["go:example.com/goapp::Server.getNote"] == {"kind": "route", "detail": "GET /api/notes/{id}"}
    assert e["go:example.com/goapp::Server.deleteNote"] == {"kind": "route", "detail": "DELETE /api/notes/{id}"}
    assert e["go:example.com/goapp::main.handler@31"]["detail"] == "ANY /health"       # inline handler
    assert e["go:example.com/goapp::main"]["kind"] == "main" and "server start" in e["go:example.com/goapp::main"]["detail"]
    assert e["go:example.com/goapp/internal/store::TestSave"]["kind"] == "test"


def test_calls_resolve_by_name_import_and_receiver_type(goapp):
    g, _ = goapp
    assert edge(g, "go:example.com/goapp::main", "go:example.com/goapp/internal/store::Open").via == "import"
    assert edge(g, "go:example.com/goapp::Server.createNote", "go:example.com/goapp::currentUser").via == "name"
    e = edge(g, "go:example.com/goapp/internal/store::TestSave", "go:example.com/goapp/internal/store::SQLStore.Save")
    assert e.via == "receiver-type" and e.confidence == "resolved"        # s := Open(...) -> *SQLStore
    assert edge(g, "go:example.com/goapp::main", "go:example.com/goapp::Server.getNote").via == "route-registration"


def test_interface_calls_are_possible_edges_to_every_implementer(goapp):
    g, _ = goapp
    e = edge(g, "go:example.com/goapp::Server.getNote", "go:example.com/goapp/internal/store::SQLStore.Get")
    assert e.confidence == "possible" and e.via == "interface"
    e = edge(g, "go:example.com/goapp::Server.createNote", "go:example.com/goapp::SMTPMailer.Send")
    assert e.confidence == "possible"


def test_untyped_receivers_are_counted_not_guessed(goapp):
    g, _ = goapp
    assert "row.Scan" in g.unresolved and "err.Error" in g.unresolved
    assert not any(k.startswith("json.NewEncoder") for k in g.unresolved)   # chains on foreign calls are not "unresolved"


def test_js_frontend_links_to_go_routes(goapp):
    g, _ = goapp
    e = edge(g, "js:web/src/api::getNote", "go:example.com/goapp::Server.getNote")
    assert e.via == "http-exact" and e.detail == "GET /api/notes/{}"
    assert edge(g, "js:web/src/api::deleteNote", "go:example.com/goapp::Server.deleteNote").confidence == "resolved"


def test_go_rules_find_the_planted_problems_and_rank_by_reach(goapp):
    _, sec = goapp
    by = {f["rule"]: f for f in sec["findings"]}
    assert by["LG-SQL-CONCAT"]["rank"] == "critical" and by["LG-SQL-CONCAT"]["reachable"]["kind"] == "route"
    assert by["LG-SQL-CONCAT"]["input"]["via"] == "parameter `id`"                   # not the receiver `s`
    assert by["LG-EXEC"]["rank"] == "critical" and by["LG-EXEC"]["reachable"]["entry"].endswith("createNote")
    assert by["LW-AUTH-MISSING"]["file"] == "handlers.go"                 # the DELETE route has no login check
    assert "LW-AUTH-MISSING" not in {f["rule"] for f in sec["findings"] if f["line"] == 19}   # createNote checks


def test_gin_groups_chi_routes_and_gorilla_methods(tmp_path):
    _write(tmp_path, {
        "go.mod": "module app\n",
        "main.go": '''package main

import (
	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
)

func listUsers(c *gin.Context) {}
func createUser(c *gin.Context) {}
func health(w http.ResponseWriter, r *http.Request) {}
func admin(w http.ResponseWriter, r *http.Request) {}
func login(w http.ResponseWriter, r *http.Request) {}

func main() {
	r := gin.Default()
	api := r.Group("/api/v1")
	api.GET("/users", auth(), listUsers)
	api.POST("/users", createUser)
	r.Run()

	c := chi.NewRouter()
	c.Route("/admin", func(cr chi.Router) {
		cr.Get("/", admin)
	})
	c.Get("/health", health)

	m := mux.NewRouter()
	s := m.PathPrefix("/auth").Subrouter()
	s.HandleFunc("/login", login).Methods("POST", "PUT")
}
''',
    })
    g = build_graph(tmp_path)
    e = entries(g)
    assert e["go:app::listUsers"]["detail"] == "GET /api/v1/users"       # middleware before the handler is skipped
    assert e["go:app::createUser"]["detail"] == "POST /api/v1/users"
    assert e["go:app::admin"]["detail"] == "GET /admin"
    assert e["go:app::health"]["detail"] == "GET /health"
    assert e["go:app::login"]["detail"] == "POST/PUT /auth/login"
    assert "server start" in e["go:app::main"]["detail"]


def test_outgoing_http_calls_reach_the_bridge(tmp_path):
    _write(tmp_path, {
        "go.mod": "module app\n",
        "client/c.go": '''package client

import (
	"fmt"
	"net/http"
)

const base = "https://api.example.com"

func Fetch(id string) {
	http.Get(fmt.Sprintf("%s/items/%s", base, id))
	http.NewRequest("POST", base+"/items", nil)
	http.Post("/local/path", "application/json", nil)
}
''',
    })
    g = build_graph(tmp_path)
    calls = {(c["method"], c["path"], c["host"], c["prefix_unknown"]) for c in g.meta["http_calls"]}
    assert ("GET", "/items/{}", None, True) in calls              # %s/items/%s: prefix is a format argument
    assert ("POST", "/items", "api.example.com", False) in calls  # constant folded in
    assert ("POST", "/local/path", None, False) in calls


def test_embedded_struct_methods_and_package_vars(tmp_path):
    _write(tmp_path, {
        "go.mod": "module app\n",
        "a.go": '''package main

type Base struct{}

func (b *Base) Log() {}

type Svc struct {
	Base
	n int
}

var svc = &Svc{}

func run() { svc.Log() }

func main() { run() }
''',
    })
    g = build_graph(tmp_path)
    assert edge(g, "go:app::run", "go:app::Base.Log").via == "embedded"
    assert edge(g, "go:app::main", "go:app::run").confidence == "resolved"
