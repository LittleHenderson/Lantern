"""C and C++: lantern/cpp_frontend.py (classes, namespaces, cpp-httplib/Crow/Drogon/Pistache routes) and LX-* rules."""

from pathlib import Path

import pytest

from lantern import cpp_frontend
from lantern.engine import build_graph
from lantern.graph import Graph
from lantern.readiness import assess
from lantern.security import _c_line, scan
from lantern.websec import cpp_rules

FIX = Path(__file__).parent / "fixtures"


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


@pytest.fixture(scope="module")
def notes():
    g = build_graph(FIX / "cppapp")
    sec = scan(g)
    return g, sec, assess(g, sec)


def by_rule(sec, rule):
    return [f for f in sec["findings"] if f["rule"] == rule]


def calls(g, src):
    return {(e.dst, e.via) for e in g.call_edges() if e.src == src}


def test_routes_programs_and_tests(notes):
    g, _, _ = notes
    e = {n.id: n.entry for n in g.entry_points()}
    assert "c/c++" in g.meta["languages"]
    assert e["cc:server/main.cpp::GET /api/notes/search"] == {"kind": "route", "detail": "GET /api/notes/search"}
    assert e["cc:server/main.cpp::DELETE /api/notes/:id"]["kind"] == "route"
    assert e["cc:server/main.cpp::POST /api/export"]["kind"] == "route"
    assert e["cc:main@server/main.cpp"]["kind"] == "main"                 # each program keeps its own main
    assert e["cc:main@tools/backup.c"]["kind"] == "main"
    assert e["cc:tests/test_store.cpp::TEST NoteStore.SearchReturnsJson"]["kind"] == "test"
    assert g.nodes["cc:notes.NoteStore.search"].lane == "server"


def test_calls_resolve(notes):
    g, _, _ = notes
    route = "cc:server/main.cpp::GET /api/notes/search"
    assert ("cc:notes.NoteStore.search", "receiver-type") in calls(g, route)   # a captured local of a repo class
    assert ("cc:notes.NoteStore.NoteStore", "constructor") in calls(g, "cc:main@server/main.cpp")   # T x(...)
    assert ("cc:archive_name", "name") in calls(g, "cc:server/main.cpp::POST /api/export")
    assert ("ext:sqlite3_exec", "import") in calls(g, "cc:notes.NoteStore.search")
    assert ("ext:system", "import") in calls(g, "cc:run_backup@tools/backup.c")  # a C static function
    assert ("cc:run_backup@tools/backup.c", "name") in calls(g, "cc:main@tools/backup.c")
    assert g.nodes["ext:sqlite3_exec"].lane == "data"
    # route bodies belong to the route, not to main
    assert ("cc:notes.NoteStore.search", "receiver-type") not in calls(g, "cc:main@server/main.cpp")
    hops = {x.dst for x in g.call_edges() if x.src == "js:web/src/Search::Search.run"}
    assert route in hops                                                       # the React page reaches the C++ route
    assert g.meta["languages"]["c/c++"]["unresolved"] == 0


def test_the_search_box_reaching_built_sql_is_critical(notes):
    _, sec, _ = notes
    f = by_rule(sec, "LX-SQL-BUILT")[0]
    assert f["rank"] == "critical" and f["node"] == "cc:notes.NoteStore.search" and f["ui_path"]
    shells = {f["file"]: f["rank"] for f in by_rule(sec, "LX-EXEC")}
    assert shells == {"server/main.cpp": "critical", "tools/backup.c": "critical"}
    assert "req.get_param_value" in by_rule(sec, "LX-EXEC")[0]["input"]["via"] or \
        "req.get_param_value" in by_rule(sec, "LX-EXEC")[1]["input"]["via"]
    fmt = by_rule(sec, "LX-FORMAT")[0]
    assert fmt["rank"] == "critical" and "argv[1]" in fmt["input"]["via"]
    assert any(f["rule"] == "LW-AUTH-MISSING" and "DELETE" in f["node"] for f in sec["findings"])
    assert not [f for f in sec["findings"] if f["file"].startswith("tests/")]


def test_readiness_reads_cpp(notes):
    _, _, r = notes
    assert "cpp-httplib" in r["stack"]["frameworks"]


def test_c_line_shapes_input_flow():
    assert _c_line('  std::string q = req.get_param_value("q");') == '  q = req.get_param_value("q");'
    assert _c_line("  const char *name = argv[1];") == "  name = argv[1];"
    assert _c_line('  sprintf(cmd, "cp %s", target);') == '  cmd =  "cp %s", target;'
    assert _c_line("  strcat(cmd, name);") == "  cmd +=  name;"


def test_lx_rules_true_and_false(tmp_path):
    _write(tmp_path, {"src/a.c": "\n".join([
        'sprintf(q, "SELECT * FROM t WHERE id = %s", id);',            # 1 SQL (+ not BUFFER on the same line)
        'snprintf(q, n, "SELECT * FROM t WHERE id = ?");',             # 2 safe
        'std::string s = "DELETE FROM t WHERE id = " + id;',            # 3 SQL
        'el.querySelector("#a-select").value = "x" + v;',             # 4 safe (not SQL)
        'system(cmd);',                                                # 5 shell
        'system("ls -l");',                                            # 6 safe (fixed string)
        'gets(buf);',                                                  # 7 gets (+ BUFFER-free)
        'strcpy(dst, src);',                                           # 8 buffer
        'scanf("%s", name);',                                          # 9 scanf
        'scanf("%63s", name);',                                        # 10 safe
        'printf(msg);',                                                # 11 format
        'printf("%s", msg);',                                          # 12 safe
        'SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);',             # 13 TLS
        'mode = ok ? SSL_VERIFY_PEER : SSL_VERIFY_NONE;',              # 14 safe (a choice, not a call)
        'curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);',           # 15 TLS
        'int token = rand();',                                         # 16 weak random
        'int dice = rand() % 6;',                                      # 17 safe
        'MD5(password, len, out);',                                    # 18 weak password hash
        'char *f = tmpnam(NULL);',                                     # 19 temp file
        'FILE *f = fopen(argv[1], "r");',                              # 20 path
        'store.remove(id);',                                           # 21 safe (a method)
        '// system(cmd);',                                             # 22 comment
        'const char *u = "http://api.example.com";',                   # 23 cleartext
    ]), "tests/t.c": "system(cmd);\n", "third_party/x.c": "system(cmd);\n", "include/httplib.h": "system(cmd);\n"})
    got = {(f["file"], f["line"]): f["rule"] for f in cpp_rules(tmp_path)}
    want = {1: "LX-SQL-BUILT", 3: "LX-SQL-BUILT", 5: "LX-EXEC", 7: "LX-GETS", 8: "LX-BUFFER", 9: "LX-SCANF",
            11: "LX-FORMAT", 13: "LX-TLS-OFF", 15: "LX-TLS-OFF", 16: "LX-WEAK-RANDOM", 18: "LX-WEAK-PASSWORD-HASH",
            19: "LX-TEMP-FILE", 20: "LX-PATH-INPUT", 23: "LX-CLEARTEXT-URL"}
    assert {ln: r for (f, ln), r in got.items() if f == "src/a.c"} == want
    assert {f for f, _ in got} == {"src/a.c"}                                   # tests, vendored code skipped


def test_reader_details(tmp_path):
    _write(tmp_path, {
        "src/shapes.hpp": "namespace geo {\nclass Shape {\n public:\n  virtual double area() const = 0;\n};\n"
                          "class Circle : public Shape {\n public:\n  double area() const override { return r * r; }\n"
                          "  static Circle unit() { return Circle(); }\n  double r = 1;\n};\n}\n",
        "src/app.cpp": "\n".join([
            '#include "shapes.hpp"',
            "#include <memory>",
            "namespace geo {",
            "double total(const Circle& c) { return c.area(); }",
            "}",
            "class Ctrl {",
            " public:",
            "  void list(const drogon::HttpRequestPtr& req);",
            "  void ping();",
            "  void run() { this->ping(); auto p = std::make_unique<geo::Circle>(); p->area(); geo::total(*p); }",
            "  ADD_METHOD_TO(Ctrl::list, \"/api/list\", Get);",
            "};",
            "void Ctrl::list(const drogon::HttpRequestPtr& req) { unknown.call(); }",
            "void Ctrl::ping() { geo::Circle::unit(); }",
            "int main() {",
            '  CROW_ROUTE(app, "/notes/<int>").methods("DELETE"_method)([](int id) { return std::to_string(id); });',
            '  Routes::Post(router, "/api/items", Routes::bind(&Ctrl::ping, nullptr));',
            '  app().registerHandler("/api/h", [](const HttpRequestPtr& r) { }, {Post});',
            '  httplib::Client cli("https://api.example.com");',
            '  cli.Get("/v1/status");',
            "  return 0;",
            "}"]),
    })
    g = Graph(str(tmp_path))
    stats = cpp_frontend.add_cpp(g, tmp_path)
    e = {n.id: n.entry["detail"] for n in g.nodes.values() if n.entry}
    assert e["cc:Ctrl.list"] == "GET /api/list"
    assert e["cc:Ctrl.ping"] == "POST /api/items"
    assert e["cc:src/app.cpp::DELETE /notes/<int>"] == "DELETE /notes/<int>"
    assert e["cc:src/app.cpp::POST /api/h"] == "POST /api/h"
    assert ("cc:Ctrl.ping", "this") in calls(g, "cc:Ctrl.run")
    assert ("cc:geo.Circle.area", "receiver-type") in calls(g, "cc:Ctrl.run")     # make_unique<T>
    assert ("cc:geo.total", "assoc") in calls(g, "cc:Ctrl.run")                  # ns::f()
    assert ("cc:geo.Circle.unit", "assoc") in calls(g, "cc:Ctrl.ping")           # Class::static()
    assert ("cc:geo.Circle.area", "receiver-type") in calls(g, "cc:geo.total")   # a const& parameter
    assert stats["unresolved"] == 1                                              # unknown.call()
    assert [h["path"] for h in g.meta["http_calls"]] == ["/v1/status"]
