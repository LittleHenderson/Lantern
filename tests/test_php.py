"""PHP: lantern/php_frontend.py (Laravel, Symfony, Slim, WordPress, plain pages), LH-* rules and the Composer audit."""

import json
from pathlib import Path

import pytest

from lantern import depaudit, php_frontend
from lantern.engine import build_graph
from lantern.graph import Graph
from lantern.readiness import assess
from lantern.security import _php_line, scan
from lantern.websec import php_rules

FIX = Path(__file__).parent / "fixtures"


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


@pytest.fixture(scope="module")
def notes():
    g = build_graph(FIX / "phpapp")
    sec = scan(g)
    return g, sec, assess(g, sec)


def by_rule(sec, rule):
    return [f for f in sec["findings"] if f["rule"] == rule]


def calls(g, src):
    return {(e.dst, e.via) for e in g.call_edges() if e.src == src}


def test_laravel_routes_pages_and_commands(notes):
    g, _, _ = notes
    e = {n.id: n.entry for n in g.entry_points()}
    assert "php" in g.meta["languages"]
    c = "php:App.Http.Controllers."
    # routes/api.php adds /api; a middleware group keeps the prefix
    assert e[c + "NoteController.index"] == {"kind": "route", "detail": "GET /api/notes"}
    assert e[c + "NoteController.destroy"] == {"kind": "route", "detail": "DELETE /api/notes/{id}"}
    assert e[c + "ExportController.run"] == {"kind": "route", "detail": "POST /api/export/{name}"}
    assert e["php:routes/api.php::GET /api/health"]["kind"] == "route"          # an inline closure is its own node
    # a plain page a browser opens (public/ is the web root); an included helper file is not a page
    assert e["php:public/legacy/login.php"] == {"kind": "route", "detail": "ANY /legacy/login.php"}
    assert "php:public/legacy/db.php" not in e
    assert e["php:App.Console.Commands.PruneNotes.handle"] == {"kind": "main", "detail": "command php artisan notes:prune"}
    assert e["php:Tests.Feature.NoteTest.test_health_is_ok"]["kind"] == "test"
    assert g.nodes[c + "NoteController.index"].lane == "server"


def test_calls_resolve(notes):
    g, _, _ = notes
    c = "php:App.Http.Controllers."
    assert ("php:App.Services.NoteService.remove", "receiver-type") in calls(g, c + "NoteController.destroy")
    assert ("php:App.Services.NoteService.mirror", "receiver-type") in calls(g, c + "NoteController.store")
    assert ("ext:DB.select", "import") in calls(g, c + "NoteController.index")
    assert ("ext:Client.post", "receiver-type") in calls(g, "php:App.Services.NoteService.mirror")
    assert ("php:public/legacy/db.php", "include") in calls(g, "php:public/legacy/login.php")
    # routes behind `auth:sanctum` pass through the auth middleware; open ones do not
    assert ("ext:middleware.auth", "middleware") in calls(g, c + "NoteController.store")
    assert ("ext:middleware.auth", "middleware") not in calls(g, c + "NoteController.destroy")
    # the React page's fetch calls reach the Laravel routes
    assert (c + "NoteController.index", "http-exact") in calls(g, "js:resources/js/Search::Search.search")
    assert (c + "NoteController.destroy", "http-exact") in calls(g, "js:resources/js/Search::Search.remove")
    assert not [k for k in g.unresolved if "where" in k]                    # DB::table()->where(): a library chain


def test_the_search_box_reaching_raw_sql_is_critical(notes):
    _, sec, _ = notes
    f = next(x for x in by_rule(sec, "LH-SQL-CONCAT") if x["file"].startswith("app/"))
    assert f["rank"] == "critical" and "$request->input(" in f["input"]["via"]
    assert f["ui_path"][-1] == "php:App.Http.Controllers.NoteController.index"
    assert f["headline"] == "The search button can change what your database is asked"


def test_the_legacy_page(notes):
    _, sec, _ = notes
    page = [f for f in sec["findings"] if f["file"] == "public/legacy/login.php"]
    rules = {f["rule"]: f for f in page}
    assert rules["LH-SQL-CONCAT"]["rank"] == "critical" and "$_POST" in rules["LH-SQL-CONCAT"]["input"]["via"]
    assert rules["LH-XSS-ECHO"]["input"] == {"via": "request data `$_GET`"}
    assert rules["LH-WEAK-PASSWORD-HASH"]["rank"] == "high"


def test_every_planted_problem_is_found(notes):
    _, sec, _ = notes
    rules = {f["rule"] for f in sec["findings"]}
    assert {"LH-SQL-CONCAT", "LH-EXEC", "LH-TLS-OFF", "LH-XSS-ECHO", "LH-XSS-BLADE", "LH-WEAK-PASSWORD-HASH",
            "LW-AUTH-MISSING"} <= rules
    assert by_rule(sec, "LH-EXEC")[0]["rank"] == "critical"
    assert [f["node"] for f in by_rule(sec, "LW-AUTH-MISSING")] == ["php:App.Http.Controllers.NoteController.destroy"]
    assert not [f for f in by_rule(sec, "LH-SQL-CONCAT") if f["line"] == 24]   # `?` placeholders are fine
    assert not [f for f in sec["findings"] if f["file"].startswith("tests/")]


def test_readiness_reads_php(notes):
    _, _, r = notes
    ids = {c["id"]: c for cat in r["categories"] for c in cat["checks"]}
    assert "Laravel" in r["stack"]["frameworks"]
    assert "composer.json" not in ids["deps-lock"]["evidence"]            # composer.lock is committed (package.json's is not)


def test_php_line_shapes_input_flow():
    assert _php_line('$r = mysqli_query($c, "SELECT * FROM u WHERE n = \'" . $user . "\'");') == \
        "r = mysqli_query(c, '' + user + '');"
    assert _php_line('$sql = "SELECT * FROM t WHERE id = {$id} AND x = $y";') == "sql = '' + id + y;"
    assert _php_line("$n = $this->notes->find($id);") == "n = this.notes.find(id);"
    assert _php_line("$s .= 'x';") == "s += '';"


def test_lh_rules_true_and_false(tmp_path):
    code = r'''<?php
$a = $db->query("SELECT * FROM t WHERE id = $id");
$b = mysqli_query($c, 'SELECT * FROM t WHERE id = ' . $id);
$sql = "DELETE FROM t WHERE id = {$id}";
$ok1 = $db->prepare('SELECT * FROM t WHERE id = ?');
$ok2 = $wpdb->get_results($wpdb->prepare("SELECT * FROM t WHERE id = %d", $id));
$c = Note::whereRaw("owner = $owner")->get();
$ok3 = Note::whereRaw('owner = ?', [$owner])->get();
system('convert ' . $file);
$ok4 = system('uptime');
eval($code);
include $_GET['page'] . '.php';
$d = unserialize($_COOKIE['cart']);
$ok5 = unserialize($raw, ['allowed_classes' => false]);
echo $_GET['q'];
echo htmlspecialchars($_GET['q']);
$h = md5($password);
$ok6 = md5($file_contents);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
extract($_POST);
header('Access-Control-Allow-Origin: *');
ini_set('display_errors', '1');
move_uploaded_file($_FILES['f']['tmp_name'], 'uploads/' . $_FILES['f']['name']);
$u = 'http://api.example.com/x';
$ok7 = 'http://localhost/x';
// $x = $db->query("SELECT * FROM t WHERE id = $id");
'''
    _write(tmp_path, {"web/a.php": code, "resources/views/x.blade.php": "{!! $html !!}\n{!! csrf_field() !!}\n{{ $safe }}\n",
                      "tests/ATest.php": "<?php eval($x);\n"})
    found = {(f["rule"], f["line"]) for f in php_rules(tmp_path)}
    want = {("LH-SQL-CONCAT", 2), ("LH-SQL-CONCAT", 3), ("LH-SQL-CONCAT", 4), ("LH-SQL-RAW", 7), ("LH-EXEC", 9),
            ("LH-EVAL", 11), ("LH-INCLUDE-INPUT", 12), ("LH-UNSERIALIZE", 13), ("LH-XSS-ECHO", 15),
            ("LH-WEAK-PASSWORD-HASH", 17), ("LH-TLS-OFF", 19), ("LH-EXTRACT", 20), ("LH-CORS-ALL", 21),
            ("LH-DEBUG", 22), ("LH-UPLOAD-NAME", 23), ("LH-CLEARTEXT-URL", 24), ("LH-XSS-BLADE", 1)}
    assert want <= found, want - found
    for line in (5, 6, 8, 10, 14, 16, 18, 25, 26):
        assert not [r for r, ln in found if ln == line and r != "LH-XSS-BLADE"], (line, found)
    assert ("LH-XSS-BLADE", 2) not in found
    assert not [f for f in php_rules(tmp_path) if f["file"].startswith("tests/")]


def test_symfony_slim_and_wordpress(tmp_path):
    _write(tmp_path, {
        "src/Controller/NoteController.php": '''<?php
namespace App\\Controller;
use Symfony\\Component\\Routing\\Attribute\\Route;
#[Route('/notes')]
class NoteController
{
    #[Route('/{id}', methods: ['GET'])]
    public function show(string $id) { return $this->load($id); }
    /**
     * @Route("/{id}", methods={"DELETE"})
     */
    public function remove(string $id) {}
    private function load(string $id) { return $id; }
}
''',
        "app/index.php": '''<?php
use App\\Handlers\\Ping;
$app = AppFactory::create();
$app->group('/api', function ($group) {
    $group->get('/ping', Ping::class . ':handle');
    $group->post('/echo', function ($request, $response) { return $response; });
});
$app->run();
''',
        "app/Handlers/Ping.php": "<?php\nnamespace App\\Handlers;\nclass Ping { public function handle($req, $res) { return $res; } }\n",
        "wp-content/plugins/share/share.php": '''<?php
/* Plugin Name: Share */
add_action('wp_ajax_nopriv_share_note', 'share_note');
add_action('wp_ajax_save_note', 'save_note');
add_action('rest_api_init', function () {
    register_rest_route('share/v1', '/notes/(?P<id>\\d+)', ['methods' => 'GET', 'callback' => 'share_get']);
});
function share_note() { $d = unserialize($_POST['data']); }
function save_note() {}
function share_get($req) { return $req['id']; }
''',
    })
    g = Graph(str(tmp_path))
    stats = php_frontend.add_php(g, tmp_path)
    e = {n.id: n.entry for n in g.nodes.values() if n.entry}
    assert e["php:App.Controller.NoteController.show"] == {"kind": "route", "detail": "GET /notes/{id}"}
    assert e["php:App.Controller.NoteController.remove"] == {"kind": "route", "detail": "DELETE /notes/{id}"}
    assert ("php:App.Controller.NoteController.load", "this") in calls(g, "php:App.Controller.NoteController.show")
    assert e["php:App.Handlers.Ping.handle"] == {"kind": "route", "detail": "GET /api/ping"}
    assert e["php:app/index.php::POST /api/echo"]["kind"] == "route"
    assert "php:app/index.php" not in e                                      # a router file, not a page
    assert e["php:share_note"]["detail"] == "POST /wp-admin/admin-ajax.php?action=share_note (anyone can call it)"
    assert e["php:save_note"]["detail"].endswith("(signed-in users)")
    assert ("ext:middleware.auth", "middleware") in calls(g, "php:save_note")
    assert e["php:share_get"]["detail"] == "GET /wp-json/share/v1/notes/{id}"
    assert stats["routes"] >= 6


def test_reader_details(tmp_path):
    _write(tmp_path, {"lib/Shapes.php": '''<?php
namespace Geo;
interface Shape { public function area(): float; }
abstract class Base implements Shape { public function describe() { return static::name() . $this->area(); } }
class Circle extends Base { public function area(): float { return 3.14; } public static function name() { return "c"; } }
trait Logs { public function log($m) { error_log($m); } }
class Square implements Shape {
    use Logs;
    public function area(): float { $this->log("a"); return 1.0; }
}
class Report {
    public function __construct(private Shape $shape, private ?Printer $printer = null) {}
    public function make(): Report { $this->shape->area(); $p = new Printer(); $p->out(); return $this; }
    public function chain() { $this->make()->make(); array_map('helper', [1]); }
}
class Printer { public function out() {} }
function helper($x) { return $x; }
'''})
    g = Graph(str(tmp_path))
    php_frontend.add_php(g, tmp_path)
    make = calls(g, "php:Geo.Report.make")
    assert {("php:Geo.Circle.area", "interface"), ("php:Geo.Square.area", "interface"),
            ("php:Geo.Printer.out", "receiver-type")} <= make
    assert ("php:Geo.Logs.log", "this") in calls(g, "php:Geo.Square.area")          # a trait's method
    chain = calls(g, "php:Geo.Report.chain")
    assert ("php:Geo.Report.make", "receiver-type") in chain and ("php:Geo.helper", "callback") in chain
    assert ("ext:error_log", "import") in calls(g, "php:Geo.Logs.log")


def test_composer_lock_pins(tmp_path):
    _write(tmp_path, {
        "composer.json": json.dumps({"require": {"laravel/framework": "^10.0"}}, indent=2),
        "composer.lock": json.dumps({"packages": [{"name": "laravel/framework", "version": "v10.0.0"},
                                                  {"name": "guzzlehttp/psr7", "version": "2.0.0"},
                                                  {"name": "weird", "version": "dev-main"}],
                                     "packages-dev": [{"name": "phpunit/phpunit", "version": "10.0.0"}]}, indent=2),
    })
    pins, files = depaudit.composer_pins(tmp_path)
    assert files == ["composer.lock"]
    assert pins["laravel/framework"] == ("10.0.0", "composer.json", 3)           # where composer.json asks for it
    assert pins["guzzlehttp/psr7"][1] == "composer.lock"                          # pulled in by another library
    assert "phpunit/phpunit" not in pins and "weird" not in pins
    out, info = depaudit.run_composer_audit(tmp_path, no_network=True)
    assert out == [] and info["status"] == "skipped: offline"
    assert depaudit.run_composer_audit(tmp_path / "nothing")[1]["status"] == "skipped: no composer.lock"


def test_composer_audit_asks_osv(tmp_path, monkeypatch):
    _write(tmp_path, {"composer.lock": json.dumps({"packages": [{"name": "guzzlehttp/psr7", "version": "2.0.0"}]})})
    asked = {}

    def post(path, body, timeout=60):
        asked["body"] = body
        return {"results": [{"vulns": [{"id": "GHSA-test"}]}]}

    monkeypatch.setattr(depaudit, "_osv_post", post)
    monkeypatch.setattr(depaudit, "_osv_get", lambda path, timeout=30: {
        "summary": "Header injection", "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"name": "guzzlehttp/psr7"}, "ranges": [{"events": [{"fixed": "2.4.5"}]}]}]})
    out, info = depaudit.run_composer_audit(tmp_path, no_network=False)
    assert asked["body"]["queries"] == [{"package": {"name": "guzzlehttp/psr7", "ecosystem": "Packagist"},
                                         "version": "2.0.0"}]
    assert info["status"] == "ok" and out[0]["tool"] == "composer-audit" and out[0]["tool_severity"] == "HIGH"
    assert "2.4.5" in out[0]["more_info"]
