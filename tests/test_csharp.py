"""C#: lantern/csharp_frontend.py (ASP.NET controllers, minimal APIs, HttpClient calls) and lantern/dotnet.py
(.NET MAUI screens and links, LC-* checks)."""

from pathlib import Path

import pytest

from lantern import csharp_frontend, dotnet
from lantern.engine import build_graph
from lantern.graph import Graph
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
    g = build_graph(FIX / "csharpapp")
    sec = scan(g)
    return g, sec, assess(g, sec)


def by_rule(sec, rule):
    return [f for f in sec["findings"] if f["rule"] == rule]


def calls(g, src):
    return {(e.dst, e.via) for e in g.call_edges() if e.src == src}


def test_routes_screens_and_links(notes):
    g, _, _ = notes
    e = {n.id: n.entry for n in g.entry_points()}
    assert g.meta["platform"] == "maui" and g.meta["maui"]["roots"] == ["NotesApp/"]
    assert "c#" in g.meta["languages"]
    # controller: [Route("api/[controller]")] + [HttpPost("{name}")]
    assert e["cs:NotesApi.Controllers.ExportController.Export"] == {"kind": "route", "detail": "POST /api/Export/{name}"}
    # minimal APIs: an inline lambda is its own node; a named handler (Class.Method) is marked in place
    assert e["cs:NotesApi/Program.cs::GET /api/notes/search"]["kind"] == "route"
    assert e["cs:NotesApi.NoteEndpoints.Delete"] == {"kind": "route", "detail": "DELETE /api/notes/{id}"}
    assert e["cs:NotesApi/Program.cs"]["kind"] == "main"                      # top-level statements
    assert e["cs:NotesApi.Tests.NoteStoreTests.FindsNothingWithoutADatabase"]["kind"] == "test"
    # MAUI: page constructor and event handlers; a view model's [RelayCommand] belongs to its page
    assert e["cs:NotesApp.MainPage.OnSearchClicked"] == {"kind": "page", "detail": "MainPage screen · OnSearchClicked"}
    assert e["cs:NotesApp.ViewModels.MainViewModel.SignIn"] == {"kind": "page", "detail": "MainPage screen · SignIn"}
    assert "cs:NotesApp.ViewModels.MainViewModel.Search" not in e            # a plain method, not a command
    assert e["cs:NotesApp.App.OnAppLinkRequestReceived"]["detail"].startswith("LINK App handles links")
    assert e["cs:NotesApp.Services.NoteRepository.OpenShared"]["detail"].startswith("LINK NoteRepository handles links")
    assert g.nodes["cs:NotesApp.MainPage.OnSearchClicked"].lane == "browser"
    assert g.nodes["cs:NotesApi.NoteStore.Search"].lane == "server"


def test_calls_resolve(notes):
    g, _, _ = notes
    assert ("cs:NotesApi.NoteStore.Search", "receiver-type") in calls(g, "cs:NotesApi/Program.cs::GET /api/notes/search")
    assert ("cs:NotesApp.ViewModels.MainViewModel.Search", "receiver-type") in calls(g, "cs:NotesApp.MainPage.OnSearchClicked")
    assert ("cs:NotesApi.Controllers.ExportController.Checksum", "name") in calls(g, "cs:NotesApi.Controllers.ExportController.Export")
    assert ("cs:NotesApp.AppShell.AppShell", "constructor") in calls(g, "cs:NotesApp.App.App")
    # the phone's HttpClient calls (relative to BaseAddress) reach the server's routes
    assert ("cs:NotesApi/Program.cs::GET /api/notes/search", "http-unknown-prefix") in calls(g, "cs:NotesApp.Services.ApiClient.Search")
    assert ("cs:NotesApi.NoteEndpoints.Delete", "http-unknown-prefix") in calls(g, "cs:NotesApp.Services.ApiClient.Remove")


def test_the_phone_search_reaching_server_sql_is_critical(notes):
    _, sec, _ = notes
    f = next(x for x in by_rule(sec, "LC-SQL-CONCAT") if x["file"] == "NotesApi/NoteStore.cs")
    assert f["rank"] == "critical" and f["input"] == {"via": "parameter `q`"}
    # phone screen → view model → HttpClient → the server's route → the query
    assert f["ui_path"] == ["cs:NotesApp.MainPage.OnSearchClicked", "cs:NotesApp.ViewModels.MainViewModel.Search",
                            "cs:NotesApp.Services.ApiClient.Search", "cs:NotesApi/Program.cs::GET /api/notes/search",
                            "cs:NotesApi.NoteStore.Search"]
    assert f["headline"] == "The MainPage screen can change what your database is asked"


def test_a_link_reaching_a_local_query_is_critical(notes):
    _, sec, _ = notes
    f = next(x for x in by_rule(sec, "LC-SQL-CONCAT") if x["file"] == "NotesApp/Services/NoteRepository.cs")
    assert f["rank"] == "critical" and "uri.Query" in f["input"]["via"]
    assert f["reachable"]["entry"] == "cs:NotesApp.Services.NoteRepository.OpenShared"


def test_every_planted_problem_is_found(notes):
    _, sec, _ = notes
    rules = {f["rule"] for f in sec["findings"]}
    assert {"LC-SQL-CONCAT", "LC-EXEC-CONCAT", "LC-WEAK-HASH", "LC-CORS-ALL", "LC-TLS-OFF", "LC-PREFS-SECRET",
            "LC-LOG-SENSITIVE", "LW-AUTH-MISSING"} <= rules
    assert by_rule(sec, "LC-EXEC-CONCAT")[0]["rank"] == "critical"
    assert by_rule(sec, "LC-PREFS-SECRET")[0]["platform"] == "maui"
    # the parameterised queries (@id) are not flagged
    assert not [f for f in by_rule(sec, "LC-SQL-CONCAT") if f["line"] in (23, 32)]
    # test code is not checked
    assert not [f for f in sec["findings"] if "Tests/" in f["file"]]


def test_maui_readiness_shape(notes):
    _, _, r = notes
    assert r["shape"] == ".NET MAUI app"
    ids = {c["id"]: c for cat in r["categories"] for c in cat["checks"]}
    assert ids["obs-crash"]["status"] == "fail"
    assert ids["pkg-lock"]["status"] == "fail" and "packages.lock.json" in ids["pkg-lock"]["fix"]
    assert ids["res-timeout"]["status"] == "fail" and "HttpClient.Timeout" in ids["res-timeout"]["fix"]


def test_lc_rules_true_and_false(tmp_path):
    code = '''
namespace A;
public class R {
    void F(string id, string q) {
        var a = new SqlCommand("SELECT * FROM t WHERE id = " + id, db);
        var b = conn.Query<Note>($"SELECT * FROM t WHERE q = '{q}'");
        db.Database.ExecuteSqlRaw($"DELETE FROM t WHERE id = {id}");
        var ok1 = db.Notes.FromSql($"SELECT * FROM t WHERE id = {id}");
        var ok2 = new SqlCommand("SELECT * FROM t WHERE id = @id", db);
        Process.Start("tar", $"-xf {q}");
        var s = JsonConvert.DeserializeObject(q, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All });
        var h = SHA1.Create();
        var ok3 = SHA256.HashData(bytes);
        builder.WithOrigins("*");
        var u = "http://api.example.com/x";
        var ok4 = "http://localhost:5000/x";
    }
}
'''
    _write(tmp_path, {"src/R.cs": code, "Views/Home.cshtml": "<p>@Html.Raw(Model.Bio)</p>\n<p>@Html.Raw(\"<br/>\")</p>\n",
                      "appsettings.json": '{"ConnectionStrings": {"Db": "Server=db;Database=n;User Id=sa;Password=' +
                                          "hunter" + '2;"}}\n'})
    found = {(f["rule"], f["line"]) for f in dotnet.code_findings(
        [(p.relative_to(tmp_path).as_posix(), p.read_text(encoding="utf-8")) for p in tmp_path.rglob("*") if p.is_file()], [])}
    assert {("LC-SQL-CONCAT", 5), ("LC-SQL-CONCAT", 6), ("LC-SQL-CONCAT", 7), ("LC-EXEC-CONCAT", 10),
            ("LC-DESERIALIZE", 11), ("LC-WEAK-HASH", 12), ("LC-CORS-ALL", 14), ("LC-CLEARTEXT-URL", 15),
            ("LC-HTML-RAW", 1), ("LC-CONN-PASSWORD", 1)} <= found
    for line in (8, 9, 13, 16):
        assert not [r for r, ln in found if ln == line and r.startswith("LC-") and r != "LC-HTML-RAW"], line
    assert ("LC-HTML-RAW", 2) not in found
    assert not [r for r, _ in found if r in ("LC-PREFS-SECRET", "LC-LOG-SENSITIVE")]   # phone rules: no phone root


def test_reader_details(tmp_path):
    _write(tmp_path, {
        "Api/Api.csproj": "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>",
        "Api/Shapes.cs": '''
using System;
namespace Shapes
{
    public interface IShape { double Area(); }
    public abstract class Base : IShape { public abstract double Area(); public void Print() => Console.WriteLine(Area()); }
    public class Circle : Base { public override double Area() => 3.14; }
    public partial class Square : IShape { public double Area() => Side * Side; }
    public static class Util {
        public const string Root = "/api/v2";
        public static void Run(IShape s) { s.Area(); Helper(); }
        static void Helper() { }
    }
}
''',
        "Api/Square.Part.cs": '''
namespace Shapes
{
    public partial class Square { public double Side { get; set; } public void Grow() { Side += 1; Util.Run(this); } }
}
''',
        "Api/Client.cs": '''
using System.Net.Http;
namespace Shapes
{
    public class Client
    {
        private readonly HttpClient http = new HttpClient();
        public async void Load(string id)
        {
            await http.GetAsync(Util.Root + "/shapes/" + id);
            await http.PostAsJsonAsync($"{Util.Root}/shapes", id);
            var req = new HttpRequestMessage(HttpMethod.Put, "/api/v2/shapes/" + id);
            http.GetStringAsync("x").Result.Trim();
        }
    }
}
'''})
    g = Graph(str(tmp_path))
    stats = csharp_frontend.add_csharp(g, tmp_path)
    assert stats["files"] == 3 and stats["http_calls"] == 4
    run = calls(g, "cs:Shapes.Util.Run")
    # an interface receiver: one possible edge per class that implements Area
    assert {("cs:Shapes.Circle.Area", "interface"), ("cs:Shapes.Square.Area", "interface"),
            ("cs:Shapes.Util.Helper", "name")} <= run
    # the two halves of a partial class are one class
    assert ("cs:Shapes.Util.Run", "assoc") in calls(g, "cs:Shapes.Square.Grow")
    assert g.nodes["cs:Shapes.Square.Grow"].parent == "cs:Shapes.Square"
    http = {(c["method"], c["path"]) for c in g.meta["http_calls"]}
    assert http == {("GET", "/api/v2/shapes/{}"), ("POST", "/api/v2/shapes"), ("PUT", "/api/v2/shapes/{}"), ("GET", "/x")}
    assert not [k for k in g.unresolved if "Trim" in k]                     # a chain on a library call: not counted
    assert dotnet.find_projects(tmp_path) == []                              # a web project is not a phone app


def test_xamarin_and_target_framework_projects(tmp_path):
    _write(tmp_path, {
        "A/A.csproj": "<Project><PropertyGroup><TargetFramework>net8.0-android</TargetFramework></PropertyGroup></Project>",
        "B/B.csproj": '<Project><ItemGroup><PackageReference Include="Xamarin.Forms" Version="5.0.0" /></ItemGroup></Project>',
        "C/C.csproj": "<Project><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>",
        "A/bin/Debug/X.csproj": "<Project><UseMaui>true</UseMaui></Project>",
    })
    assert dotnet.find_projects(tmp_path) == ["A/", "B/"]
