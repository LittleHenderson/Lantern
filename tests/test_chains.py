"""A chain of calls on one line does not keep the check busy (2026-11-13).

`a.b().c().d()` is read from the outside in: to say what `d` is called on, a reader asks what `c()` gives, and for
that what `b()` gives. Two readers asked more than once per link:

* C#: where a link's type is not known (every link after a library call: `sb.Append(a).Append(b)`, a LINQ query, a
  builder), the reader asked for the link before it twice, so each link more doubled the time. Twenty links took
  5 seconds and thirty were still being read after 150: chains that real C# code holds.
* Ruby: each link walked the rest of the chain again, and that for every link it was asked about, so twice the
  links took eight times the time (800 links: 26 seconds).

Both now read each link once. A third reader was slow in another way and is read each link once since the same day:

* PHP: to say what a call is made on, the reader asked for the call below it, and that one for the one below it,
  anew for every call of the chain and again for every call it was asked about: twice the links took eight times
  the time (400 links 2.12 seconds; forty functions with a chain of 300 links each 37.6 seconds, now 0.85).

Three kinds of test:

* the check ends, in a child process with a time limit (on the code before, the C# ones run into the limit and the
  Ruby one does not end in time or stops with an error);
* every reader is given a chain of sixty calls, so a reader that starts to ask twice is seen;
* nothing else changed: short chains of every shape the three readers tell apart (the project's own type, a library
  call, a receiver nobody knows, an awaited or bracketed link) give the links and the count of unknown calls they
  gave, written down from the code before."""

import json
import subprocess
import sys

import pytest

from lantern.engine import build_graph

LIMIT = 60


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _analyze(src, out, limit=LIMIT):
    """`lantern analyze` in a child process: its result, or None when it was still running at the limit."""
    try:
        return subprocess.run([sys.executable, "-m", "lantern.cli", "analyze", str(src), "--offline", "--out", str(out)],
                              capture_output=True, text=True, encoding="utf-8", timeout=limit)
    except subprocess.TimeoutExpired:
        return None


def seen(g):
    """What the map says of each function's calls, and what it could not place."""
    edges = {}
    for e in g.call_edges():
        edges.setdefault(e.src, []).append(f"{e.dst} ({e.via})")
    return {"calls": {k: sorted(v) for k, v in sorted(edges.items())}, "unresolved": dict(sorted(g.unresolved.items()))}


# ---------------------------------------------------------------- the check ends

def _links(n, link):
    return "".join(link(i) for i in range(n))


CS_LONG = {
    # what a real file holds: text put together piece by piece, forty pieces
    "Report.cs": lambda n: (
        "using System.Text;\nnamespace App;\n\npublic class Report\n{\n    public string Build(string[] rows)\n    {\n"
        "        var sb = new StringBuilder();\n        sb" + _links(n, lambda i: f'.Append("row {i}: ").Append(rows[{i}])')
        + ";\n        return sb.ToString();\n    }\n}\n"),
    # a query: every link is a library call on what the one before gave
    "Query.cs": lambda n: (
        "using System.Linq;\nnamespace App;\n\npublic class Query\n{\n    public object Run(System.Collections.Generic.List<int> xs)\n"
        "    {\n        return xs" + _links(n, lambda i: f".Where(x => x > {i}).Select(x => x + {i})") + ".ToList();\n    }\n}\n"),
    # a receiver nobody knows
    "Unknown.cs": lambda n: (
        "namespace App;\n\npublic class Unknown\n{\n    public object Run(dynamic x)\n    {\n        return x"
        + _links(n, lambda i: ".Next()") + ";\n    }\n}\n"),
    # the project's own type all the way: each link's type is known
    "Own.cs": lambda n: (
        "namespace App;\n\npublic class Step\n{\n    public Step Next() { return this; }\n}\n\npublic class Own\n{\n"
        "    public Step Run(Step s)\n    {\n        return s" + _links(n, lambda i: ".Next()") + ";\n    }\n}\n"),
}


@pytest.mark.parametrize("name", sorted(CS_LONG))
def test_a_long_chain_in_csharp_is_read(name, tmp_path):
    links = 20 if name in ("Report.cs", "Query.cs") else 40           # two calls a link in the first two: forty calls
    _write(tmp_path / "src", {name: CS_LONG[name](links)})
    r = _analyze(tmp_path / "src", tmp_path / "out")
    assert r is not None, f"{name}: a chain of 40 calls was still being read after {LIMIT} seconds"
    assert r.returncode == 0, (r.returncode, r.stdout[-400:], r.stderr[-400:])
    graph = json.loads((tmp_path / "out" / "graph.json").read_text(encoding="utf-8"))
    ids = {n["id"] for n in graph["nodes"]}
    assert f"cs:App.{name[:-3]}.{'Build' if name == 'Report.cs' else 'Run'}" in ids
    if name == "Own.cs":                                                # and the chain is still followed
        assert any(e["src"] == "cs:App.Own.Run" and e["dst"] == "cs:App.Step.Next" for e in graph["edges"])


def test_a_long_chain_in_ruby_is_read(tmp_path):
    # 900 links: the code before took about eight times as long for twice the links (800: 26 seconds)
    _write(tmp_path / "src", {"report.rb": "def build(x)\n  x" + ".step" * 900 + "\nend\n"})
    r = _analyze(tmp_path / "src", tmp_path / "out", limit=20)
    assert r is not None, "a chain of 900 calls was still being read after 20 seconds"
    assert r.returncode == 0, (r.returncode, r.stdout[-400:], r.stderr[-400:])


def test_long_chains_in_php_are_read(tmp_path):
    # forty functions, each with one chain of 300 calls: the code before took 37.6 seconds for the PHP reader alone
    text = "<?php\n" + "".join(f"function f{i}($x) {{\n    $y = $x" + "->g()" * 300 + ";\n    return $x;\n}}\n" for i in range(40))
    _write(tmp_path / "src", {"report.php": text})
    r = _analyze(tmp_path / "src", tmp_path / "out", limit=20)
    assert r is not None, "forty chains of 300 calls were still being read after 20 seconds"
    assert r.returncode == 0, (r.returncode, r.stdout[-400:], r.stderr[-400:])
    graph = json.loads((tmp_path / "out" / "graph.json").read_text(encoding="utf-8"))
    assert {f"php:f{i}" for i in range(40)} <= {n["id"] for n in graph["nodes"]}
    assert "too_deep" not in graph["meta"], graph["meta"]["too_deep"]      # read, every call of it, not left out


def _chain(n, link=".f()"):
    return "x" + link * n


EVERY_READER = {
    "Python": ("a.py", "def run(x):\n    return {c}\n", ".f()"),
    "JavaScript": ("a.js", "function run(x) {{\n  return {c};\n}}\nmodule.exports = run;\n", ".f()"),
    "TypeScript": ("a.ts", "export function run(x: any) {{\n  return {c};\n}}\n", ".f()"),
    "Go": ("a.go", "package main\n\nfunc run(x T) {{\n\t_ = {c}\n}}\n", ".F()"),
    "Rust": ("src/main.rs", "fn run(x: T) {{\n    let _ = {c};\n}}\nfn main() {{}}\n", ".f()"),
    "Java": ("A.java", "class A {{\n  void run(T x) {{\n    Object o = {c};\n  }}\n}}\n", ".f()"),
    "Kotlin": ("A.kt", "fun run(x: T) {{\n    val o = {c}\n}}\n", ".f()"),
    "Swift": ("A.swift", "func run(x: T) {{\n    let o = {c}\n}}\n", ".f()"),
    "Dart": ("a.dart", "void run(T x) {{\n  var o = {c};\n}}\n", ".f()"),
    "C#": ("A.cs", "class A {{\n  void Run(T x) {{\n    var o = {c};\n  }}\n}}\n", ".F()"),
    "PHP": ("a.php", "<?php\nfunction run($x) {{\n  return ${c};\n}}\n", "->f()"),
    "Ruby": ("a.rb", "def run(x)\n  {c}\nend\n", ".f"),
    "C++": ("a.cpp", "int run(T x) {{\n  auto o = {c};\n  return 0;\n}}\n", ".f()"),
}


@pytest.mark.parametrize("reader", sorted(EVERY_READER))
def test_every_reader_ends_on_a_chain_of_sixty_calls(reader, tmp_path):
    name, text, link = EVERY_READER[reader]
    files = {name: text.format(c=_chain(60, link))}
    if reader == "Rust":
        files["Cargo.toml"] = '[package]\nname = "a"\nversion = "0.1.0"\n'
    _write(tmp_path / "src", files)
    r = _analyze(tmp_path / "src", tmp_path / "out")
    assert r is not None, f"{reader}: a chain of 60 calls was still being read after {LIMIT} seconds"
    assert r.returncode == 0, (reader, r.returncode, r.stdout[-400:], r.stderr[-400:])


# ---------------------------------------------------------------- nothing else changed

CS_SHAPES = {
    "Model.cs": '''
namespace App
{
    public class Note
    {
        public string Title { get; set; }
        public Note Next() { return this; }
        public string Name() { return Title; }
    }

    public class Repo
    {
        public Note Find(int id) { return new Note(); }
        public Repo Where(string q) { return this; }
        public Repo Order() { return this; }
        public System.Threading.Tasks.Task<Note> Load(int id) { return null; }
    }

    public interface IStore
    {
        Note Get(int id);
    }

    public class MemStore : IStore
    {
        public Note Get(int id) { return new Note(); }
    }
}
''',
    "Svc.cs": '''
using System.Linq;
using System.Text;
namespace App
{
    public class Svc
    {
        private readonly Repo _repo = new Repo();
        private readonly IStore _store;

        // the project's own types all the way: each link is found through what the one before returns
        public string OwnChain(int id) { return _repo.Find(id).Next().Next().Name(); }
        public Repo OwnBuilder(string q) { return _repo.Where(q).Order().Where(q).Order(); }
        // a library call ends what Lantern knows: the links after it are not counted
        public string LibraryTail(int id) { return _repo.Find(id).Name().Trim().ToUpper().Substring(1); }
        public string LibraryChain() { var sb = new StringBuilder(); return sb.Append("a").Append("b").Append("c").ToString(); }
        public object LibraryStatic(string s) { return System.IO.Path.GetFileName(s).Trim().ToLower(); }
        public object Query(System.Collections.Generic.List<Note> xs) { return xs.Where(n => n.Name() != null).Select(n => n.Next()).ToList(); }
        // a receiver nobody knows: counted as not placed, at every link
        public object Unknown(dynamic x) { return x.First().Second().Third(); }
        // bracketed and awaited links
        public string Bracketed(int id) { return (_repo.Find(id)).Next().Name(); }
        public async System.Threading.Tasks.Task<string> Awaited(int id) { return (await _repo.Load(id)).Name(); }
        // an interface in the middle
        public string ThroughInterface(int id) { return _store.Get(id).Next().Name(); }
        // a new object, then a chain on it
        public string OnNew() { return new Repo().Find(1).Name(); }
        // a chain as an argument of a chain
        public string Nested(int id) { return _repo.Where(_repo.Find(id).Name()).Order().Find(id).Name(); }
        public string OnThis() { return this.Self().Self().OwnChain(1); }
        public Svc Self() { return this; }
    }
}
''',
}

# written down from the code before (2026-11-13, main c43acce); both readers must still say exactly this
CS_SEEN = {'calls': {'cs:App.Svc.Awaited': ['cs:App.Note.Name (receiver-type)', 'cs:App.Repo.Load (receiver-type)'],
           'cs:App.Svc.Bracketed': ['cs:App.Note.Name (receiver-type)',
                                    'cs:App.Note.Next (receiver-type)',
                                    'cs:App.Repo.Find (receiver-type)'],
           'cs:App.Svc.LibraryChain': ['ext:StringBuilder.Append (receiver-type)'],
           'cs:App.Svc.LibraryTail': ['cs:App.Note.Name (receiver-type)', 'cs:App.Repo.Find (receiver-type)'],
           'cs:App.Svc.Nested': ['cs:App.Note.Name (receiver-type)',
                                 'cs:App.Repo.Find (receiver-type)',
                                 'cs:App.Repo.Order (receiver-type)',
                                 'cs:App.Repo.Where (receiver-type)'],
           'cs:App.Svc.OnNew': ['cs:App.Note.Name (receiver-type)', 'cs:App.Repo.Find (receiver-type)'],
           'cs:App.Svc.OnThis': ['cs:App.Svc.OwnChain (receiver-type)', 'cs:App.Svc.Self (receiver-type)'],
           'cs:App.Svc.OwnBuilder': ['cs:App.Repo.Order (receiver-type)', 'cs:App.Repo.Where (receiver-type)'],
           'cs:App.Svc.OwnChain': ['cs:App.Note.Name (receiver-type)',
                                   'cs:App.Note.Next (receiver-type)',
                                   'cs:App.Repo.Find (receiver-type)'],
           'cs:App.Svc.Query': ['ext:List.Where (receiver-type)'],
           'cs:App.Svc.ThroughInterface': ['cs:App.MemStore.Get (interface)'],
           'cs:App.Svc.Unknown': ['ext:dynamic.First (receiver-type)']},
 'unresolved': {'cs:App.Svc.LibraryStatic: System.IO.Path.GetFileName': 1,
                'cs:App.Svc.LibraryStatic: System.IO.Path.GetFileName(s).Trim': 1,
                'cs:App.Svc.LibraryStatic: System.IO.Path.GetFileName(s).Trim().ToLower': 1,
                'cs:App.Svc.LibraryTail: _repo.Find(id).Name().Trim': 1,
                'cs:App.Svc.LibraryTail: _repo.Find(id).Name().Trim().ToUpper': 1,
                'cs:App.Svc.LibraryTail: _repo.Find(id).Name().Trim().ToUpper().Substring': 1,
                'cs:App.Svc.Query: n.Name': 1,
                'cs:App.Svc.Query: n.Next': 1,
                'cs:App.Svc.ThroughInterface: _store.Get(id).Next': 1,
                'cs:App.Svc.ThroughInterface: _store.Get(id).Next().Name': 1}}

RB_SHAPES = {
    "model.rb": '''
class Note
  def nxt
    self
  end

  def name
    "n"
  end
end

class Repo
  def find(id)
    Note.new
  end

  def where(q)
    self
  end

  def self.default
    Repo.new
  end
end
''',
    "svc.rb": '''
require "net/http"

class Svc
  def initialize
    @repo = Repo.new
  end

  def own_chain(id)
    @repo.find(id).nxt.nxt.name
  end

  def own_builder(q)
    @repo.where(q).where(q).find(1)
  end

  def library_tail(id)
    @repo.find(id).to_s.strip.upcase
  end

  def library_chain(url)
    Net::HTTP.get(url).body.strip.downcase
  end

  def unknown(x)
    x.first.second.third
  end

  def on_new
    Repo.new.find(1).name
  end

  def class_method
    Repo.default.find(1).name
  end

  def nested(id)
    @repo.where(@repo.find(id).name).find(id)
  end

  def with_block(xs)
    xs.map { |n| n.name }.compact.uniq.first
  end

  def local(id)
    r = Repo.new
    r.find(id).nxt.name
  end

  def on_self
    self.me.me.own_chain(1)
  end

  def me
    self
  end

  def bracketed(id)
    (@repo.find(id)).nxt.name
  end
end
''',
}

RB_SEEN = {'calls': {'rb:Svc.bracketed': ['rb:Repo.find (receiver-type)'],
           'rb:Svc.class_method': ['rb:Repo.default (assoc)'],
           'rb:Svc.library_chain': ['ext:Net.HTTP.get (import)'],
           'rb:Svc.library_tail': ['rb:Repo.find (receiver-type)'],
           'rb:Svc.local': ['rb:Repo.find (receiver-type)'],
           'rb:Svc.nested': ['rb:Repo.find (receiver-type)', 'rb:Repo.where (receiver-type)'],
           'rb:Svc.on_new': ['rb:Repo.find (receiver-type)'],
           'rb:Svc.on_self': ['rb:Svc.me (this)'],
           'rb:Svc.own_builder': ['rb:Repo.where (receiver-type)'],
           'rb:Svc.own_chain': ['rb:Repo.find (receiver-type)']},
 'unresolved': {'rb:Svc.class_method: Repo.default.find': 1,
                'rb:Svc.class_method: Repo.default.find(1).name': 1,
                'rb:Svc.library_tail: @repo.find(id).to_s': 1,
                'rb:Svc.library_tail: @repo.find(id).to_s.strip': 1,
                'rb:Svc.library_tail: @repo.find(id).to_s.strip.upcase': 1,
                'rb:Svc.local: r.find(id).nxt': 1,
                'rb:Svc.local: r.find(id).nxt.name': 1,
                'rb:Svc.nested: @repo.find(id).name': 1,
                'rb:Svc.nested: @repo.where(@repo.find(id).name).find': 1,
                'rb:Svc.on_new: Repo.new.find(1).name': 1,
                'rb:Svc.on_self: self.me.me': 1,
                'rb:Svc.on_self: self.me.me.own_chain': 1,
                'rb:Svc.own_builder: @repo.where(q).where': 1,
                'rb:Svc.own_builder: @repo.where(q).where(q).find': 1,
                'rb:Svc.own_chain: @repo.find(id).nxt': 1,
                'rb:Svc.own_chain: @repo.find(id).nxt.nxt': 1,
                'rb:Svc.own_chain: @repo.find(id).nxt.nxt.name': 1,
                'rb:Svc.unknown: x.first': 1,
                'rb:Svc.unknown: x.first.second': 1,
                'rb:Svc.unknown: x.first.second.third': 1,
                'rb:Svc.with_block: n.name': 1,
                'rb:Svc.with_block: xs.map': 1,
                'rb:Svc.with_block: xs.map { |n| n.name }.compact': 1,
                'rb:Svc.with_block: xs.map { |n| n.name }.compact.uniq': 1,
                'rb:Svc.with_block: xs.map { |n| n.name }.compact.uniq.first': 1}}


PHP_SHAPES = {
    "src/Model.php": '''<?php
namespace App;

interface Store
{
    public function find(int $id): Note;
}

class Note
{
    public function nxt(): Note
    {
        return $this;
    }

    public function name(): string
    {
        return "n";
    }

    public function untyped()
    {
        return $this;
    }
}

class Repo implements Store
{
    public Note $last;

    public function find(int $id): Note
    {
        return new Note();
    }

    public function where(string $q): self
    {
        return $this;
    }

    public static function make(): Repo
    {
        return new Repo();
    }
}

class Cache implements Store
{
    public function find(int $id): Note
    {
        return new Note();
    }
}

function open_repo(): Repo
{
    return new Repo();
}
''',
    "src/Svc.php": '''<?php
namespace App;

use GuzzleHttp\\Client;
use Illuminate\\Support\\Facades\\DB;

class Base
{
    public function log(string $m): Base
    {
        return $this;
    }
}

class Svc extends Base
{
    private Repo $repo;
    private Client $client;
    private Store $store;

    public function own_types(int $id)
    {
        return $this->repo->where("a")->where("b")->find($id)->nxt()->nxt()->name();
    }

    public function through_this()
    {
        return $this->log("a")->log("b")->log("c");
    }

    public function through_parent()
    {
        return parent::log("a")->log("b");
    }

    public function from_static()
    {
        return Repo::make()->where("a")->find(1)->name();
    }

    public function from_function()
    {
        return open_repo()->where("a")->find(1)->nxt();
    }

    public function from_new()
    {
        return (new Repo())->where("a")->find(2)->name();
    }

    public function nullsafe(?Repo $r)
    {
        return $r?->where("a")?->find(1)?->name();
    }

    public function untyped_link(Repo $r)
    {
        return $r->find(1)->untyped()->name()->more();
    }

    public function unknown($x)
    {
        return $x->a()->b()->c();
    }

    public function library_chain()
    {
        return DB::table("notes")->where("a", 1)->orderBy("id")->get();
    }

    public function library_value()
    {
        return $this->client->get("https://api.example.com/notes")->getBody()->getContents();
    }

    public function interface_first(int $id)
    {
        return $this->store->find($id)->nxt()->name();
    }

    public function property_between(Repo $r)
    {
        return $r->last->nxt()->name();
    }

    public function renamed(Repo $r)
    {
        $n = $r->find(1);
        $a = $n->nxt()->name();
        $n = $n->untyped();
        $b = $n->nxt()->name();
        $r = $r->where("x")->where("y");
        return $r->find(3)->name();
    }

    public function in_arguments(Repo $r, $xs)
    {
        return $r->where($r->find(1)->name())->find(array_map(fn ($x) => $r->find($x)->nxt(), $xs))->name();
    }

    public function twice(Repo $r)
    {
        $r->find(1)->nxt()->name();
        $r->find(1)->nxt()->name();
        return $r->find(1)->nxt();
    }
}
''',
    "page.php": '''<?php
require __DIR__ . '/src/Model.php';

$repo = new \\App\\Repo();
$name = $repo->where("a")->find(1)->nxt()->name();
$repo = $repo->where("b");
echo $repo->find(2)->name();
''',
}

PHP_SEEN = {'calls': {'php:App.Svc.from_function': ['php:App.Repo.where (receiver-type)', 'php:App.open_repo (name)'],
           'php:App.Svc.from_new': ['php:App.Repo.where (receiver-type)'],
           'php:App.Svc.from_static': ['php:App.Repo.make (assoc)', 'php:App.Repo.where (receiver-type)'],
           'php:App.Svc.in_arguments': ['ext:array_map (import)',
                                        'php:App.Note.name (receiver-type)',
                                        'php:App.Note.nxt (receiver-type)',
                                        'php:App.Repo.find (receiver-type)',
                                        'php:App.Repo.where (receiver-type)'],
           'php:App.Svc.interface_first': ['php:App.Cache.find (interface)', 'php:App.Repo.find (interface)'],
           'php:App.Svc.library_chain': ['ext:DB.table (import)'],
           'php:App.Svc.library_value': ['ext:Client.get (receiver-type)',
                                         'ext:HTTP GET api.example.com (http-external)'],
           'php:App.Svc.nullsafe': ['php:App.Repo.where (receiver-type)'],
           'php:App.Svc.own_types': ['php:App.Repo.where (receiver-type)'],
           'php:App.Svc.property_between': ['php:App.Note.name (receiver-type)', 'php:App.Note.nxt (receiver-type)'],
           'php:App.Svc.renamed': ['php:App.Note.name (receiver-type)',
                                   'php:App.Note.nxt (receiver-type)',
                                   'php:App.Repo.find (receiver-type)'],
           'php:App.Svc.through_parent': ['php:App.Base.log (receiver-type)'],
           'php:App.Svc.through_this': ['php:App.Base.log (receiver-type)'],
           'php:App.Svc.twice': ['php:App.Note.name (receiver-type)',
                                 'php:App.Note.nxt (receiver-type)',
                                 'php:App.Repo.find (receiver-type)'],
           'php:App.Svc.untyped_link': ['php:App.Note.untyped (receiver-type)', 'php:App.Repo.find (receiver-type)'],
           'php:page.php': ['php:App.Repo.where (receiver-type)', 'php:src/Model.php (include)']},
 'unresolved': {'php:App.Svc.from_function: open_repo()->where("a")->find': 1,
                'php:App.Svc.from_function: open_repo()->where("a")->find(1)->nxt': 1,
                'php:App.Svc.from_new: (new Repo())->where("a")->find': 1,
                'php:App.Svc.from_new: (new Repo())->where("a")->find(2)->name': 1,
                'php:App.Svc.from_static: Repo::make()->where("a")->find': 1,
                'php:App.Svc.from_static: Repo::make()->where("a")->find(1)->name': 1,
                'php:App.Svc.in_arguments: $r->where($r->find(1)->name())->find': 1,
                'php:App.Svc.in_arguments: $r->where($r->find(1)->name())->find(arr->name': 1,
                'php:App.Svc.interface_first: $this->store->find($id)->nxt': 1,
                'php:App.Svc.interface_first: $this->store->find($id)->nxt()->name': 1,
                'php:App.Svc.library_value: $this->client->get("https://api.example.->getBody': 1,
                'php:App.Svc.library_value: $this->client->get("https://api.example.->getContents': 1,
                'php:App.Svc.nullsafe: $r?->where("a")->find': 1,
                'php:App.Svc.nullsafe: $r?->where("a")?->find(1)->name': 1,
                'php:App.Svc.own_types: $this->repo->where("a")->where': 1,
                'php:App.Svc.own_types: $this->repo->where("a")->where("b")->fin->name': 1,
                'php:App.Svc.own_types: $this->repo->where("a")->where("b")->fin->nxt': 2,
                'php:App.Svc.own_types: $this->repo->where("a")->where("b")->find': 1,
                'php:App.Svc.renamed: $n->nxt': 1,
                'php:App.Svc.renamed: $n->nxt()->name': 1,
                'php:App.Svc.renamed: $n->untyped': 1,
                'php:App.Svc.renamed: $r->find': 1,
                'php:App.Svc.renamed: $r->find(3)->name': 1,
                'php:App.Svc.renamed: $r->where': 1,
                'php:App.Svc.renamed: $r->where("x")->where': 1,
                'php:App.Svc.unknown: $x->a': 1,
                'php:App.Svc.unknown: $x->a()->b': 1,
                'php:App.Svc.unknown: $x->a()->b()->c': 1,
                'php:App.Svc.untyped_link: $r->find(1)->untyped()->name': 1,
                'php:App.Svc.untyped_link: $r->find(1)->untyped()->name()->more': 1,
                'php:page.php: $repo->find': 1,
                'php:page.php: $repo->find(2)->name': 1,
                'php:page.php: $repo->where': 1,
                'php:page.php: $repo->where("a")->find': 1,
                'php:page.php: $repo->where("a")->find(1)->nxt': 1,
                'php:page.php: $repo->where("a")->find(1)->nxt()->name': 1}}


def test_short_chains_in_csharp_are_read_as_before(tmp_path):
    _write(tmp_path, CS_SHAPES)
    assert seen(build_graph(tmp_path)) == CS_SEEN


def test_short_chains_in_ruby_are_read_as_before(tmp_path):
    _write(tmp_path, RB_SHAPES)
    assert seen(build_graph(tmp_path)) == RB_SEEN


def test_short_chains_in_php_are_read_as_before(tmp_path):
    _write(tmp_path, PHP_SHAPES)
    assert seen(build_graph(tmp_path)) == PHP_SEEN
