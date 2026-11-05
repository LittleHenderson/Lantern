"""Ruby: lantern/ruby_frontend.py (Rails, Sinatra, jobs), LB-* rules and the Gemfile.lock audit."""

from pathlib import Path

import pytest

from lantern import depaudit, ruby_frontend
from lantern.engine import build_graph
from lantern.graph import Graph
from lantern.readiness import assess
from lantern.security import _rb_line, scan
from lantern.websec import ruby_rules

FIX = Path(__file__).parent / "fixtures"


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


@pytest.fixture(scope="module")
def notes():
    g = build_graph(FIX / "rubyapp")
    sec = scan(g)
    return g, sec, assess(g, sec)


def by_rule(sec, rule):
    return [f for f in sec["findings"] if f["rule"] == rule]


def calls(g, src):
    return {(e.dst, e.via) for e in g.call_edges() if e.src == src}


def test_rails_routes_sinatra_and_jobs(notes):
    g, _, _ = notes
    e = {n.id: n.entry for n in g.entry_points()}
    assert "ruby" in g.meta["languages"]
    # namespace :api + resources :notes (only:) + a collection route + `get "export", to:` + `post "/login" => …`
    assert e["rb:Api.NotesController.index"] == {"kind": "route", "detail": "GET /api/notes"}
    assert e["rb:Api.NotesController.show"] == {"kind": "route", "detail": "GET /api/notes/:id"}
    assert e["rb:Api.NotesController.search"] == {"kind": "route", "detail": "GET /api/notes/search"}
    assert e["rb:Api.NotesController.destroy"] == {"kind": "route", "detail": "DELETE /api/notes/:id"}
    assert e["rb:Api.ExportsController.run"] == {"kind": "route", "detail": "GET /api/export"}
    assert e["rb:SessionsController.create"] == {"kind": "route", "detail": "POST /login"}
    assert e["rb:HomeController.index"] == {"kind": "route", "detail": "GET /"}
    assert "rb:Api.NotesController.cleanup" not in e                      # private helper, no route
    assert e["rb:hooks/app.rb::POST /hooks/run"]["kind"] == "route"       # a Sinatra block is its own node
    assert e["rb:PruneJob.perform"] == {"kind": "main", "detail": "background job (PruneJob)"}
    assert e["rb:spec/notes_spec.rb"]["kind"] == "test"
    assert g.nodes["rb:Api.NotesController.index"].lane == "server"


def test_calls_resolve(notes):
    g, _, _ = notes
    assert ("rb:NoteService.initialize", "constructor") in calls(g, "rb:Api.NotesController.index")
    assert ("rb:NoteService.all", "receiver-type") in calls(g, "rb:Api.NotesController.index")     # @svc = NoteService.new
    assert ("ext:ActiveRecord.where", "assoc") in calls(g, "rb:Api.NotesController.search")
    assert ("ext:ActiveRecord.destroy", "receiver-type") in calls(g, "rb:Api.NotesController.destroy")   # note = Note.find
    assert ("rb:Api.NotesController.cleanup", "name") in calls(g, "rb:Api.NotesController.destroy")
    assert ("rb:helper_thing", "name") in calls(g, "rb:Api.NotesController.cleanup")              # a top-level method
    assert ("ext:Kernel.`", "import") in calls(g, "rb:Api.ExportsController.run")
    assert ("ext:Kernel.system", "import") in calls(g, "rb:hooks/app.rb::POST /hooks/run")
    assert g.nodes["ext:Kernel.system"].lane == "data"
    # the React search box reaches the Rails action through the bridge
    hops = {e.dst for e in g.call_edges() if e.src == "js:web/src/Search::Search.run"}
    assert "rb:Api.NotesController.search" in hops
    assert g.meta["languages"]["ruby"]["unresolved"] <= 1


def test_auth_filters(notes):
    g, sec, _ = notes
    auth = {e.src for e in g.call_edges() if e.dst == "ext:middleware.auth"}
    # ApplicationController's before_action covers every action except the ones a subclass skips
    assert {"rb:Api.NotesController.index", "rb:Api.NotesController.search", "rb:Api.ExportsController.run"} <= auth
    assert not {"rb:Api.NotesController.destroy", "rb:HomeController.index", "rb:SessionsController.create"} & auth
    missing = {f["node"] for f in by_rule(sec, "LW-AUTH-MISSING")}
    assert "rb:Api.NotesController.destroy" in missing
    assert "rb:Api.NotesController.search" not in missing


def test_the_search_box_reaching_interpolated_sql_is_critical(notes):
    _, sec, _ = notes
    f = by_rule(sec, "LB-SQL-INTERP")[0]
    assert f["rank"] == "critical" and f["node"] == "rb:Api.NotesController.search"
    assert "params[" in f["input"]["via"]
    assert f["ui_path"]                                                   # clicks from the React page
    assert f["scenario"]


def test_every_planted_problem_is_found(notes):
    _, sec, _ = notes
    rules = {f["rule"] for f in sec["findings"]}
    assert {"LB-SQL-INTERP", "LB-EXEC", "LB-WEAK-PASSWORD-HASH", "LB-XSS-RAW", "LB-DEBUG", "LW-AUTH-MISSING"} <= rules
    shells = {f["file"]: f["rank"] for f in by_rule(sec, "LB-EXEC")}
    assert shells == {"app/controllers/api/exports_controller.rb": "critical", "hooks/app.rb": "critical"}
    assert not [f for f in sec["findings"] if f["file"].startswith("spec/")]


def test_readiness_reads_ruby(notes):
    _, _, r = notes
    checks = {c["id"]: c for cat in r["categories"] for c in cat["checks"]}
    assert "Rails" in r["stack"]["frameworks"] and "Sinatra" in r["stack"]["frameworks"]
    assert checks["deps-lock"]["status"] in ("pass", "partial") and "Gemfile" not in checks["deps-lock"]["evidence"]


def test_rb_line_shapes_input_flow():
    assert _rb_line("@svc.run(@name)") == "svc.run(name)"
    assert _rb_line("out = %x(ls #{dir})") == 'out = "ls #{dir}"'


def test_lb_rules_true_and_false(tmp_path):
    _write(tmp_path, {"app/x.rb": "\n".join([
        'Note.where("id = #{id}")',                                   # 1 SQL
        'Note.where("id = ?", id)',                                   # 2 safe
        'Note.order(params[:sort])',                                  # 3 SQL params
        'system("ls", dir)',                                          # 4 safe (argument list)
        '`rm #{path}`',                                               # 5 shell
        'eval(params[:code])',                                        # 6 eval
        'params[:kind].constantize',                                  # 7 eval
        'Marshal.load(cookies[:cart])',                               # 8 deserialize
        'Note.create(params[:note])',                                 # 9 mass assignment
        'Note.create(note_params)',                                   # 10 safe
        'params.require(:note).permit!',                              # 11 mass assignment
        'redirect_to params[:next]',                                  # 12 redirect
        'send_file params[:path]',                                    # 13 file
        'http.verify_mode = OpenSSL::SSL::VERIFY_NONE',               # 14 TLS
        'Faraday.new(url, ssl: { verify: false })',                   # 15 TLS
        'Digest::SHA1.hexdigest(password)',                           # 16 weak password hash
        'token = Digest::MD5.hexdigest(Time.now.to_s)',               # 17 weak hash
        'skip_before_action :verify_authenticity_token',              # 18 CSRF
        "origins '*'",                                                # 19 CORS
        '# Note.where("id = #{id}")',                                 # 20 comment
        'URL = "http://api.example.com/v1"',                          # 21 cleartext
        'URL2 = "http://localhost:3000"',                             # 22 safe
    ]), "spec/x_spec.rb": 'Note.where("id = #{id}")\n', "app/views/a.html.erb": "<%== @x %>\n<%= @y %>\n"})
    got = {(f["file"], f["line"]): f["rule"] for f in ruby_rules(tmp_path)}
    want = {1: "LB-SQL-INTERP", 3: "LB-SQL-PARAMS", 5: "LB-EXEC", 6: "LB-EVAL", 7: "LB-EVAL", 8: "LB-DESERIALIZE",
            9: "LB-MASS-ASSIGN", 11: "LB-MASS-ASSIGN", 12: "LB-REDIRECT", 13: "LB-FILE-INPUT", 14: "LB-TLS-OFF",
            15: "LB-TLS-OFF", 16: "LB-WEAK-PASSWORD-HASH", 17: "LB-WEAK-HASH", 18: "LB-CSRF-OFF", 19: "LB-CORS-ALL",
            21: "LB-CLEARTEXT-URL"}
    assert {ln: r for (f, ln), r in got.items() if f == "app/x.rb"} == want
    assert ("app/views/a.html.erb", 1) in got and ("app/views/a.html.erb", 2) not in got
    assert not [k for k in got if k[0].startswith("spec/")]


def test_reader_details(tmp_path):
    _write(tmp_path, {
        "config/routes.rb": "\n".join([
            "Rails.application.routes.draw do",
            "  scope '/v2' do",
            "    resource :profile, only: [:show, :update]",
            "  end",
            "  resources :posts, except: [:new, :edit, :destroy] do",
            "    member do",
            "      post :publish",
            "    end",
            "  end",
            "  match 'ping', to: 'health#ping', via: :get",
            "end"]),
        "app/controllers/profiles_controller.rb": "class ProfilesController < ActionController::API\n"
                                                  "  before_action :require_login, only: [:update]\n"
                                                  "  def show; end\n  def update; end\nend\n",
        "app/controllers/posts_controller.rb": "class PostsController < ActionController::API\n"
                                               "  def index; end\n  def show; end\n  def create; end\n"
                                               "  def update; end\n  def publish\n    Publisher.new.go\n  end\nend\n",
        "app/controllers/health_controller.rb": "class HealthController < ActionController::API\n  def ping; end\nend\n",
        "lib/publisher.rb": "module Shared\n  module Notify\n    def tell; end\n  end\nend\n"
                            "class Publisher\n  include Shared::Notify\n  def go\n    tell\n    self.done\n  end\n"
                            "  def done; end\n  def self.build\n    new\n  end\nend\n",
        "app/workers/mail_worker.rb": "class MailWorker\n  include Sidekiq::Job\n  def perform(id)\n    x.y\n  end\nend\n",
    })
    g = Graph(str(tmp_path))
    stats = ruby_frontend.add_ruby(g, tmp_path)
    e = {n.id: n.entry["detail"] for n in g.nodes.values() if n.entry}
    assert e["rb:ProfilesController.show"] == "GET /v2/profile"
    assert e["rb:ProfilesController.update"] == "PATCH /v2/profile"
    assert e["rb:PostsController.index"] == "GET /posts"
    assert e["rb:PostsController.update"] == "PATCH /posts/:id"
    assert e["rb:PostsController.publish"] == "POST /posts/:id/publish"
    assert e["rb:HealthController.ping"] == "GET /ping"
    assert e["rb:MailWorker.perform"] == "background job (MailWorker)"
    auth = {x.src for x in g.call_edges() if x.dst == "ext:middleware.auth"}
    assert auth == {"rb:ProfilesController.update"}
    assert ("rb:Publisher.go", "receiver-type") in calls(g, "rb:PostsController.publish")
    assert ("rb:Shared.Notify.tell", "name") in calls(g, "rb:Publisher.go")      # an included module's method
    assert ("rb:Publisher.done", "this") in calls(g, "rb:Publisher.go")
    assert stats["unresolved"] == 1                                              # `x.y`: x is not known


def test_gem_pins(tmp_path):
    _write(tmp_path, {"Gemfile": 'gem "rails"\ngroup :test do\n  gem "rspec"\nend\ngem "pg", group: :production\n',
                      "Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n"
                                      "      rack (>= 2)\n    rack (2.2.3)\n    rspec (3.12.0)\n"
                                      "    nokogiri (1.13.0-x86_64-linux)\n    pg (1.4.5)\n\nPLATFORMS\n  ruby\n"})
    pins, files = depaudit.gem_pins(tmp_path)
    assert files == ["Gemfile.lock"]
    assert pins["rails"] == ("7.0.4", "Gemfile", 1)
    assert pins["rack"] == ("2.2.3", "Gemfile.lock", 6)                          # pulled in by rails
    assert pins["nokogiri"][0] == "1.13.0"                                       # platform suffix dropped
    assert pins["pg"] == ("1.4.5", "Gemfile", 5)
    assert "rspec" not in pins                                                   # test group only
    assert depaudit.run_gem_audit(tmp_path / "nothing")[1]["status"] == "skipped: no Gemfile.lock"


def test_gem_audit_asks_osv(tmp_path, monkeypatch):
    _write(tmp_path, {"Gemfile.lock": "GEM\n  specs:\n    rack (2.2.3)\n"})
    asked = {}

    def post(path, body, timeout=60):
        asked["body"] = body
        return {"results": [{"vulns": [{"id": "GHSA-test"}]}]}

    monkeypatch.setattr(depaudit, "_osv_post", post)
    monkeypatch.setattr(depaudit, "_osv_get", lambda path, timeout=30: {
        "summary": "Header injection", "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"name": "rack"}, "ranges": [{"events": [{"fixed": "2.2.6"}]}]}]})
    out, info = depaudit.run_gem_audit(tmp_path, no_network=False)
    assert asked["body"]["queries"] == [{"package": {"name": "rack", "ecosystem": "RubyGems"}, "version": "2.2.3"}]
    assert info["status"] == "ok" and out[0]["tool"] == "gem-audit" and "2.2.6" in out[0]["more_info"]


def test_login_filters_by_name_and_condition(tmp_path):
    _write(tmp_path, {
        "config/routes.rb": "Rails.application.routes.draw do\n  resources :pays, only: [:index, :create]\n"
                            "  resources :admins, only: [:index]\nend\n",
        "app/controllers/application_controller.rb": "class ApplicationController < ActionController::Base\n"
                                                     "  before_action :authenticated\nend\n",
        "app/controllers/pays_controller.rb": "class PaysController < ApplicationController\n"
                                              "  def index; end\n  def create; end\nend\n",
        "app/controllers/admins_controller.rb": "class AdminsController < ActionController::Base\n"
                                                "  before_action :administrative, if: :admin_param\n  def index; end\nend\n",
    })
    g = Graph(str(tmp_path))
    ruby_frontend.add_ruby(g, tmp_path)
    auth = {x.src for x in g.call_edges() if x.dst == "ext:middleware.auth"}
    assert auth == {"rb:PaysController.index", "rb:PaysController.create"}     # `if:` runs only sometimes


def test_marshal_from_params_and_chained_constantize(tmp_path):
    _write(tmp_path, {"app/a.rb": "user = Marshal.load(Base64.decode64(params[:user]))\n"
                                  "model = params[:class].classify.constantize\n"})
    got = {(f["line"], f["rule"], f["tool_confidence"]) for f in ruby_rules(tmp_path)}
    assert got == {(1, "LB-DESERIALIZE", "HIGH"), (2, "LB-EVAL", "HIGH")}
