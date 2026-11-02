"""Rust frontend: crates and modules, impl/trait resolution, axum/actix/rocket routers, the bridge, LR-* rules."""

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
def rustapp():
    g = build_graph(FIX / "rustapp")
    return g, scan(g)


def test_rust_is_a_language_of_its_own(rustapp):
    g, _ = rustapp
    assert set(g.meta["languages"]) == {"rust", "typescript/javascript"}
    assert g.meta["languages"]["rust"]["crates"] == 1 and g.meta["languages"]["rust"]["routes"] == 4


def test_axum_routes_nest_main_and_tests_are_entries(rustapp):
    g, _ = rustapp
    e = entries(g)
    assert e["rs:notes_api::handlers::get_note"] == {"kind": "route", "detail": "GET /api/notes/:id"}
    assert e["rs:notes_api::handlers::delete_note"]["detail"] == "DELETE /api/notes/:id"      # get(h).delete(h2)
    assert e["rs:notes_api::handlers::create_note"]["detail"] == "POST /api/notes"           # nest("/api", api_routes())
    assert e["rs:notes_api::health"]["detail"] == "GET /health"
    assert "server start" in e["rs:notes_api::main"]["detail"]
    assert e["rs:notes_api::store::tests::saves_a_note"]["kind"] == "test"                    # #[cfg(test)] mod + #[test]


def test_calls_resolve_by_name_assoc_and_receiver_type(rustapp):
    g, _ = rustapp
    assert edge(g, "rs:notes_api::handlers::create_note", "rs:notes_api::handlers::current_user").via == "name"
    assert edge(g, "rs:notes_api::main", "rs:notes_api::store::SqlStore::open").via == "assoc"
    # State(state): State<Arc<AppState>> -> state.repo (Arc<SqlStore>) -> SqlStore::get, across three modules
    e = edge(g, "rs:notes_api::handlers::get_note", "rs:notes_api::store::SqlStore::get")
    assert e.via == "receiver-type" and e.confidence == "resolved"
    # `use super::*;` in the test module, then `let s = SqlStore::open(..)` typed by the return type
    assert edge(g, "rs:notes_api::store::tests::saves_a_note", "rs:notes_api::store::SqlStore::save").via == "receiver-type"
    assert edge(g, "rs:notes_api::main", "rs:notes_api::handlers::get_note").via == "route-registration"


def test_trait_object_calls_are_possible_edges_to_implementers(rustapp):
    g, _ = rustapp
    e = edge(g, "rs:notes_api::handlers::create_note", "rs:notes_api::mail::Smtp::send")   # Box<dyn Mailer>
    assert e.confidence == "possible" and e.via == "trait"


def test_untyped_receivers_are_counted_not_guessed(rustapp):
    g, _ = rustapp
    assert "user.to_string" in g.unresolved                      # &str parameter: no repo type
    assert not any(".and_then" in k or "unwrap" in k for k in g.unresolved)   # chains on foreign calls are not counted


def test_js_frontend_links_to_rust_routes(rustapp):
    g, _ = rustapp
    e = edge(g, "js:web/src/api::getNote", "rs:notes_api::handlers::get_note")
    assert e.via == "http-exact" and e.detail == "GET /api/notes/{}"


def test_rust_rules_find_the_planted_problems_and_rank_by_reach(rustapp):
    _, sec = rustapp
    by = {f["rule"]: f for f in sec["findings"]}
    assert by["LR-SQL-FORMAT"]["rank"] == "critical" and by["LR-SQL-FORMAT"]["reachable"]["entry"].endswith("get_note")
    assert by["LR-SQL-FORMAT"]["input"]["via"] == "parameter `id`"
    assert by["LR-EXEC-FORMAT"]["rank"] == "critical" and by["LR-EXEC-FORMAT"]["reachable"]["entry"].endswith("create_note")
    assert by["LW-AUTH-MISSING"]["line"] == 29                    # delete_note has no login check; create_note does


def test_actix_attributes_scopes_and_route_to(tmp_path):
    _write(tmp_path, {
        "Cargo.toml": '[package]\nname = "svc"\nversion = "0.1.0"\n\n[dependencies]\nactix-web = "4"\n',
        "src/main.rs": '''use actix_web::{get, post, web, App, HttpServer};

mod api;

#[get("/health")]
async fn health() -> &'static str { "ok" }

async fn login() -> &'static str { "" }

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(health)
            .service(web::scope("/api").service(api::list).service(api::create))
            .route("/login", web::post().to(login))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
''',
        "src/api.rs": '''use actix_web::{get, post};

#[get("/items")]
pub async fn list() -> &'static str { "" }

#[post("/items")]
pub async fn create() -> &'static str { "" }
''',
    })
    g = build_graph(tmp_path)
    e = entries(g)
    assert e["rs:svc::health"]["detail"] == "GET /health"
    assert e["rs:svc::api::list"]["detail"] == "GET /api/items"
    assert e["rs:svc::api::create"]["detail"] == "POST /api/items"
    assert e["rs:svc::login"]["detail"] == "POST /login"
    assert "server start" in e["rs:svc::main"]["detail"]


def test_rocket_mount_and_outgoing_http(tmp_path):
    _write(tmp_path, {
        "Cargo.toml": '[package]\nname = "rk"\nversion = "0.1.0"\n\n[dependencies]\nrocket = "0.5"\nreqwest = "0.12"\n',
        "src/main.rs": '''#[macro_use] extern crate rocket;

const BASE: &str = "https://api.example.com";

#[get("/users/<id>")]
fn user(id: u32) -> String { String::new() }

#[post("/users")]
fn add_user() -> String { String::new() }

async fn sync(client: &reqwest::Client, id: u32) {
    client.post(format!("{}/users/{}", BASE, id)).send().await;
    reqwest::get("/local/ping").await;
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/api", routes![user, add_user])
}
''',
    })
    g = build_graph(tmp_path)
    e = entries(g)
    assert e["rs:rk::user"]["detail"] == "GET /api/users/<id>"
    assert e["rs:rk::add_user"]["detail"] == "POST /api/users"
    calls = {(c["method"], c["path"], c["host"], c["prefix_unknown"]) for c in g.meta["http_calls"]}
    assert ("POST", "/users/{}", "api.example.com", False) in calls      # const folded into format!
    assert ("GET", "/local/ping", None, False) in calls


def test_workspace_crates_and_generic_trait_bounds(tmp_path):
    _write(tmp_path, {
        "Cargo.toml": '[workspace]\nmembers = ["core", "app"]\n',
        "core/Cargo.toml": '[package]\nname = "core"\nversion = "0.1.0"\n',
        "core/src/lib.rs": '''pub trait Notify { fn ping(&self); }
pub struct Bell;
impl Notify for Bell { fn ping(&self) {} }
pub fn ring<N: Notify>(n: &N) { n.ping(); }
''',
        "app/Cargo.toml": '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\ncore = { path = "../core" }\n',
        "app/src/main.rs": '''use core::{ring, Bell};
fn main() { ring(&Bell); }
''',
    })
    g = build_graph(tmp_path)
    assert edge(g, "rs:app::main", "rs:core::ring").via == "use"
    assert edge(g, "rs:core::ring", "rs:core::Bell::ping").confidence == "possible"      # N: Notify
    assert g.meta["languages"]["rust"]["crates"] == 2
