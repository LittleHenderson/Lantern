//! A small axum web service with a React frontend in web/: Lantern's Rust sample.
use std::sync::Arc;

use axum::{routing::{get, post}, Router};

mod handlers;
mod store;
mod mail;

use store::{SqlStore, Store};

pub struct AppState {
    pub repo: Arc<SqlStore>,
    pub mailer: Box<dyn mail::Mailer>,
}

fn api_routes() -> Router<Arc<AppState>> {
    Router::new().route("/notes", post(handlers::create_note))
}

#[tokio::main]
async fn main() {
    let repo = Arc::new(SqlStore::open("notes.db"));
    let state = Arc::new(AppState { repo, mailer: Box::new(mail::Smtp {}) });
    let app = Router::new()
        .route("/api/notes/:id", get(handlers::get_note).delete(handlers::delete_note))
        .nest("/api", api_routes())
        .route("/health", get(health))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health() -> &'static str {
    "ok"
}
