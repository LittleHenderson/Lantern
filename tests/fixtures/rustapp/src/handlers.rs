use std::process::Command;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;

use crate::store::Store;
use crate::AppState;

pub async fn get_note(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> String {
    match state.repo.get(&id) {
        Some(n) => n.text,
        None => String::new(),
    }
}

pub async fn create_note(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(text): Json<String>) -> String {
    let user = current_user(&headers);
    if user.is_empty() {
        return "login required".to_string();
    }
    let note = state.repo.save(&user, &text);
    state.mailer.send(&user, &note.text);
    export_note(&note.text);
    note.text
}

pub async fn delete_note(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> &'static str {
    state.repo.delete(&id);
    ""
}

fn current_user(headers: &HeaderMap) -> String {
    headers.get("x-session").and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
}

/// Runs a shell command with user text in it.
fn export_note(text: &str) {
    Command::new("sh").arg("-c").arg(format!("echo {} >> export.txt", text)).status().ok();
}
