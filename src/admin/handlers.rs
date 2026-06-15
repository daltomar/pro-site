use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use constant_time_eq::constant_time_eq;
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::{
    auth::credentials::{generate_password, generate_username, hash_password},
    AppState,
};

fn check_admin_auth(headers: &HeaderMap, config: &crate::config::Config) -> bool {
    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");

    constant_time_eq(provided.as_bytes(), config.admin_secret.as_bytes())
}

fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "Forbidden").into_response()
}

pub async fn issue(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !check_admin_auth(&headers, &state.config) {
        return forbidden();
    }

    let password = generate_password();
    let password_hash = match hash_password(&password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("Failed to hash password: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
        }
    };

    // Retry on username collision (up to 10 attempts)
    for attempt in 0..10 {
        let username = generate_username();

        let result = sqlx::query(
            "INSERT INTO users (username, password_hash) VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING username",
        )
        .bind(&username)
        .bind(&password_hash)
        .fetch_optional(&state.pool)
        .await;

        match result {
            Ok(Some(_)) => {
                return Json(serde_json::json!({
                    "username": username,
                    "password": password,
                    "max_uses": 3,
                    "message": "Copy these credentials now. The password cannot be recovered."
                }))
                .into_response();
            }
            Ok(None) => {
                tracing::warn!("Username collision on attempt {}: {}", attempt + 1, username);
                continue;
            }
            Err(e) => {
                tracing::error!("Failed to insert user: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
            }
        }
    }

    (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate unique username after 10 attempts")
        .into_response()
}

#[derive(Serialize)]
struct UserRecord {
    username: String,
    use_count: i32,
    max_uses: i32,
    active: bool,
    created_at: String,
}

pub async fn list_users(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !check_admin_auth(&headers, &state.config) {
        return forbidden();
    }

    let rows = sqlx::query(
        "SELECT username, use_count, max_uses, active, created_at FROM users ORDER BY created_at DESC",
    )
    .fetch_all(&state.pool)
    .await;

    match rows {
        Ok(rows) => {
            let users: Vec<UserRecord> = rows
                .iter()
                .map(|row| {
                    let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
                    UserRecord {
                        username: row.get("username"),
                        use_count: row.get("use_count"),
                        max_uses: row.get("max_uses"),
                        active: row.get("active"),
                        created_at: created_at.to_rfc3339(),
                    }
                })
                .collect();
            Json(users).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to list users: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct UsernameBody {
    pub username: String,
}

pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UsernameBody>,
) -> Response {
    if !check_admin_auth(&headers, &state.config) {
        return forbidden();
    }

    match sqlx::query("UPDATE users SET active = FALSE WHERE username = $1")
        .bind(&body.username)
        .execute(&state.pool)
        .await
    {
        Ok(result) if result.rows_affected() == 0 => {
            (StatusCode::NOT_FOUND, "User not found").into_response()
        }
        Ok(_) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(e) => {
            tracing::error!("Failed to revoke user {}: {}", body.username, e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        }
    }
}

pub async fn reset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UsernameBody>,
) -> Response {
    if !check_admin_auth(&headers, &state.config) {
        return forbidden();
    }

    match sqlx::query(
        "UPDATE users SET use_count = 0, active = TRUE WHERE username = $1",
    )
    .bind(&body.username)
    .execute(&state.pool)
    .await
    {
        Ok(result) if result.rows_affected() == 0 => {
            (StatusCode::NOT_FOUND, "User not found").into_response()
        }
        Ok(_) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(e) => {
            tracing::error!("Failed to reset user {}: {}", body.username, e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        }
    }
}
