use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json, Redirect, Response},
    Form,
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

fn is_valid_image_filename(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let dot = match name.rfind('.') {
        Some(i) => i,
        None => return false,
    };
    let stem = &name[..dot];
    let ext = &name[dot + 1..];
    if stem.is_empty() {
        return false;
    }
    let valid_ext = matches!(ext, "jpg" | "jpeg" | "png" | "webp" | "gif");
    let valid_stem = stem.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    valid_ext && valid_stem
}

#[derive(Deserialize)]
pub struct TabContentBody {
    pub body_text: Option<String>,
    pub image_filename: Option<String>,
}

#[derive(Serialize)]
struct TabContentRow {
    tab_number: i16,
    body_text: Option<String>,
    image_filename: Option<String>,
    updated_at: String,
}

pub async fn put_tab_content(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(tab_number): Path<i16>,
    Json(body): Json<TabContentBody>,
) -> Response {
    if !check_admin_auth(&headers, &state.config) {
        return forbidden();
    }

    if !(1..=4).contains(&tab_number) {
        return (StatusCode::BAD_REQUEST, "tab_number must be between 1 and 4").into_response();
    }

    let body_text = body.body_text.map(|s| {
        let trimmed = s.trim().to_string();
        if trimmed.is_empty() { None } else { Some(trimmed) }
    }).flatten();

    if let Some(ref text) = body_text {
        if text.len() > 10_000 {
            return (StatusCode::BAD_REQUEST, "body_text exceeds 10000 characters").into_response();
        }
    }

    let image_filename = match body.image_filename {
        Some(ref name) if !name.is_empty() => {
            if !is_valid_image_filename(name) {
                return (
                    StatusCode::BAD_REQUEST,
                    "image_filename must match ^[A-Za-z0-9_-]+\\.(jpg|jpeg|png|webp|gif)$",
                )
                    .into_response();
            }
            let path = format!("{}/{}", state.config.restricted_images_dir, name);
            match tokio::fs::metadata(&path).await {
                Ok(_) => Some(name.clone()),
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        "image_filename does not exist in the images directory",
                    )
                        .into_response();
                }
            }
        }
        _ => None,
    };

    let result = sqlx::query(
        "INSERT INTO tab_content (tab_number, body_text, image_filename, updated_at)
         VALUES ($1, $2, $3, now())
         ON CONFLICT (tab_number) DO UPDATE
         SET body_text = EXCLUDED.body_text,
             image_filename = EXCLUDED.image_filename,
             updated_at = now()
         RETURNING tab_number, body_text, image_filename, updated_at",
    )
    .bind(tab_number)
    .bind(&body_text)
    .bind(&image_filename)
    .fetch_one(&state.pool)
    .await;

    match result {
        Ok(row) => {
            let updated_at: chrono::DateTime<chrono::Utc> = row.get("updated_at");
            Json(TabContentRow {
                tab_number: row.get("tab_number"),
                body_text: row.get("body_text"),
                image_filename: row.get("image_filename"),
                updated_at: updated_at.to_rfc3339(),
            })
            .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to upsert tab_content for tab {}: {}", tab_number, e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        }
    }
}

// ── Admin content web form ────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SavedQuery {
    pub saved: Option<u8>,
}

pub async fn content_form(
    State(state): State<AppState>,
    Query(params): Query<SavedQuery>,
) -> Response {
    let rows = sqlx::query(
        "SELECT tab_number, body_text, image_filename FROM tab_content WHERE tab_number BETWEEN 1 AND 4",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let mut tabs: [(String, String); 4] = Default::default();
    for row in &rows {
        let n: i16 = row.get("tab_number");
        if (1..=4).contains(&n) {
            let body: String = row.get::<Option<String>, _>("body_text").unwrap_or_default();
            let img: String = row.get::<Option<String>, _>("image_filename").unwrap_or_default();
            tabs[(n - 1) as usize] = (body, img);
        }
    }

    let saved_banner = if params.saved == Some(1) {
        r#"<p class="banner ok">Content saved.</p>"#
    } else {
        ""
    };

    let mut tab_sections = String::new();
    for i in 0..4usize {
        let n = i + 1;
        let (ref body, ref img) = tabs[i];
        tab_sections.push_str(&format!(
            r#"
      <section>
        <h2>Tab {n}</h2>
        <label for="body_{n}">Body (Markdown)</label>
        <textarea id="body_{n}" name="body_text_{n}" rows="12">{body_escaped}</textarea>
        <label for="img_{n}">Image filename</label>
        <input id="img_{n}" name="image_filename_{n}" type="text" value="{img_escaped}">
      </section>"#,
            n = n,
            body_escaped = crate::restricted::handlers::html_escape(body),
            img_escaped = crate::restricted::handlers::html_escape(img),
        ));
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin — Edit Tab Content</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; }}
    body {{ background: #0d0d0d; color: #c8ffc8; font-family: monospace; font-size: 0.95rem; margin: 0; padding: 2rem; }}
    h1 {{ color: #80ff80; margin-bottom: 1.5rem; }}
    h2 {{ color: #80ff80; font-size: 1rem; border-bottom: 1px solid #2a2a2a; padding-bottom: 0.25rem; margin-top: 2rem; }}
    label {{ display: block; margin-bottom: 0.25rem; color: #7aad7a; font-size: 0.85rem; }}
    textarea, input[type="text"], input[type="password"] {{ width: 100%; background: #1a1a1a; color: #c8ffc8; border: 1px solid #2e4d2e; border-radius: 3px; padding: 0.5rem; font-family: monospace; font-size: 0.9rem; margin-bottom: 0.75rem; }}
    textarea {{ resize: vertical; }}
    button {{ background: #1a3a1a; color: #80ff80; border: 1px solid #2e4d2e; padding: 0.6rem 1.4rem; font-family: monospace; font-size: 0.95rem; cursor: pointer; border-radius: 3px; margin-top: 1rem; }}
    button:hover {{ background: #2a4a2a; }}
    section {{ max-width: 780px; }}
    .banner {{ padding: 0.6rem 1rem; border-radius: 3px; margin-bottom: 1rem; max-width: 780px; }}
    .banner.ok {{ background: #1a3a1a; border: 1px solid #2e6e2e; color: #80ff80; }}
    .banner.err {{ background: #3a1a1a; border: 1px solid #6e2e2e; color: #ff8080; }}
  </style>
</head>
<body>
  <h1>Edit Tab Content</h1>
  {saved_banner}
  <form method="post" action="/admin/content">
    <label for="secret">Admin secret</label>
    <input id="secret" name="admin_secret" type="password" autocomplete="current-password">
    {tab_sections}
    <button type="submit">Save all tabs</button>
  </form>
</body>
</html>"#,
        saved_banner = saved_banner,
        tab_sections = tab_sections,
    );

    Html(html).into_response()
}

#[derive(Deserialize)]
pub struct ContentFormBody {
    pub admin_secret: String,
    pub body_text_1: Option<String>,
    pub body_text_2: Option<String>,
    pub body_text_3: Option<String>,
    pub body_text_4: Option<String>,
    pub image_filename_1: Option<String>,
    pub image_filename_2: Option<String>,
    pub image_filename_3: Option<String>,
    pub image_filename_4: Option<String>,
}

pub async fn save_content_form(
    State(state): State<AppState>,
    Form(body): Form<ContentFormBody>,
) -> Response {
    if !constant_time_eq(body.admin_secret.as_bytes(), state.config.admin_secret.as_bytes()) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    let body_texts = [
        body.body_text_1,
        body.body_text_2,
        body.body_text_3,
        body.body_text_4,
    ];
    let image_filenames = [
        body.image_filename_1,
        body.image_filename_2,
        body.image_filename_3,
        body.image_filename_4,
    ];

    for i in 0..4usize {
        let tab_number = (i + 1) as i16;

        let body_text = body_texts[i]
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        if let Some(ref text) = body_text {
            if text.len() > 10_000 {
                let err_html = form_error_page(&format!(
                    "Tab {}: body text exceeds 10 000 characters.",
                    tab_number
                ));
                return Html(err_html).into_response();
            }
        }

        let image_filename = match image_filenames[i].as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            Some(name) => {
                if !is_valid_image_filename(name) {
                    let err_html = form_error_page(&format!(
                        "Tab {}: invalid image filename \"{}\".",
                        tab_number, name
                    ));
                    return Html(err_html).into_response();
                }
                let path = format!("{}/{}", state.config.restricted_images_dir, name);
                if tokio::fs::metadata(&path).await.is_err() {
                    let err_html = form_error_page(&format!(
                        "Tab {}: file \"{}\" not found in images directory.",
                        tab_number, name
                    ));
                    return Html(err_html).into_response();
                }
                Some(name.to_string())
            }
            None => None,
        };

        if let Err(e) = sqlx::query(
            "INSERT INTO tab_content (tab_number, body_text, image_filename, updated_at)
             VALUES ($1, $2, $3, now())
             ON CONFLICT (tab_number) DO UPDATE
             SET body_text = EXCLUDED.body_text,
                 image_filename = EXCLUDED.image_filename,
                 updated_at = now()",
        )
        .bind(tab_number)
        .bind(&body_text)
        .bind(&image_filename)
        .execute(&state.pool)
        .await
        {
            tracing::error!("Failed to upsert tab_content for tab {}: {}", tab_number, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
        }
    }

    Redirect::to("/admin/content?saved=1").into_response()
}

fn form_error_page(message: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Admin — Error</title>
  <style>
    body {{ background: #0d0d0d; color: #c8ffc8; font-family: monospace; padding: 2rem; }}
    .banner {{ background: #3a1a1a; border: 1px solid #6e2e2e; color: #ff8080; padding: 0.6rem 1rem; border-radius: 3px; margin-bottom: 1rem; max-width: 780px; }}
    a {{ color: #80ff80; }}
  </style>
</head>
<body>
  <p class="banner">{}</p>
  <p><a href="/admin/content">← Back to editor</a></p>
</body>
</html>"#,
        crate::restricted::handlers::html_escape(message)
    )
}
