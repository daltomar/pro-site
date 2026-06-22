use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Json, Redirect, Response},
    Form,
};
use axum_extra::extract::CookieJar;
use chrono::Utc;
use constant_time_eq::constant_time_eq;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::net::IpAddr;

use crate::{
    admin::middleware::AdminSession,
    auth::credentials::{generate_password, generate_session_token, generate_username, hash_password},
    restricted::handlers::html_escape,
    AppState,
};

// ── Shared page helpers ───────────────────────────────────────────────────────

// Defined as a const so CSS braces don't need escaping in format! calls.
const ADMIN_STYLE: &str = r#"
    *, *::before, *::after { box-sizing: border-box; }
    body { background: #0d0d0d; color: #c8ffc8; font-family: monospace; font-size: 0.95rem; margin: 0; padding: 2rem; }
    h1 { color: #80ff80; margin-bottom: 1.5rem; }
    h2 { color: #80ff80; font-size: 1rem; border-bottom: 1px solid #2a2a2a; padding-bottom: 0.25rem; margin-top: 2rem; }
    nav { margin-bottom: 2rem; border-bottom: 1px solid #2a2a2a; padding-bottom: 0.75rem; }
    nav a { color: #80ff80; text-decoration: none; margin-right: 1rem; }
    nav a:hover { text-decoration: underline; }
    label { display: block; margin-bottom: 0.25rem; color: #7aad7a; font-size: 0.85rem; }
    textarea, input[type="text"], input[type="password"], input[type="number"] { width: 100%; background: #1a1a1a; color: #c8ffc8; border: 1px solid #2e4d2e; border-radius: 3px; padding: 0.5rem; font-family: monospace; font-size: 0.9rem; margin-bottom: 0.75rem; }
    textarea { resize: vertical; }
    button { background: #1a3a1a; color: #80ff80; border: 1px solid #2e4d2e; padding: 0.6rem 1.4rem; font-family: monospace; font-size: 0.95rem; cursor: pointer; border-radius: 3px; margin-top: 1rem; }
    button:hover { background: #2a4a2a; }
    section, .form-section { max-width: 780px; }
    .banner { padding: 0.6rem 1rem; border-radius: 3px; margin-bottom: 1rem; max-width: 780px; }
    .banner.ok { background: #1a3a1a; border: 1px solid #2e6e2e; color: #80ff80; }
    .banner.err { background: #3a1a1a; border: 1px solid #6e2e2e; color: #ff8080; }
    table { border-collapse: collapse; width: 100%; max-width: 780px; margin-bottom: 2rem; }
    th, td { text-align: left; padding: 0.4rem 0.75rem; border-bottom: 1px solid #2a2a2a; font-size: 0.9rem; }
    th { color: #7aad7a; font-weight: normal; }
    .dimmed { opacity: 0.45; }
    .login-card { max-width: 380px; margin: 4rem auto 0; }
"#;

fn admin_page_html(title: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin — {title}</title>
  <style>{style}</style>
</head>
<body>
  <nav><a href="/admin/content">Content</a> · <a href="/admin/credentials">Credentials</a> · <a href="/admin/logout">Logout</a></nav>
  {body}
</body>
</html>"#,
        title = title,
        style = ADMIN_STYLE,
        body = body,
    )
}

fn admin_login_page_html(error_banner: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Login</title>
  <style>{style}</style>
</head>
<body>
  <div class="login-card">
    <h1>Admin</h1>
    {error_banner}
    <form method="post" action="/admin/login">
      <label for="username">Username</label>
      <input id="username" name="username" type="text" required autocomplete="username">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" required autocomplete="current-password">
      <button type="submit">Sign in</button>
    </form>
  </div>
</body>
</html>"#,
        style = ADMIN_STYLE,
        error_banner = error_banner,
    )
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

// ── Legacy API auth (unchanged) ───────────────────────────────────────────────

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

// ── Legacy API routes (header-based auth, unchanged) ─────────────────────────

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
    _session: AdminSession,
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

    let body_text = body.body_text.and_then(|s| {
        let trimmed = s.trim().to_string();
        if trimmed.is_empty() { None } else { Some(trimmed) }
    });

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

// ── Admin content web form (now requires admin session) ───────────────────────

#[derive(Deserialize)]
pub struct SavedQuery {
    pub saved: Option<u8>,
}

pub async fn content_form(
    State(state): State<AppState>,
    _session: AdminSession,
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
            body_escaped = html_escape(body),
            img_escaped = html_escape(img),
        ));
    }

    let page_body = format!(
        r#"<h1>Edit Tab Content</h1>
{saved_banner}
<form method="post" action="/admin/content">
  <label for="secret">Admin secret</label>
  <input id="secret" name="admin_secret" type="password" autocomplete="current-password">
  {tab_sections}
  <button type="submit">Save all tabs</button>
</form>"#,
        saved_banner = saved_banner,
        tab_sections = tab_sections,
    );

    Html(admin_page_html("Edit Tab Content", &page_body)).into_response()
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
    _session: AdminSession,
    Form(body): Form<ContentFormBody>,
) -> Response {
    if !constant_time_eq(body.admin_secret.as_bytes(), state.config.admin_secret.as_bytes()) {
        return Html(admin_page_html(
            "Error",
            r#"<p class="banner err">Invalid secret key.</p><p><a href="/admin/content">← Back to editor</a></p>"#,
        ))
        .into_response();
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
                let msg = format!("Tab {}: body text exceeds 10 000 characters.", tab_number);
                return Html(admin_page_html(
                    "Error",
                    &format!(
                        r#"<p class="banner err">{}</p><p><a href="/admin/content">← Back to editor</a></p>"#,
                        html_escape(&msg)
                    ),
                ))
                .into_response();
            }
        }

        let image_filename = match image_filenames[i].as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            Some(name) => {
                if !is_valid_image_filename(name) {
                    let msg = format!("Tab {}: invalid image filename \"{}\".", tab_number, name);
                    return Html(admin_page_html(
                        "Error",
                        &format!(
                            r#"<p class="banner err">{}</p><p><a href="/admin/content">← Back to editor</a></p>"#,
                            html_escape(&msg)
                        ),
                    ))
                    .into_response();
                }
                let path = format!("{}/{}", state.config.restricted_images_dir, name);
                if tokio::fs::metadata(&path).await.is_err() {
                    let msg = format!("Tab {}: file \"{}\" not found in images directory.", tab_number, name);
                    return Html(admin_page_html(
                        "Error",
                        &format!(
                            r#"<p class="banner err">{}</p><p><a href="/admin/content">← Back to editor</a></p>"#,
                            html_escape(&msg)
                        ),
                    ))
                    .into_response();
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

// ── Admin login / logout ──────────────────────────────────────────────────────

pub async fn admin_login_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    // Redirect if already authenticated.
    let cookies = CookieJar::from_headers(&headers);
    if let Some(raw_token) = cookies.get("admin_session").map(|c| c.value().to_string()) {
        if let Ok(raw_bytes) = hex::decode(&raw_token) {
            let hashed = hex::encode(Sha256::digest(&raw_bytes));
            let already_auth = sqlx::query(
                "SELECT token_hash FROM admin_sessions WHERE token_hash = $1 AND expires_at > NOW()",
            )
            .bind(&hashed)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten()
            .is_some();
            if already_auth {
                return Redirect::to("/admin/content").into_response();
            }
        }
    }
    Html(admin_login_page_html("")).into_response()
}

#[derive(Deserialize)]
pub struct AdminLoginForm {
    pub username: String,
    pub password: String,
}

pub async fn admin_login_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AdminLoginForm>,
) -> Response {
    let ip_str = headers
        .get("x-real-ip")
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string());

    let ip_key: IpAddr = ip_str
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

    if state.admin_login_limiter.check_key(&ip_key).is_err() {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        return Html(admin_login_page_html(
            r#"<p class="banner err">Too many attempts. Please wait a minute.</p>"#,
        ))
        .into_response();
    }

    let username_ok = constant_time_eq(
        form.username.as_bytes(),
        state.config.admin_username.as_bytes(),
    );
    let password_ok = constant_time_eq(
        form.password.as_bytes(),
        state.config.admin_password.as_bytes(),
    );

    if !username_ok || !password_ok {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        return Html(admin_login_page_html(
            r#"<p class="banner err">Invalid credentials.</p>"#,
        ))
        .into_response();
    }

    // Clean up expired sessions on successful login.
    if let Err(e) = sqlx::query("DELETE FROM admin_sessions WHERE expires_at < NOW()")
        .execute(&state.pool)
        .await
    {
        tracing::warn!("Failed to clean up expired admin sessions: {}", e);
    }

    let (raw_token, hashed_token) = generate_session_token();
    let expires_at = Utc::now()
        + chrono::Duration::seconds(state.config.admin_session_duration_secs);

    if let Err(e) = sqlx::query(
        "INSERT INTO admin_sessions (token_hash, expires_at) VALUES ($1, $2)",
    )
    .bind(&hashed_token)
    .bind(expires_at)
    .execute(&state.pool)
    .await
    {
        tracing::error!("Failed to create admin session: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
    }

    let cookie = format!(
        "admin_session={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={}",
        raw_token, state.config.admin_session_duration_secs
    );

    let mut response = Redirect::to("/admin/content").into_response();
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        HeaderValue::from_str(&cookie).unwrap(),
    );
    response
}

pub async fn admin_logout(
    State(state): State<AppState>,
    session: AdminSession,
) -> Response {
    if let Err(e) = sqlx::query("DELETE FROM admin_sessions WHERE token_hash = $1")
        .bind(&session.token_hash)
        .execute(&state.pool)
        .await
    {
        tracing::error!("Failed to delete admin session: {}", e);
    }

    let mut response = Redirect::to("/admin/login").into_response();
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        "admin_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
            .parse()
            .unwrap(),
    );
    response
}

// ── Admin credentials page ────────────────────────────────────────────────────

async fn credentials_page_body(state: &AppState, banner_html: &str) -> String {
    let rows = sqlx::query(
        "SELECT username, use_count, max_uses FROM users ORDER BY created_at DESC",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let mut table_rows = String::new();
    for row in &rows {
        let username: String = row.get("username");
        let use_count: i32 = row.get("use_count");
        let max_uses: i32 = row.get("max_uses");
        let remaining = (max_uses - use_count).max(0);
        let dim = if remaining == 0 { r#" class="dimmed""# } else { "" };
        table_rows.push_str(&format!(
            "<tr{dim}><td>{user}</td><td>{remaining}</td></tr>",
            dim = dim,
            user = html_escape(&username),
            remaining = remaining,
        ));
    }

    format!(
        r#"<h1>Credentials</h1>
{banner}
<h2>Existing credentials</h2>
<table>
  <thead><tr><th>Username</th><th>Uses remaining</th></tr></thead>
  <tbody>{table_rows}</tbody>
</table>
<h2>Create credential</h2>
<div class="form-section">
  <form method="post" action="/admin/credentials">
    <label for="cred_username">Username</label>
    <input id="cred_username" name="username" type="text" required autocomplete="off">
    <label for="cred_password">Password</label>
    <input id="cred_password" name="password" type="text" required autocomplete="off">
    <label for="cred_max_uses">Max uses</label>
    <input id="cred_max_uses" name="max_uses" type="number" min="1" value="3" required>
    <label for="cred_secret">Secret key</label>
    <input id="cred_secret" name="secret_key" type="password" required autocomplete="current-password">
    <button type="submit">Create</button>
  </form>
</div>"#,
        banner = banner_html,
        table_rows = table_rows,
    )
}

#[derive(Deserialize)]
pub struct CredentialsQuery {
    pub created: Option<String>,
}

pub async fn admin_credentials_get(
    State(state): State<AppState>,
    _session: AdminSession,
    Query(params): Query<CredentialsQuery>,
) -> Response {
    let banner = match params.created.as_deref().filter(|s| !s.is_empty()) {
        Some(username) => format!(
            r#"<p class="banner ok">Credential '{}' created.</p>"#,
            html_escape(username)
        ),
        None => String::new(),
    };
    let body = credentials_page_body(&state, &banner).await;
    Html(admin_page_html("Credentials", &body)).into_response()
}

#[derive(Deserialize)]
pub struct NewCredentialForm {
    pub username: String,
    pub password: String,
    pub max_uses: String,
    pub secret_key: String,
}

pub async fn admin_credentials_post(
    State(state): State<AppState>,
    _session: AdminSession,
    Form(form): Form<NewCredentialForm>,
) -> Response {
    if !constant_time_eq(form.secret_key.as_bytes(), state.config.admin_secret.as_bytes()) {
        let body = credentials_page_body(&state, r#"<p class="banner err">Invalid secret key.</p>"#).await;
        return Html(admin_page_html("Credentials", &body)).into_response();
    }

    let username = form.username.trim().to_string();
    if username.is_empty() {
        let body = credentials_page_body(&state, r#"<p class="banner err">Username is required.</p>"#).await;
        return Html(admin_page_html("Credentials", &body)).into_response();
    }

    if form.password.is_empty() {
        let body = credentials_page_body(&state, r#"<p class="banner err">Password is required.</p>"#).await;
        return Html(admin_page_html("Credentials", &body)).into_response();
    }

    let max_uses: i32 = match form.max_uses.trim().parse() {
        Ok(n) if n >= 1 => n,
        _ => {
            let body = credentials_page_body(
                &state,
                r#"<p class="banner err">Max uses must be a positive integer.</p>"#,
            )
            .await;
            return Html(admin_page_html("Credentials", &body)).into_response();
        }
    };

    let password_hash = match hash_password(&form.password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("Failed to hash password: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
        }
    };

    let result = sqlx::query(
        "INSERT INTO users (username, password_hash, max_uses) VALUES ($1, $2, $3)",
    )
    .bind(&username)
    .bind(&password_hash)
    .bind(max_uses)
    .execute(&state.pool)
    .await;

    match result {
        Ok(_) => Redirect::to(&format!("/admin/credentials?created={}", url_encode(&username)))
            .into_response(),
        Err(e) if e.as_database_error().map_or(false, |d| d.is_unique_violation()) => {
            let msg = format!(
                r#"<p class="banner err">Username '{}' already exists.</p>"#,
                html_escape(&username)
            );
            let body = credentials_page_body(&state, &msg).await;
            Html(admin_page_html("Credentials", &body)).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to insert credential: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        }
    }
}
