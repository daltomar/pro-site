use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::CookieJar;
use chrono::Utc;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::net::IpAddr;
use uuid::Uuid;

use crate::{
    auth::credentials::{dummy_verify, generate_session_token, verify_password},
    AppState,
};

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
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

    if state.login_limiter.check_key(&ip_key).is_err() {
        tracing::warn!("Rate limit hit for IP {:?}", ip_str);
        return login_page_with_error("Too many attempts. Please wait a minute.").into_response();
    }

    // Look up user
    let maybe_user = sqlx::query(
        "SELECT id, password_hash, active, use_count, max_uses FROM users WHERE username = $1",
    )
    .bind(&form.username)
    .fetch_optional(&state.pool)
    .await;

    let user_row = match maybe_user {
        Ok(Some(row)) => row,
        Ok(None) => {
            dummy_verify(&form.password);
            return login_page_with_error("Invalid username or password.").into_response();
        }
        Err(e) => {
            tracing::error!("DB error during login lookup: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
        }
    };

    let user_id: Uuid = user_row.get("id");
    let password_hash: String = user_row.get("password_hash");
    let active: bool = user_row.get("active");
    let use_count: i32 = user_row.get("use_count");
    let max_uses: i32 = user_row.get("max_uses");

    if !active || use_count >= max_uses {
        dummy_verify(&form.password);
        return login_page_with_error("Invalid username or password.").into_response();
    }

    if !verify_password(&form.password, &password_hash) {
        return login_page_with_error("Invalid username or password.").into_response();
    }

    // Atomic increment and optional deactivation in a transaction
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!("Failed to start transaction: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
        }
    };

    let updated = sqlx::query(
        "UPDATE users SET use_count = use_count + 1 WHERE id = $1 RETURNING use_count",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await;

    let new_use_count: i32 = match updated {
        Ok(row) => row.get("use_count"),
        Err(e) => {
            tracing::error!("Failed to increment use_count: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
        }
    };

    if new_use_count >= max_uses {
        if let Err(e) = sqlx::query("UPDATE users SET active = FALSE WHERE id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await
        {
            tracing::error!("Failed to deactivate user: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
        }
    }

    let (raw_token, hashed_token) = generate_session_token();
    let expires_at = Utc::now() + chrono::Duration::seconds(state.config.session_duration_secs);

    if let Err(e) = sqlx::query(
        "INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(&hashed_token)
    .bind(user_id)
    .bind(expires_at)
    .execute(&mut *tx)
    .await
    {
        tracing::error!("Failed to insert session: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
    }

    if let Err(e) = sqlx::query(
        "INSERT INTO access_log (user_id, username, ip_address) VALUES ($1, $2, $3)",
    )
    .bind(user_id)
    .bind(&form.username)
    .bind(ip_str.as_deref())
    .execute(&mut *tx)
    .await
    {
        tracing::error!("Failed to insert access log: {}", e);
    }

    if let Err(e) = tx.commit().await {
        tracing::error!("Failed to commit login transaction: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
    }

    let cookie = format!(
        "session={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={}",
        raw_token, state.config.session_duration_secs
    );

    let mut response = Redirect::to("/restricted/").into_response();
    response
        .headers_mut()
        .insert(axum::http::header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    response
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let cookies = CookieJar::from_headers(&headers);

    if let Some(raw_token) = cookies.get("session").map(|c| c.value().to_string()) {
        if let Ok(raw_bytes) = hex::decode(&raw_token) {
            let hashed = hex::encode(Sha256::digest(&raw_bytes));
            if let Err(e) = sqlx::query("DELETE FROM sessions WHERE id = $1")
                .bind(&hashed)
                .execute(&state.pool)
                .await
            {
                tracing::error!("Failed to delete session on logout: {}", e);
            }
        }
    }

    let mut response = Redirect::to("/").into_response();
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        "session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
            .parse()
            .unwrap(),
    );
    response
}

fn login_page_with_error(msg: &str) -> Html<String> {
    let template = std::fs::read_to_string("static/login.html")
        .unwrap_or_else(|_| "<html><body><p>Login</p></body></html>".to_string());
    let error_html = format!(r#"<p class="error">{}</p>"#, msg);
    Html(template.replace("<!-- ERROR -->", &error_html))
}
