use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::AppState;

#[allow(dead_code)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub username: String,
    pub use_count: i32,
    pub max_uses: i32,
}

#[async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let cookies = CookieJar::from_headers(&parts.headers);

        let raw_token = match cookies.get("session").map(|c| c.value().to_string()) {
            Some(t) => t,
            None => return Err(Redirect::to("/login").into_response()),
        };

        let raw_bytes = match hex::decode(&raw_token) {
            Ok(b) => b,
            Err(_) => return Err(clear_and_redirect()),
        };

        let hashed = hex::encode(Sha256::digest(&raw_bytes));

        let maybe_row = sqlx::query(
            "SELECT s.user_id, u.username, u.use_count, u.max_uses
             FROM sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.id = $1 AND s.expires_at > NOW()",
        )
        .bind(&hashed)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!("DB error in session validation: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        })?;

        match maybe_row {
            Some(row) => Ok(AuthUser {
                user_id: row.get("user_id"),
                username: row.get("username"),
                use_count: row.get("use_count"),
                max_uses: row.get("max_uses"),
            }),
            None => Err(clear_and_redirect()),
        }
    }
}

fn clear_and_redirect() -> Response {
    let mut response = Redirect::to("/login").into_response();
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        "session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
            .parse()
            .unwrap(),
    );
    response
}
