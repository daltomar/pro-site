use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use sha2::{Digest, Sha256};

use crate::AppState;

pub struct AdminSession {
    pub token_hash: String,
}

#[async_trait]
impl FromRequestParts<AppState> for AdminSession {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let cookies = CookieJar::from_headers(&parts.headers);

        let raw_token = match cookies.get("admin_session").map(|c| c.value().to_string()) {
            Some(t) => t,
            None => return Err(Redirect::to("/admin/login").into_response()),
        };

        let raw_bytes = match hex::decode(&raw_token) {
            Ok(b) => b,
            Err(_) => return Err(clear_and_redirect()),
        };

        let hashed = hex::encode(Sha256::digest(&raw_bytes));

        let maybe_row = sqlx::query(
            "SELECT token_hash FROM admin_sessions WHERE token_hash = $1 AND expires_at > NOW()",
        )
        .bind(&hashed)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!("DB error in admin session validation: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        })?;

        match maybe_row {
            Some(_) => Ok(AdminSession { token_hash: hashed }),
            None => Err(clear_and_redirect()),
        }
    }
}

fn clear_and_redirect() -> Response {
    let mut response = Redirect::to("/admin/login").into_response();
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        "admin_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
            .parse()
            .unwrap(),
    );
    response
}
