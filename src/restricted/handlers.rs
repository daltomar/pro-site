use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

use crate::{auth::middleware::AuthUser, AppState};

pub async fn index(_state: State<AppState>, user: AuthUser) -> Response {
    serve_restricted_html("static/restricted/index.html", &user).await
}

pub async fn asset(
    _state: State<AppState>,
    user: AuthUser,
    Path(path): Path<String>,
) -> Response {
    let file_path = format!("static/restricted/{}", path);

    if path.contains("..") {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    if path.ends_with(".html") {
        return serve_restricted_html(&file_path, &user).await;
    }

    // Serve non-HTML assets (css, images, etc.) after auth check
    match tokio::fs::read(&file_path).await {
        Ok(bytes) => {
            let mime = mime_guess(&path);
            ([(axum::http::header::CONTENT_TYPE, mime)], bytes).into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

async fn serve_restricted_html(file_path: &str, user: &AuthUser) -> Response {
    let content = match tokio::fs::read_to_string(file_path).await {
        Ok(c) => c,
        Err(_) => return (StatusCode::NOT_FOUND, "Not found").into_response(),
    };

    let banner = build_banner(user);
    let injected = content.replace("<!-- BANNER -->", &banner);

    Html(injected).into_response()
}

fn build_banner(user: &AuthUser) -> String {
    let (class, message) = if user.use_count >= user.max_uses {
        (
            "access-banner final",
            "This is your last access. When you log out, this credential will be permanently \
             expired. To request new access, contact the administrator."
                .to_string(),
        )
    } else if user.use_count == 1 {
        (
            "access-banner",
            format!(
                "Welcome. This is your first access. You have {} remaining session{}.",
                user.max_uses - user.use_count,
                if user.max_uses - user.use_count == 1 { "" } else { "s" }
            ),
        )
    } else {
        let ordinal = ordinal(user.use_count);
        (
            "access-banner",
            format!(
                "This is your {} access. You have {} remaining session{}.",
                ordinal,
                user.max_uses - user.use_count,
                if user.max_uses - user.use_count == 1 { "" } else { "s" }
            ),
        )
    };

    format!(
        r#"<div class="{class}"><p>{message}</p></div>"#,
        class = class,
        message = message
    )
}

fn ordinal(n: i32) -> &'static str {
    match n {
        1 => "first",
        2 => "second",
        3 => "third",
        4 => "fourth",
        5 => "fifth",
        _ => "nth",
    }
}

fn mime_guess(path: &str) -> &'static str {
    if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".jpg") || path.ends_with(".jpeg") {
        "image/jpeg"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".ico") {
        "image/x-icon"
    } else {
        "application/octet-stream"
    }
}
