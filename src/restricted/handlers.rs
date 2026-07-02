use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use comrak::{markdown_to_html, Options};
use sqlx::Row;

use crate::{auth::middleware::AuthUser, AppState};

pub async fn index(State(state): State<AppState>, user: AuthUser) -> Response {
    serve_restricted_html("static/restricted/index.html", &user, &state).await
}

pub async fn asset(
    State(state): State<AppState>,
    user: AuthUser,
    Path(path): Path<String>,
) -> Response {
    let file_path = format!("static/restricted/{}", path);

    if path.contains("..") {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    if path.ends_with(".html") {
        return serve_restricted_html(&file_path, &user, &state).await;
    }

    match tokio::fs::read(&file_path).await {
        Ok(bytes) => {
            let mime = mime_guess(&path);
            ([(axum::http::header::CONTENT_TYPE, mime)], bytes).into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

pub async fn serve_image(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(filename): Path<String>,
) -> Response {
    if !is_valid_image_filename(&filename) {
        return (StatusCode::BAD_REQUEST, "Invalid filename").into_response();
    }

    let file_path = format!("{}/{}", state.config.restricted_images_dir, filename);
    match tokio::fs::read(&file_path).await {
        Ok(bytes) => {
            let mime = image_mime(&filename);
            ([(axum::http::header::CONTENT_TYPE, mime)], bytes).into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

async fn serve_restricted_html(file_path: &str, user: &AuthUser, state: &AppState) -> Response {
    let content = match tokio::fs::read_to_string(file_path).await {
        Ok(c) => c,
        Err(_) => return (StatusCode::NOT_FOUND, "Not found").into_response(),
    };

    let tab_rows = sqlx::query(
        "SELECT tab_number, body_text, image_filename FROM tab_content WHERE tab_number BETWEEN 1 AND 3",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let mut tab_content: [Option<(Option<String>, Option<String>)>; 3] = [None, None, None];
    for row in &tab_rows {
        let n: i16 = row.get("tab_number");
        if (1..=3).contains(&n) {
            let body: Option<String> = row.get("body_text");
            let img: Option<String> = row.get("image_filename");
            tab_content[(n - 1) as usize] = Some((body, img));
        }
    }

    let mut html = content;
    for i in 0..3 {
        let marker = format!("<!-- TAB{}_CONTENT -->", i + 1);
        let rendered = render_tab_content(tab_content[i].as_ref());
        html = html.replace(&marker, &rendered);
    }

    let banner = build_banner(user);
    let html = html.replace("<!-- BANNER -->", &banner);

    Html(html).into_response()
}

fn render_tab_content(entry: Option<&(Option<String>, Option<String>)>) -> String {
    match entry {
        None => "<p><em>No content yet.</em></p>".to_string(),
        Some((body, img)) => {
            let has_body = body.as_deref().map(|s| !s.is_empty()).unwrap_or(false);
            let has_img = img.as_deref().map(|s| !s.is_empty()).unwrap_or(false);
            if !has_body && !has_img {
                return "<p><em>No content yet.</em></p>".to_string();
            }
            let mut out = String::new();
            if let Some(text) = body {
                if !text.is_empty() {
                    out.push_str(&markdown_to_html(text, &Options::default()));
                }
            }
            if let Some(filename) = img {
                if !filename.is_empty() {
                    out.push_str(&format!(
                        r#"<img src="/restricted/images/{}" alt="">"#,
                        html_escape(filename)
                    ));
                }
            }
            out
        }
    }
}

pub fn html_escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '&' => "&amp;".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect(),
            '>' => "&gt;".chars().collect(),
            '"' => "&quot;".chars().collect(),
            '\'' => "&#x27;".chars().collect(),
            other => vec![other],
        })
        .collect()
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

fn image_mime(filename: &str) -> &'static str {
    if filename.ends_with(".jpg") || filename.ends_with(".jpeg") {
        "image/jpeg"
    } else if filename.ends_with(".png") {
        "image/png"
    } else if filename.ends_with(".webp") {
        "image/webp"
    } else if filename.ends_with(".gif") {
        "image/gif"
    } else {
        "application/octet-stream"
    }
}
