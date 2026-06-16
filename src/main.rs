use axum::{
    extract::Query,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use governor::{Quota, RateLimiter};
use std::{collections::HashMap, net::IpAddr, num::NonZeroU32, sync::Arc};
use tower_http::{services::ServeDir, trace::TraceLayer};

mod admin;
mod auth;
mod config;
mod db;
mod error;
mod restricted;

use config::Config;

pub type LoginLimiter = RateLimiter<
    IpAddr,
    governor::state::keyed::DefaultKeyedStateStore<IpAddr>,
    governor::clock::DefaultClock,
>;

#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub config: Arc<Config>,
    pub login_limiter: Arc<LoginLimiter>,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env();
    let pool = db::create_pool(&config.database_url).await;
    let server_addr = config.server_addr.clone();

    auth::credentials::init_dummy_hash();

    let quota = Quota::per_minute(NonZeroU32::new(5).unwrap());
    let login_limiter = Arc::new(RateLimiter::keyed(quota));

    let state = AppState {
        pool,
        config: Arc::new(config),
        login_limiter,
    };

    let app = Router::new()
        .nest_service("/css", ServeDir::new("static/css"))
        .route("/", get(serve_index))
        .route("/login", get(serve_login).post(auth::handlers::login))
        .route("/logout", post(auth::handlers::logout))
        .route("/restricted/", get(restricted::handlers::index))
        .route("/restricted/*path", get(restricted::handlers::asset))
        .route("/admin/issue", post(admin::handlers::issue))
        .route("/admin/users", get(admin::handlers::list_users))
        .route("/admin/revoke", post(admin::handlers::revoke))
        .route("/admin/reset", post(admin::handlers::reset))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&server_addr).await.unwrap();
    tracing::info!("Listening on {}", server_addr);
    axum::serve(listener, app).await.unwrap();
}

async fn serve_index() -> impl IntoResponse {
    match tokio::fs::read_to_string("static/index.html").await {
        Ok(content) => Html(content).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

async fn serve_login(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let template = match tokio::fs::read_to_string("static/login.html").await {
        Ok(c) => c,
        Err(_) => return (StatusCode::NOT_FOUND, "Not found").into_response(),
    };

    let html = if params.contains_key("error") {
        template.replace(
            "<!-- ERROR -->",
            r#"<p class="error">Invalid username or password.</p>"#,
        )
    } else {
        template.replace("<!-- ERROR -->", "")
    };

    Html(html).into_response()
}
