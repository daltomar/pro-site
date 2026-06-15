use std::env;

pub struct Config {
    pub database_url: String,
    pub admin_secret: String,
    pub session_duration_secs: i64,
    pub server_addr: String,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            database_url: env::var("DATABASE_URL").expect("DATABASE_URL must be set"),
            admin_secret: env::var("ADMIN_SECRET").expect("ADMIN_SECRET must be set"),
            session_duration_secs: env::var("SESSION_DURATION_SECS")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .expect("SESSION_DURATION_SECS must be a number"),
            server_addr: env::var("SERVER_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:3000".to_string()),
        }
    }
}
