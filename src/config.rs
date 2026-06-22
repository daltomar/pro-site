use std::env;

pub struct Config {
    pub database_url: String,
    pub admin_secret: String,
    pub admin_username: String,
    pub admin_password: String,
    pub admin_session_duration_secs: i64,
    pub session_duration_secs: i64,
    pub server_addr: String,
    pub restricted_images_dir: String,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            database_url: env::var("DATABASE_URL").expect("DATABASE_URL must be set"),
            admin_secret: env::var("ADMIN_SECRET").expect("ADMIN_SECRET must be set"),
            admin_username: env::var("ADMIN_USERNAME").expect("ADMIN_USERNAME must be set"),
            admin_password: env::var("ADMIN_PASSWORD").expect("ADMIN_PASSWORD must be set"),
            admin_session_duration_secs: env::var("ADMIN_SESSION_DURATION_SECS")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .expect("ADMIN_SESSION_DURATION_SECS must be a number"),
            session_duration_secs: env::var("SESSION_DURATION_SECS")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .expect("SESSION_DURATION_SECS must be a number"),
            server_addr: env::var("SERVER_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:3000".to_string()),
            restricted_images_dir: env::var("RESTRICTED_IMAGES_DIR")
                .expect("RESTRICTED_IMAGES_DIR must be set"),
        }
    }
}
