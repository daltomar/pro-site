use sqlx::PgPool;

pub async fn create_pool(database_url: &str) -> PgPool {
    let pool = PgPool::connect(database_url)
        .await
        .expect("Failed to connect to database");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}
