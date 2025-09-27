use sqlx::PgPool;

pub async fn initialize_database(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(50)  // Increased for production
        .min_connections(5)   // Maintain minimum connections
        .acquire_timeout(std::time::Duration::from_secs(30))
        .idle_timeout(std::time::Duration::from_secs(300))
        .max_lifetime(std::time::Duration::from_secs(3600))
        .connect(database_url)
        .await?;

    sqlx::query("SELECT 1").execute(&pool).await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    
    tracing::info!("Database initialized successfully with {} max connections", 50);
    Ok(pool)
}

#[allow(dead_code)]
pub async fn health_check(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT 1").execute(pool).await?;
    Ok(())
}
