use sqlx::PgPool;

pub async fn initialize_database(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(20)
        .min_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect(database_url)
        .await?;
    
    // Run the migrations that we have
    sqlx::migrate!("./migrations").run(&pool).await?;
    
    tracing::info!("Database initialized successfully");
    Ok(pool)
}

pub async fn health_check(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT 1").execute(pool).await?;
    Ok(())
}
