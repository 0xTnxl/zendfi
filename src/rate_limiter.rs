use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use crate::AppState;

#[derive(Debug, Clone)]
pub struct PersistentRateLimiter {
    max_requests: i32,
    window_seconds: i64,
}

#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    pub allowed: bool,
    pub remaining: i32,
    pub reset_time: i64,
    pub retry_after: Option<i64>,
}

impl PersistentRateLimiter {
    pub fn new(max_requests: i32, window_seconds: i64) -> Self {
        Self {
            max_requests,
            window_seconds,
        }
    }

    pub async fn check_rate_limit(
        &self,
        state: &AppState,
        key: &str,
        identifier: Option<Uuid>,
    ) -> Result<RateLimitInfo, Box<dyn std::error::Error + Send + Sync>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() as i64;
        
        let window_start = now - self.window_seconds;

        let mut tx = state.db.begin().await?;

        sqlx::query!(
            r#"
            DELETE FROM rate_limit_entries 
            WHERE rate_limit_key = $1 AND created_at < $2
            "#,
            key,
            chrono::DateTime::from_timestamp(window_start, 0).unwrap()
        )
        .execute(&mut *tx)
        .await?;

        let current_count = sqlx::query!(
            r#"
            SELECT COUNT(*) as count
            FROM rate_limit_entries 
            WHERE rate_limit_key = $1 AND created_at >= $2
            "#,
            key,
            chrono::DateTime::from_timestamp(window_start, 0).unwrap()
        )
        .fetch_one(&mut *tx)
        .await?;

        let current_requests = current_count.count.unwrap_or(0) as i32;
        let remaining = (self.max_requests - current_requests).max(0);
        let reset_time = now + self.window_seconds;

        if current_requests >= self.max_requests {
            tx.rollback().await?;
            return Ok(RateLimitInfo {
                allowed: false,
                remaining: 0,
                reset_time,
                retry_after: Some(self.window_seconds),
            });
        }

        sqlx::query!(
            r#"
            INSERT INTO rate_limit_entries (id, rate_limit_key, identifier, created_at)
            VALUES ($1, $2, $3, $4)
            "#,
            Uuid::new_v4(),
            key,
            identifier,
            chrono::Utc::now()
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(RateLimitInfo {
            allowed: true,
            remaining: remaining - 1, 
            reset_time,
            retry_after: None,
        })
    }

    pub async fn get_current_usage(
        &self,
        state: &AppState,
        key: &str,
    ) -> Result<i32, Box<dyn std::error::Error + Send + Sync>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() as i64;
        
        let window_start = now - self.window_seconds;

        let result = sqlx::query!(
            r#"
            SELECT COUNT(*) as count
            FROM rate_limit_entries 
            WHERE rate_limit_key = $1 AND created_at >= $2
            "#,
            key,
            chrono::DateTime::from_timestamp(window_start, 0).unwrap()
        )
        .fetch_one(&state.db)
        .await?;

        Ok(result.count.unwrap_or(0) as i32)
    }

    pub async fn reset_rate_limit(
        &self,
        state: &AppState,
        key: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        sqlx::query!(
            "DELETE FROM rate_limit_entries WHERE rate_limit_key = $1",
            key
        )
        .execute(&state.db)
        .await?;

        tracing::info!("Rate limit reset for key: {}", key);
        Ok(())
    }
}

pub async fn start_rate_limit_cleanup_worker(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(300)); 
    
    loop {
        interval.tick().await;
        
        let cutoff_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64 - 3600; 

        match sqlx::query!(
            r#"
            DELETE FROM rate_limit_entries 
            WHERE created_at < $1
            "#,
            chrono::DateTime::from_timestamp(cutoff_time, 0).unwrap()
        )
        .execute(&state.db)
        .await
        {
            Ok(result) => {
                if result.rows_affected() > 0 {
                    tracing::debug!("Cleaned up {} old rate limit entries", result.rows_affected());
                }
            }
            Err(e) => {
                tracing::error!("Failed to clean up rate limit entries: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    #[sqlx::test]
    async fn test_rate_limiter(pool: PgPool) {
        let state = AppState {
            db: pool,
            // ... other fields
        };

        let limiter = PersistentRateLimiter::new(3, 60); // 3 requests per minute
        let key = "test_key";

        // First 3 requests should be allowed
        for i in 1..=3 {
            let result = limiter.check_rate_limit(&state, key, None).await.unwrap();
            assert!(result.allowed, "Request {} should be allowed", i);
            assert_eq!(result.remaining, 3 - i);
        }

        // 4th request should be denied
        let result = limiter.check_rate_limit(&state, key, None).await.unwrap();
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
        assert!(result.retry_after.is_some());
    }
}