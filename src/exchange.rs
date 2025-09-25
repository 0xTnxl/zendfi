use crate::{AppState, models::ExchangeRate};
use serde_json::Value;
use bigdecimal::{BigDecimal, FromPrimitive, ToPrimitive};

pub async fn get_current_rate(state: &AppState) -> Result<ExchangeRate, Box<dyn std::error::Error + Send + Sync>> {
    if let Ok(cached_rate) = get_cached_rate(state).await {
        return Ok(ExchangeRate {
            usd_to_ngn: cached_rate,
            updated_at: chrono::Utc::now(),
        });
    }

    let rate = match fetch_binance_rate().await {
        Ok(rate) => rate,
        Err(_) => fetch_backup_rate().await?,
    };
    cache_exchange_rate(state, rate).await?;

    Ok(ExchangeRate {
        usd_to_ngn: rate,
        updated_at: chrono::Utc::now(),
    })
}

async fn fetch_binance_rate() -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::new();
    let response: Value = client
        .get("https://api.binance.com/api/v3/ticker/price?symbol=USDTNGN")
        .send()
        .await?
        .json()
        .await?;

    if let Some(price_str) = response["price"].as_str() {
        Ok(price_str.parse::<f64>()?)
    } else {
        Err("Invalid response from Binance".into())
    }
}

async fn fetch_backup_rate() -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::new();
    let response: Value = client
        .get("https://api.coingecko.com/api/v3/simple/price?ids=usd&vs_currencies=ngn")
        .send()
        .await?
        .json()
        .await?;

    if let Some(ngn_rate) = response["usd"]["ngn"].as_f64() {
        Ok(ngn_rate)
    } else {
        Err("Invalid response from CoinGecko".into())
    }
}

async fn cache_exchange_rate(state: &AppState, rate: f64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let rate_bd = BigDecimal::from_f64(rate).ok_or("Failed to convert rate to BigDecimal")?;
    
    sqlx::query!(
        r#"
        INSERT INTO exchange_rates (rate, source, created_at)
        VALUES ($1, $2, $3)
        ON CONFLICT (source) DO UPDATE SET 
            rate = EXCLUDED.rate,
            created_at = EXCLUDED.created_at
        "#,
        rate_bd,
        "live",
        chrono::Utc::now()
    )
    .execute(&state.db)
    .await?;

    Ok(())
}

pub async fn get_cached_rate(state: &AppState) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    let cached = sqlx::query!(
        r#"
        SELECT rate FROM exchange_rates
        WHERE source = 'live' AND created_at > NOW() - INTERVAL '1 hour'
        ORDER BY created_at DESC
        LIMIT 1
        "#
    )
    .fetch_optional(&state.db)
    .await?;

    match cached {
        Some(record) => {
            let rate_f64 = record.rate.to_f64().ok_or("Failed to convert BigDecimal to f64")?;
            Ok(rate_f64)
        },
        None => Err("No cached rate found".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_fetch_binance_rate() {
        if let Ok(rate) = fetch_binance_rate().await {
            assert!(rate > 0.0);
            assert!(rate < 10000.0);
        }
    }
}