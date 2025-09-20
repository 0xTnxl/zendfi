use axum::{
    extract::{State, Path},
    http::StatusCode,
    Json
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use bigdecimal::ToPrimitive;
use crate::{AppState, models::*};
use crate::auth::AuthenticatedMerchant;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
    
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct WebhookEvent {
    pub id: Uuid,
    pub payment_id: Uuid,
    pub merchant_id: Uuid,
    pub event_type: WebhookEventType,
    pub payload: serde_json::Value,
    pub webhook_url: String,
    pub status: WebhookStatus,
    pub attempts: i32,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub response_code: Option<i32>,
    pub response_body: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::Type, Clone)]
#[sqlx(type_name = "webhook_event_type", rename_all = "snake_case")]
pub enum WebhookEventType {
    PaymentCreated,
    PaymentConfirmed,
    PaymentFailed,
    PaymentExpired,
    SettlementCompleted,
}

#[derive(Debug, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "webhook_status", rename_all = "lowercase")]
pub enum WebhookStatus {
    Pending,
    Delivered,
    Failed,
    Exhausted,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub event: WebhookEventType,
    pub payment: PaymentWebhookData,
    pub timestamp: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaymentWebhookData {
    pub id: Uuid,
    pub merchant_id: Uuid,
    pub amount_usd: f64,
    pub amount_ngn: Option<f64>,
    pub status: PaymentStatus,
    pub transaction_signature: Option<String>,
    pub customer_wallet: Option<String>,
    pub metadata: serde_json::Value,
}

// Webhook signature generation for security
pub fn generate_webhook_signature(payload: &str, secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(payload.as_bytes());
    
    let result = mac.finalize();
    format!("sha256={}", hex::encode(result.into_bytes()))
}

#[allow(dead_code)]
// Verify incoming webhook signatures (for webhook endpoints)
pub fn verify_webhook_signature(payload: &str, signature: &str, secret: &str) -> bool {
    let expected_signature = generate_webhook_signature(payload, secret);
    signature.as_bytes().ct_eq(expected_signature.as_bytes()).into()
}

pub async fn create_webhook_event(
    state: &AppState,
    payment_id: Uuid,
    event_type: WebhookEventType,
) -> Result<(), Box<dyn std::error::Error>> {
    let payment = sqlx::query!(
        r#"SELECT id, merchant_id, amount_usd, amount_ngn, 
                  status as "status: PaymentStatus", transaction_signature, 
                  customer_wallet, metadata, created_at, expires_at 
           FROM payments WHERE id = $1"#,
        payment_id
    )
    .fetch_one(&state.db)
    .await?;

    let merchant = sqlx::query!(
        r#"SELECT id, name, email, wallet_address, webhook_url, webhook_secret, created_at, updated_at
           FROM merchants WHERE id = $1"#,
        payment.merchant_id
    )
    .fetch_one(&state.db)
    .await?;

    // Skip only if the merchant has no webhook URL
    let webhook_url = match merchant.webhook_url {
        Some(url) => url,
        None => {
            tracing::info!("No webhook URL configured for merchant {}", merchant.id);
            return Ok(());
        }
    };

    // Convert BigDecimal to f64 for the webhook payload
    let amount_usd_f64 = payment.amount_usd.to_f64().unwrap_or(0.0);
    let amount_ngn_f64 = payment.amount_ngn.and_then(|bd| bd.to_f64());

    // Create webhook payload
    let webhook_data = PaymentWebhookData {
        id: payment.id,
        merchant_id: payment.merchant_id,
        amount_usd: amount_usd_f64,
        amount_ngn: amount_ngn_f64,
        status: payment.status,
        transaction_signature: payment.transaction_signature,
        customer_wallet: payment.customer_wallet,
        metadata: payment.metadata,
    };

    let payload = WebhookPayload {
        event: event_type.clone(),
        payment: webhook_data,
        timestamp: Utc::now(),
        signature: String::new(),
    };

    // Store webhook event in database
    let webhook_id = Uuid::new_v4();
    sqlx::query!(
        r#"
        INSERT INTO webhook_events 
        (id, payment_id, merchant_id, event_type, payload, webhook_url, status, attempts, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
        webhook_id,
        payment_id,
        payment.merchant_id,
        event_type as WebhookEventType,
        serde_json::to_value(&payload)?,
        webhook_url,
        WebhookStatus::Pending as WebhookStatus,
        0,
        Utc::now()
    )
    .execute(&state.db)
    .await?;
    
    tokio::spawn(deliver_webhook(state.clone(), webhook_id));

    Ok(())
}

async fn get_webhook_event(state: &AppState, webhook_id: Uuid) -> Result<WebhookEvent, sqlx::Error> {
    sqlx::query_as!(
        WebhookEvent,
        r#"
        SELECT id, payment_id, merchant_id, event_type as "event_type: WebhookEventType", 
               payload, webhook_url, status as "status: WebhookStatus", attempts,
               last_attempt_at, next_retry_at, response_code, response_body, created_at
        FROM webhook_events WHERE id = $1
        "#,
        webhook_id
    )
    .fetch_one(&state.db)
    .await
}

async fn mark_webhook_exhausted(state: &AppState, webhook_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE webhook_events SET status = 'exhausted' WHERE id = $1",
        webhook_id
    )
    .execute(&state.db)
    .await?;
    Ok(())
}

pub async fn deliver_webhook(state: AppState, webhook_id: Uuid) {
    const MAX_RETRIES: i32 = 5;

    let webhook = match get_webhook_event(&state, webhook_id).await {
        Ok(webhook) => webhook,
        Err(e) => {
            tracing::error!("Failed to get webhook {}: {}", webhook_id, e);
            return;
        }
    };

    // Don't retry if already delivered or exhausted
    if matches!(webhook.status, WebhookStatus::Delivered | WebhookStatus::Exhausted) {
        return;
    }

    let attempt_count = webhook.attempts + 1;
    
    // Check if we've exceeded max retries
    if attempt_count > MAX_RETRIES {
        let _ = mark_webhook_exhausted(&state, webhook_id).await;
        tracing::error!("Webhook {} exhausted after {} attempts", webhook_id, MAX_RETRIES);
        return;
    }

    // Generate signature
    let payload_json = serde_json::to_string(&webhook.payload).unwrap();
    let merchant_secret = format!("webhook_secret_{}", webhook.merchant_id);
    let signature = generate_webhook_signature(&payload_json, &merchant_secret);

    // Update payload with signature
    let mut payload: WebhookPayload = serde_json::from_value(webhook.payload).unwrap();
    payload.signature = signature.clone();
    let signed_payload = serde_json::to_string(&payload).unwrap();

    // Attempt delivery
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("Content-Type", "application/json".parse().unwrap());
    headers.insert("X-ZendFi-Signature", signature.parse().unwrap());
    headers.insert("X-ZendFi-Event", format!("{:?}", payload.event).parse().unwrap());
    headers.insert("X-ZendFi-Delivery", webhook_id.to_string().parse().unwrap());

    let response = client
        .post(&webhook.webhook_url)
        .headers(headers)
        .body(signed_payload)
        .send()
        .await;

    let now = Utc::now();
    
    match response {
        Ok(resp) => {
            let status_code = resp.status().as_u16() as i32;
            let response_body = resp.text().await.unwrap_or_default();
            
            if (200..300).contains(&status_code) {
                let _ = sqlx::query!(
                    r#"
                    UPDATE webhook_events 
                    SET status = 'delivered', attempts = $1, last_attempt_at = $2,
                        response_code = $3, response_body = $4
                    WHERE id = $5
                    "#,
                    attempt_count,
                    now,
                    status_code,
                    response_body,
                    webhook_id
                )
                .execute(&state.db)
                .await;
                
                tracing::info!("Webhook {} delivered successfully", webhook_id);
            } else {
                // ✅ Direct call instead of await to avoid Send issues
                let _ = update_webhook_failed(&state, webhook_id, attempt_count, status_code, response_body).await;
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            let _ = update_webhook_failed(&state, webhook_id, attempt_count, 0, error_msg).await;
        }
    }
}

// This function handles background tasks to retry failed webhooks
pub async fn webhook_retry_worker(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    
    loop {
        interval.tick().await;
        
        // Find webhooks that need retry
        let webhooks = sqlx::query!(
            r#"
            SELECT id FROM webhook_events 
            WHERE status = 'failed' AND next_retry_at <= NOW()
            LIMIT 10
            "#
        )
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

        for webhook in webhooks {
            let state_clone = state.clone();
            tokio::spawn(deliver_webhook(state_clone, webhook.id));
        }
    }
}

async fn update_webhook_failed(
    state: &AppState,
    webhook_id: Uuid,
    attempt_count: i32,
    response_code: i32,
    response_body: String,
) -> Result<(), sqlx::Error> {
    let delay_seconds = 2_u64.pow((attempt_count - 1) as u32);
    let next_retry = Utc::now() + chrono::Duration::seconds(delay_seconds as i64);

    sqlx::query!(
        r#"
        UPDATE webhook_events 
        SET status = 'failed', attempts = $1, last_attempt_at = $2, 
            next_retry_at = $3, response_code = $4, response_body = $5
        WHERE id = $6
        "#,
        attempt_count,
        Utc::now(),
        next_retry,
        if response_code > 0 { Some(response_code) } else { None },
        response_body,
        webhook_id
    )
    .execute(&state.db)
    .await?;

    tracing::warn!(
        "Webhook {} failed (attempt {}), will retry in {}s", 
        webhook_id, attempt_count, delay_seconds
    );

    Ok(())
}

// API endpoints for webhook management
pub async fn list_webhook_events(
    State(state): State<AppState>,
    axum::Extension(merchant): axum::Extension<AuthenticatedMerchant>,
) -> Result<Json<Vec<WebhookEvent>>, StatusCode> {
    let webhooks = sqlx::query_as!(
        WebhookEvent,
        r#"
        SELECT id, payment_id, merchant_id, event_type as "event_type: WebhookEventType",
               payload, webhook_url, status as "status: WebhookStatus", attempts,
               last_attempt_at, next_retry_at, response_code, response_body, created_at
        FROM webhook_events 
        WHERE merchant_id = $1 
        ORDER BY created_at DESC 
        LIMIT 50
        "#,
        merchant.merchant_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(webhooks))
}

pub async fn retry_webhook(
    State(state): State<AppState>,
    Path(webhook_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Let's reset webhook for retry
    sqlx::query!(
        r#"
        UPDATE webhook_events 
        SET status = 'pending', next_retry_at = NOW()
        WHERE id = $1 AND status IN ('failed', 'exhausted')
        "#,
        webhook_id
    )
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Trigger immediate retry
    tokio::spawn(deliver_webhook(state, webhook_id));

    Ok(Json(serde_json::json!({
        "message": "Webhook retry triggered",
        "webhook_id": webhook_id
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_signature() {
        let payload = r#"{"event":"payment_confirmed","payment":{"id":"123"}}"#;
        let secret = "test_secret";
        
        let signature = generate_webhook_signature(payload, secret);
        assert!(signature.starts_with("sha256="));
        
        let is_valid = verify_webhook_signature(payload, &signature, secret);
        assert!(is_valid);
        
        let is_invalid = verify_webhook_signature(payload, &signature, "wrong_secret");
        assert!(!is_invalid);
    }
}