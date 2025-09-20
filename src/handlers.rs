#[allow(dead_code)]

use axum::{
    extract::{State, Path, Extension},
    http::StatusCode,
    Json,
};
use uuid::Uuid;
use bigdecimal::{BigDecimal, FromPrimitive};
use crate::webhooks::{create_webhook_event, WebhookEventType};
use crate::auth::AuthenticatedMerchant;
use crate::{AppState, models::*};

pub async fn create_payment(
    State(state): State<AppState>,
    Extension(merchant): Extension<AuthenticatedMerchant>,
    Json(request): Json<CreatePaymentRequest>,
) -> Result<Json<PaymentResponse>, StatusCode> {
    // Validate amount first
    if request.amount <= 0.0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Convert NGN to USD if it's needed
    let (amount_usd, amount_ngn) = if request.currency == "NGN" {
        let rate = crate::exchange::get_current_rate(&state).await
            .map_err(|e| {
                tracing::error!("Failed to get exchange rate: {}", e);
                StatusCode::SERVICE_UNAVAILABLE
            })?;
        let usd_amount = request.amount / rate.usd_to_ngn;
        (usd_amount, Some(request.amount))
    } else {
        // Assume USD
        let rate = crate::exchange::get_current_rate(&state).await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let ngn_amount = request.amount * rate.usd_to_ngn;
        (request.amount, Some(ngn_amount))
    };
    
    let payment_id = Uuid::new_v4();
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(15);
    let amount_usd_bd = BigDecimal::from_f64(amount_usd).unwrap();
    let amount_ngn_bd = amount_ngn.and_then(|n| BigDecimal::from_f64(n));
    
    // Create a new payment
    sqlx::query!(
        r#"
        INSERT INTO payments (id, merchant_id, amount_usd, amount_ngn, status, metadata, created_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
        payment_id,
        merchant.merchant_id,
        amount_usd_bd,
        amount_ngn_bd,
        PaymentStatus::Pending as PaymentStatus,
        request.metadata.unwrap_or(serde_json::json!({})),
        chrono::Utc::now(),
        expires_at
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create payment: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    // Generate the Solana Pay QR code
    let qr_code = crate::solana::generate_payment_qr(
        &payment_id,
        amount_usd,
        &state.config.recipient_wallet
    ).await.map_err(|e| {
        tracing::error!("Failed to generate QR code: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Trigger webhook for payment created
    let _ = create_webhook_event(&state, payment_id, WebhookEventType::PaymentCreated).await;
    
    Ok(Json(PaymentResponse {
        id: payment_id,
        amount: request.amount,
        currency: request.currency,
        status: PaymentStatus::Pending,
        qr_code,
        payment_url: format!("{}/pay/{}", state.config.frontend_url, payment_id),
        expires_at,
    }))
}

pub async fn confirm_payment(
    State(state): State<AppState>,
    Path(payment_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    sqlx::query!(
        "UPDATE payments SET status = 'confirmed' WHERE id = $1",
        payment_id
    )
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let state_clone = state.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::settlements::process_settlement(&state_clone, payment_id).await {
            tracing::error!("Manual settlement processing failed for payment {}: {}", payment_id, e);
        } else {
            tracing::info!("✅ Manual settlement processed successfully for payment {}", payment_id);
        }
    });

    let _ = create_webhook_event(&state, payment_id, WebhookEventType::PaymentConfirmed).await;

    Ok(Json(serde_json::json!({
        "message": "Payment confirmed and settlement initiated",
        "payment_id": payment_id
    })))
}

pub async fn get_payment(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Payment>, StatusCode> {
    let payment = sqlx::query_as!(
        Payment,
        r#"SELECT id, merchant_id, amount_usd, amount_ngn, 
                  status as "status: PaymentStatus", transaction_signature, 
                  customer_wallet, metadata, created_at, expires_at 
           FROM payments WHERE id = $1"#,
        id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;
    
    Ok(Json(payment))
}

pub async fn get_payment_status(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let status = crate::solana::check_payment_status(&state, id).await
        .map_err(|e| {
            tracing::error!("Failed to check payment status: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    Ok(Json(serde_json::json!({
        "payment_id": id,
        "status": status,
        "timestamp": chrono::Utc::now()
    })))
}

pub async fn create_merchant(
    State(state): State<AppState>,
    Json(request): Json<CreateMerchantRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if crate::solana::validate_solana_address(&request.wallet_address).is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }

    if !is_valid_nigerian_bank_code(&request.bank_code) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let merchant_id = Uuid::new_v4();
    let merchant = sqlx::query!(
        r#"
        INSERT INTO merchants 
        (id, name, email, wallet_address, webhook_url, 
         bank_account_number, bank_code, account_name, business_address, settlement_currency,
         created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)
        RETURNING id, name, email, wallet_address, webhook_url
        "#,
        merchant_id,
        request.name,
        request.email,
        request.wallet_address,
        request.webhook_url,
        request.bank_account_number,
        request.bank_code,
        request.account_name,
        request.business_address,
        request.settlement_currency,
        chrono::Utc::now()
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create merchant: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let api_key = crate::auth::generate_api_key(&state, merchant_id).await
        .map_err(|e| {
            tracing::error!("Failed to generate API key: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    Ok(Json(serde_json::json!({
        "merchant": {
            "id": merchant.id,
            "name": merchant.name,
            "email": merchant.email,
            "wallet_address": merchant.wallet_address,
            "webhook_url": merchant.webhook_url
        },
        "api_key": api_key,
        "message": "Merchant created successfully. Settlements will be processed to your provided bank account.",
        "warning": "Store this API key securely. It will not be shown again."
    })))
}

fn is_valid_nigerian_bank_code(bank_code: &str) -> bool {
    let valid_codes = [
        "044", "023", "063", "050", "070", "011", "058", "076", "082", "084",
        "221", "068", "057", "032", "033", "215", "035", "039", "040", "214",
        "090175", "090110", "090134", "090149", "090097"
    ];
    valid_codes.contains(&bank_code)
}

pub async fn get_settlement_status(
    State(state): State<AppState>,
    Path(payment_id): Path<Uuid>,
    Extension(merchant): Extension<AuthenticatedMerchant>,
) -> Result<Json<crate::settlements::Settlement>, StatusCode> {
    let settlement = crate::settlements::get_settlement_status(&state, payment_id).await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    
    // Verify merchant owns this settlement
    if settlement.merchant_id != merchant.merchant_id {
        return Err(StatusCode::FORBIDDEN);
    }
    
    Ok(Json(settlement))
}

pub async fn list_settlements(
    State(state): State<AppState>,
    Extension(merchant): Extension<AuthenticatedMerchant>,
) -> Result<Json<Vec<crate::settlements::Settlement>>, StatusCode> {
    let settlements = sqlx::query_as!(
        crate::settlements::Settlement,
        r#"SELECT id, payment_id, merchant_id, amount_ngn, bank_account, bank_code, 
                  account_name, status, external_reference, provider, created_at, completed_at
           FROM settlements 
           WHERE merchant_id = $1 
           ORDER BY created_at DESC 
           LIMIT 50"#,
        merchant.merchant_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(settlements))
}

pub async fn get_merchant_dashboard(
    State(state): State<AppState>,
    Extension(merchant): Extension<AuthenticatedMerchant>,
) -> Result<Json<MerchantDashboard>, StatusCode> {
    let stats = sqlx::query!(
        r#"
        SELECT 
            COUNT(*) as total_transactions,
            SUM(CASE WHEN status = 'confirmed' THEN 1 ELSE 0 END) as successful_transactions,
            SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_transactions,
            SUM(CASE WHEN status = 'confirmed' THEN amount_usd ELSE 0 END) as total_volume_usd,
            SUM(CASE WHEN status = 'confirmed' THEN COALESCE(amount_ngn, 0) ELSE 0 END) as total_volume_ngn
        FROM payments 
        WHERE merchant_id = $1
        "#,
        merchant.merchant_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;
    
    let success_rate = if stats.total_transactions.unwrap_or(0) > 0 {
        stats.successful_transactions.unwrap_or(0) as f64 / stats.total_transactions.unwrap_or(1) as f64 * 100.0
    } else {
        0.0
    };

    let total_volume_usd = stats.total_volume_usd
        .map(|bd| bd.to_string().parse::<f64>().unwrap_or(0.0))
        .unwrap_or(0.0);
    let total_volume_ngn = stats.total_volume_ngn
        .map(|bd| bd.to_string().parse::<f64>().unwrap_or(0.0))
        .unwrap_or(0.0);
    
    Ok(Json(MerchantDashboard {
        merchant_id: merchant.merchant_id,
        total_volume_usd,
        total_volume_ngn,
        total_transactions: stats.total_transactions.unwrap_or(0),
        successful_transactions: stats.successful_transactions.unwrap_or(0),
        pending_transactions: stats.pending_transactions.unwrap_or(0),
        success_rate,
    }))
}

pub async fn get_exchange_rates(
    State(state): State<AppState>,
) -> Result<Json<ExchangeRate>, StatusCode> {
    let rate = crate::exchange::get_current_rate(&state).await
        .map_err(|e| {
            tracing::error!("Failed to get exchange rate: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    Ok(Json(rate))
}

pub async fn system_health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let db_healthy = check_database_health(&state.db).await;
    let solana_stats = state.solana_client.get_endpoint_stats().await;
    let exchange_healthy = crate::exchange::get_current_rate(&state).await.is_ok();
    
    let solana_healthy = solana_stats.iter().any(|(_, health)| health.consecutive_failures < 3);
    
    Json(serde_json::json!({
        "status": if db_healthy && solana_healthy && exchange_healthy { "healthy" } else { "degraded" },
        "services": {
            "database": if db_healthy { "up" } else { "down" },
            "solana_endpoints": solana_stats.iter().map(|(url, health)| {
                serde_json::json!({
                    "url": url,
                    "status": if health.consecutive_failures < 3 { "up" } else { "down" },
                    "success_rate": health.success_rate,
                    "avg_latency_ms": health.avg_latency_ms,
                    "consecutive_failures": health.consecutive_failures
                })
            }).collect::<Vec<_>>(),
            "exchange_api": if exchange_healthy { "up" } else { "down" }
        },
        "timestamp": chrono::Utc::now(),
        "version": "0.1.0"
    }))
}

async fn check_database_health(db: &sqlx::PgPool) -> bool {
    sqlx::query("SELECT 1").fetch_one(db).await.is_ok()
}

pub async fn handle_webhook(
    State(_state): State<AppState>,
    Path(_payment_id): Path<Uuid>,
    Json(_payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // TODO: Implement webhook handling for payment confirmations
    Ok(Json(serde_json::json!({
        "status": "received",
        "timestamp": chrono::Utc::now()
    })))
}

pub async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "ZendFi Payment Gateway",
        "timestamp": chrono::Utc::now(),
        "version": "0.1.0"
    }))
}