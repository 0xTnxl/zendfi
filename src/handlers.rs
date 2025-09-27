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
use hmac::{Hmac, Mac};
use sha2::Sha256;
use bigdecimal::ToPrimitive;
use bip39::{Mnemonic, Language};
use ed25519_dalek::Signer;
use tracing::instrument;

fn validate_payment_amount(amount: f64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if amount <= 0.0 {
        return Err("Payment amount must be positive".into());
    }
    if amount > 1_000_000.0 {
        return Err("Payment amount exceeds maximum limit".into());
    }
    if amount < 0.01 {
        return Err("Payment amount below minimum ($0.01)".into());
    }
    Ok(())
}

fn validate_merchant_data(request: &CreateMerchantRequest) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if request.name.trim().is_empty() {
        return Err("Merchant name cannot be empty".into());
    }
    if request.name.len() > 100 {
        return Err("Merchant name too long (max 100 characters)".into());
    }
    if !request.email.contains('@') {
        return Err("Invalid email format".into());
    }
    if request.business_address.trim().is_empty() {
        return Err("Business address is required".into());
    }
    Ok(())
}

#[instrument(skip(state), fields(merchant_id = %merchant.merchant_id))]
pub async fn create_payment(
    State(state): State<AppState>,
    Extension(merchant): Extension<AuthenticatedMerchant>,
    Json(request): Json<CreatePaymentRequest>,
) -> Result<Json<PaymentResponse>, StatusCode> {
    tracing::info!("Creating payment for ${} {}", request.amount, request.currency);

    validate_payment_amount(request.amount)
        .map_err(|e| {
            tracing::warn!("Invalid payment amount: {}", e);
            StatusCode::BAD_REQUEST
        })?;
    
    if request.amount <= 0.0 || request.amount > 1_000_000.0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    if request.currency != "USD" {
        tracing::warn!("Unsupported currency: {}", request.currency);
        return Err(StatusCode::BAD_REQUEST);
    }

    if !check_merchant_limits(&state, merchant.merchant_id, request.amount).await
        .map_err(|e| {
            tracing::error!("Error checking merchant limits: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    {
        tracing::warn!("Merchant {} exceeded payment limits", merchant.merchant_id);
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let token = match request.token.as_deref() {
        Some("USDT") => crate::solana::SupportedToken::Usdt,
        Some("SOL") => crate::solana::SupportedToken::Sol,
        _ => crate::solana::SupportedToken::Usdc,
    };

    if token.get_mint_address(&state.config.solana_network).is_none() && !matches!(token, crate::solana::SupportedToken::Sol) {
        tracing::warn!("Unsupported token for network: {:?} on {}", token, state.config.solana_network);
        return Err(StatusCode::BAD_REQUEST);
    }

    let amount_usd = request.amount;
    let payment_id = Uuid::new_v4();
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(15);
    let amount_usd_bd = BigDecimal::from_f64(amount_usd).unwrap();
    let token_string = format!("{:?}", token).to_uppercase();
    
    let qr_code = crate::solana::generate_payment_qr(
        &payment_id,
        amount_usd,
        &state.config.recipient_wallet,
        &state.config.solana_network,
        token.clone()
    ).await.map_err(|e| {
        tracing::error!("Failed to generate QR code: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut tx = state.db.begin().await
        .map_err(|e| {
            tracing::error!("Failed to begin transaction: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    sqlx::query!(
        r#"
        INSERT INTO payments (id, merchant_id, amount_usd, status, metadata, 
                             payment_token, settlement_preference_override, created_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
        payment_id,
        merchant.merchant_id,
        amount_usd_bd,
        PaymentStatus::Pending as PaymentStatus,
        request.metadata.unwrap_or(serde_json::json!({})),
        token_string,
        request.settlement_preference_override,
        chrono::Utc::now(),
        expires_at
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create payment: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Audit log with correlation ID
    sqlx::query!(
        r#"
        INSERT INTO audit_log (table_name, record_id, action, new_values, changed_by)
        VALUES ('payments', $1, 'INSERT', $2, $3)
        "#,
        payment_id,
        serde_json::json!({
            "amount_usd": amount_usd,
            "payment_token": token_string,
            "merchant_id": merchant.merchant_id
        }),
        merchant.merchant_id
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("Failed to insert audit log: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tx.commit().await
        .map_err(|e| {
            tracing::error!("Failed to commit transaction: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Create webhook event (non-blocking)
    if let Err(e) = crate::webhooks::create_webhook_event(&state, payment_id, crate::webhooks::WebhookEventType::PaymentCreated).await {
        tracing::error!("Failed to create webhook event: {}", e);
        // Don't fail the payment creation for webhook errors
    }

    tracing::info!("Payment {} created successfully", payment_id);
    
    Ok(Json(PaymentResponse {
        id: payment_id,
        amount: request.amount,
        currency: request.currency,
        status: PaymentStatus::Pending,
        qr_code,
        payment_url: format!("{}/pay/{}", state.config.frontend_url, payment_id),
        expires_at,
        settlement_info: None,
    }))
}

async fn check_merchant_limits(
    state: &AppState,
    merchant_id: Uuid,
    amount: f64,
) -> Result<bool, StatusCode> {
    let limits = sqlx::query!(
        r#"
        SELECT max_payment_amount, daily_volume_limit, rate_limit_per_hour
        FROM merchant_limits 
        WHERE merchant_id = $1 AND is_active = true
        "#,
        merchant_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let (max_payment, daily_limit, hourly_rate) = if let Some(l) = limits {
        (
            l.max_payment_amount.to_f64().unwrap_or(10000.0),
            l.daily_volume_limit.to_f64().unwrap_or(50000.0),
            l.rate_limit_per_hour
        )
    } else {
        (10000.0, 50000.0, 100)
    };

    if amount > max_payment {
        return Ok(false);
    }

    let today_volume = sqlx::query!(
        r#"
        SELECT COALESCE(SUM(amount_usd), 0) as daily_volume
        FROM payments 
        WHERE merchant_id = $1 
          AND created_at >= CURRENT_DATE 
          AND status IN ('pending', 'confirmed')
        "#,
        merchant_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let daily_volume_f64 = today_volume.daily_volume
        .and_then(|v| v.to_f64())
        .unwrap_or(0.0);
        
    if daily_volume_f64 + amount > daily_limit {
        return Ok(false);
    }

    let hourly_count = sqlx::query!(
        r#"
        SELECT COUNT(*) as hourly_count
        FROM payments 
        WHERE merchant_id = $1 
          AND created_at >= NOW() - INTERVAL '1 hour'
        "#,
        merchant_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if hourly_count.hourly_count.unwrap_or(0) >= hourly_rate as i64 {
        return Ok(false);
    }

    Ok(true)
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
            tracing::info!("Manual settlement processed successfully for payment {}", payment_id);
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
        r#"SELECT id, merchant_id, amount_usd, status as "status: PaymentStatus",
           transaction_signature, customer_wallet, metadata, created_at, expires_at
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

#[instrument(skip(state))]
pub async fn create_merchant(
    State(state): State<AppState>,
    Json(request): Json<CreateMerchantRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    tracing::info!("Creating merchant: {}", request.name);

    validate_merchant_data(&request)
        .map_err(|e| {
            tracing::warn!("Invalid merchant data: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    if let Some(ref webhook_url) = request.webhook_url {
        if !is_valid_webhook_url(webhook_url).await {
            tracing::warn!("Invalid webhook URL provided: {}", webhook_url);
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    let merchant_id = Uuid::new_v4();

    let (merchant_wallet, wallet_generated, generation_method) = if let Some(provided_wallet) = request.wallet_address {
        crate::solana::validate_solana_address(&provided_wallet)
            .map_err(|e| {
                tracing::warn!("Invalid wallet address: {}", e);
                StatusCode::BAD_REQUEST
            })?;
        (provided_wallet, false, "provided".to_string())
    } else {
        let method = request.wallet_generation_method
            .as_deref()
            .unwrap_or("simple");

        match method {
            "mnemonic" => {
                let wallet_pubkey = generate_merchant_wallet_from_mnemonic(&merchant_id, &state).await
                    .map_err(|e| {
                        tracing::error!("Failed to generate mnemonic wallet: {}", e);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;
                (wallet_pubkey, true, "mnemonic".to_string())
            }
            _ => {
                let wallet_pubkey = generate_simple_merchant_wallet(&merchant_id, &state).await
                    .map_err(|e| {
                        tracing::error!("Failed to generate simple wallet: {}", e);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;
                (wallet_pubkey, true, "simple".to_string())
            }
        }
    };

    let settlement_preference = request.settlement_preference
        .as_deref()
        .map(SettlementPreference::from)
        .unwrap_or(SettlementPreference::AutoUsdc);

    let _merchant = sqlx::query!(
        r#"
        INSERT INTO merchants 
        (id, name, email, wallet_address, settlement_preference, wallet_generated,
         business_address, webhook_url, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
        RETURNING id, name, email, wallet_address
        "#,
        merchant_id,
        request.name,
        request.email,
        merchant_wallet,
        format!("{:?}", settlement_preference).to_lowercase(), 
        wallet_generated,
        request.business_address,
        request.webhook_url,
        chrono::Utc::now()
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create merchant: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let api_key = crate::auth::generate_api_key_string(&state, merchant_id).await
        .map_err(|e| {
            tracing::error!("Failed to generate API key: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    tracing::info!("Merchant {} created successfully with wallet {}", merchant_id, merchant_wallet);

    Ok(Json(serde_json::json!({
        "merchant": {
            "id": merchant_id,
            "name": request.name,
            "wallet_address": merchant_wallet,
            "settlement_preference": format!("{:?}", settlement_preference).to_lowercase(),
            "wallet_generation_method": generation_method
        },
        "api_key": api_key,
        "message": match generation_method.as_str() {
            "mnemonic" => "Merchant created with BIP39 mnemonic-derived wallet! Store your master mnemonic securely.",
            "simple" => "Merchant created with secure deterministic wallet! Your wallet is secured by our enterprise key management.",
            "provided" => "Merchant created with your provided wallet address.",
            _ => "Merchant created successfully!"
        },
        "security_note": match generation_method.as_str() {
            "mnemonic" => "Your wallet can be recovered using the master mnemonic phrase. Keep it secure!",
            "simple" => "Your wallet is derived deterministically from secure system keys.",
            "provided" => "You control your wallet private keys directly.",
            _ => ""
        },
        "warning": "Store this API key securely. It will not be shown again."
    })))
}

async fn generate_simple_merchant_wallet(
    merchant_id: &Uuid,
    state: &AppState,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let master_secret = std::env::var("SOLAPAY_MASTER_SEED")
        .map_err(|_| "SOLAPAY_MASTER_SEED environment variable is required for security")?;
    
    if master_secret.len() < 32 {
        return Err("SOLAPAY_MASTER_SEED must be at least 32 characters".into());
    }
    
    let mut mac = Hmac::<Sha256>::new_from_slice(master_secret.as_bytes())?;
    mac.update(merchant_id.as_bytes());
    let seed = mac.finalize();

    let seed_bytes: [u8; 32] = seed.into_bytes().into();

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
    let verifying_key = signing_key.verifying_key();
    let public_key = bs58::encode(verifying_key.to_bytes()).into_string();

    store_wallet_metadata(merchant_id, &public_key, 0, "simple", state).await?;
    
    tracing::info!("Generated wallet {} for merchant {}", public_key, merchant_id);
    
    Ok(public_key)
}

async fn generate_merchant_wallet_from_mnemonic(
    merchant_id: &Uuid,
    state: &AppState,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let mnemonic_phrase = std::env::var("SOLAPAY_MASTER_MNEMONIC")
        .map_err(|_| "SOLAPAY_MASTER_MNEMONIC environment variable must be set")?;

    let mnemonic = Mnemonic::parse_in_normalized(Language::English, &mnemonic_phrase)
        .map_err(|e| format!("Invalid mnemonic phrase: {}", e))?;

    let passphrase = format!("merchant_{}", merchant_id);
    let seed = mnemonic.to_seed(&passphrase);

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&seed[..32]);

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();
    let public_key = bs58::encode(verifying_key.to_bytes()).into_string();

    let merchant_index = get_merchant_derivation_index(merchant_id, state).await?;

    store_wallet_metadata(merchant_id, &public_key, merchant_index, "mnemonic-derived", state).await?;
    
    tracing::info!("Generated mnemonic-derived wallet {} for merchant {}", public_key, merchant_id);
    
    Ok(public_key)
}

async fn get_merchant_derivation_index(
    _merchant_id: &Uuid,
    state: &AppState
) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
    let result = sqlx::query!(
        "SELECT COALESCE(MAX(derivation_index), 0) + 1 as next_index FROM merchant_wallets"
    )
    .fetch_one(&state.db)
    .await?;
    
    Ok(result.next_index.unwrap_or(1) as u32)
}

async fn store_wallet_metadata(
    merchant_id: &Uuid,
    public_key: &str,
    derivation_index: u32,
    derivation_path: &str,
    state: &AppState
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    sqlx::query!(
        r#"
        INSERT INTO merchant_wallets 
        (merchant_id, public_key, derivation_index, derivation_path, created_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        merchant_id,
        public_key,
        derivation_index as i32,
        derivation_path,
        chrono::Utc::now()
    )
    .execute(&state.db)
    .await?;
    
    Ok(())
}

#[allow(dead_code)]
pub async fn sign_settlement_transaction(
    state: &AppState,
    merchant_id: Uuid,
    transaction_data: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let wallet_info = sqlx::query!(
        "SELECT derivation_path FROM merchant_wallets WHERE merchant_id = $1",
        merchant_id
    )
    .fetch_one(&state.db)
    .await?;

    let signature = if wallet_info.derivation_path == "simple" {
        let master_secret = std::env::var("SOLAPAY_MASTER_SEED")
            .map_err(|_| "SOLAPAY_MASTER_SEED environment variable is required for security")?;
        
        if master_secret.len() < 32 {
            return Err("SOLAPAY_MASTER_SEED must be at least 32 characters".into());
        }
        
        let mut mac = Hmac::<Sha256>::new_from_slice(master_secret.as_bytes())?;
        mac.update(merchant_id.as_bytes());
        let seed = mac.finalize();

        let seed_bytes: [u8; 32] = seed.into_bytes().into();
        
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
        signing_key.sign(transaction_data)
    } else if wallet_info.derivation_path == "mnemonic-derived" {
        let mnemonic_phrase = std::env::var("SOLAPAY_MASTER_MNEMONIC")
            .map_err(|_| "SOLAPAY_MASTER_MNEMONIC environment variable is required")?;
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &mnemonic_phrase)
            .map_err(|e| format!("Invalid mnemonic phrase: {}", e))?;
        let passphrase = format!("merchant_{}", merchant_id);
        let seed = mnemonic.to_seed(&passphrase);
        
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&seed[..32]);
        
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
        signing_key.sign(transaction_data)
    } else {
        return Err("Unknown wallet derivation method".into());
    };
    
    Ok(signature.to_bytes().to_vec())
}

async fn is_valid_webhook_url(url: &str) -> bool {
    if !validate_webhook_url_format(url) {
        return false;
    }
    
    let env = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
    
    match env.as_str() {
        "development" | "test" => {
            tracing::info!("Development mode: accepting webhook URL {}", url);
            true
        }
        "staging" => {
            is_testing_webhook_url(url) || perform_lightweight_webhook_check(url).await
        }
        "production" => {
            if is_testing_webhook_url(url) {
                tracing::warn!("Testing webhook URL in production: {}", url);
                false
            } else {
                perform_production_webhook_check(url).await
            }
        }
        _ => validate_webhook_url_format(url)
    }
}

async fn perform_production_webhook_check(url: &str) -> bool {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .user_agent("Solapay-Webhook-Validator/1.0")
        .build()
        .unwrap();

    match client.head(url).send().await {
        Ok(response) => {
            let status = response.status();
            if status.is_success() || status.is_client_error() {
                true
            } else {
                tracing::warn!("Webhook URL returned server error {}: {}", status, url);
                false
            }
        }
        Err(e) => {
            if e.is_timeout() {
                tracing::warn!("Webhook URL timeout (allowing): {}", url);
                true 
            } else {
                tracing::error!("Webhook URL connection failed: {}: {}", url, e);
                false 
            }
        }
    }
}

fn validate_webhook_url_format(url: &str) -> bool {
    if !url.starts_with("https://") {
        tracing::warn!("Webhook URL must use HTTPS: {}", url);
        return false;
    }

    if url::Url::parse(url).is_err() {
        tracing::warn!("Invalid URL format: {}", url);
        return false;
    }

    if url.contains("localhost") || url.contains("127.0.0.1") || url.contains("192.168.") {
        tracing::warn!("Webhook URL cannot be localhost or private IP: {}", url);
        return false;
    }

    if url.len() > 2048 {
        tracing::warn!("Webhook URL too long: {}", url);
        return false;
    }

    true
}

fn is_testing_webhook_url(url: &str) -> bool {
    let testing_domains = [
        "webhook.site",
        "webhooks.test",
        "ngrok.io",
        "ngrok.app", 
        "localtunnel.me",
        "requestbin.com",
        "hookb.in",
        "beeceptor.com"
    ];
    
    testing_domains.iter().any(|domain| url.contains(domain))
}

async fn perform_lightweight_webhook_check(url: &str) -> bool {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap();

    match client.get(url).send().await {
        Ok(_) => {
            tracing::info!("Webhook URL connectivity verified: {}", url);
            true
        }
        Err(e) => {
            tracing::warn!("Webhook URL check failed (but allowing): {}: {}", url, e);
            true 
        }
    }
}

pub async fn get_merchant_dashboard(
    State(state): State<AppState>,
    Extension(merchant): Extension<AuthenticatedMerchant>,
) -> Result<Json<MerchantDashboard>, StatusCode> {
    let stats = sqlx::query!(
        r#"
        SELECT 
            COUNT(*) as total_transactions,
            COUNT(*) FILTER (WHERE status = 'confirmed') as successful_transactions,
            COUNT(*) FILTER (WHERE status = 'pending') as pending_transactions,
            COALESCE(SUM(amount_usd), 0) as total_volume_usd
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
        .and_then(|v| v.to_f64())
        .unwrap_or(0.0);
    
    Ok(Json(MerchantDashboard {
        merchant_id: merchant.merchant_id,
        total_volume_usd,
        total_volume_ngn: 0.0, 
        total_transactions: stats.total_transactions.unwrap_or(0),
        successful_transactions: stats.successful_transactions.unwrap_or(0),
        pending_transactions: stats.pending_transactions.unwrap_or(0),
        success_rate,
    }))
}

pub async fn system_health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let db_healthy = check_database_health(&state.db).await;
    let solana_stats = state.solana_client.get_endpoint_stats().await;
    let solana_healthy = solana_stats.iter().any(|(_, health)| health.consecutive_failures < 3);

    let config_issues = check_security_config().await;
    let security_healthy = config_issues.is_empty();
    
    let system_metrics = get_system_metrics(&state.db).await;
    
    let overall_status = if db_healthy && solana_healthy && security_healthy {
        "healthy"
    } else if db_healthy && solana_healthy {
        "warning"
    } else {
        "unhealthy"
    };
    
    Json(serde_json::json!({
        "status": overall_status,
        "services": {
            "database": if db_healthy { "up" } else { "down" },
            "solana_rpc": if solana_healthy { "up" } else { "degraded" },
            "security": if security_healthy { "ok" } else { "warning" },
            "jupiter_dex": "up"
        },
        "security_warnings": config_issues,
        "metrics": system_metrics,
        "timestamp": chrono::Utc::now(),
        "version": "0.3.0 - Security Improved"
    }))
}

async fn check_security_config() -> Vec<String> {
    let mut warnings = Vec::new();
    
    // Check if master seed is set
    if std::env::var("SOLAPAY_MASTER_SEED").is_err() {
        warnings.push("SOLAPAY_MASTER_SEED not configured - merchant wallets cannot be generated".to_string());
    } else if let Ok(seed) = std::env::var("SOLAPAY_MASTER_SEED") {
        if seed.len() < 32 {
            warnings.push("SOLAPAY_MASTER_SEED is too short (minimum 32 characters)".to_string());
        }
    }
    
    // Check if running in development with weak settings
    if let Ok(env) = std::env::var("ENVIRONMENT") {
        if env == "production" {
            if std::env::var("RUST_LOG").unwrap_or_default().contains("debug") {
                warnings.push("Debug logging enabled in production".to_string());
            }
        }
    }
    
    warnings
}

async fn get_system_metrics(db: &sqlx::PgPool) -> serde_json::Value {
    let stats = sqlx::query!(
        r#"
        SELECT 
            COUNT(*) as total_payments,
            COUNT(*) FILTER (WHERE status = 'confirmed') as confirmed_payments,
            COUNT(*) FILTER (WHERE status = 'pending') as pending_payments,
            COALESCE(SUM(amount_usd), 0) as total_volume
        FROM payments
        WHERE created_at >= NOW() - INTERVAL '24 hours'
        "#
    )
    .fetch_optional(db)
    .await
    .unwrap_or(None);

    if let Some(row) = stats {
        serde_json::json!({
            "total_payments_24h": row.total_payments.unwrap_or(0),
            "confirmed_payments_24h": row.confirmed_payments.unwrap_or(0),
            "pending_payments_24h": row.pending_payments.unwrap_or(0),
            "total_volume_24h": row.total_volume
                .and_then(|v| v.to_f64())
                .unwrap_or(0.0)
        })
    } else {
        serde_json::json!({
            "total_payments_24h": 0,
            "confirmed_payments_24h": 0,
            "pending_payments_24h": 0,
            "total_volume_24h": 0.0
        })
    }
}

async fn check_database_health(db: &sqlx::PgPool) -> bool {
    sqlx::query("SELECT 1").fetch_one(db).await.is_ok()
}

pub async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "Solapay Payment Gateway",
        "timestamp": chrono::Utc::now(),
        "version": "0.1.0"
    }))
}