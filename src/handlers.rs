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
use rand::rngs::OsRng;
use rand::Rng;
use ed25519_dalek::SigningKey;
use base64::Engine;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, Key
};
use argon2::Argon2;
use zeroize::Zeroize;

pub async fn create_payment(
    State(state): State<AppState>,
    Extension(merchant): Extension<AuthenticatedMerchant>,
    Json(request): Json<CreatePaymentRequest>,
) -> Result<Json<PaymentResponse>, StatusCode> {
    if request.amount <= 0.0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let token = match request.token.as_deref() {
        Some("USDT") => crate::solana::SupportedToken::Usdt,
        Some("SOL") => crate::solana::SupportedToken::Sol,
        _ => crate::solana::SupportedToken::Usdc,
    };

    tracing::info!("Creating {} payment for ${} {} (merchant: {})", 
                   format!("{:?}", token).to_uppercase(), 
                   request.amount, 
                   request.currency,
                   merchant.merchant_id);

    let (amount_usd, amount_ngn) = if request.currency == "NGN" {
        let rate = crate::exchange::get_current_rate(&state).await
            .map_err(|e| {
                tracing::error!("Failed to get exchange rate: {}", e);
                StatusCode::SERVICE_UNAVAILABLE
            })?;
        let usd_amount = request.amount / rate.usd_to_ngn;
        (usd_amount, Some(request.amount))
    } else {
        let rate = crate::exchange::get_current_rate(&state).await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let ngn_amount = request.amount * rate.usd_to_ngn;
        (request.amount, Some(ngn_amount))
    };
    
    let payment_id = Uuid::new_v4();
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(15);
    let amount_usd_bd = BigDecimal::from_f64(amount_usd).unwrap();
    let amount_ngn_bd = amount_ngn.and_then(|n| BigDecimal::from_f64(n));

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

    tracing::info!("Generated {} payment QR: {}",
        format!("{:?}", token).to_uppercase(),
        qr_code);

    sqlx::query!(
        r#"
        INSERT INTO payments (id, merchant_id, amount_usd, amount_ngn, status, metadata, 
                             payment_token, sol_settlement_preference, created_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#,
        payment_id,
        merchant.merchant_id,
        amount_usd_bd,
        amount_ngn_bd,
        PaymentStatus::Pending as PaymentStatus,
        request.metadata.unwrap_or(serde_json::json!({})),
        token_string,
        request.sol_settlement_preference,
        chrono::Utc::now(),
        expires_at
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create payment: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let _ = create_webhook_event(&state, payment_id, WebhookEventType::PaymentCreated).await;
    
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
    if let Some(ref wallet_addr) = request.wallet_address {
        if crate::solana::validate_solana_address(wallet_addr).is_err() {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    if let Some(ref bank_code) = request.bank_code {
        if !is_valid_nigerian_bank_code(bank_code) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    if let Some(ref webhook_url) = request.webhook_url {
        if !is_valid_webhook_url(webhook_url).await {
            tracing::warn!("Invalid webhook URL provided: {}", webhook_url);
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    let settlement_pref = request.settlement_preference
        .as_deref()
        .map(SettlementPreference::from)
        .unwrap_or(SettlementPreference::AutoNgn);

    match settlement_pref {
        SettlementPreference::AutoNgn | SettlementPreference::PerPayment => {
            if request.bank_account_number.is_none() || request.bank_code.is_none() {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
        SettlementPreference::AutoUsdc => {
            // USDC-only merchants don't need bank details
        }
    }

    let merchant_id = Uuid::new_v4();

    let (merchant_wallet, wallet_generated) = if let Some(provided_wallet) = request.wallet_address {
        crate::solana::validate_solana_address(&provided_wallet)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        (provided_wallet, false)
    } else {
        let (wallet_pubkey, _keypair_path) = generate_merchant_wallet(&merchant_id, &state.config).await
        .map_err(|e| {
            tracing::error!("Failed to generate merchant wallet: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        (wallet_pubkey, true)
    };

    let merchant = sqlx::query!(
        r#"
        INSERT INTO merchants 
        (id, name, email, wallet_address, settlement_preference, wallet_generated,
         bank_account_number, bank_code, account_name, business_address,
         webhook_url, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12)
        RETURNING id, name, email, wallet_address
        "#,
        merchant_id,
        request.name,
        request.email,
        merchant_wallet,
        format!("{:?}", settlement_pref).to_lowercase(), 
        wallet_generated,
        request.bank_account_number,
        request.bank_code,
        request.account_name,
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
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(serde_json::json!({
        "merchant": {
            "id": merchant.id,
            "name": merchant.name,
            "email": merchant.email,
            "wallet_address": merchant.wallet_address,
            "wallet_generated": wallet_generated
        },
        "api_key": api_key,
        "message": format!(
            "Merchant created successfully. Settlements will be processed to {}.", 
            match settlement_pref {
                SettlementPreference::AutoNgn => "your NGN bank account",
                SettlementPreference::AutoUsdc => "your USDC wallet", 
                SettlementPreference::PerPayment => "NGN or USDC based on payment settings"
            }
        ),
        "warning": "Store this API key securely. It will not be shown again."
    })))
}

async fn generate_merchant_wallet(
    merchant_id: &Uuid,
    config: &crate::config::Config,
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    
    let public_key_bytes = verifying_key.to_bytes();
    let address = bs58::encode(public_key_bytes).into_string();
    
    let keypair_data = serde_json::json!({
        "public_key": address,
        "private_key": hex::encode(signing_key.to_bytes()),
        "merchant_id": merchant_id,
        "created_at": chrono::Utc::now(),
        "algorithm": "ed25519",
        "curve": "curve25519",
        "version": "1.0"
    });

    let keypair_dir = &config.merchant_wallet_dir;
    std::fs::create_dir_all(keypair_dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(keypair_dir)?.permissions();
        perms.set_mode(0o700); // rwx------
        std::fs::set_permissions(keypair_dir, perms)?;
    }
    
    let keypair_path = format!("{}/{}.json", keypair_dir, merchant_id);
    
    let encrypted_data = encrypt_keypair_data(&keypair_data.to_string(), merchant_id)?;
    std::fs::write(&keypair_path, encrypted_data)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&keypair_path)?.permissions();
        perms.set_mode(0o600); // rw-------
        std::fs::set_permissions(&keypair_path, perms)?;
    }
    
    tracing::info!("Generated secure Solana wallet {} for merchant {}", address, merchant_id);
    
    Ok((address, keypair_path))
}

fn encrypt_keypair_data(data: &str, merchant_id: &Uuid) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let master_key = std::env::var("SOLAPAY_MASTER_KEY")
        .unwrap_or_else(|_| "solapay_default_key_change_in_production".to_string());
    
    let salt = format!("solapay_salt_{}", merchant_id);
    let argon2 = Argon2::default();

    let mut derived_key = [0u8; 32];
    argon2.hash_password_into(
        master_key.as_bytes(),
        salt.as_bytes(),
        &mut derived_key
    ).map_err(|e| format!("Key derivation failed: {}", e))?;
    
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
    let nonce_bytes = aes_gcm::aead::OsRng.gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, data.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;
    
    let mut encrypted_data = Vec::new();
    encrypted_data.extend_from_slice(&nonce_bytes);
    encrypted_data.extend_from_slice(&ciphertext);
    
    let mut derived_key_mut = derived_key;
    derived_key_mut.zeroize();
    
    Ok(base64::engine::general_purpose::STANDARD.encode(encrypted_data))
}

fn decrypt_keypair_data(encrypted: &str, merchant_id: &Uuid) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let master_key = std::env::var("SOLAPAY_MASTER_KEY")
        .unwrap_or_else(|_| "solapay_default_key_change_in_production".to_string());
    
    let salt = format!("solapay_salt_{}", merchant_id);
    let argon2 = Argon2::default();
    
    let mut derived_key = [0u8; 32];
    argon2.hash_password_into(
        master_key.as_bytes(),
        salt.as_bytes(),
        &mut derived_key
    ).map_err(|e| format!("Key derivation failed: {}", e))?;

    let encrypted_data = base64::engine::general_purpose::STANDARD.decode(encrypted)?;
    
    if encrypted_data.len() < 12 {
        return Err("Invalid encrypted data: too short".into());
    }

    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))?;
    
    let mut derived_key_mut = derived_key;
    derived_key_mut.zeroize();
    
    Ok(String::from_utf8(plaintext)?)
}

#[allow(dead_code)]
async fn load_merchant_keypair(merchant_id: &Uuid) -> Result<SigningKey, Box<dyn std::error::Error + Send + Sync>> {
    let keypair_path = format!("/secure/merchant_wallets/{}.json", merchant_id);
    
    let encrypted_data = std::fs::read_to_string(&keypair_path)?;
    let decrypted_json = decrypt_keypair_data(&encrypted_data, merchant_id)?;
    
    let keypair_info: serde_json::Value = serde_json::from_str(&decrypted_json)?;
    let private_key_hex = keypair_info["private_key"]
        .as_str()
        .ok_or("Missing private key in keypair data")?;
    
    let private_key_bytes = hex::decode(private_key_hex)?;
    let signing_key = SigningKey::from_bytes(&private_key_bytes.try_into()
        .map_err(|_| "Invalid private key length")?);
    
    Ok(signing_key)
}

fn is_valid_nigerian_bank_code(bank_code: &str) -> bool {
    let valid_codes = [
        "044", "023", "063", "050", "070", "011", "058", "076", "082", "084",
        "221", "068", "057", "032", "033", "215", "035", "039", "040", "214",
        "090175", "090110", "090134", "090149", "090097"
    ];
    valid_codes.contains(&bank_code)
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

pub async fn get_settlement_status(
    State(state): State<AppState>,
    Path(payment_id): Path<Uuid>,
    Extension(merchant): Extension<AuthenticatedMerchant>,
) -> Result<Json<crate::models::Settlement>, StatusCode> {
    let settlement = sqlx::query_as!(
        crate::models::Settlement,
        r#"SELECT id, payment_id, 
                  COALESCE(payment_token, 'USDC') as "payment_token!: String",
                  COALESCE(settlement_token, 'NGN') as "settlement_token!: String", 
                  COALESCE(amount_recieved, 0) as "amount_recieved!: BigDecimal",
                  COALESCE(amount_settled, amount_ngn) as "amount_settled!: BigDecimal",
                  exchange_rate_used,
                  sol_swap_signature,
                  merchant_id, amount_ngn, bank_account, bank_code, 
                  account_name, status, batch_id, estimated_processing_time,
                  external_reference, provider, created_at, completed_at
           FROM settlements WHERE payment_id = $1"#,
        payment_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;

    if settlement.merchant_id != merchant.merchant_id {
        return Err(StatusCode::FORBIDDEN);
    }
    
    Ok(Json(settlement))
}

pub async fn list_settlements(
    State(state): State<AppState>,
    Extension(merchant): Extension<AuthenticatedMerchant>,
) -> Result<Json<Vec<crate::models::Settlement>>, StatusCode> {
    let settlements = sqlx::query_as!(
        crate::models::Settlement,
        r#"SELECT id, payment_id,
                  COALESCE(payment_token, 'USDC') as "payment_token!: String",
                  COALESCE(settlement_token, 'NGN') as "settlement_token!: String",
                  COALESCE(amount_recieved, 0) as "amount_recieved!: BigDecimal", 
                  COALESCE(amount_settled, amount_ngn) as "amount_settled!: BigDecimal",
                  exchange_rate_used,
                  sol_swap_signature,
                  merchant_id, amount_ngn, bank_account, bank_code, 
                  account_name, status, batch_id, estimated_processing_time,
                  external_reference, provider, created_at, completed_at
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
            SUM(CASE WHEN status = 'confirmed' THEN COALESCE(amount_usd, 0) ELSE 0 END) as total_volume_usd,
            SUM(CASE WHEN status = 'confirmed' THEN COALESCE(amount_ngn, 0) ELSE 0 END) as total_volume_ngn,
            COUNT(*) as total_transactions,
            COUNT(CASE WHEN status = 'confirmed' THEN 1 END) as successful_transactions,
            COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_transactions
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
    
    let system_metrics = get_system_metrics(&state.db).await;
    
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
        "metrics": system_metrics,
        "timestamp": chrono::Utc::now(),
        "version": "0.1.0"
    }))
}

async fn get_system_metrics(db: &sqlx::PgPool) -> serde_json::Value {
    let stats = sqlx::query!(
        r#"
        SELECT 
            COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending,
            COUNT(CASE WHEN status = 'confirmed' THEN 1 END) as confirmed,
            COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed,
            COUNT(CASE WHEN created_at > NOW() - INTERVAL '24 hours' THEN 1 END) as payments_24h,
            COUNT(CASE WHEN created_at > NOW() - INTERVAL '1 hour' THEN 1 END) as payments_1h
        FROM payments
        "#
    )
    .fetch_optional(db)
    .await
    .unwrap_or(None);

    if let Some(row) = stats {
        serde_json::json!({
            "payments": {
                "pending": row.pending.unwrap_or(0),
                "confirmed": row.confirmed.unwrap_or(0),
                "failed": row.failed.unwrap_or(0),
                "last_24h": row.payments_24h.unwrap_or(0),
                "last_1h": row.payments_1h.unwrap_or(0)
            }
        })
    } else {
        serde_json::json!({
            "payments": {
                "pending": 0,
                "confirmed": 0,
                "failed": 0,
                "last_24h": 0,
                "last_1h": 0
            }
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