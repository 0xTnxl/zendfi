use axum::{
    extract::{State, Path},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use solana_sdk::signature::Signer;
use crate::{AppState, key_manager::SecureKeyManager, backup::BackupManager};

pub async fn verify_admin_token(token: &str) -> Result<(), StatusCode> {
    let admin_token = std::env::var("ADMIN_API_TOKEN")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    if token != admin_token {
        return Err(StatusCode::UNAUTHORIZED);
    }
    
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigrateKeyRequest {
    pub merchant_id: Option<Uuid>, 
    pub key_type: String, 
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigrateKeyResponse {
    pub success: bool,
    pub key_id: Uuid,
    pub public_key: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupTriggerResponse {
    pub backup_id: Uuid,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupListResponse {
    pub backups: Vec<BackupInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupInfo {
    pub id: Uuid,
    pub backup_type: String,
    pub backup_location: String,
    pub backup_size_bytes: Option<i64>,
    pub status: String,
    pub verification_status: Option<String>,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
}

/// Migrate filesystem key to encrypted storage
pub async fn migrate_key_to_encrypted(
    State(state): State<AppState>,
    Json(request): Json<MigrateKeyRequest>,
) -> Result<Json<MigrateKeyResponse>, StatusCode> {
    let key_manager = SecureKeyManager::from_env()
        .map_err(|e| {
            tracing::error!("Failed to initialize key manager: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let (keypair, owner_id, key_type) = if request.key_type == "escrow_wallet" {
        let keypair = crate::settlements::load_keypair_from_filesystem(&state)
            .map_err(|e| {
                tracing::error!("Failed to load escrow keypair: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        
        let system_uuid = Uuid::parse_str("00000000-0000-0000-0000-000000000001")
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        
        (keypair, system_uuid, "escrow_wallet")
    } else if request.key_type == "merchant_wallet" {
        let merchant_id = request.merchant_id
            .ok_or(StatusCode::BAD_REQUEST)?;

        let wallet_record = sqlx::query!(
            r#"
            SELECT public_key, derivation_index, derivation_path
            FROM merchant_wallets
            WHERE merchant_id = $1
            "#,
            merchant_id
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch merchant wallet: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            tracing::error!("No wallet found for merchant {}", merchant_id);
            StatusCode::NOT_FOUND
        })?;

        let master_seed = std::env::var("SOLAPAY_MASTER_SEED")
            .map_err(|_| {
                tracing::error!("SOLAPAY_MASTER_SEED not set");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        let derivation_index = wallet_record.derivation_index;
        
        if derivation_index <= 0 {
            tracing::error!("Invalid derivation index for merchant wallet: {}", derivation_index);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }

        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(master_seed.as_bytes())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        mac.update(format!("merchant_{}", derivation_index).as_bytes());
        let derived_seed = mac.finalize().into_bytes();

        let mut seed_32 = [0u8; 32];
        seed_32.copy_from_slice(&derived_seed[..32]);
        
        let keypair = solana_sdk::signer::keypair::Keypair::try_from(&seed_32[..])
            .map_err(|e| {
                tracing::error!("Failed to derive keypair: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        if keypair.pubkey().to_string() != wallet_record.public_key {
            tracing::error!("Derived keypair doesn't match stored public key");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }

        (keypair, merchant_id, "merchant_wallet")
    } else {
        return Err(StatusCode::BAD_REQUEST);
    };

    let key_id = key_manager
        .store_encrypted_keypair(
            &state,
            &keypair,
            key_type,
            owner_id,
            Some(serde_json::json!({
                "migrated_from": "filesystem",
                "migration_date": chrono::Utc::now()
            }))
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to store encrypted key: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let public_key = keypair.pubkey().to_string();

    tracing::info!("Successfully migrated {} key to encrypted storage: {}", key_type, key_id);

    Ok(Json(MigrateKeyResponse {
        success: true,
        key_id,
        public_key,
        message: format!("Key migrated successfully to encrypted storage"),
    }))
}

pub async fn trigger_backup(
    State(state): State<AppState>,
) -> Result<Json<BackupTriggerResponse>, StatusCode> {
    let backup_manager = BackupManager::from_env()
        .map_err(|e| {
            tracing::error!("Failed to initialize backup manager: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let backup_id = backup_manager
        .create_full_backup(&state)
        .await
        .map_err(|e| {
            tracing::error!("Backup failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(BackupTriggerResponse {
        backup_id,
        status: "in_progress".to_string(),
        message: "Backup initiated successfully".to_string(),
    }))
}

pub async fn list_backups(
    State(state): State<AppState>,
) -> Result<Json<BackupListResponse>, StatusCode> {
    let backups = sqlx::query!(
        r#"
        SELECT id, backup_type, backup_location, backup_size_bytes, 
               status, verification_status, start_time, end_time
        FROM backup_metadata
        ORDER BY start_time DESC
        LIMIT 50
        "#
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch backups: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let backup_list = backups
        .into_iter()
        .map(|b| BackupInfo {
            id: b.id,
            backup_type: b.backup_type,
            backup_location: b.backup_location,
            backup_size_bytes: b.backup_size_bytes,
            status: b.status,
            verification_status: b.verification_status,
            start_time: b.start_time,
            end_time: b.end_time,
        })
        .collect();

    Ok(Json(BackupListResponse {
        backups: backup_list,
    }))
}

pub async fn rotate_encryption_keys(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let old_manager = SecureKeyManager::from_env()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let new_master_key = SecureKeyManager::generate_master_key();
    
    tracing::warn!("Generated new master key - MUST BE SAVED SECURELY: {}", new_master_key);

    std::env::set_var("MASTER_ENCRYPTION_KEY_NEW", &new_master_key);
    
    let new_manager = SecureKeyManager::from_env()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let keys = sqlx::query!(
        "SELECT id FROM encrypted_keys WHERE is_active = TRUE"
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut rotated_count = 0;
    let mut failed_keys = Vec::new();

    for key_record in keys {
        match old_manager.rotate_key(&state, key_record.id, &new_manager).await {
            Ok(_) => {
                rotated_count += 1;
                tracing::info!("Rotated key: {}", key_record.id);
            }
            Err(e) => {
                tracing::error!("Failed to rotate key {}: {}", key_record.id, e);
                failed_keys.push(key_record.id.to_string());
            }
        }
    }

    Ok(Json(serde_json::json!({
        "success": failed_keys.is_empty(),
        "rotated_count": rotated_count,
        "failed_keys": failed_keys,
        "new_master_key": new_master_key,
        "message": "Key rotation completed. Save the new master key securely!"
    })))
}

pub async fn get_encryption_status(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let key_manager_available = SecureKeyManager::from_env().is_ok();
    
    let encrypted_key_count = sqlx::query!(
        "SELECT COUNT(*) as count FROM encrypted_keys WHERE is_active = TRUE"
    )
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .count
    .unwrap_or(0);

    let filesystem_key_exists = std::env::var("WALLET_KEYPAIR_PATH")
        .ok()
        .and_then(|path| std::fs::metadata(&path).ok())
        .is_some();

    Ok(Json(serde_json::json!({
        "key_manager_configured": key_manager_available,
        "encrypted_keys_count": encrypted_key_count,
        "filesystem_key_exists": filesystem_key_exists,
        "recommendation": if !key_manager_available {
            "Set MASTER_ENCRYPTION_KEY environment variable"
        } else if filesystem_key_exists && encrypted_key_count == 0 {
            "Migrate filesystem keys to encrypted storage"
        } else {
            "System is properly configured"
        }
    })))
}

pub async fn cleanup_old_backups(
    State(state): State<AppState>,
    Path(retention_days): Path<i32>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let backup_manager = BackupManager::from_env()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let deleted_count = backup_manager
        .cleanup_old_backups(&state, retention_days)
        .await
        .map_err(|e| {
            tracing::error!("Cleanup failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(serde_json::json!({
        "success": true,
        "deleted_count": deleted_count,
        "retention_days": retention_days
    })))
}

pub async fn get_settlement_history(
    State(state): State<AppState>,
    Path(merchant_id): Path<Uuid>,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    let settlements = sqlx::query!(
        r#"
        SELECT id, payment_id, payment_token, settlement_token, 
               amount_recieved, amount_settled, exchange_rate_used, 
               sol_swap_signature, merchant_id, status, external_reference,
               provider, created_at, completed_at, settlement_currency,
               recipient_wallet, transaction_signature
        FROM settlements
        WHERE merchant_id = $1
        ORDER BY created_at DESC
        LIMIT 100
        "#,
        merchant_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch settlements: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let settlements_json: Vec<serde_json::Value> = settlements
        .into_iter()
        .map(|s| {
            serde_json::json!({
                "id": s.id,
                "payment_id": s.payment_id,
                "payment_token": s.payment_token,
                "settlement_token": s.settlement_token,
                "amount_recieved": s.amount_recieved.map(|a| a.to_string()).unwrap_or_else(|| "0".to_string()),
                "amount_settled": s.amount_settled.map(|a| a.to_string()).unwrap_or_else(|| "0".to_string()),
                "exchange_rate_used": s.exchange_rate_used.map(|e| e.to_string()),
                "sol_swap_signature": s.sol_swap_signature,
                "merchant_id": s.merchant_id,
                "status": s.status,
                "external_reference": s.external_reference,
                "provider": s.provider,
                "created_at": s.created_at,
                "completed_at": s.completed_at,
                "settlement_currency": s.settlement_currency,
                "recipient_wallet": s.recipient_wallet,
                "transaction_signature": s.transaction_signature,
            })
        })
        .collect();

    Ok(Json(settlements_json))
}

pub async fn verify_encrypted_key(
    State(state): State<AppState>,
    Path(public_key): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let key_manager = SecureKeyManager::from_env()
        .map_err(|e| {
            tracing::error!("Key manager not configured: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    match key_manager.retrieve_keypair_by_pubkey(&state, &public_key).await {
        Ok(keypair) => {
            Ok(Json(serde_json::json!({
                "success": true,
                "public_key": keypair.pubkey().to_string(),
                "message": "Key verified successfully",
                "can_decrypt": true
            })))
        }
        Err(e) => {
            tracing::error!("Key verification failed: {}", e);
            Ok(Json(serde_json::json!({
                "success": false,
                "public_key": public_key,
                "message": format!("Verification failed: {}", e),
                "can_decrypt": false
            })))
        }
    }
}

pub async fn restore_from_backup(
    State(state): State<AppState>,
    Path(backup_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    tracing::warn!("CRITICAL: Database restore initiated for backup {}", backup_id);
    
    let backup_manager = BackupManager::from_env()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    backup_manager
        .restore_backup(backup_id, &state)
        .await
        .map_err(|e| {
            tracing::error!("Restore failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::warn!("Database restore completed for backup {}", backup_id);

    Ok(Json(serde_json::json!({
        "success": true,
        "backup_id": backup_id,
        "message": "Database restored successfully. Application restart recommended."
    })))
}

#[allow(dead_code)]
pub async fn get_key_info(
    State(state): State<AppState>,
    Path(public_key): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let key_info = sqlx::query!(
        r#"
        SELECT id, key_type, owner_id, public_key, encryption_version, is_active, created_at, last_used_at
        FROM encrypted_keys
        WHERE public_key = $1
        "#,
        public_key
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(serde_json::json!({
        "id": key_info.id,
        "key_type": key_info.key_type,
        "owner_id": key_info.owner_id,
        "public_key": key_info.public_key,
        "encryption_version": key_info.encryption_version,
        "is_active": key_info.is_active,
        "created_at": key_info.created_at,
        "last_used_at": key_info.last_used_at
    })))
}
