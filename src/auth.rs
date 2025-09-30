use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use sha2::{Sha256, Digest};
use crate::AppState;
use rand::RngCore;

#[derive(Debug, Clone)]
pub struct AuthenticatedMerchant {
    pub merchant_id: Uuid,
    pub api_key_id: Uuid,
}

pub async fn authenticate_merchant(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !auth_header.starts_with("Bearer ") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let api_key = &auth_header[7..];
    
    if !api_key.starts_with("zfi_live_") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Create a cryptographic hash of the entire API key
    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    let key_hash = hex::encode(hasher.finalize());

    // Look up by full hash - NO PREFIX LOOKUP
    let api_key_record = sqlx::query!(
        r#"
        SELECT id, merchant_id, argon2_hash, is_active, last_used_at, created_at
        FROM api_keys 
        WHERE sha256_hash = $1 AND is_active = true
        "#,
        key_hash
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error during authentication: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let record = api_key_record.ok_or_else(|| {
        tracing::warn!("Invalid API key attempted");
        StatusCode::UNAUTHORIZED
    })?;

    // Double verification with Argon2 (defense in depth)
    let hash_str = record.argon2_hash
        .as_ref()
        .ok_or_else(|| {
            tracing::error!("Missing Argon2 hash in database for key {}", record.id);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let parsed_hash = PasswordHash::new(hash_str)
        .map_err(|_| {
            tracing::error!("Invalid Argon2 hash format in database for key {}", record.id);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let argon2 = Argon2::default();
    if argon2.verify_password(api_key.as_bytes(), &parsed_hash).is_err() {
        tracing::warn!("API key failed Argon2 verification");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Update last used timestamp (non-blocking)
    let db_clone = state.db.clone();
    let key_id = record.id;
    tokio::spawn(async move {
        let _ = sqlx::query!(
            "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1",
            key_id
        )
        .execute(&db_clone)
        .await;
    });

    let authenticated_merchant = AuthenticatedMerchant {
        merchant_id: record.merchant_id,
        api_key_id: record.id,
    };
    
    request.extensions_mut().insert(authenticated_merchant);
    
    Ok(next.run(request).await)
}

pub async fn generate_api_key_string(
    state: &AppState, 
    merchant_id: Uuid
) -> Result<String, Box<dyn std::error::Error>> {
    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let api_key = format!("zfi_live_{}", hex::encode(key_bytes));

    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    let sha256_hash = hex::encode(hasher.finalize());

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let argon2_hash = argon2.hash_password(api_key.as_bytes(), &salt)
        .map_err(|e| format!("Argon2 hashing failed: {}", e))?; 

    sqlx::query!(
        r#"
        INSERT INTO api_keys (id, merchant_id, sha256_hash, argon2_hash, is_active, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        Uuid::new_v4(),
        merchant_id,
        sha256_hash,
        argon2_hash.to_string(),
        true,
        chrono::Utc::now()
    )
    .execute(&state.db)
    .await?;
    
    tracing::info!("Generated secure API key for merchant {}", merchant_id);
    Ok(api_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_api_key_format() {
        let key_bytes: [u8; 32] = [1; 32];
        let api_key = format!("zfi_live_{}", hex::encode(key_bytes));
        assert!(api_key.starts_with("zfi_live_"));
        assert_eq!(api_key.len(), 73); // "zfi_live_" (9) + 64 hex chars

        let mut hasher = Sha256::new();
        hasher.update(api_key.as_bytes());
        let hash = hex::encode(hasher.finalize());
        assert_eq!(hash.len(), 64); // SHA256 produces 64 hex chars
    }
}