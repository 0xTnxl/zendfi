use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;
use sha2::Digest;

use crate::AppState;

#[derive(Debug, Clone)]
pub struct AuthenticatedMerchant {
    pub merchant_id: Uuid,
    #[allow(dead_code)]
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

    // Hash the API key for lookup
    let key_hash = sha2::Sha256::digest(api_key.as_bytes());
    let key_hash_hex = hex::encode(key_hash);

    let api_key_record = sqlx::query!(
        r#"
        SELECT id, merchant_id, key_hash, is_active, last_used_at, created_at
        FROM api_keys 
        WHERE key_hash = $1 AND is_active = true
        "#,
        key_hash_hex
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::UNAUTHORIZED)?;

    // Update last used timestamp
    let _ = sqlx::query!(
        "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1",
        api_key_record.id
    )
    .execute(&state.db)
    .await;

    // Add merchant info to request extensions
    let authenticated_merchant = AuthenticatedMerchant {
        merchant_id: api_key_record.merchant_id,
        api_key_id: api_key_record.id,
    };
    
    request.extensions_mut().insert(authenticated_merchant);
    
    Ok(next.run(request).await)
}

pub async fn generate_api_key(
    state: &AppState,
    merchant_id: Uuid,
) -> Result<String, Box<dyn std::error::Error>> {
    // Generate a secure random API key
    let key_bytes: [u8; 32] = rand::random();
    let api_key = format!("zfi_live_{}", hex::encode(key_bytes));
    
    // Hash the key for storage
    let key_hash = sha2::Sha256::digest(api_key.as_bytes());
    let key_hash_hex = hex::encode(key_hash);
    
    sqlx::query!(
        r#"
        INSERT INTO api_keys (id, merchant_id, key_hash, is_active, created_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        Uuid::new_v4(),
        merchant_id,
        key_hash_hex,
        true,
        chrono::Utc::now()
    )
    .execute(&state.db)
    .await?;
    
    Ok(api_key)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_api_key_format() {
        let key_bytes: [u8; 32] = [1; 32];
        let api_key = format!("zfi_live_{}", hex::encode(key_bytes));
        assert!(api_key.starts_with("zfi_live_"));
        assert_eq!(api_key.len(), 73); // "zfi_live_" (9) + 64 hex chars
    }
}