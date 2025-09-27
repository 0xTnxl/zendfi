use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
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

    let key_prefix = api_key.chars().take(12).collect::<String>();
    let api_key_records = sqlx::query!(
        r#"
        SELECT id, merchant_id, key_hash, is_active, last_used_at, created_at
        FROM api_keys 
        WHERE key_prefix = $1 AND is_active = true
        "#,
        key_prefix
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let argon2 = Argon2::default();
    let mut authenticated_record = None;

    for record in api_key_records {
        if let Ok(parsed_hash) = PasswordHash::new(&record.key_hash) {
            if argon2.verify_password(api_key.as_bytes(), &parsed_hash).is_ok() {
                authenticated_record = Some(record);
                break;
            }
        }
    }

    let api_key_record = authenticated_record.ok_or(StatusCode::UNAUTHORIZED)?;

    let _ = sqlx::query!(
        "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1",
        api_key_record.id
    )
    .execute(&state.db)
    .await;

    let authenticated_merchant = AuthenticatedMerchant {
        merchant_id: api_key_record.merchant_id,
        api_key_id: api_key_record.id,
    };
    
    request.extensions_mut().insert(authenticated_merchant);
    
    Ok(next.run(request).await)
}

pub async fn generate_api_key_string(
    state: &AppState, 
    merchant_id: Uuid
) -> Result<String, Box<dyn std::error::Error>> {
    let key_bytes: [u8; 32] = rand::random();
    let api_key = format!("zfi_live_{}", hex::encode(key_bytes));

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let key_hash = argon2.hash_password(api_key.as_bytes(), &salt)
        .map_err(|e| format!("Password hashing failed: {}", e))?; 
    
    let key_prefix = api_key.chars().take(12).collect::<String>();
    
    sqlx::query!(
        r#"
        INSERT INTO api_keys (id, merchant_id, key_hash, key_prefix, is_active, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        Uuid::new_v4(),
        merchant_id,
        key_hash.to_string(),
        key_prefix,
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