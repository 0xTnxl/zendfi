use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use solana_sdk::signer::keypair::Keypair;
use solana_sdk::signature::Signer;
use uuid::Uuid;
use zeroize::Zeroize;
use crate::AppState;

const NONCE_SIZE: usize = 12;

#[derive(Debug)]
pub enum KeyManagerError {
    EncryptionFailed(String),
    DecryptionFailed(String),
    MissingMasterKey,
    InvalidMasterKey,
    DatabaseError(String),
    KeyNotFound,
    InvalidKeyData,
}

impl std::fmt::Display for KeyManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            KeyManagerError::EncryptionFailed(e) => write!(f, "Encryption failed: {}", e),
            KeyManagerError::DecryptionFailed(e) => write!(f, "Decryption failed: {}", e),
            KeyManagerError::MissingMasterKey => write!(f, "MASTER_ENCRYPTION_KEY environment variable not set"),
            KeyManagerError::InvalidMasterKey => write!(f, "Master key must be 64 hex characters (32 bytes)"),
            KeyManagerError::DatabaseError(e) => write!(f, "Database error: {}", e),
            KeyManagerError::KeyNotFound => write!(f, "Encryption key not found"),
            KeyManagerError::InvalidKeyData => write!(f, "Invalid key data format"),
        }
    }
}

impl std::error::Error for KeyManagerError {}

pub struct SecureKeyManager {
    master_key: [u8; 32],
}

impl SecureKeyManager {
    pub fn from_env() -> Result<Self, KeyManagerError> {
        let master_key_hex = std::env::var("MASTER_ENCRYPTION_KEY")
            .map_err(|_| KeyManagerError::MissingMasterKey)?;

        if master_key_hex.len() != 64 {
            return Err(KeyManagerError::InvalidMasterKey);
        }

        let master_key_bytes = hex::decode(&master_key_hex)
            .map_err(|_| KeyManagerError::InvalidMasterKey)?;

        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&master_key_bytes);

        Ok(Self { master_key })
    }

    pub fn encrypt_keypair(&self, keypair: &Keypair) -> Result<(Vec<u8>, Vec<u8>), KeyManagerError> {
        let cipher = Aes256Gcm::new_from_slice(&self.master_key)
            .map_err(|e| KeyManagerError::EncryptionFailed(e.to_string()))?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| KeyManagerError::EncryptionFailed(format!("Nonce generation failed: {}", e)))?;
        
        let nonce = Nonce::from(nonce_bytes);

        let keypair_bytes = keypair.to_bytes();

        let encrypted_data = cipher
            .encrypt(&nonce, keypair_bytes.as_ref())
            .map_err(|e| KeyManagerError::EncryptionFailed(e.to_string()))?;

        Ok((encrypted_data, nonce_bytes.to_vec()))
    }

    pub fn decrypt_keypair(&self, encrypted_data: &[u8], nonce: &[u8]) -> Result<Keypair, KeyManagerError> {
        let cipher = Aes256Gcm::new_from_slice(&self.master_key)
            .map_err(|e| KeyManagerError::DecryptionFailed(e.to_string()))?;

        if nonce.len() != NONCE_SIZE {
            return Err(KeyManagerError::InvalidKeyData);
        }

        let nonce_array: [u8; NONCE_SIZE] = nonce.try_into()
            .map_err(|_| KeyManagerError::InvalidKeyData)?;
        let nonce = Nonce::from(nonce_array);

        let decrypted = cipher
            .decrypt(&nonce, encrypted_data)
            .map_err(|e| KeyManagerError::DecryptionFailed(e.to_string()))?;

        if decrypted.len() != 64 {
            return Err(KeyManagerError::InvalidKeyData);
        }

        Keypair::try_from(&decrypted[..])
            .map_err(|_| KeyManagerError::InvalidKeyData)
    }

    pub async fn store_encrypted_keypair(
        &self,
        state: &AppState,
        keypair: &Keypair,
        key_type: &str,
        owner_id: Uuid,
        metadata: Option<serde_json::Value>,
    ) -> Result<Uuid, KeyManagerError> {
        let (encrypted_data, nonce) = self.encrypt_keypair(keypair)?;
        let public_key = keypair.pubkey().to_string();

        let key_id = Uuid::new_v4();

        sqlx::query!(
            r#"
            INSERT INTO encrypted_keys 
            (id, key_type, owner_id, encrypted_key_data, encryption_version, nonce, public_key, key_metadata, is_active, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
            "#,
            key_id,
            key_type,
            owner_id,
            encrypted_data,
            1,
            nonce,
            public_key,
            metadata.unwrap_or(serde_json::json!({})),
            true
        )
        .execute(&state.db)
        .await
        .map_err(|e| KeyManagerError::DatabaseError(e.to_string()))?;

        self.log_key_operation(state, key_id, "created", true, None).await;

        tracing::info!("Stored encrypted {} key for owner {}", key_type, owner_id);
        Ok(key_id)
    }

    pub async fn retrieve_keypair(
        &self,
        state: &AppState,
        key_type: &str,
        owner_id: Uuid,
    ) -> Result<Keypair, KeyManagerError> {
        let record = sqlx::query!(
            r#"
            SELECT id, encrypted_key_data, nonce
            FROM encrypted_keys
            WHERE key_type = $1 AND owner_id = $2 AND is_active = TRUE
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            key_type,
            owner_id
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| KeyManagerError::DatabaseError(e.to_string()))?
        .ok_or(KeyManagerError::KeyNotFound)?;

        let keypair = self.decrypt_keypair(&record.encrypted_key_data, &record.nonce)?;

        // Update last used timestamp
        let key_id = record.id;
        let db_clone = state.db.clone();
        tokio::spawn(async move {
            let _ = sqlx::query!(
                "UPDATE encrypted_keys SET last_used_at = NOW() WHERE id = $1",
                key_id
            )
            .execute(&db_clone)
            .await;
        });

        self.log_key_operation(state, record.id, "accessed", true, None).await;

        Ok(keypair)
    }

    pub async fn retrieve_keypair_by_pubkey(
        &self,
        state: &AppState,
        public_key: &str,
    ) -> Result<Keypair, KeyManagerError> {
        let record = sqlx::query!(
            r#"
            SELECT id, encrypted_key_data, nonce
            FROM encrypted_keys
            WHERE public_key = $1 AND is_active = TRUE
            LIMIT 1
            "#,
            public_key
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| KeyManagerError::DatabaseError(e.to_string()))?
        .ok_or(KeyManagerError::KeyNotFound)?;

        let keypair = self.decrypt_keypair(&record.encrypted_key_data, &record.nonce)?;

        self.log_key_operation(state, record.id, "accessed", true, None).await;

        Ok(keypair)
    }

    pub async fn rotate_key(
        &self,
        state: &AppState,
        key_id: Uuid,
        new_manager: &SecureKeyManager,
    ) -> Result<(), KeyManagerError> {
        let record = sqlx::query!(
            r#"
            SELECT encrypted_key_data, nonce, key_type, owner_id, key_metadata
            FROM encrypted_keys
            WHERE id = $1 AND is_active = TRUE
            "#,
            key_id
        )
        .fetch_one(&state.db)
        .await
        .map_err(|e| KeyManagerError::DatabaseError(e.to_string()))?;

        let keypair = self.decrypt_keypair(&record.encrypted_key_data, &record.nonce)?;

        let (new_encrypted_data, new_nonce) = new_manager.encrypt_keypair(&keypair)?;

        sqlx::query!(
            r#"
            UPDATE encrypted_keys
            SET encrypted_key_data = $1, nonce = $2, encryption_version = encryption_version + 1, rotated_at = NOW()
            WHERE id = $3
            "#,
            new_encrypted_data,
            new_nonce,
            key_id
        )
        .execute(&state.db)
        .await
        .map_err(|e| KeyManagerError::DatabaseError(e.to_string()))?;

        self.log_key_operation(state, key_id, "rotated", true, None).await;

        tracing::info!("Rotated encryption key {}", key_id);
        Ok(())
    }

    async fn log_key_operation(
        &self,
        state: &AppState,
        key_id: Uuid,
        operation: &str,
        success: bool,
        error_message: Option<String>,
    ) {
        let _ = sqlx::query!(
            r#"
            INSERT INTO key_operation_logs (id, key_id, operation, operator, success, error_message, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
            "#,
            Uuid::new_v4(),
            key_id,
            operation,
            "system",
            success,
            error_message
        )
        .execute(&state.db)
        .await;
    }

    pub fn generate_master_key() -> String {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).expect("Failed to generate random key");
        hex::encode(key)
    }
}


impl Drop for SecureKeyManager {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_master_key() {
        let key1 = SecureKeyManager::generate_master_key();
        let key2 = SecureKeyManager::generate_master_key();
        
        assert_eq!(key1.len(), 64);
        assert_ne!(key1, key2); 
    }

    #[test]
    fn test_encrypt_decrypt_keypair() {
        let master_key = SecureKeyManager::generate_master_key();
        std::env::set_var("MASTER_ENCRYPTION_KEY", &master_key);

        let manager = SecureKeyManager::from_env().unwrap();
        let original_keypair = Keypair::new();
        
        let (encrypted, nonce) = manager.encrypt_keypair(&original_keypair).unwrap();
        let decrypted_keypair = manager.decrypt_keypair(&encrypted, &nonce).unwrap();

        assert_eq!(
            original_keypair.pubkey().to_string(),
            decrypted_keypair.pubkey().to_string()
        );
    }
}
