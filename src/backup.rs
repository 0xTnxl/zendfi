use uuid::Uuid;
use chrono::Utc;
use sha2::{Sha256, Digest};
use std::path::Path;
use crate::AppState;

#[derive(Debug)]
pub enum BackupError {
    PostgresCommandFailed(String),
    VerificationFailed(String),
    StorageError(String),
    DatabaseError(String),
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BackupError::PostgresCommandFailed(e) => write!(f, "PostgreSQL backup failed: {}", e),
            BackupError::VerificationFailed(e) => write!(f, "Backup verification failed: {}", e),
            BackupError::StorageError(e) => write!(f, "Storage error: {}", e),
            BackupError::DatabaseError(e) => write!(f, "Database error: {}", e),
        }
    }
}

impl std::error::Error for BackupError {}

pub struct BackupManager {
    backup_dir: String,
    postgres_host: String,
    postgres_user: String,
    postgres_db: String,
}

impl BackupManager {
    pub fn from_env() -> Result<Self, BackupError> {
        let backup_dir = std::env::var("BACKUP_DIR")
            .unwrap_or_else(|_| "./backups".to_string());

        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| BackupError::DatabaseError("DATABASE_URL not set".to_string()))?;

        let (postgres_host, postgres_user, postgres_db) = Self::parse_database_url(&database_url)?;

        std::fs::create_dir_all(&backup_dir)
            .map_err(|e| BackupError::StorageError(format!("Failed to create backup dir: {}", e)))?;

        Ok(Self {
            backup_dir,
            postgres_host,
            postgres_user,
            postgres_db,
        })
    }

    fn parse_database_url(url: &str) -> Result<(String, String, String), BackupError> {
        let without_prefix = url.strip_prefix("postgres://")
            .or_else(|| url.strip_prefix("postgresql://"))
            .ok_or_else(|| BackupError::DatabaseError("Invalid DATABASE_URL format".to_string()))?;

        let parts: Vec<&str> = without_prefix.split('@').collect();
        if parts.len() != 2 {
            return Err(BackupError::DatabaseError("Invalid DATABASE_URL format".to_string()));
        }

        let user_pass: Vec<&str> = parts[0].split(':').collect();
        let user = user_pass[0].to_string();

        let host_db: Vec<&str> = parts[1].split('/').collect();
        let host = host_db[0].split(':').next().unwrap_or("localhost").to_string();
        let db = host_db.get(1).map(|s| s.to_string()).unwrap_or_else(|| "solapay".to_string());

        Ok((host, user, db))
    }

    pub async fn create_full_backup(
        &self,
        state: &AppState,
    ) -> Result<Uuid, BackupError> {
        let backup_id = Uuid::new_v4();
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let backup_filename = format!("backup_full_{}_{}.sql.gz", timestamp, backup_id);
        let backup_path = format!("{}/{}", self.backup_dir, backup_filename);

        tracing::info!("Starting full database backup to {}", backup_path);

        sqlx::query!(
            r#"
            INSERT INTO backup_metadata 
            (id, backup_type, backup_location, start_time, status, created_by)
            VALUES ($1, $2, $3, NOW(), $4, $5)
            "#,
            backup_id,
            "full",
            backup_path,
            "in_progress",
            "system"
        )
        .execute(&state.db)
        .await
        .map_err(|e| BackupError::DatabaseError(e.to_string()))?;

        let pg_dump_result = tokio::process::Command::new("pg_dump")
            .arg("-h").arg(&self.postgres_host)
            .arg("-U").arg(&self.postgres_user)
            .arg("-d").arg(&self.postgres_db)
            .arg("-F").arg("c") 
            .arg("-f").arg(&backup_path)
            .arg("--verbose")
            .output()
            .await
            .map_err(|e| BackupError::PostgresCommandFailed(e.to_string()))?;

        if !pg_dump_result.status.success() {
            let error_msg = String::from_utf8_lossy(&pg_dump_result.stderr).to_string();
            
            sqlx::query!(
                "UPDATE backup_metadata SET status = $1, error_message = $2, end_time = NOW() WHERE id = $3",
                "failed",
                error_msg,
                backup_id
            )
            .execute(&state.db)
            .await
            .ok();

            return Err(BackupError::PostgresCommandFailed(error_msg));
        }

        let file_hash = self.calculate_file_hash(&backup_path)?;
        let file_size = std::fs::metadata(&backup_path)
            .map(|m| m.len() as i64)
            .unwrap_or(0);

        let wal_position = self.get_current_wal_position(state).await.ok();

        sqlx::query!(
            r#"
            UPDATE backup_metadata
            SET status = $1, end_time = NOW(), backup_size_bytes = $2, 
                verification_hash = $3, pg_wal_position = $4, verification_status = $5
            WHERE id = $6
            "#,
            "completed",
            file_size,
            file_hash,
            wal_position,
            "pending",
            backup_id
        )
        .execute(&state.db)
        .await
        .map_err(|e| BackupError::DatabaseError(e.to_string()))?;

        tracing::info!("Backup completed: {} ({} bytes)", backup_path, file_size);

        let state_clone = state.clone();
        let backup_path_clone = backup_path.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::verify_backup_integrity(&state_clone, backup_id, &backup_path_clone).await {
                tracing::error!("Backup verification failed: {}", e);
            }
        });

        Ok(backup_id)
    }

    async fn verify_backup_integrity(
        state: &AppState,
        backup_id: Uuid,
        backup_path: &str,
    ) -> Result<(), BackupError> {
        tracing::info!("Verifying backup integrity: {}", backup_path);

        if !Path::new(backup_path).exists() {
            return Err(BackupError::VerificationFailed("Backup file not found".to_string()));
        }

        let restore_test = tokio::process::Command::new("pg_restore")
            .arg("--list")
            .arg(backup_path)
            .output()
            .await
            .map_err(|e| BackupError::VerificationFailed(e.to_string()))?;

        let verification_status = if restore_test.status.success() {
            "verified"
        } else {
            "failed"
        };

        sqlx::query!(
            "UPDATE backup_metadata SET verification_status = $1 WHERE id = $2",
            verification_status,
            backup_id
        )
        .execute(&state.db)
        .await
        .map_err(|e| BackupError::DatabaseError(e.to_string()))?;

        if verification_status == "verified" {
            tracing::info!("Backup verified successfully: {}", backup_id);
            Ok(())
        } else {
            Err(BackupError::VerificationFailed("pg_restore test failed".to_string()))
        }
    }

    pub async fn restore_backup(
        &self,
        backup_id: Uuid,
        state: &AppState,
    ) -> Result<(), BackupError> {
        let backup_record = sqlx::query!(
            r#"
            SELECT backup_location, verification_status
            FROM backup_metadata
            WHERE id = $1 AND status = 'completed'
            "#,
            backup_id
        )
        .fetch_one(&state.db)
        .await
        .map_err(|e| BackupError::DatabaseError(e.to_string()))?;

        if backup_record.verification_status.as_deref() != Some("verified") {
            return Err(BackupError::VerificationFailed("Backup not verified".to_string()));
        }

        tracing::warn!("Restoring database from backup: {}", backup_record.backup_location);

        // Drop existing connections (if needed)
        // This is dangerous - only use in controlled restore scenarios
        
        let restore_result = tokio::process::Command::new("pg_restore")
            .arg("-h").arg(&self.postgres_host)
            .arg("-U").arg(&self.postgres_user)
            .arg("-d").arg(&self.postgres_db)
            .arg("--clean") 
            .arg("--if-exists")
            .arg("--verbose")
            .arg(&backup_record.backup_location)
            .output()
            .await
            .map_err(|e| BackupError::PostgresCommandFailed(e.to_string()))?;

        if !restore_result.status.success() {
            let error_msg = String::from_utf8_lossy(&restore_result.stderr).to_string();
            return Err(BackupError::PostgresCommandFailed(error_msg));
        }

        tracing::info!("Database restored successfully from backup {}", backup_id);
        Ok(())
    }

    async fn get_current_wal_position(&self, state: &AppState) -> Result<String, BackupError> {
        let result = sqlx::query!(
            "SELECT pg_current_wal_lsn()::text as lsn"
        )
        .fetch_one(&state.db)
        .await
        .map_err(|e| BackupError::DatabaseError(e.to_string()))?;

        Ok(result.lsn.unwrap_or_default())
    }

    fn calculate_file_hash(&self, path: &str) -> Result<String, BackupError> {
        let file_content = std::fs::read(path)
            .map_err(|e| BackupError::VerificationFailed(format!("Failed to read backup file: {}", e)))?;

        let mut hasher = Sha256::new();
        hasher.update(&file_content);
        Ok(hex::encode(hasher.finalize()))
    }

    pub async fn cleanup_old_backups(
        &self,
        state: &AppState,
        retention_days: i32,
    ) -> Result<usize, BackupError> {
        let cutoff_date = Utc::now() - chrono::Duration::days(retention_days as i64);

        let old_backups = sqlx::query!(
            r#"
            SELECT id, backup_location
            FROM backup_metadata
            WHERE start_time < $1 AND status = 'completed'
            "#,
            cutoff_date
        )
        .fetch_all(&state.db)
        .await
        .map_err(|e| BackupError::DatabaseError(e.to_string()))?;

        let mut deleted_count = 0;

        for backup in old_backups {
            if Path::new(&backup.backup_location).exists() {
                std::fs::remove_file(&backup.backup_location)
                    .map_err(|e| BackupError::StorageError(e.to_string()))?;
            }

            sqlx::query!("DELETE FROM backup_metadata WHERE id = $1", backup.id)
                .execute(&state.db)
                .await
                .map_err(|e| BackupError::DatabaseError(e.to_string()))?;

            deleted_count += 1;
        }

        tracing::info!("Cleaned up {} old backups", deleted_count);
        Ok(deleted_count)
    }
}

pub async fn start_backup_worker(state: AppState) {
    let backup_interval_hours = std::env::var("BACKUP_INTERVAL_HOURS")
        .unwrap_or_else(|_| "24".to_string())
        .parse::<u64>()
        .unwrap_or(24);

    let mut interval = tokio::time::interval(
        std::time::Duration::from_secs(backup_interval_hours * 3600)
    );

    loop {
        interval.tick().await;

        tracing::info!("Starting scheduled database backup");

        match BackupManager::from_env() {
            Ok(manager) => {
                match manager.create_full_backup(&state).await {
                    Ok(backup_id) => {
                        tracing::info!("Scheduled backup completed: {}", backup_id);

                        if let Err(e) = manager.cleanup_old_backups(&state, 7).await {
                            tracing::error!("Failed to cleanup old backups: {}", e);
                        }
                    }
                    Err(e) => {
                        tracing::error!("Scheduled backup failed: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to initialize backup manager: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_database_url() {
        let url = "postgres://user:pass@localhost:5432/mydb";
        let (host, user, db) = BackupManager::parse_database_url(url).unwrap();
        
        assert_eq!(host, "localhost");
        assert_eq!(user, "user");
        assert_eq!(db, "mydb");
    }
}
