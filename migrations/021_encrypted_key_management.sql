-- Encrypted Key Storage (replaces filesystem storage)
CREATE TABLE IF NOT EXISTS encrypted_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_type VARCHAR(50) NOT NULL, -- 'merchant_wallet', 'escrow_wallet', 'settlement_key'
    owner_id UUID NOT NULL, -- merchant_id for merchant wallets, system UUID for escrow
    encrypted_key_data BYTEA NOT NULL, -- AES-256-GCM encrypted keypair
    encryption_version INTEGER NOT NULL DEFAULT 1, -- For key rotation
    nonce BYTEA NOT NULL, -- Unique nonce for each encryption
    public_key VARCHAR(255) NOT NULL, -- Solana public key (unencrypted for lookups)
    key_metadata JSONB DEFAULT '{}', -- Additional metadata (derivation path, etc.)
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    rotated_at TIMESTAMPTZ,
    CONSTRAINT valid_key_type CHECK (key_type IN ('merchant_wallet', 'escrow_wallet', 'settlement_key'))
);

CREATE INDEX idx_encrypted_keys_owner ON encrypted_keys(owner_id, key_type);
CREATE INDEX idx_encrypted_keys_public ON encrypted_keys(public_key);
CREATE INDEX idx_encrypted_keys_active ON encrypted_keys(is_active) WHERE is_active = TRUE;

-- Database backup metadata
CREATE TABLE IF NOT EXISTS backup_metadata (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backup_type VARCHAR(20) NOT NULL, -- 'full', 'incremental'
    backup_location TEXT NOT NULL, -- S3 URL or local path
    backup_size_bytes BIGINT,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL DEFAULT 'in_progress',
    pg_wal_position TEXT, -- For point-in-time recovery
    verification_hash VARCHAR(64), -- SHA256 of backup file
    verification_status VARCHAR(20), -- 'pending', 'verified', 'failed'
    error_message TEXT,
    created_by VARCHAR(100) DEFAULT 'system',
    CONSTRAINT valid_backup_type CHECK (backup_type IN ('full', 'incremental')),
    CONSTRAINT valid_backup_status CHECK (status IN ('in_progress', 'completed', 'failed', 'verified'))
);

CREATE INDEX idx_backup_metadata_status ON backup_metadata(status, start_time);
CREATE INDEX idx_backup_metadata_type ON backup_metadata(backup_type, start_time);

-- Recovery test logs
CREATE TABLE IF NOT EXISTS recovery_tests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backup_id UUID NOT NULL REFERENCES backup_metadata(id) ON DELETE CASCADE,
    test_type VARCHAR(20) NOT NULL, -- 'restore', 'integrity'
    test_status VARCHAR(20) NOT NULL,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ,
    records_verified INTEGER,
    error_message TEXT,
    test_metadata JSONB DEFAULT '{}',
    CONSTRAINT valid_test_type CHECK (test_type IN ('restore', 'integrity', 'point_in_time')),
    CONSTRAINT valid_test_status CHECK (test_status IN ('running', 'passed', 'failed'))
);

CREATE INDEX idx_recovery_tests_backup ON recovery_tests(backup_id);
CREATE INDEX idx_recovery_tests_status ON recovery_tests(test_status, start_time);

-- Audit log for key operations
CREATE TABLE IF NOT EXISTS key_operation_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id UUID REFERENCES encrypted_keys(id) ON DELETE SET NULL,
    operation VARCHAR(50) NOT NULL, -- 'created', 'accessed', 'rotated', 'deleted'
    operator VARCHAR(100), -- User/system that performed operation
    ip_address INET,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT valid_key_operation CHECK (operation IN ('created', 'accessed', 'rotated', 'deleted', 'decryption_failed'))
);

CREATE INDEX idx_key_operation_logs_key ON key_operation_logs(key_id);
CREATE INDEX idx_key_operation_logs_time ON key_operation_logs(created_at);
CREATE INDEX idx_key_operation_logs_failed ON key_operation_logs(success) WHERE success = FALSE;

-- Add column to track which encryption system is being used
ALTER TABLE merchant_wallets ADD COLUMN IF NOT EXISTS encryption_key_id UUID REFERENCES encrypted_keys(id) ON DELETE SET NULL;

CREATE INDEX idx_merchant_wallets_encryption ON merchant_wallets(encryption_key_id);
