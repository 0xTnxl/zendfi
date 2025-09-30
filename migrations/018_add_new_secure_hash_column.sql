-- Add new secure hash columns
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS sha256_hash VARCHAR(64);
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS argon2_hash VARCHAR(256);

-- Remove the insecure prefix column
ALTER TABLE api_keys DROP COLUMN IF EXISTS key_prefix;
ALTER TABLE api_keys DROP COLUMN IF EXISTS key_hash;

-- Clean slate: Delete all existing API keys (they were insecure anyway)
DELETE FROM api_keys;

-- Now we can add the constraint safely
ALTER TABLE api_keys ADD CONSTRAINT chk_api_keys_hashes 
    CHECK (sha256_hash IS NOT NULL AND argon2_hash IS NOT NULL);

-- Add indexes
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_sha256_hash ON api_keys(sha256_hash) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_api_keys_merchant_active ON api_keys(merchant_id, is_active);

-- Remove old indexes
DROP INDEX IF EXISTS idx_api_keys_merchant;