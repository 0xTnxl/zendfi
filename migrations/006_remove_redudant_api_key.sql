-- Remove the redundant api_key column from merchants table

ALTER TABLE merchants DROP COLUMN IF EXISTS api_key;
DROP INDEX IF EXISTS idx_merchants_api_key;
DROP INDEX IF EXISTS merchants_api_key_key;