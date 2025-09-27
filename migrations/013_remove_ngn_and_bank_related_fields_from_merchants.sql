-- Remove NGN and bank-related fields from merchants
ALTER TABLE merchants 
DROP COLUMN IF EXISTS bank_account_number,
DROP COLUMN IF EXISTS bank_code,
DROP COLUMN IF EXISTS account_name,
DROP COLUMN IF EXISTS settlement_currency;

-- Remove NGN fields from payments  
ALTER TABLE payments
DROP COLUMN IF EXISTS amount_ngn,
DROP COLUMN IF EXISTS sol_settlement_preference,
DROP COLUMN IF EXISTS settlement_currency_override;

-- Add settlement preference override to payments
ALTER TABLE payments
ADD COLUMN IF NOT EXISTS settlement_preference_override VARCHAR(20);

-- Remove NGN fields from settlements
ALTER TABLE settlements
DROP COLUMN IF EXISTS amount_ngn,
DROP COLUMN IF EXISTS bank_account,
DROP COLUMN IF EXISTS bank_code,
DROP COLUMN IF EXISTS account_name,
DROP COLUMN IF EXISTS batch_id,
DROP COLUMN IF EXISTS estimated_processing_time,
DROP COLUMN IF EXISTS amount_usd; -- Redundant with amount_recieved

-- Update existing data
UPDATE merchants SET settlement_preference = 'auto_usdc' WHERE settlement_preference = 'auto_ngn';
UPDATE settlements SET provider = 'zendfi_direct' WHERE provider LIKE '%quidax%';

-- Remove batch-related tables (no longer needed)
DROP TABLE IF EXISTS settlement_batches;

-- Remove NGN exchange rate table (no longer needed)
DROP TABLE IF EXISTS exchange_rates;

-- Drop unused indexes
DROP INDEX IF EXISTS idx_settlements_batch_id;
DROP INDEX IF EXISTS idx_settlements_estimated_processing;
DROP INDEX IF EXISTS idx_merchants_bank_code;
DROP INDEX IF EXISTS idx_merchants_settlement_currency;

-- Add new indexes for direct crypto settlements
CREATE INDEX IF NOT EXISTS idx_settlements_token_pair ON settlements(payment_token, settlement_token);
CREATE INDEX IF NOT EXISTS idx_payments_settlement_override ON payments(settlement_preference_override);
