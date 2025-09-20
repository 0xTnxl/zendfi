-- Ensure all settlement fields exist with proper defaults

ALTER TABLE merchants 
ADD COLUMN IF NOT EXISTS account_name VARCHAR(255),
ADD COLUMN IF NOT EXISTS settlement_currency VARCHAR(3) DEFAULT 'NGN';

-- Update any existing merchants without settlement currency
UPDATE merchants SET settlement_currency = 'NGN' WHERE settlement_currency IS NULL;

-- Add useful indexes
CREATE INDEX IF NOT EXISTS idx_merchants_bank_code ON merchants(bank_code);
CREATE INDEX IF NOT EXISTS idx_merchants_settlement_currency ON merchants(settlement_currency);