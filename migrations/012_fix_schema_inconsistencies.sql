-- Add missing fields to merchants table
ALTER TABLE merchants 
ADD COLUMN IF NOT EXISTS settlement_preference VARCHAR(20) DEFAULT 'auto_ngn',
ADD COLUMN IF NOT EXISTS wallet_generated BOOLEAN DEFAULT FALSE;

-- Add missing fields to payments table  
ALTER TABLE payments
ADD COLUMN IF NOT EXISTS payment_token VARCHAR(10) DEFAULT 'USDC',
ADD COLUMN IF NOT EXISTS settlement_currency_override VARCHAR(10);

-- Ensure all settlement fields exist
ALTER TABLE settlements
ADD COLUMN IF NOT EXISTS settlement_currency VARCHAR(10) DEFAULT 'NGN',
ADD COLUMN IF NOT EXISTS recipient_wallet TEXT;

-- Update existing data
UPDATE merchants SET settlement_preference = 'auto_ngn' WHERE settlement_preference IS NULL;
UPDATE payments SET payment_token = 'USDC' WHERE payment_token IS NULL;
UPDATE settlements SET settlement_currency = 'NGN' WHERE settlement_currency IS NULL;

-- Add helpful indexes
CREATE INDEX IF NOT EXISTS idx_settlements_status_type ON settlements(status, settlement_currency);
CREATE INDEX IF NOT EXISTS idx_payments_token ON payments(payment_token);
CREATE INDEX IF NOT EXISTS idx_merchants_settlement_pref ON merchants(settlement_preference);