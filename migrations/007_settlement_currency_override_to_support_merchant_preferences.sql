-- Add new columns to merchants table
ALTER TABLE merchants 
ADD COLUMN settlement_preference VARCHAR(20) DEFAULT 'auto_ngn',
ADD COLUMN wallet_keypair_path TEXT,
ADD COLUMN wallet_generated BOOLEAN DEFAULT FALSE;

-- Add settlement currency override to payments
ALTER TABLE payments 
ADD COLUMN settlement_currency_override VARCHAR(10);

-- Update settlements table to support USDC
ALTER TABLE settlements 
ADD COLUMN settlement_currency VARCHAR(10) DEFAULT 'NGN',
ADD COLUMN recipient_wallet TEXT,
ADD COLUMN transaction_signature TEXT,
ADD COLUMN amount_usd DECIMAL(20,8);