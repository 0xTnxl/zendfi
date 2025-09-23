-- UPDATE migrations/008_add_multichain_support.sql:
-- Add multi-token support to payments table
ALTER TABLE payments 
ADD COLUMN IF NOT EXISTS payment_token VARCHAR(10) DEFAULT 'USDC',
ADD COLUMN IF NOT EXISTS sol_settlement_preference VARCHAR(20);

-- Add ALL the new fields to settlements table to match the Settlement struct
ALTER TABLE settlements
ADD COLUMN IF NOT EXISTS payment_token VARCHAR(10) DEFAULT 'USDC',
ADD COLUMN IF NOT EXISTS settlement_token VARCHAR(10) DEFAULT 'NGN',
ADD COLUMN IF NOT EXISTS amount_recieved DECIMAL(20,8),
ADD COLUMN IF NOT EXISTS amount_settled DECIMAL(20,8), 
ADD COLUMN IF NOT EXISTS exchange_rate_used DECIMAL(20,8),
ADD COLUMN IF NOT EXISTS sol_swap_signature TEXT;

-- Create supported tokens lookup table
CREATE TABLE IF NOT EXISTS supported_tokens (
    token_symbol VARCHAR(10) PRIMARY KEY,
    mint_address_mainnet VARCHAR(44),
    mint_address_devnet VARCHAR(44),
    decimals INTEGER NOT NULL,
    is_active BOOLEAN DEFAULT true,
    is_stablecoin BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert initial supported tokens
INSERT INTO supported_tokens (token_symbol, mint_address_mainnet, mint_address_devnet, decimals, is_active, is_stablecoin) 
VALUES 
    ('USDC', 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU', 6, true, true),
    ('USDT', 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', 'EgEHQxJ8aPe7bsrR88zG3w8Y9N5CZg3w8d1K1CZg3w8d', 6, true, true),
    ('SOL', 'So11111111111111111111111111111111111111112', 'So11111111111111111111111111111111111111112', 9, true, false)
ON CONFLICT (token_symbol) DO NOTHING;

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_payments_payment_token ON payments(payment_token);
CREATE INDEX IF NOT EXISTS idx_payments_sol_preference ON payments(sol_settlement_preference);
CREATE INDEX IF NOT EXISTS idx_settlements_tokens ON settlements(payment_token, settlement_token);
CREATE INDEX IF NOT EXISTS idx_supported_tokens_active ON supported_tokens(is_active);