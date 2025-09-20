-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create custom types
CREATE TYPE payment_status AS ENUM ('pending', 'confirmed', 'failed', 'expired');

-- Merchants table
CREATE TABLE merchants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    wallet_address VARCHAR(44) NOT NULL, -- Solana wallet addresses are 44 chars
    webhook_url VARCHAR(512),
    api_key VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Payments table
CREATE TABLE payments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
    amount_usd DECIMAL(20,8) NOT NULL, -- Support up to 8 decimal places for crypto
    amount_ngn DECIMAL(20,2), -- NGN amounts with 2 decimal places
    status payment_status NOT NULL DEFAULT 'pending',
    transaction_signature VARCHAR(88), -- Solana transaction signatures
    customer_wallet VARCHAR(44), -- Customer's Solana wallet
    metadata JSONB DEFAULT '{}' NOT NULL,
    webhook_url VARCHAR(512), -- Per-payment webhook override
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- Exchange rates cache table
CREATE TABLE exchange_rates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rate DECIMAL(10,4) NOT NULL, -- NGN per USD
    source VARCHAR(50) NOT NULL, -- 'binance', 'coingecko', etc.
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Webhook logs for debugging
CREATE TABLE webhook_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    payment_id UUID NOT NULL REFERENCES payments(id),
    webhook_url VARCHAR(512) NOT NULL,
    payload JSONB NOT NULL,
    response_status INTEGER,
    response_body TEXT,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    succeeded BOOLEAN DEFAULT FALSE
);

-- Indexes for performance
CREATE INDEX idx_payments_status ON payments(status);
CREATE INDEX idx_payments_merchant ON payments(merchant_id);
CREATE INDEX idx_payments_created ON payments(created_at);
CREATE INDEX idx_payments_expires ON payments(expires_at);
CREATE INDEX idx_payments_signature ON payments(transaction_signature);

CREATE INDEX idx_merchants_api_key ON merchants(api_key);
CREATE INDEX idx_merchants_email ON merchants(email);

CREATE INDEX idx_exchange_rates_source ON exchange_rates(source, created_at);
CREATE INDEX idx_webhook_logs_payment ON webhook_logs(payment_id);

-- Add unique constraint for exchange rates source
CREATE UNIQUE INDEX idx_exchange_rates_source_unique ON exchange_rates(source);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers to automatically update updated_at
CREATE TRIGGER update_merchants_updated_at 
    BEFORE UPDATE ON merchants 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_payments_updated_at 
    BEFORE UPDATE ON payments 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert a default exchange rate (should be updated by the application)
INSERT INTO exchange_rates (rate, source) VALUES (1650.0, 'live') 
ON CONFLICT (source) DO NOTHING;