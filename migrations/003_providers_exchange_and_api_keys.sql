-- Add API keys table for better security
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    merchant_id UUID NOT NULL REFERENCES merchants(id),
    key_hash VARCHAR NOT NULL UNIQUE,
    key_prefix VARCHAR NOT NULL, -- First 8 chars for identification
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

-- Add settlements table for tracking payouts
CREATE TABLE settlements (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    payment_id UUID NOT NULL REFERENCES payments(id),
    merchant_id UUID NOT NULL REFERENCES merchants(id),
    amount_ngn DECIMAL(15,2) NOT NULL,
    bank_account VARCHAR NOT NULL,
    bank_code VARCHAR NOT NULL,
    account_name VARCHAR NOT NULL,
    status VARCHAR NOT NULL DEFAULT 'pending',
    external_reference VARCHAR,
    provider VARCHAR NOT NULL, -- 'flutterwave', 'paystack', etc.
    provider_response JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- Indexes
CREATE INDEX idx_settlements_status ON settlements(status);
CREATE INDEX idx_settlements_merchant ON settlements(merchant_id);
CREATE INDEX idx_api_keys_merchant ON api_keys(merchant_id);