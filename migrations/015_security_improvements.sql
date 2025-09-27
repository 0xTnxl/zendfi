-- Add audit logging table
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    table_name VARCHAR NOT NULL,
    record_id UUID NOT NULL,
    action VARCHAR NOT NULL, -- INSERT, UPDATE, DELETE
    old_values JSONB,
    new_values JSONB,
    changed_by UUID, -- merchant_id or system
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_table_record ON audit_log(table_name, record_id);
CREATE INDEX idx_audit_log_changed_at ON audit_log(changed_at);

-- Add payment limits table for merchant risk management
CREATE TABLE merchant_limits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    merchant_id UUID NOT NULL REFERENCES merchants(id),
    max_payment_amount DECIMAL(20,8) NOT NULL DEFAULT 10000,
    daily_volume_limit DECIMAL(20,8) NOT NULL DEFAULT 50000,
    monthly_volume_limit DECIMAL(20,8) NOT NULL DEFAULT 500000,
    rate_limit_per_hour INTEGER NOT NULL DEFAULT 100,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_merchant_limits_merchant ON merchant_limits(merchant_id) WHERE is_active = true;

-- Add webhook idempotency column (remove IF NOT EXISTS - not supported in ALTER TABLE ADD COLUMN)
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'webhook_events' AND column_name = 'idempotency_key'
    ) THEN
        ALTER TABLE webhook_events ADD COLUMN idempotency_key VARCHAR;
    END IF;
END $$;

-- Create index for webhook idempotency
CREATE INDEX idx_webhook_events_idempotency ON webhook_events(payment_id, event_type) WHERE idempotency_key IS NOT NULL;

-- Fix API keys table for Argon2 hashes
ALTER TABLE api_keys ALTER COLUMN key_hash TYPE VARCHAR(256);

-- Add critical indexes for performance 
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'idx_payments_merchant_status'
    ) THEN
        CREATE INDEX idx_payments_merchant_status ON payments(merchant_id, status);
    END IF;
END $$;

DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'idx_payments_expires_status'
    ) THEN
        CREATE INDEX idx_payments_expires_status ON payments(expires_at, status) WHERE status = 'pending';
    END IF;
END $$;

DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'idx_payments_signature_unique'
    ) THEN
        CREATE UNIQUE INDEX idx_payments_signature_unique ON payments(transaction_signature) WHERE transaction_signature IS NOT NULL;
    END IF;
END $$;

-- Add constraints to prevent data corruption (use DO blocks for conditional constraints)
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE constraint_name = 'chk_amount_positive' AND table_name = 'payments'
    ) THEN
        ALTER TABLE payments ADD CONSTRAINT chk_amount_positive CHECK (amount_usd > 0);
    END IF;
END $$;

DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE constraint_name = 'chk_settlement_amounts' AND table_name = 'settlements'
    ) THEN
        ALTER TABLE settlements ADD CONSTRAINT chk_settlement_amounts CHECK (amount_settled > 0 AND amount_recieved > 0);
    END IF;
END $$;

-- Create default limits for existing merchants
INSERT INTO merchant_limits (merchant_id, max_payment_amount, daily_volume_limit, rate_limit_per_hour)
SELECT id, 10000.0, 50000.0, 100 
FROM merchants 
WHERE id NOT IN (SELECT merchant_id FROM merchant_limits WHERE is_active = true)
ON CONFLICT DO NOTHING;