-- Add webhook event types
CREATE TYPE webhook_event_type AS ENUM (
    'payment_created',
    'payment_confirmed', 
    'payment_failed',
    'payment_expired',
    'settlement_completed'
);

CREATE TYPE webhook_status AS ENUM ('pending', 'delivered', 'failed', 'exhausted');

-- Webhook events table
CREATE TABLE webhook_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    payment_id UUID NOT NULL REFERENCES payments(id),
    merchant_id UUID NOT NULL REFERENCES merchants(id),
    event_type webhook_event_type NOT NULL,
    payload JSONB NOT NULL,
    webhook_url VARCHAR NOT NULL,
    status webhook_status NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,
    next_retry_at TIMESTAMPTZ,
    response_code INTEGER,
    response_body TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_webhook_events_status ON webhook_events(status);
CREATE INDEX idx_webhook_events_retry ON webhook_events(next_retry_at) WHERE status = 'failed';
CREATE INDEX idx_webhook_events_merchant ON webhook_events(merchant_id);
CREATE INDEX idx_webhook_events_payment ON webhook_events(payment_id);

-- Add webhook secret to merchants table
ALTER TABLE merchants ADD COLUMN webhook_secret VARCHAR;

-- Update existing merchants with webhook secrets
UPDATE merchants SET webhook_secret = 'webhook_secret_' || id::text WHERE webhook_secret IS NULL;