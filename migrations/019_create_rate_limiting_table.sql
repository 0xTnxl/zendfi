-- Create rate limiting table
CREATE TABLE rate_limit_entries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rate_limit_key VARCHAR(255) NOT NULL,
    identifier UUID, -- merchant_id, api_key_id, or IP hash
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for efficient cleanup and counting
CREATE INDEX idx_rate_limit_key_time ON rate_limit_entries(rate_limit_key, created_at);
CREATE INDEX idx_rate_limit_cleanup ON rate_limit_entries(created_at);

-- Partitioning for better performance (optional, for high-traffic systems)
-- This creates monthly partitions automatically
CREATE TABLE rate_limit_entries_template (LIKE rate_limit_entries INCLUDING ALL);

-- Add constraint to auto-delete old entries (PostgreSQL 15+)
-- ALTER TABLE rate_limit_entries ADD CONSTRAINT ttl_constraint 
--     CHECK (created_at > NOW() - INTERVAL '24 hours');