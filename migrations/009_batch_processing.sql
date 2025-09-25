-- ADD new migration file: 009_settlement_batches.sql
CREATE TABLE settlement_batches (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cycle_start TIMESTAMP WITH TIME ZONE NOT NULL,
    cycle_end TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) NOT NULL DEFAULT 'processing',
    total_settlements INTEGER NOT NULL DEFAULT 0,
    total_amount_ngn NUMERIC(20,8) NOT NULL DEFAULT 0,
    processed_count INTEGER NOT NULL DEFAULT 0,
    failed_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Add batch tracking to settlements
ALTER TABLE settlements 
ADD COLUMN batch_id UUID REFERENCES settlement_batches(id),
ADD COLUMN estimated_processing_time TIMESTAMP WITH TIME ZONE;

-- Index for batch processing queries
CREATE INDEX idx_settlements_batch_status ON settlements(status, created_at);
CREATE INDEX idx_settlements_batch_id ON settlements(batch_id);