-- ADD new migration file: 010_add_batch_fields_to_settlements.sql

-- Add the missing fields to settlements table
ALTER TABLE settlements 
ADD COLUMN IF NOT EXISTS batch_id UUID REFERENCES settlement_batches(id),
ADD COLUMN IF NOT EXISTS estimated_processing_time TIMESTAMP WITH TIME ZONE;

-- Create index for batch queries
CREATE INDEX IF NOT EXISTS idx_settlements_batch_id ON settlements(batch_id);
CREATE INDEX IF NOT EXISTS idx_settlements_estimated_processing ON settlements(estimated_processing_time);

-- Update existing settlements to have proper defaults
UPDATE settlements 
SET estimated_processing_time = created_at + INTERVAL '30 minutes'
WHERE estimated_processing_time IS NULL;