ALTER TABLE settlements ADD COLUMN IF NOT EXISTS transaction_signature VARCHAR(88);
ALTER TABLE settlements ADD COLUMN IF NOT EXISTS sol_swap_signature VARCHAR(88);

-- Index for transaction lookups
CREATE INDEX IF NOT EXISTS idx_settlements_transaction_signature ON settlements(transaction_signature);
CREATE INDEX IF NOT EXISTS idx_settlements_sol_swap_signature ON settlements(sol_swap_signature);