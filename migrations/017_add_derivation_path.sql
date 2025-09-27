-- Add derivation path to merchant_wallets for BIP32/BIP44
ALTER TABLE merchant_wallets ADD COLUMN IF NOT EXISTS derivation_path VARCHAR(100);

-- Update existing records with legacy path format (if any exist)
UPDATE merchant_wallets 
SET derivation_path = 'm/44''/501''/' || derivation_index::text || ''''
WHERE derivation_path IS NULL;

-- Make derivation_path required for new records
ALTER TABLE merchant_wallets ALTER COLUMN derivation_path SET NOT NULL;

-- Add index for derivation path lookups
CREATE INDEX IF NOT EXISTS idx_merchant_wallets_derivation_path ON merchant_wallets(derivation_path);