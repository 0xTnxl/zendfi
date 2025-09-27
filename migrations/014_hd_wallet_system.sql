-- HD Wallet metadata table (no private keys stored!)
CREATE TABLE merchant_wallets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    merchant_id UUID NOT NULL REFERENCES merchants(id),
    public_key VARCHAR(44) NOT NULL UNIQUE,
    derivation_index INTEGER NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_merchant_wallets_merchant ON merchant_wallets(merchant_id);
CREATE INDEX idx_merchant_wallets_derivation ON merchant_wallets(derivation_index);

-- Remove old dangerous fields
ALTER TABLE merchants DROP COLUMN IF EXISTS wallet_keypair_path;