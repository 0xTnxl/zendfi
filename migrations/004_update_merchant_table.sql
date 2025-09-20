-- Add to merchants table
ALTER TABLE merchants ADD COLUMN bank_account_number VARCHAR(20);
ALTER TABLE merchants ADD COLUMN bank_code VARCHAR(10);
ALTER TABLE merchants ADD COLUMN account_name VARCHAR(255);
ALTER TABLE merchants ADD COLUMN settlement_currency VARCHAR(3) DEFAULT 'NGN';
ALTER TABLE merchants ADD COLUMN business_address TEXT;