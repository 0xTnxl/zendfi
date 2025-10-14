-- Payment Links Table (Shareable URLs)
CREATE TABLE IF NOT EXISTS payment_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
    link_code VARCHAR(32) UNIQUE NOT NULL, -- Short code for URL: /pay/link/{code}
    amount_usd DECIMAL(20, 8) NOT NULL,
    currency VARCHAR(10) NOT NULL DEFAULT 'USD',
    token VARCHAR(10) NOT NULL DEFAULT 'USDC',
    description TEXT,
    metadata JSONB DEFAULT '{}',
    max_uses INTEGER, -- NULL = unlimited
    uses_count INTEGER DEFAULT 0,
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT positive_amount CHECK (amount_usd > 0),
    CONSTRAINT valid_token CHECK (token IN ('SOL', 'USDC', 'USDT')),
    CONSTRAINT valid_uses CHECK (uses_count >= 0 AND (max_uses IS NULL OR uses_count <= max_uses))
);

CREATE INDEX idx_payment_links_merchant ON payment_links(merchant_id);
CREATE INDEX idx_payment_links_code ON payment_links(link_code);
CREATE INDEX idx_payment_links_active ON payment_links(is_active, expires_at) WHERE is_active = TRUE;

-- Invoices Table
CREATE TABLE IF NOT EXISTS invoices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
    invoice_number VARCHAR(50) UNIQUE NOT NULL, -- e.g., INV-2024-001
    customer_email VARCHAR(255) NOT NULL,
    customer_name VARCHAR(255),
    amount_usd DECIMAL(20, 8) NOT NULL,
    currency VARCHAR(10) NOT NULL DEFAULT 'USD',
    token VARCHAR(10) NOT NULL DEFAULT 'USDC',
    description TEXT NOT NULL,
    line_items JSONB DEFAULT '[]', -- Array of {description, quantity, unit_price}
    metadata JSONB DEFAULT '{}',
    status VARCHAR(20) NOT NULL DEFAULT 'draft',
    payment_id UUID REFERENCES payments(id) ON DELETE SET NULL,
    due_date TIMESTAMPTZ,
    sent_at TIMESTAMPTZ,
    paid_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT positive_invoice_amount CHECK (amount_usd > 0),
    CONSTRAINT valid_invoice_status CHECK (status IN ('draft', 'sent', 'paid', 'cancelled', 'overdue')),
    CONSTRAINT valid_invoice_token CHECK (token IN ('SOL', 'USDC', 'USDT'))
);

CREATE INDEX idx_invoices_merchant ON invoices(merchant_id);
CREATE INDEX idx_invoices_status ON invoices(status);
CREATE INDEX idx_invoices_customer_email ON invoices(customer_email);
CREATE INDEX idx_invoices_payment ON invoices(payment_id);
CREATE INDEX idx_invoices_due_date ON invoices(due_date) WHERE status = 'sent';

-- Track payment link usage
CREATE TABLE IF NOT EXISTS payment_link_uses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payment_link_id UUID NOT NULL REFERENCES payment_links(id) ON DELETE CASCADE,
    payment_id UUID NOT NULL REFERENCES payments(id) ON DELETE CASCADE,
    customer_wallet VARCHAR(255),
    used_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(payment_link_id, payment_id)
);

CREATE INDEX idx_payment_link_uses_link ON payment_link_uses(payment_link_id);
CREATE INDEX idx_payment_link_uses_payment ON payment_link_uses(payment_id);

-- Add payment_link_id to payments table
ALTER TABLE payments ADD COLUMN IF NOT EXISTS payment_link_id UUID REFERENCES payment_links(id) ON DELETE SET NULL;
ALTER TABLE payments ADD COLUMN IF NOT EXISTS invoice_id UUID REFERENCES invoices(id) ON DELETE SET NULL;

CREATE INDEX idx_payments_link ON payments(payment_link_id);
CREATE INDEX idx_payments_invoice ON payments(invoice_id);

-- Update trigger for payment_links
CREATE OR REPLACE FUNCTION update_payment_links_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER payment_links_updated_at_trigger
BEFORE UPDATE ON payment_links
FOR EACH ROW
EXECUTE FUNCTION update_payment_links_updated_at();

-- Update trigger for invoices
CREATE OR REPLACE FUNCTION update_invoices_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER invoices_updated_at_trigger
BEFORE UPDATE ON invoices
FOR EACH ROW
EXECUTE FUNCTION update_invoices_updated_at();

-- Auto-mark invoices as overdue
CREATE OR REPLACE FUNCTION mark_overdue_invoices()
RETURNS void AS $$
BEGIN
    UPDATE invoices
    SET status = 'overdue'
    WHERE status = 'sent' 
    AND due_date < NOW() 
    AND paid_at IS NULL;
END;
$$ LANGUAGE plpgsql;
