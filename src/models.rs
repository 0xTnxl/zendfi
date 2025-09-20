use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use bigdecimal::BigDecimal;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Merchant {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub wallet_address: String,
    pub webhook_url: Option<String>,
    pub webhook_secret: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Payment {
    pub id: Uuid,
    pub merchant_id: Uuid,
    pub amount_usd: BigDecimal,
    pub amount_ngn: Option<BigDecimal>,
    pub status: PaymentStatus,
    pub transaction_signature: Option<String>,
    pub customer_wallet: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::Type, Clone)]
#[sqlx(type_name = "payment_status", rename_all = "lowercase")]
pub enum PaymentStatus {
    Pending,
    Confirmed,
    Failed,
    Expired,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreatePaymentRequest {
    pub amount: f64,
    pub currency: String,
    pub description: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub webhook_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateMerchantRequest {
    pub name: String,
    pub email: String,
    pub wallet_address: String, // We'll keep this here in case merchants want to recieve USDC directly
    pub webhook_url: Option<String>,
    pub bank_account_number: String,
    pub bank_code: String, // GTBank = "058", Zenith = "057", etc.
    pub account_name: String,
    pub business_address: String,
    pub settlement_currency: String, // "NGN" or "USD"
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaymentResponse {
    pub id: Uuid,
    pub amount: f64,
    pub currency: String,
    pub status: PaymentStatus,
    pub qr_code: String,
    pub payment_url: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExchangeRate {
    pub usd_to_ngn: f64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MerchantDashboard {
    pub merchant_id: Uuid,
    pub total_volume_usd: f64,
    pub total_volume_ngn: f64,
    pub total_transactions: i64,
    pub successful_transactions: i64,
    pub pending_transactions: i64,
    pub success_rate: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub payment_id: Uuid,
    pub status: PaymentStatus,
    pub amount_usd: f64,
    pub amount_ngn: Option<f64>,
    pub transaction_signature: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub metadata: serde_json::Value,
}
