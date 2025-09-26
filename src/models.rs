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
    pub token: Option<String>,
    pub description: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub webhook_url: Option<String>,
    pub settlement_currency: Option<String>,
    pub sol_settlement_preference: Option<String>, 
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateMerchantRequest {
    pub name: String,
    pub email: String,
    pub settlement_preference: Option<String>, 
    pub wallet_address: Option<String>, 
    pub bank_account_number: Option<String>,
    pub bank_code: Option<String>, 
    pub account_name: Option<String>,
    pub business_address: String,
    pub settlement_currency: Option<String>,
    
    pub webhook_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum SettlementPreference {
    AutoNgn,      // Always settle to NGN bank account
    AutoUsdc,     // Always settle to USDC wallet  
    PerPayment,   // Merchant chooses per payment
}

impl From<&str> for SettlementPreference {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "auto_usdc" => SettlementPreference::AutoUsdc,
            "per_payment" => SettlementPreference::PerPayment,
            _ => SettlementPreference::AutoNgn,
        }
    }
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
    pub settlement_info: Option<SettlementInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SettlementInfo {
    pub estimated_processing_time: DateTime<Utc>,
    pub batch_schedule: String,
    pub processing_message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExchangeRate {
    pub usd_to_ngn: f64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManualSettlementItem {
    pub id: Uuid,
    pub payment_id: Uuid,
    pub amount_ngn: BigDecimal,
    pub bank_account: String,
    pub bank_code: String,
    pub account_name: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub estimated_processing_time: Option<DateTime<Utc>>,
    pub amount_usd: BigDecimal,
    pub payment_token: Option<String>,
    pub merchant_name: String,
    pub merchant_email: String,
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

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Settlement {
    pub id: Uuid,
    pub payment_id: Uuid,
    pub payment_token: String,
    pub settlement_token: String,
    pub amount_recieved: BigDecimal,
    pub amount_settled: BigDecimal,
    pub exchange_rate_used: Option<BigDecimal>,
    pub sol_swap_signature: Option<String>,
    pub merchant_id: Uuid,
    pub amount_ngn: Option<BigDecimal>,
    pub bank_account: Option<String>,
    pub bank_code: Option<String>,
    pub account_name: Option<String>,
    pub status: String,
    pub batch_id: Option<Uuid>,
    pub estimated_processing_time: Option<DateTime<Utc>>,
    pub external_reference: Option<String>,
    pub provider: Option<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}