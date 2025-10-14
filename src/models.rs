use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use bigdecimal::BigDecimal;

#[derive(Debug, Serialize, Deserialize, FromRow)]
#[allow(dead_code)] 
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
    pub settlement_preference_override: Option<String>, 
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateMerchantRequest {
    pub name: String,
    pub email: String,
    pub settlement_preference: Option<String>, 
    pub wallet_address: Option<String>, 
    pub business_address: String,
    pub webhook_url: Option<String>,
    pub wallet_generation_method: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum SettlementPreference {
    AutoUsdc, 
    DirectToken,
}

impl From<&str> for SettlementPreference {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "direct_token" => SettlementPreference::DirectToken,
            _ => SettlementPreference::AutoUsdc,
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
#[allow(dead_code)]
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

// Note: Settlement struct kept for database queries
#[allow(dead_code)]
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
    pub status: String,
    pub external_reference: Option<String>,
    pub provider: Option<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub settlement_currency: Option<String>,
    pub recipient_wallet: Option<String>,
    pub transaction_signature: Option<String>,
}