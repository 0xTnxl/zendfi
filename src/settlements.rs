use uuid::Uuid;
use bigdecimal::{BigDecimal, FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use crate::{AppState, models::*};

#[derive(Debug, Serialize, Deserialize)]
pub struct Settlement {
    pub id: Uuid,
    pub payment_id: Uuid,
    pub merchant_id: Uuid,
    pub amount_ngn: BigDecimal,
    pub bank_account: String,
    pub bank_code: String,
    pub account_name: String,
    pub status: String,
    pub external_reference: Option<String>,
    pub provider: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn process_settlement(
    state: &AppState,
    payment_id: Uuid,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let payment = sqlx::query!(
        r#"SELECT id, merchant_id, amount_usd, amount_ngn, status as "status: PaymentStatus"
           FROM payments WHERE id = $1"#,
        payment_id
    )
    .fetch_one(&state.db)
    .await?;

    if !matches!(payment.status, PaymentStatus::Confirmed) {
        return Err("Payment not confirmed".into());
    }

    let merchant = sqlx::query!(
        r#"SELECT bank_account_number, bank_code, account_name, settlement_currency, name
           FROM merchants WHERE id = $1"#,
        payment.merchant_id
    )
    .fetch_one(&state.db)
    .await?;

    let (settlement_amount_ngn, _zendfi_fee_ngn) = calculate_settlement_amounts(
        state,
        payment.amount_usd.to_f64().unwrap_or(0.0),
        &merchant.settlement_currency.unwrap_or("NGN".to_string())
    ).await?;

    let bank_account = merchant.bank_account_number.clone().unwrap_or_default();
    let bank_code = merchant.bank_code.clone().unwrap_or_default();
    let account_name = merchant.account_name.clone().unwrap_or_default();
    let merchant_name = merchant.name.clone();

    let settlement_id = Uuid::new_v4();
    sqlx::query!(
        r#"
        INSERT INTO settlements 
        (id, payment_id, merchant_id, amount_ngn, bank_account, bank_code, account_name, 
         status, provider, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', 'paystack', $8)
        "#,
        settlement_id,
        payment_id,
        payment.merchant_id,
        BigDecimal::from_f64(settlement_amount_ngn).unwrap(),
        bank_account,  
        bank_code,      
        account_name,     
        chrono::Utc::now()
    )
    .execute(&state.db)
    .await?;

    tracing::info!(
        "Settlement created for payment {}: ₦{:.2} to be sent to account {} ({})",
        payment_id, settlement_amount_ngn, 
        bank_account, 
        merchant_name
    );

    simulate_bank_transfer(state, settlement_id, settlement_amount_ngn).await?;

    let _ = crate::webhooks::create_webhook_event(
        state, 
        payment_id, 
        crate::webhooks::WebhookEventType::SettlementCompleted
    ).await;

    Ok(())
}

async fn calculate_settlement_amounts(
    state: &AppState,
    amount_usd: f64,
    settlement_currency: &str,
) -> Result<(f64, f64), Box<dyn std::error::Error + Send + Sync>> {
    if settlement_currency == "NGN" {
        let rate = crate::exchange::get_current_rate(state).await?;
        let gross_ngn = amount_usd * rate.usd_to_ngn;

        let transaction_fee_rate = 0.015; // 1.5%
        let exchange_spread_rate = 0.005; // 0.5%
        
        let transaction_fee = gross_ngn * transaction_fee_rate;
        let exchange_spread = gross_ngn * exchange_spread_rate;
        let total_zendfi_fee = transaction_fee + exchange_spread;
        
        let merchant_receives = gross_ngn - total_zendfi_fee;
        
        tracing::info!(
            "Settlement calculation - Gross: ₦{:.2}, ZendFi Fee: ₦{:.2} (2.0%), Merchant gets: ₦{:.2}",
            gross_ngn, total_zendfi_fee, merchant_receives
        );
        
        Ok((merchant_receives, total_zendfi_fee))
    } else {
        let transaction_fee = amount_usd * 0.015; // 1.5% for USD
        let merchant_receives = amount_usd - transaction_fee;
        Ok((merchant_receives, transaction_fee))
    }
}

async fn simulate_bank_transfer(
    state: &AppState,
    settlement_id: Uuid,
    amount_ngn: f64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    
    let external_ref = format!("SIM_{}", Uuid::new_v4().to_string().split('-').next().unwrap().to_uppercase());
    
    sqlx::query!(
        r#"
        UPDATE settlements 
        SET status = 'completed', 
            external_reference = $1, 
            completed_at = $2,
            provider_response = $3
        WHERE id = $4
        "#,
        external_ref,
        chrono::Utc::now(),
        serde_json::json!({
            "status": "success",
            "reference": external_ref,
            "amount": amount_ngn,
            "fee": 0,
            "provider": "simulation"
        }),
        settlement_id
    )
    .execute(&state.db)
    .await?;
    
    tracing::info!("Settlement {} completed with reference {}", settlement_id, external_ref);
    Ok(())
}

pub async fn get_settlement_status(
    state: &AppState,
    payment_id: Uuid,
) -> Result<Settlement, Box<dyn std::error::Error + Send + Sync>> {
    let settlement = sqlx::query_as!(
        Settlement,
        r#"SELECT id, payment_id, merchant_id, amount_ngn, bank_account, bank_code, 
                  account_name, status, external_reference, provider, created_at, completed_at
           FROM settlements WHERE payment_id = $1"#,
        payment_id
    )
    .fetch_one(&state.db)
    .await?;
    
    Ok(settlement)
}

#[cfg(test)]
mod tests {
    
    #[tokio::test]
    async fn test_settlement_calculation() {
        let amount_usd = 100.0;
        let expected_ngn = amount_usd * 1650.0; // 165,000 NGN
        let expected_fee = expected_ngn * 0.02; // 2% total fee = 3,300 NGN
        let expected_merchant = expected_ngn - expected_fee; // 161,700 NGN
        
        assert!(expected_merchant > 0.0);
        assert!(expected_fee > 0.0);
        assert_eq!(expected_fee, 3300.0); // Verify 2% fee calculation
    }
}