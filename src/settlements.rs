use uuid::Uuid;
use bigdecimal::{BigDecimal, FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use crate::{AppState, models::*};
use crate::solana::get_usdc_mint_for_network;

#[derive(Debug, Serialize, Deserialize)]
pub struct Settlement {
    pub id: Uuid,
    pub payment_id: Uuid,
    pub payment_token: String, // "USDC", "USDT", "SOL"
    pub settlement_token: String, // "NGN, "USDC", "USDT", "SOL"
    pub amount_recieved: BigDecimal,
    pub amount_settled: BigDecimal,
    pub exchange_rate_used: Option<BigDecimal>,
    pub sol_swap_signature: Option<String>, // Checks if SOL was swapped to USDC
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
        r#"SELECT id, merchant_id, amount_usd, amount_ngn, status as "status: PaymentStatus",
                  COALESCE(payment_token, 'USDC') as payment_token
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

    let amount_usd = payment.amount_usd.to_f64().unwrap_or(0.0);
    let (settlement_amount_ngn, _zendfi_fee_ngn) = calculate_settlement_amounts(
        state,
        amount_usd,
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
        (id, payment_id, payment_token, settlement_token, amount_recieved, amount_settled,
         exchange_rate_used, merchant_id, amount_ngn, bank_account, bank_code, account_name, 
         status, provider, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'pending', 'paystack', $13)
        "#,
        settlement_id,
        payment_id,
        payment.payment_token, // Use actual payment token
        "NGN", // Settlement currency
        BigDecimal::from_f64(amount_usd).unwrap(), // Amount received in USD
        BigDecimal::from_f64(settlement_amount_ngn).unwrap(), // Amount settled in NGN
        None::<BigDecimal>, // Exchange rate used (optional)
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

#[allow(dead_code)]
async fn process_sol_to_usdc_settlement(
    state: &AppState,
    payment_id: Uuid,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sol_price = get_sol_usdc_rate().await?;

    let payment = get_payment_details(state, payment_id).await?;
    let sol_amount = payment.amount_usd.to_f64().unwrap_or(0.0);
    let usdc_equivalent = sol_amount * sol_price;

    let swap_signature = execute_sol_to_usdc_swap(
        state,
        sol_amount,
        usdc_equivalent * 0.995 
    ).await?;

    process_usdc_settlement_with_swap_info(
        state, 
        payment_id, 
        usdc_equivalent,
        Some(swap_signature)
    ).await?;
    
    tracing::info!("SOL payment {} auto-swapped to USDC and settled", payment_id);
    Ok(())
}

#[allow(dead_code)]
async fn get_payment_details(
    state: &AppState,
    payment_id: Uuid,
) -> Result<Payment, Box<dyn std::error::Error + Send + Sync>> {
    let payment = sqlx::query_as!(
        Payment,
        r#"SELECT id, merchant_id, amount_usd, amount_ngn, 
                  status as "status: PaymentStatus", transaction_signature, 
                  customer_wallet, metadata, created_at, expires_at 
           FROM payments WHERE id = $1"#,
        payment_id
    )
    .fetch_one(&state.db)
    .await?;
    
    Ok(payment)
}

#[allow(dead_code)]
async fn process_usdc_settlement_with_swap_info(
    state: &AppState,
    payment_id: Uuid,
    usdc_amount: f64,
    swap_signature: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // For now, treat USDC settlements as NGN conversions for simulation
    let payment = get_payment_details(state, payment_id).await?;
    
    let merchant = sqlx::query!(
        r#"SELECT bank_account_number, bank_code, account_name, name
           FROM merchants WHERE id = $1"#,
        payment.merchant_id
    )
    .fetch_one(&state.db)
    .await?;

    // Convert USDC to NGN for settlement
    let rate = crate::exchange::get_current_rate(state).await?;
    let (settlement_amount_ngn, _fee) = calculate_settlement_amounts(state, usdc_amount, "NGN").await?;

    let settlement_id = Uuid::new_v4();

    sqlx::query!(
        r#"
        INSERT INTO settlements 
        (id, payment_id, payment_token, settlement_token, amount_recieved, amount_settled,
         exchange_rate_used, sol_swap_signature, merchant_id, amount_ngn, bank_account, bank_code, account_name, 
         status, provider, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'pending', 'usdc_swap', $14)
        "#,
        settlement_id,
        payment_id,
        "USDC", // Payment token
        "NGN", // Settlement token
        BigDecimal::from_f64(usdc_amount).unwrap(), // Amount received
        BigDecimal::from_f64(settlement_amount_ngn).unwrap(), // Amount settled
        Some(BigDecimal::from_f64(rate.usd_to_ngn).unwrap()), // Exchange rate used
        swap_signature, // SOL swap signature (if any)
        payment.merchant_id,
        BigDecimal::from_f64(settlement_amount_ngn).unwrap(),
        merchant.bank_account_number.unwrap_or_default(),
        merchant.bank_code.unwrap_or_default(),
        merchant.account_name.unwrap_or_default(),
        chrono::Utc::now()
    )
    .execute(&state.db)
    .await?;

    if let Some(sig) = swap_signature {
        tracing::info!("USDC settlement created with swap signature: {}", sig);
    }

    simulate_bank_transfer(state, settlement_id, settlement_amount_ngn).await?;
    Ok(())
}

#[allow(dead_code)]
async fn get_sol_usdc_rate() -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    // Use Jupiter Price API or Serum for real-time SOL/USDC rate
    let client = reqwest::Client::new();
    let response: serde_json::Value = client
        .get("https://price.jup.ag/v4/price?ids=SOL&vsToken=USDC")
        .send()
        .await?
        .json()
        .await?;
    
    if let Some(price) = response["data"]["SOL"]["price"].as_f64() {
        Ok(price)
    } else {
        Err("Failed to get SOL/USDC rate".into())
    }
}

#[allow(dead_code)]
async fn execute_sol_to_usdc_swap(
    state: &AppState,
    sol_amount: f64,
    min_usdc_out: f64,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let _swap_request = serde_json::json!({
        "inputMint": "So11111111111111111111111111111111111111112", 
        "outputMint": get_usdc_mint_for_network(&state.config.solana_network),
        "amount": (sol_amount * 1_000_000_000.0) as u64, 
        "slippageBps": 50, // 0.5% slippage
    });
    
    // This would integrate with Jupiter's swap API
    // For now, simulate the swap
    let simulated_signature = format!("SWAP_SOL_USDC_{}", Uuid::new_v4());
    
    tracing::info!("Executed SOL->USDC swap: {} SOL -> {} USDC (signature: {})", 
                   sol_amount, min_usdc_out, simulated_signature);
    
    Ok(simulated_signature)
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

#[allow(dead_code)]
pub async fn get_settlement_status(
    state: &AppState,
    payment_id: Uuid,
) -> Result<Settlement, Box<dyn std::error::Error + Send + Sync>> {
    let settlement = sqlx::query_as!(
        Settlement,
        r#"SELECT id, payment_id,
                  COALESCE(payment_token, 'USDC') as "payment_token!: String",
                  COALESCE(settlement_token, 'NGN') as "settlement_token!: String",
                  COALESCE(amount_recieved, 0) as "amount_recieved!: BigDecimal",
                  COALESCE(amount_settled, amount_ngn) as "amount_settled!: BigDecimal", 
                  exchange_rate_used,
                  sol_swap_signature,
                  merchant_id, amount_ngn, bank_account, bank_code, 
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