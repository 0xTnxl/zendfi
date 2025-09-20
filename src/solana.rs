use uuid::Uuid;
use serde_json::{json, Value};
use bigdecimal::ToPrimitive;
use crate::{AppState, models::PaymentStatus};

pub const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

pub async fn generate_payment_qr(
    payment_id: &Uuid,
    amount_usd: f64,
    recipient: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    validate_solana_address(recipient)?;
    
    let amount_usdc = (amount_usd * 1_000_000.0) as u64;
    
    // Create Solana Pay URL
    let solana_pay_url = format!(
        "solana:{}?amount={}&spl-token={}&reference={}&label=ZendFi%20Payment&message=Payment%20{}",
        recipient,
        amount_usdc,
        USDC_MINT,
        payment_id,
        payment_id
    );
    
    Ok(solana_pay_url)
}

pub async fn check_payment_status(
    state: &AppState,
    payment_id: Uuid,
) -> Result<String, Box<dyn std::error::Error>> {
    // Get payment from database
    let payment = sqlx::query!(
        r#"SELECT id, status as "status: PaymentStatus", expires_at, transaction_signature, amount_usd
           FROM payments WHERE id = $1"#,
        payment_id
    )
    .fetch_one(&state.db)
    .await?;
    
    // If already confirmed, return status
    if matches!(payment.status, PaymentStatus::Confirmed) {
        return Ok("confirmed".to_string());
    }
    
    // Check if expired
    if payment.expires_at < chrono::Utc::now() {
        sqlx::query!(
            r#"UPDATE payments SET status = 'expired' WHERE id = $1"#,
            payment_id
        )
        .execute(&state.db)
        .await?;
        
        return Ok("expired".to_string());
    }
    
    // Convert BigDecimal to f64 for payment discovery
    let amount_usd_f64 = payment.amount_usd.to_f64().unwrap_or(0.0);
    
    // Check for new transactions if no signature recorded yet
    if payment.transaction_signature.is_none() {
        let found_signature = discover_payment_transaction(state, payment_id, amount_usd_f64).await?;
        if let Some(signature) = found_signature {
            // Update payment with discovered transaction
            sqlx::query!(
                r#"UPDATE payments SET transaction_signature = $1 WHERE id = $2"#,
                signature,
                payment_id
            )
            .execute(&state.db)
            .await?;
            
            // Check if this transaction is confirmed
            return verify_transaction_confirmation(state, &signature, payment_id).await;
        }
    } else {
        // We have a signature, check its confirmation status
        return verify_transaction_confirmation(
            state, 
            &payment.transaction_signature.unwrap(), 
            payment_id
        ).await;
    }
    
    Ok("pending".to_string())
}

async fn verify_transaction_confirmation(
    state: &AppState,
    signature: &str,
    payment_id: Uuid,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    
    // Check transaction status via RPC
    let response: Value = client
        .post(&state.solana_rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSignatureStatuses",
            "params": [[signature]]
        }))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await?
        .json()
        .await?;
    
    if let Some(status_info) = response["result"]["value"][0].as_object() {
        if status_info.get("err").is_none() { // No error means success
            if let Some(confirmation_status) = status_info["confirmationStatus"].as_str() {
                if confirmation_status == "confirmed" || confirmation_status == "finalized" {
                    // Transaction confirmed - update database
                    sqlx::query!(
                        r#"UPDATE payments SET status = 'confirmed' WHERE id = $1"#,
                        payment_id
                    )
                    .execute(&state.db)
                    .await?;
                    
                    // Trigger webhook
                    let _ = crate::webhooks::create_webhook_event(
                        state, 
                        payment_id, 
                        crate::webhooks::WebhookEventType::PaymentConfirmed
                    ).await;
                    
                    return Ok("confirmed".to_string());
                }
            }
        } else {
            // Transaction failed
            sqlx::query!(
                r#"UPDATE payments SET status = 'failed' WHERE id = $1"#,
                payment_id
            )
            .execute(&state.db)
            .await?;
            
            return Ok("failed".to_string());
        }
    }
    
    Ok("pending".to_string())
}

async fn discover_payment_transaction(
    state: &AppState,
    payment_id: Uuid,
    expected_amount: f64,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    
    // Get recent transactions for recipient wallet
    let response: Value = client
        .post(&state.solana_rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSignaturesForAddress",
            "params": [
                state.config.recipient_wallet,
                {
                    "limit": 50,
                    "commitment": "confirmed"
                }
            ]
        }))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await?
        .json()
        .await?;
    
    if let Some(signatures) = response["result"].as_array() {
        for sig_info in signatures {
            if let Some(signature) = sig_info["signature"].as_str() {
                // Get transaction details
                if let Ok(tx_details) = get_transaction_details(&state.solana_rpc_url, signature).await {
                    if check_transaction_for_payment_reference(&tx_details, &payment_id.to_string(), expected_amount) {
                        return Ok(Some(signature.to_string()));
                    }
                }
            }
        }
    }
    
    Ok(None)
}

async fn get_transaction_details(
    rpc_url: &str,
    signature: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    
    let response: Value = client
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [
                signature,
                {
                    "encoding": "jsonParsed",
                    "commitment": "confirmed",
                    "maxSupportedTransactionVersion": 0
                }
            ]
        }))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await?
        .json()
        .await?;
    
    Ok(response)
}

fn check_transaction_for_payment_reference(
    transaction: &Value,
    payment_reference: &str,
    expected_amount: f64,
) -> bool {
    if let Some(result) = transaction["result"].as_object() {
        if let Some(meta) = result["meta"].as_object() {
            if let Some(log_messages) = meta["logMessages"].as_array() {
                for log in log_messages {
                    if let Some(log_str) = log.as_str() {
                        if log_str.contains(payment_reference) {
                            return true;
                        }
                    }
                }
            }
            
            if let Some(pre_balances) = meta["preBalances"].as_array() {
                if let Some(post_balances) = meta["postBalances"].as_array() {
                    for (i, pre_balance) in pre_balances.iter().enumerate() {
                        if let (Some(pre), Some(post)) = (pre_balance.as_u64(), post_balances.get(i).and_then(|p| p.as_u64())) {
                            let transferred = if post > pre { post - pre } else { pre - post };
                            let expected_lamports = (expected_amount * 1_000_000.0) as u64;
                            if transferred >= (expected_lamports * 99 / 100) && transferred <= (expected_lamports * 101 / 100) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    
    false
}

// Background monitor for all pending payments
pub async fn start_payment_monitor(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    
    loop {
        interval.tick().await;
        
        let pending_payments = sqlx::query!(
            r#"SELECT id FROM payments WHERE status = 'pending' AND expires_at > NOW() LIMIT 20"#
        )
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
        
        for payment in pending_payments {
            let state_clone = state.clone();
            tokio::spawn(async move {
                if let Err(e) = check_payment_status(&state_clone, payment.id).await {
                    tracing::error!("Error monitoring payment {}: {}", payment.id, e);
                }
            });
        }
    }
}

// Helper function to validate the Solana addresses
pub fn validate_solana_address(address: &str) -> Result<(), Box<dyn std::error::Error>> {
    let decoded = bs58::decode(address).into_vec()
        .map_err(|_| "Invalid base58 encoding")?;
    
    if decoded.len() != 32 {
        return Err("Invalid Solana address length".into());
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_validate_solana_address() {
        // Valid Solana address
        assert!(validate_solana_address("11111111111111111111111111111112").is_ok());
        
        // Invalid address
        assert!(validate_solana_address("invalid").is_err());
    }
    
    #[tokio::test]
    async fn test_generate_payment_qr() {
        let payment_id = Uuid::new_v4();
        let amount_usd = 10.5;
        let recipient = "11111111111111111111111111111112"; // System program for testing
        
        let result = generate_payment_qr(&payment_id, amount_usd, recipient).await;
        assert!(result.is_ok());
        
        let url = result.unwrap();
        assert!(url.starts_with("solana:"));
        assert!(url.contains(&payment_id.to_string()));
        assert!(url.contains("amount=10500000")); // 10.5 USDC in micro-units
    }
}