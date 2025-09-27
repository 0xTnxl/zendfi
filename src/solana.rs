use core::str;

use uuid::Uuid;
use serde_json::Value;
use bigdecimal::ToPrimitive;
use crate::{AppState, models::PaymentStatus};
use base64::Engine;
use serde::{Serialize, Deserialize};

pub const DEVNET_USDC_MINT: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
pub const MAINNET_USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
pub const DEVNET_USDT_MINT: &str = "EgEHQxJ8aPe7bsrR88zG3w3Y9N5CZg3w8d1K1CZg3w8d";
pub const MAINNET_USDT_MINT: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SupportedToken {
    Usdc,
    Usdt,
    Sol,
}

impl SupportedToken {
    pub fn get_mint_address(&self, network: &str) -> Option<&'static str> {
        match (self, network.to_lowercase().as_str()) {
            (SupportedToken::Usdc, "mainnet" | "mainnet-beta") => Some(MAINNET_USDC_MINT),
            (SupportedToken::Usdc, _) => Some(DEVNET_USDC_MINT),
            (SupportedToken::Usdt, "mainnet" | "mainnet-beta") => Some(MAINNET_USDT_MINT),
            (SupportedToken::Usdt, _) => Some(DEVNET_USDT_MINT),
            (SupportedToken::Sol, _) => None,
        }
    }

    pub fn decimals(&self) -> u8 {
        match self {
            SupportedToken::Usdc | SupportedToken::Usdt => 6, 
            SupportedToken::Sol => 9,
        }
    } 
}

#[allow(dead_code)]
pub fn get_usdc_mint_for_network(network: &str) -> &'static str {
    match network.to_lowercase().as_str() {
        "mainnet" | "mainnet-beta" => MAINNET_USDC_MINT,
        "devnet" | "testnet" => DEVNET_USDC_MINT,
        _ => {
            tracing::warn!("Unknown network '{}', defaulting to devnet USDC", network);
            DEVNET_USDC_MINT
        }
    }
}

pub async fn generate_payment_qr(
    payment_id: &Uuid,
    amount_usd: f64,
    recipient: &str,
    network: &str,
    token: SupportedToken,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    validate_solana_address(recipient)?;
    
    let solana_pay_url = match token {
        SupportedToken::Sol => {
            // Native SOL transfer
            let amount_lamports = (amount_usd * 1_000_000_000.0) as u64;
            format!(
                "solana:{}?amount={}&reference={}&label=Solapay%20Payment%20(SOL)&message=Payment%20{}",
                recipient, amount_lamports, payment_id, payment_id
            )
        }
        SupportedToken::Usdc | SupportedToken::Usdt => {
            // SPL Token transfer
            let amount_tokens = (amount_usd * 10_u64.pow(token.decimals() as u32) as f64) as u64;
            let mint_address = token.get_mint_address(network)
                .ok_or("Unsupported token for network")?;
            
            format!(
                "solana:{}?amount={}&spl-token={}&reference={}&label=Solapay%20Payment%20({:?})&message=Payment%20{}",
                recipient, amount_tokens, mint_address, payment_id, token, payment_id
            )
        }
    };
    
    Ok(solana_pay_url)
}

pub async fn check_payment_status(
    state: &AppState,
    payment_id: Uuid,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    tracing::debug!("Checking payment status for {}", payment_id);
    
    // Get payment from database
    let payment = sqlx::query!(
        r#"SELECT id, status as "status: PaymentStatus", expires_at, transaction_signature, amount_usd
           FROM payments WHERE id = $1"#,
        payment_id
    )
    .fetch_one(&state.db)
    .await?;
    
    tracing::debug!("Payment {} current status: {:?}, amount: ${}", 
                   payment_id, payment.status, payment.amount_usd);
    
    if matches!(payment.status, PaymentStatus::Confirmed) {
        return Ok("confirmed".to_string());
    }
    
    if payment.expires_at < chrono::Utc::now() {
        tracing::info!("Payment {} expired at {}", payment_id, payment.expires_at);
        sqlx::query!(
            r#"UPDATE payments SET status = 'expired' WHERE id = $1"#,
            payment_id
        )
        .execute(&state.db)
        .await?;
        
        return Ok("expired".to_string());
    }
    
    let amount_usd_f64 = payment.amount_usd.to_f64().unwrap_or(0.0);

    if payment.transaction_signature.is_none() {
        tracing::debug!("Searching for transaction for payment {} (amount: ${})", payment_id, amount_usd_f64);
        
        let found_signature = discover_payment_transaction(state, payment_id, amount_usd_f64).await?;
        if let Some(signature) = found_signature {
            tracing::info!("🎉 Found transaction signature {} for payment {}", signature, payment_id);
            
            sqlx::query!(
                r#"UPDATE payments SET transaction_signature = $1 WHERE id = $2"#,
                signature,
                payment_id
            )
            .execute(&state.db)
            .await?;
            
            return verify_transaction_confirmation_resilient(state, &signature, payment_id).await;
        } else {
            tracing::debug!("No matching transaction found for payment {}", payment_id);
        }
    } else {
        tracing::debug!("Payment {} already has transaction signature, verifying confirmation", payment_id);
        return verify_transaction_confirmation_resilient(
            state, 
            &payment.transaction_signature.unwrap(), 
            payment_id
        ).await;
    }
    
    Ok("pending".to_string())
}

async fn verify_transaction_confirmation_resilient(
    state: &AppState,
    signature: &str,
    payment_id: Uuid,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {  
    let response = state.solana_client.make_rpc_call(
        "getSignatureStatuses",
        serde_json::json!([[signature]])
    ).await?; 
    
    if let Some(status_info) = response["result"]["value"][0].as_object() {
        if status_info.get("err").is_none() {
            if let Some(confirmation_status) = status_info["confirmationStatus"].as_str() {
                if confirmation_status == "confirmed" || confirmation_status == "finalized" {
                    sqlx::query!(
                        r#"UPDATE payments SET status = 'confirmed' WHERE id = $1"#,
                        payment_id
                    )
                    .execute(&state.db)
                    .await?;
                    

                    let state_clone = state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = crate::settlements::process_settlement(&state_clone, payment_id).await {
                            tracing::error!("Settlement processing failed for payment {}: {}", payment_id, e);
                        } else {
                            tracing::info!("Settlement processed successfully for payment {}", payment_id);
                        }
                    });
                    
                    let _ = crate::webhooks::create_webhook_event(
                        state, 
                        payment_id, 
                        crate::webhooks::WebhookEventType::PaymentConfirmed
                    ).await;
                    
                    return Ok("confirmed".to_string());
                }
            }
        } else {
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
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let payment_info = sqlx::query!(
        r#"SELECT COALESCE(payment_token, 'USDC') as payment_token 
           FROM payments WHERE id = $1"#,
        payment_id
    )
    .fetch_one(&state.db)
    .await?;

    let expected_token = match payment_info.payment_token.as_deref() {
        Some("USDC") => SupportedToken::Usdc,
        Some("USDT") => SupportedToken::Usdt,
        Some("SOL") => SupportedToken::Sol,
        _ => SupportedToken::Usdc,
    };

    tracing::info!("Monitoring for {} payment {} (amount: {})", 
                   payment_info.payment_token.as_deref().unwrap_or("USDC"), payment_id, expected_amount);

    let response = state.solana_client.make_rpc_call(
        "getSignaturesForAddress",
        serde_json::json!([
            state.config.recipient_wallet,
            { "limit": 50, "commitment": "confirmed" }
        ])
    ).await?;
    
    if let Some(result) = response.get("result") {
        if let Some(signatures) = result.as_array() {
            tracing::info!("Found {} signatures for wallet {}", signatures.len(), state.config.recipient_wallet);
            
            for sig_info in signatures.iter() {
                if let Some(signature) = sig_info["signature"].as_str() {
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        get_transaction_details_resilient(state, signature)
                    ).await {
                        Ok(Ok(tx_details)) => {
                            if check_transaction_for_payment_reference(
                                &tx_details, 
                                &payment_id.to_string(), 
                                expected_amount,
                                &state.config.solana_network,
                                expected_token
                            ) {
                                tracing::info!("Found matching {} transaction {} for payment {}", 
                                             payment_info.payment_token.as_deref().unwrap_or("USDC"), signature, payment_id);
                                return Ok(Some(signature.to_string()));
                            }
                        }
                        Ok(Err(e)) => {
                            tracing::debug!("Failed to get transaction details for {}: {}", signature, e);
                            continue;
                        }
                        Err(_) => {
                            tracing::debug!("Timeout getting transaction details for {}", signature);
                            continue;
                        }
                    }
                }
            }
        }
    }
    
    Ok(None)
}

async fn get_transaction_details_resilient(
    state: &AppState,
    signature: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> { 
    state.solana_client.make_rpc_call(
        "getTransaction",
        serde_json::json!([
            signature,
            {
                "encoding": "jsonParsed",
                "commitment": "confirmed",
                "maxSupportedTransactionVersion": 0
            }
        ])
    ).await
}


fn check_transaction_for_payment_reference(
    transaction: &Value,
    payment_reference: &str,
    expected_amount: f64,
    network: &str,
    expected_token: SupportedToken,
) -> bool {
    if let Some(result) = transaction.get("result") {
        if result.is_null() {
            return false;
        }

        // Check memo/logs for payment reference
        if let Some(meta) = result["meta"].as_object() {
            if let Some(log_messages) = meta["logMessages"].as_array() {
                for log in log_messages {
                    if let Some(log_str) = log.as_str() {
                        if log_str.contains(payment_reference) {
                            tracing::info!("Found payment reference {} in transaction logs", payment_reference);
                            return true; 
                        }
                    }
                }
            }
        }

        // Check instruction data for payment reference
        if let Some(transaction_obj) = result["transaction"].as_object() {
            if let Some(message) = transaction_obj["message"].as_object() {
                if let Some(instructions) = message["instructions"].as_array() {
                    for instruction in instructions {
                        if let Some(data) = instruction["data"].as_str() {
                            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(data) {
                                if let Ok(decoded_str) = String::from_utf8(decoded) {
                                    if decoded_str.contains(payment_reference) {
                                        tracing::info!("Found payment reference {} in instruction data", payment_reference);
                                        return true; 
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        match expected_token {
            SupportedToken::Sol => {
                check_sol_balance_changes(transaction, expected_amount, payment_reference)
            }
            SupportedToken::Usdc | SupportedToken::Usdt => {
                let mint_address = expected_token.get_mint_address(network).unwrap();
                check_spl_token_changes(transaction, expected_amount, mint_address, payment_reference)
            }
        }
    } else {
        false
    }
}


fn check_spl_token_changes(
    transaction: &Value,
    expected_amount: f64,
    mint_address: &str,
    _payment_reference: &str,
) -> bool {
    if let Some(meta) = transaction["result"]["meta"].as_object() {
        if let Some(pre_token_balances) = meta["preTokenBalances"].as_array() {
            if let Some(post_token_balances) = meta["postTokenBalances"].as_array() {
                for (pre_idx, pre_balance) in pre_token_balances.iter().enumerate() {
                    if let Some(post_balance) = post_token_balances.get(pre_idx) {
                        // Check if this is the expected token transfer
                        if let (Some(pre_mint), Some(post_mint)) = (
                            pre_balance["mint"].as_str(),
                            post_balance["mint"].as_str()
                        ) {
                            if pre_mint == mint_address && post_mint == mint_address {
                                if let (Some(pre_amount), Some(post_amount)) = (
                                    pre_balance["uiTokenAmount"]["uiAmount"].as_f64(),
                                    post_balance["uiTokenAmount"]["uiAmount"].as_f64()
                                ) {
                                    let transferred = (post_amount - pre_amount).abs();
                                    let tolerance = expected_amount * 0.05; // 5% tolerance

                                    if (transferred - expected_amount).abs() <= tolerance {
                                        tracing::info!("Found {} transfer of {} (expected {}, tolerance {})", 
                                                      mint_address, transferred, expected_amount, tolerance);
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

fn check_sol_balance_changes(
    transaction: &Value,
    expected_amount: f64,
    _payment_reference: &str,
) -> bool {
    if let Some(meta) = transaction["result"]["meta"].as_object() {
        if let (Some(pre_balances), Some(post_balances)) = (
            meta["preBalances"].as_array(),
            meta["postBalances"].as_array()
        ) {
            for (i, pre_balance) in pre_balances.iter().enumerate() {
                if let Some(post_balance) = post_balances.get(i) {
                    if let (Some(pre_lamports), Some(post_lamports)) = (
                        pre_balance.as_u64(),
                        post_balance.as_u64()
                    ) {
                        let transferred_sol = (post_lamports as f64 - pre_lamports as f64) / 1_000_000_000.0;
                        let tolerance = expected_amount * 0.05; // 5% tolerance
                        
                        if (transferred_sol - expected_amount).abs() <= tolerance {
                            tracing::info!("Found SOL transfer of {} (expected {})", transferred_sol, expected_amount);
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

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

pub fn validate_solana_address(address: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let decoded = bs58::decode(address).into_vec()
        .map_err(|_| "Invalid base58 encoding")?;
    
    if decoded.len() != 32 {
        return Err("Invalid Solana address length".into());
    }

    if address == "11111111111111111111111111111112" {
        return Err("Cannot use system program as recipient wallet".into());
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_validate_solana_address() {
        assert!(validate_solana_address("11111111111111111111111111111112").is_ok());
        assert!(validate_solana_address("invalid").is_err());
    }
    
    #[tokio::test]
    async fn test_generate_payment_qr() {
        let payment_id = Uuid::new_v4();
        let amount_usd = 10.5;
        let recipient = "11111111111111111111111111111112";
        
        let result = generate_payment_qr(&payment_id, amount_usd, recipient, "devnet", SupportedToken::Usdc).await;
        assert!(result.is_ok());
        
        let url = result.unwrap();
        assert!(url.starts_with("solana:"));
        assert!(url.contains(&payment_id.to_string()));
        assert!(url.contains("amount=10500000"));
    }
}