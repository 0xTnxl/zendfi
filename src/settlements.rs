use uuid::Uuid;
use bigdecimal::{BigDecimal, FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use crate::{AppState, models::*};
use crate::solana::get_usdc_mint_for_network;
use crate::quidax::get_quidax_client;
use chrono::Timelike;
use solana_sdk::{
    signature::Keypair,
    pubkey::Pubkey,
    transaction::Transaction,
    instruction::Instruction,
};
use solana_client::rpc_client::RpcClient;
use spl_token::instruction as token_instruction;
use spl_associated_token_account::{
    instruction as ata_instruction,
    get_associated_token_address,
};
use std::str::FromStr;
use std::fs;
use solana_sdk::signature::Signer;
use axum::{extract::{State, Path}, http::StatusCode, Json};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use reqwest::Client;
use serde_json::Value;

static PRICE_CACHE: once_cell::sync::Lazy<Arc<Mutex<(f64, Instant)>>> = 
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new((150.0, Instant::now() - Duration::from_secs(3600)))));

#[derive(Debug, Serialize, Deserialize)]
pub struct SettlementCompletionRequest {
    pub quidax_reference: String,
    pub completed_by: String,
    pub notes: Option<String>,
}

pub async fn process_settlement(
    state: &AppState,
    payment_id: Uuid,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Get payment and merchant info
    let payment = sqlx::query!(
        r#"SELECT p.id, p.merchant_id, p.amount_usd, p.amount_ngn, 
                  p.status as "status: PaymentStatus", 
                  COALESCE(p.payment_token, 'USDC') as payment_token,
                  p.settlement_currency_override,
                  m.settlement_preference, m.wallet_address,
                  m.bank_account_number, m.bank_code, m.account_name, m.name
           FROM payments p 
           JOIN merchants m ON p.merchant_id = m.id 
           WHERE p.id = $1"#,
        payment_id
    )
    .fetch_one(&state.db)
    .await?;

    if !matches!(payment.status, PaymentStatus::Confirmed) {
        return Err("Payment not confirmed".into());
    }

    let amount_usd = payment.amount_usd.to_f64().unwrap_or(0.0);
    let payment_token = payment.payment_token.as_deref().unwrap_or("USDC");
    
    // Determine settlement type based on merchant preferences
    let settlement_preference = payment.settlement_currency_override
        .as_deref()
        .or(payment.settlement_preference.as_deref())
        .unwrap_or("auto_ngn");

    match settlement_preference {
        "auto_usdc" => {
            process_crypto_settlement(
                state, 
                payment_id, 
                amount_usd, 
                payment_token, 
                payment.merchant_id,
                &payment.wallet_address
            ).await
        }
        _ => {
            process_ngn_settlement(
                state,
                payment_id,
                amount_usd,
                payment_token,
                payment.merchant_id,
                payment.bank_account_number.unwrap_or_default(),
                payment.bank_code.unwrap_or_default(),
                payment.account_name.unwrap_or_default(),
                payment.name
            ).await
        }
    }
}

async fn process_crypto_settlement(
    state: &AppState,
    payment_id: Uuid,
    amount_usd: f64,
    payment_token: &str,
    merchant_id: Uuid,
    merchant_wallet: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!("Processing crypto settlement: {} {} -> USDC", amount_usd, payment_token);

    let quidax_client = get_quidax_client(state);

    let is_valid_wallet = quidax_client.validate_address("usdc", merchant_wallet).await
        .unwrap_or(false);
    
    if !is_valid_wallet {
        return Err(format!("Invalid merchant wallet address: {}", merchant_wallet).into());
    }


    let final_usdc_amount = match payment_token {
        "USDC" => {
            tracing::info!("Direct USDC settlement: ${}", amount_usd);
            amount_usd
        }
        "USDT" => {
            tracing::info!("Converting USDT -> USDC via Quidax: ${}", amount_usd);
            execute_quidax_swap(state, "USDT", "USDC", amount_usd).await?;
            amount_usd 
        }
        "SOL" => {
            tracing::info!("Converting SOL -> USDC via Quidax: ${}", amount_usd);
            let sol_amount = amount_usd / get_sol_price().await?;
            execute_quidax_swap(state, "SOL", "USDC", sol_amount).await?;
            amount_usd * 0.995 
        }
        _ => return Err(format!("Unsupported payment token: {}", payment_token).into())
    };

    let (merchant_receives_usdc, _solapay_fee) = calculate_settlement_amounts(
        state, 
        final_usdc_amount,
        "USDC"
    ).await?;

    if !check_escrow_balance(state, merchant_receives_usdc).await? {
        return Err("Insufficient USDC balance in escrow wallet".into());
    }

    let settlement_id = Uuid::new_v4();

    // Create settlement record
    sqlx::query!(
        r#"
        INSERT INTO settlements 
        (id, payment_id, payment_token, settlement_token, amount_recieved, amount_settled,
         settlement_currency, recipient_wallet, merchant_id, status, provider, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'processing', 'solapay_escrow', $10)
        "#,
        settlement_id,
        payment_id,
        payment_token,
        "USDC",
        BigDecimal::from_f64(final_usdc_amount).unwrap(),
        BigDecimal::from_f64(merchant_receives_usdc).unwrap(),
        "USDC",
        merchant_wallet,
        merchant_id,
        chrono::Utc::now()
    )
    .execute(&state.db)
    .await?;

    // Execute USDC transfer
    process_usdc_wallet_transfer(state, settlement_id, merchant_receives_usdc, merchant_wallet).await?;

    tracing::info!("Crypto settlement completed for payment {}", payment_id);

    let _ = crate::webhooks::create_webhook_event(
        state, 
        payment_id, 
        crate::webhooks::WebhookEventType::SettlementCompleted
    ).await;

    Ok(())
}

async fn process_ngn_settlement(
    state: &AppState,
    payment_id: Uuid,
    amount_usd: f64,
    payment_token: &str,
    merchant_id: Uuid,
    bank_account: String,
    bank_code: String,
    account_name: String,
    merchant_name: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!("Processing NGN settlement: {} {} -> NGN", amount_usd, payment_token);

    if payment_token != "USDC" {
        execute_quidax_swap(state, payment_token, "USDC", amount_usd).await?;
    }

    let (settlement_amount_ngn, _solapay_fee_ngn) = calculate_settlement_amounts(
        state,
        amount_usd,
        "NGN"
    ).await?;

    let settlement_id = Uuid::new_v4();
    let next_batch_time = calculate_next_batch_time().await;

    sqlx::query!(
        r#"
        INSERT INTO settlements 
        (id, payment_id, payment_token, settlement_token, amount_recieved, amount_settled,
         settlement_currency, merchant_id, amount_ngn, bank_account, bank_code, account_name, 
         status, provider, estimated_processing_time, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'pending_manual', 'quidax_manual', $13, $14)
        "#,
        settlement_id,
        payment_id,
        payment_token,
        "NGN",
        BigDecimal::from_f64(amount_usd).unwrap(),
        BigDecimal::from_f64(settlement_amount_ngn).unwrap(),
        "NGN",
        merchant_id,
        BigDecimal::from_f64(settlement_amount_ngn).unwrap(),
        bank_account,  
        bank_code,      
        account_name,
        next_batch_time,
        chrono::Utc::now()
    )
    .execute(&state.db)
    .await?;

    tracing::info!(
        "NGN settlement {} queued for manual processing: ₦{:.2} to {} ({})",
        settlement_id, settlement_amount_ngn, account_name, merchant_name
    );

    let _ = crate::webhooks::create_webhook_event(
        state, 
        payment_id, 
        crate::webhooks::WebhookEventType::SettlementQueued
    ).await;

    Ok(())
}

async fn execute_quidax_swap(
    state: &AppState,
    from_currency: &str,
    to_currency: &str,
    amount: f64,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let quidax_client = get_quidax_client(state);

    let network = match from_currency.to_uppercase().as_str() {
        "USDT" => Some("solana"), // USDT SPL token on Solana
        "USDC" => Some("solana"), // USDC SPL token on Solana  
        "SOL" => Some("solana"),  // Native SOL on Solana
        _ => Some("solana"), // Default to Solana for all tokens
    };
    
    let quidax_address = quidax_client.create_payment_address(
        &from_currency.to_lowercase(),
        network,
    ).await?;
    
    tracing::info!("Created Quidax {} address: {}", from_currency, quidax_address.address);

    let transfer_signature = transfer_crypto_to_quidax(
        state,
        from_currency,
        amount,
        &quidax_address.address,
    ).await?;
    
    tracing::info!("Transferred {} {} to Quidax: tx {}", 
                   amount, from_currency, transfer_signature);

    wait_for_quidax_deposit_confirmation(state, &quidax_address.id, amount, 60).await?;

    let quotation = quidax_client.create_swap_quotation(
        &from_currency.to_lowercase(),
        &to_currency.to_lowercase(),
        amount
    ).await?;

    let _swap_result = quidax_client.confirm_swap(&quotation.id).await?;

    wait_for_quidax_swap_completion(state, &quotation.id, 30).await?;
    
    tracing::info!(
        "Quidax swap completed: {} {} -> {} {} (quotation: {})",
        amount, from_currency, quotation.to_amount, to_currency, quotation.id
    );
    
    Ok(quotation.id)
}

async fn transfer_crypto_to_quidax(
    state: &AppState,
    currency: &str,
    amount: f64,
    quidax_address: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    use solana_sdk::{signature::Keypair, pubkey::Pubkey, transaction::Transaction};
    use solana_client::rpc_client::RpcClient;
    use spl_token::instruction as token_instruction;
    use spl_associated_token_account::get_associated_token_address;
    use std::str::FromStr;
    use std::fs;
    
    let keypair_path = state.config.wallet_keypair_path
        .as_ref()
        .ok_or("Escrow wallet keypair path not configured")?;
    
    let keypair_bytes = fs::read(keypair_path)?;
    let mut keypair_array = [0u8; 64];
    keypair_array.copy_from_slice(&keypair_bytes);
    let escrow_keypair = Keypair::try_from(&keypair_array[..])?;
    
    let rpc_client = RpcClient::new(&state.solana_rpc_url);
    let recipient_pubkey = Pubkey::from_str(quidax_address)?;
    
    match currency.to_uppercase().as_str() {
        "SOL" => {
            // Native SOL transfer
            let lamports = (amount * 1_000_000_000.0) as u64;
            let transfer_ix = solana_sdk::system_instruction::transfer(
                &escrow_keypair.pubkey(),
                &recipient_pubkey,
                lamports,
            );
            
            let recent_blockhash = rpc_client.get_latest_blockhash()?;
            let transaction = Transaction::new_signed_with_payer(
                &[transfer_ix],
                Some(&escrow_keypair.pubkey()),
                &[&escrow_keypair],
                recent_blockhash,
            );
            
            let signature = rpc_client.send_and_confirm_transaction(&transaction)?;
            Ok(signature.to_string())
        }
        "USDC" | "USDT" => {
            // SPL Token transfer
            let mint_address = match currency {
                "USDC" => get_usdc_mint_for_network(&state.config.solana_network),
                "USDT" => "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", // Mainnet USDT
                _ => return Err("Unsupported token".into())
            };
            
            let token_mint = Pubkey::from_str(mint_address)?;
            let amount_tokens = (amount * 1_000_000.0) as u64; // 6 decimals for USDC/USDT
            
            let escrow_ata = get_associated_token_address(&escrow_keypair.pubkey(), &token_mint);
            let recipient_ata = get_associated_token_address(&recipient_pubkey, &token_mint);
            
            let mut instructions = Vec::new();
            
            // Create recipient ATA if needed
            if rpc_client.get_account(&recipient_ata).is_err() {
                let create_ata_ix = spl_associated_token_account::instruction::create_associated_token_account(
                    &escrow_keypair.pubkey(),
                    &recipient_pubkey,
                    &token_mint,
                    &spl_token::id(),
                );
                instructions.push(create_ata_ix);
            }
            
            // Transfer tokens
            let transfer_ix = token_instruction::transfer(
                &spl_token::id(),
                &escrow_ata,
                &recipient_ata,
                &escrow_keypair.pubkey(),
                &[&escrow_keypair.pubkey()],
                amount_tokens,
            )?;
            instructions.push(transfer_ix);
            
            let recent_blockhash = rpc_client.get_latest_blockhash()?;
            let transaction = Transaction::new_signed_with_payer(
                &instructions,
                Some(&escrow_keypair.pubkey()),
                &[&escrow_keypair],
                recent_blockhash,
            );
            
            let signature = rpc_client.send_and_confirm_transaction(&transaction)?;
            Ok(signature.to_string())
        }
        _ => Err(format!("Unsupported currency: {}", currency).into())
    }
}

async fn wait_for_quidax_deposit_confirmation(
    state: &AppState,
    currency: &str,
    expected_amount: f64,
    timeout_seconds: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let quidax_client = get_quidax_client(state);
    let start_time = std::time::Instant::now();
    let timeout_duration = std::time::Duration::from_secs(timeout_seconds);
    
    // Get initial balance
    let initial_balance = quidax_client.get_wallet_balance(currency).await
        .unwrap_or(0.0);
    
    tracing::info!("Waiting for {} {} deposit. Initial balance: {}", 
                   expected_amount, currency, initial_balance);
    
    while start_time.elapsed() < timeout_duration {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        
        match quidax_client.get_wallet_balance(currency).await {
            Ok(current_balance) => {
                let received_amount = current_balance - initial_balance;
                
                tracing::debug!("Current {} balance: {} (received: {})", 
                               currency, current_balance, received_amount);
                
                // Allow 1% tolerance for the deposit amount
                if received_amount >= expected_amount * 0.99 {
                    tracing::info!("Deposit confirmed: {} {} received", received_amount, currency);
                    return Ok(());
                }
            }
            Err(e) => {
                tracing::warn!("Error checking {} wallet balance: {}", currency, e);
            }
        }
    }
    
    Err(format!("Deposit confirmation timeout after {}s", timeout_seconds).into())
}

async fn wait_for_quidax_swap_completion(
    state: &AppState,
    quotation_id: &str,
    timeout_seconds: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let quidax_client = get_quidax_client(state);
    let start_time = std::time::Instant::now();
    let timeout_duration = std::time::Duration::from_secs(timeout_seconds);
    
    tracing::info!("Waiting for Quidax swap {} to complete", quotation_id);
    
    while start_time.elapsed() < timeout_duration {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        
        // Check swap transaction status using get_swap_transaction
        match quidax_client.get_swap_transaction(quotation_id).await {
            Ok(swap_status) => {
                match swap_status["status"].as_str() {
                    Some("completed") | Some("success") => {
                        tracing::info!("✅ Swap {} completed successfully", quotation_id);
                        return Ok(());
                    }
                    Some("failed") | Some("error") => {
                        return Err(format!("Swap {} failed", quotation_id).into());
                    }
                    Some(status) => {
                        tracing::debug!("Swap {} status: {}", quotation_id, status);
                    }
                    None => {
                        tracing::debug!("Swap {} status unknown", quotation_id);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Error checking swap status: {}", e);
            }
        }
    }
    
    Err(format!("Swap completion timeout after {}s", timeout_seconds).into())
}

async fn process_usdc_wallet_transfer(
    state: &AppState,
    settlement_id: Uuid,
    usdc_amount: f64,
    merchant_wallet: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let keypair_path = state.config.wallet_keypair_path
        .as_ref()
        .ok_or("Escrow wallet keypair path not configured")?;
    
    let keypair_bytes = fs::read(keypair_path)?;
    let mut keypair_array = [0u8; 64];
    keypair_array.copy_from_slice(&keypair_bytes);
    let escrow_keypair = Keypair::try_from(&keypair_array[..])?;

    let rpc_client = RpcClient::new(&state.solana_rpc_url);
    let recipient_pubkey = Pubkey::from_str(merchant_wallet)?;
    let usdc_mint = Pubkey::from_str(&get_usdc_mint_for_network(&state.config.solana_network))?;

    let usdc_amount_tokens = (usdc_amount * 1_000_000.0) as u64;
    let escrow_ata = get_associated_token_address(&escrow_keypair.pubkey(), &usdc_mint);
    let recipient_ata = get_associated_token_address(&recipient_pubkey, &usdc_mint);

    let mut instructions = Vec::new();

    // Create recipient ATA if needed
    if rpc_client.get_account(&recipient_ata).is_err() {
        let create_ata_ix = ata_instruction::create_associated_token_account(
            &escrow_keypair.pubkey(),
            &recipient_pubkey,
            &usdc_mint,
            &spl_token::id(),
        );
        instructions.push(create_ata_ix);
    }

    // Transfer USDC
    let transfer_ix = token_instruction::transfer(
        &spl_token::id(),
        &escrow_ata,
        &recipient_ata,
        &escrow_keypair.pubkey(),
        &[&escrow_keypair.pubkey()],
        usdc_amount_tokens,     
    )?;
    instructions.push(transfer_ix);

    // Add memo
    let memo_data = format!("Solapay settlement: {}", settlement_id);
    let memo_ix = create_memo_instruction(&memo_data);
    instructions.push(memo_ix);

    let recent_blockhash = rpc_client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&escrow_keypair.pubkey()),
        &[&escrow_keypair],
        recent_blockhash,
    );

    let signature = rpc_client.send_and_confirm_transaction(&transaction)?;
    
    // Update settlement record
    sqlx::query!(
        r#"UPDATE settlements 
           SET status = 'completed', transaction_signature = $1, completed_at = $2
           WHERE id = $3"#,
        signature.to_string(),
        chrono::Utc::now(),
        settlement_id
    )
    .execute(&state.db)
    .await?;

    tracing::info!("USDC transfer completed! Signature: {}", signature);
    Ok(())
}

fn create_memo_instruction(memo: &str) -> Instruction {
    Instruction {
        program_id: spl_memo::id(),
        accounts: vec![],
        data: memo.as_bytes().to_vec(),
    }
}

async fn check_escrow_balance(
    state: &AppState,
    required_usdc: f64,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let keypair_path = state.config.wallet_keypair_path
        .as_ref()
        .ok_or("Escrow wallet keypair path not configured")?;
    
    let keypair_bytes = fs::read(keypair_path)?;
    let mut keypair_array = [0u8; 64];
    keypair_array.copy_from_slice(&keypair_bytes);
    let escrow_keypair = Keypair::try_from(&keypair_array[..])?;
    
    let rpc_client = RpcClient::new(&state.solana_rpc_url);
    let usdc_mint = Pubkey::from_str(&get_usdc_mint_for_network(&state.config.solana_network))?;
    let escrow_ata = get_associated_token_address(&escrow_keypair.pubkey(), &usdc_mint);
    
    match rpc_client.get_token_account_balance(&escrow_ata) {
        Ok(balance) => {
            let current_balance = balance.ui_amount.unwrap_or(0.0);
            tracing::info!("Escrow USDC balance: {}, required: {}", current_balance, required_usdc);
            Ok(current_balance >= required_usdc)
        }
        Err(e) => {
            tracing::error!("Failed to get escrow balance: {}", e);
            Ok(false)
        }
    }
}

async fn calculate_next_batch_time() -> chrono::DateTime<chrono::Utc> {
    let now = chrono::Utc::now();
    let batch_interval_minutes = 30; // Fixed 30-minute intervals
    let minutes_since_hour = now.minute() as i64;
    let minutes_to_next_batch = batch_interval_minutes - (minutes_since_hour % batch_interval_minutes);
    
    now + chrono::Duration::minutes(minutes_to_next_batch)
}

async fn calculate_settlement_amounts(
    state: &AppState,
    amount_usd: f64,
    settlement_currency: &str,
) -> Result<(f64, f64), Box<dyn std::error::Error + Send + Sync>> {
    let solapay_fee_rate = 0.029; // 2.9% fee
    
    if settlement_currency == "NGN" {
        let rate = crate::exchange::get_current_rate(state).await?;
        let gross_ngn = amount_usd * rate.usd_to_ngn;
        let fee_ngn = gross_ngn * solapay_fee_rate;
        let merchant_receives = gross_ngn - fee_ngn;
        Ok((merchant_receives, fee_ngn))
    } else {
        // USDC settlement
        let fee_usd = amount_usd * solapay_fee_rate;
        let merchant_receives = amount_usd - fee_usd;
        Ok((merchant_receives, fee_usd))
    }
}

async fn get_sol_price() -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    {
        let cache = PRICE_CACHE.lock().unwrap();
        if cache.1.elapsed() < Duration::from_secs(300) { // 5 minutes
            tracing::debug!("Using cached SOL price: ${:.2}", cache.0);
            return Ok(cache.0);
        }
    }
    
    let client = Client::new();
    let url = "https://lite-api.jup.ag/price/v3?ids=So11111111111111111111111111111111111111112";
    
    let response = client
        .get(url)
        .header("User-Agent", "Solapay/1.0")
        .send()
        .await?;
    
    if !response.status().is_success() {
        tracing::warn!("Jupiter API request failed, using fallback price");
        return Ok(150.0); // Fallback price
    }
    
    let json: Value = response.json().await?;

    if let Some(sol_data) = json.get("So11111111111111111111111111111111111111112") {
        if let Some(usd_price) = sol_data.get("usdPrice").and_then(|v| v.as_f64()) {
            tracing::info!("Retrieved SOL price from Jupiter: ${:.2}", usd_price);
            return Ok(usd_price);
        }
    }
    
    tracing::warn!("Could not parse Jupiter API response, using fallback price");
    Ok(150.0) // Fallback if parsing fails
}

pub async fn get_pending_manual_settlements(
    State(state): State<AppState>,
) -> Result<Json<Vec<ManualSettlementItem>>, StatusCode> {
    let settlements = sqlx::query_as!(
        ManualSettlementItem,
        r#"
        SELECT s.id, s.payment_id, 
               COALESCE(s.amount_ngn, 0) as "amount_ngn!: BigDecimal", 
               COALESCE(s.bank_account, '') as "bank_account!: String", 
               COALESCE(s.bank_code, '') as "bank_code!: String", 
               COALESCE(s.account_name, '') as "account_name!: String", 
               s.status, s.created_at, s.estimated_processing_time,
               s.amount_recieved as "amount_usd!: BigDecimal", 
               s.payment_token, 
               m.name as "merchant_name!: String", 
               m.email as "merchant_email!: String"
        FROM settlements s
        JOIN payments p ON s.payment_id = p.id  
        JOIN merchants m ON s.merchant_id = m.id
        WHERE s.status IN ('pending_manual', 'ready_for_manual_processing')
        ORDER BY s.estimated_processing_time ASC
        LIMIT 100
        "#
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(settlements))
}

pub async fn mark_settlement_completed(
    State(state): State<AppState>,
    Path(settlement_id): Path<Uuid>,
    Json(completion_data): Json<SettlementCompletionRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    sqlx::query!(
        r#"
        UPDATE settlements 
        SET status = 'completed',
            external_reference = $1,
            completed_at = $2,
            provider_response = $3
        WHERE id = $4
        "#,
        completion_data.quidax_reference,
        chrono::Utc::now(),
        serde_json::json!({
            "manual_completion": true,
            "completed_by": completion_data.completed_by,
            "quidax_reference": completion_data.quidax_reference,
            "notes": completion_data.notes
        }),
        settlement_id
    )
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Get payment ID for webhook
    let payment_id = get_payment_id_from_settlement(&state, settlement_id).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let _ = crate::webhooks::create_webhook_event(
        &state, 
        payment_id, 
        crate::webhooks::WebhookEventType::SettlementCompleted
    ).await;

    Ok(Json(serde_json::json!({
        "message": "Settlement marked as completed",
        "settlement_id": settlement_id,
        "webhook_triggered": true
    })))
}

async fn get_payment_id_from_settlement(
    state: &AppState,
    settlement_id: Uuid,
) -> Result<Uuid, Box<dyn std::error::Error + Send + Sync>> {
    let result = sqlx::query!(
        "SELECT payment_id FROM settlements WHERE id = $1",
        settlement_id
    )
    .fetch_one(&state.db)
    .await?;
    
    Ok(result.payment_id)
}

pub async fn start_settlement_batch_worker(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1800)); 
    
    loop {
        interval.tick().await;
        
        tracing::info!("Running settlement batch worker...");

        let updated_count = sqlx::query!(
            r#"
            UPDATE settlements 
            SET status = 'ready_for_manual_processing'
            WHERE status = 'pending_manual' 
              AND estimated_processing_time <= NOW()
            "#
        )
        .execute(&state.db)
        .await
        .map(|result| result.rows_affected())
        .unwrap_or(0);
        
        if updated_count > 0 {
            tracing::info!("Updated {} settlements to ready for manual processing", updated_count);
        }
    }
}
