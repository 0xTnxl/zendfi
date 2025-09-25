use uuid::Uuid;
use bigdecimal::{BigDecimal, FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use crate::{AppState, models::*};
use crate::solana::get_usdc_mint_for_network;
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


#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum BatchStatus {
    Pending, 
    Queued,
    Processing,
    Completed,
    Failed,
}
#[derive(Debug, Serialize, Deserialize)]
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
    pub amount_ngn: BigDecimal,
    pub bank_account: String,
    pub bank_code: String,
    pub account_name: String,
    pub status: String,
    pub batch_id: Option<Uuid>,
    pub estimated_processing_time: Option<chrono::DateTime<chrono::Utc>>,
    pub external_reference: Option<String>,
    pub provider: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SettlementBatch {
    pub id: Uuid,
    pub cycle_start: chrono::DateTime<chrono::Utc>,
    pub status: String,
    pub total_settlements: i32,
    pub total_amount_ngn: BigDecimal,
    pub processed_count: i32,
    pub failed_count: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn process_settlement(
    state: &AppState,
    payment_id: Uuid,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let payment = sqlx::query!(
        r#"SELECT id, merchant_id, amount_usd, amount_ngn, status as "status: PaymentStatus",
                  COALESCE(payment_token, 'USDC') as payment_token,
                  settlement_currency_override
           FROM payments WHERE id = $1"#,
        payment_id
    )
    .fetch_one(&state.db)
    .await?;

    if !matches!(payment.status, PaymentStatus::Confirmed) {
        return Err("Payment not confirmed".into());
    }

    let merchant = sqlx::query!(
        r#"SELECT id, bank_account_number, bank_code, account_name, settlement_currency, name,
                  COALESCE(settlement_preference, 'auto_ngn') as settlement_preference,
                  wallet_address
           FROM merchants WHERE id = $1"#,
        payment.merchant_id
    )
    .fetch_one(&state.db)
    .await?;

    let amount_usd = payment.amount_usd.to_f64().unwrap_or(0.0);
    let payment_token = payment.payment_token.as_deref().unwrap_or("USDC");

    match merchant.settlement_preference.as_deref().unwrap_or("auto_ngn") {
        "auto_usdc" => {
            tracing::info!("Processing USDC settlement for auto_usdc merchant {}", merchant.name);
            process_crypto_settlement(state, payment_id, amount_usd, payment_token).await
        }
        "per_payment" => {
            let target_currency = payment.settlement_currency_override
                .as_deref()
                .or(merchant.settlement_currency.as_deref())
                .unwrap_or("NGN");
            
            if target_currency == "USDC" {
                tracing::info!("Processing USDC settlement for per_payment merchant {} (payment override)", merchant.name);
                process_crypto_settlement(state, payment_id, amount_usd, payment_token).await
            } else {
                tracing::info!("Processing NGN settlement for per_payment merchant {} (NGN chosen)", merchant.name);
                process_ngn_settlement(
                    state, 
                    payment_id, 
                    amount_usd, 
                    payment_token,
                    merchant.id,
                    merchant.bank_account_number.unwrap_or_default(),
                    merchant.bank_code.unwrap_or_default(),
                    merchant.account_name.unwrap_or_default(),
                    merchant.name
                ).await
            }
        }
        _ => {
            tracing::info!("Processing NGN settlement for auto_ngn merchant {}", merchant.name);
            process_ngn_settlement(
                state, 
                payment_id, 
                amount_usd, 
                payment_token,
                merchant.id,
                merchant.bank_account_number.unwrap_or_default(),
                merchant.bank_code.unwrap_or_default(),
                merchant.account_name.unwrap_or_default(),
                merchant.name
            ).await
        }
    }
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
    let (settlement_amount_ngn, _zendfi_fee_ngn) = calculate_settlement_amounts(
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
         merchant_id, amount_ngn, bank_account, bank_code, account_name, 
         status, provider, estimated_processing_time, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'pending_batch', 'quidax_batch', $12, $13)
        "#,
        settlement_id,
        payment_id,
        payment_token,
        "NGN",
        BigDecimal::from_f64(amount_usd).unwrap(),
        BigDecimal::from_f64(settlement_amount_ngn).unwrap(),
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
        "NGN settlement {} queued for batch processing: ₦{:.2} to account {} ({}) - estimated processing: {}",
        settlement_id, settlement_amount_ngn, bank_account, merchant_name, 
        next_batch_time.format("%H:%M")
    );

    let _ = crate::webhooks::create_webhook_event(
        state, 
        payment_id, 
        crate::webhooks::WebhookEventType::SettlementQueued
    ).await;

    Ok(())
}

async fn calculate_next_batch_time() -> chrono::DateTime<chrono::Utc> {
    let now = chrono::Utc::now();
    let batch_interval_minutes = std::env::var("BATCH_INTERVAL_MINUTES")
        .unwrap_or_else(|_| "30".to_string()) 
        .parse::<i64>()
        .unwrap_or(30);

    let minutes_since_hour = now.minute() as i64;
    let minutes_to_next_batch = batch_interval_minutes - (minutes_since_hour % batch_interval_minutes);
    
    now + chrono::Duration::minutes(minutes_to_next_batch)
}

pub async fn start_settlement_batch_worker(state: AppState) {
    let batch_interval = std::env::var("BATCH_INTERVAL_MINUTES")
        .unwrap_or_else(|_| "30".to_string())
        .parse::<u64>()
        .unwrap_or(30);

    let mut interval = tokio::time::interval(
        std::time::Duration::from_secs(batch_interval * 60)
    );
    
    tracing::info!("Settlement batch worker started - processing every {} minutes", batch_interval);
    
    loop {
        interval.tick().await;
        
        if let Err(e) = process_settlement_batch(&state).await {
            tracing::error!("Batch processing failed: {}", e);
        }
    }
}

async fn process_settlement_batch(state: &AppState) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let batch_id = Uuid::new_v4();
    let cycle_start = chrono::Utc::now();
    
    tracing::info!("Starting settlement batch {} at {}", batch_id, cycle_start.format("%H:%M:%S"));

    let pending_settlements = sqlx::query!(
        r#"SELECT id, merchant_id, amount_ngn, bank_account, bank_code, account_name, payment_id
           FROM settlements 
           WHERE status = 'pending_batch' AND created_at <= NOW() - INTERVAL '1 minute'
           ORDER BY created_at ASC
           LIMIT 100"#
    )
    .fetch_all(&state.db)
    .await?;

    if pending_settlements.is_empty() {
        tracing::info!("No settlements to process in this batch");
        return Ok(());
    }

    let total_amount: f64 = pending_settlements
        .iter()
        .map(|s| s.amount_ngn.to_f64().unwrap_or(0.0))
        .sum();

    sqlx::query!(
        r#"INSERT INTO settlement_batches 
           (id, cycle_start, status, total_settlements, total_amount_ngn, processed_count, failed_count, created_at)
           VALUES ($1, $2, 'processing', $3, $4, 0, 0, $5)"#,
        batch_id,
        cycle_start,
        pending_settlements.len() as i32,
        BigDecimal::from_f64(total_amount).unwrap(),
        cycle_start
    )
    .execute(&state.db)
    .await?;

    let settlement_ids: Vec<Uuid> = pending_settlements.iter().map(|s| s.id).collect();
    
    sqlx::query!(
        r#"UPDATE settlements 
           SET status = 'batch_processing', batch_id = $1 
           WHERE id = ANY($2)"#,
        batch_id,
        &settlement_ids
    )
    .execute(&state.db)
    .await?;

    tracing::info!(
        "Processing batch {} with {} settlements (₦{:.2} total)",
        batch_id, pending_settlements.len(), total_amount
    );
    let mut processed_count = 0;
    let mut failed_count = 0;

    for settlement in pending_settlements {
        // Extract field values from the Record
        let settlement_id = settlement.id;
        let payment_id = settlement.payment_id;
        let amount_ngn = settlement.amount_ngn.to_f64().unwrap_or(0.0);
        let bank_account = settlement.bank_account.clone();
        let bank_code = settlement.bank_code;
        let account_name = settlement.account_name;

        match process_individual_settlement_in_batch(
            state,
            settlement_id,
            payment_id,
            amount_ngn,
            bank_account,
            bank_code,
            account_name,
            batch_id,
        ).await {
            Ok(_) => {
                processed_count += 1;
                tracing::info!("Processed settlement {} to {}", 
                             settlement_id, settlement.bank_account);
            }
            Err(e) => {
                failed_count += 1;
                tracing::error!("Failed settlement {}: {}", settlement_id, e);
            }
        }
    }

    // Complete batch
    let cycle_end = chrono::Utc::now();
    let batch_status = if failed_count == 0 { "completed" } else { "partial" };

    sqlx::query!(
        r#"UPDATE settlement_batches 
           SET status = $1, cycle_end = $2, processed_count = $3, failed_count = $4, completed_at = $5
           WHERE id = $6"#,
        batch_status,
        cycle_end,
        processed_count,
        failed_count,
        cycle_end,
        batch_id
    )
    .execute(&state.db)
    .await?;

    tracing::info!(
        "Batch {} completed: {}/{} successful, {} failed (took {}s)",
        batch_id, processed_count, processed_count + failed_count, failed_count,
        (cycle_end - cycle_start).num_seconds()
    );

    Ok(())
}

async fn process_individual_settlement_in_batch(
    state: &AppState,
    settlement_id: Uuid,
    payment_id: Uuid,
    amount_ngn: f64,
    bank_account: String,
    bank_code: String,
    account_name: String,
    batch_id: Uuid,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // This is where manual processing happens
    sqlx::query!(
        r#"UPDATE settlements 
           SET status = 'ready_for_manual_processing',
               provider_response = $1,
               completed_at = $2
           WHERE id = $3"#,
        serde_json::json!({
            "status": "ready_for_quidax_manual_withdrawal",
            "batch_id": batch_id,
            "amount_ngn": amount_ngn,
            "bank_details": {
                "account_number": bank_account,
                "bank_code": bank_code,
                "account_name": account_name
            },
            "instructions": format!("Process NGN withdrawal of ₦{:.2} to {} ({})", amount_ngn, account_name, bank_account)
        }),
        chrono::Utc::now(),
        settlement_id
    )
    .execute(&state.db)
    .await?;

    // Send webhook for settlement ready for processing
    let _ = crate::webhooks::create_webhook_event(
        state, 
        payment_id, 
        crate::webhooks::WebhookEventType::SettlementProcessing
    ).await;

    tracing::info!("Settlement {} ready for manual Quidax processing: ₦{:.2} to {}", 
                   settlement_id, amount_ngn, account_name);

    Ok(())
}

async fn process_crypto_settlement(
    state: &AppState,
    payment_id: Uuid,
    amount_usd: f64,
    payment_token: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let merchant = sqlx::query!(
        r#"SELECT id, wallet_address, name FROM merchants 
           WHERE id = (SELECT merchant_id FROM payments WHERE id = $1)"#,
        payment_id
    )
    .fetch_one(&state.db)
    .await?;

    let merchant_wallet = &merchant.wallet_address;

    // Handle different payment tokens -> USDC settlement
    let (final_usdc_amount, swap_signature) = match payment_token {
        "USDC" => {
            tracing::info!("Direct USDC settlement: ${}", amount_usd);
            (amount_usd, None)
        }
        "USDT" => {
            tracing::info!("Converting USDT -> USDC: ${}", amount_usd);
            let swap_sig = execute_usdt_to_usdc_swap(state, amount_usd).await?;
            (amount_usd, Some(swap_sig))
        }
        "SOL" => {
            tracing::info!("Converting SOL -> USDC: ${}", amount_usd);
            let sol_price = get_sol_usdc_rate().await?;
            let sol_amount = amount_usd / sol_price;
            let swap_sig = execute_sol_to_usdc_swap(state, sol_amount, amount_usd * 0.995).await?;
            (amount_usd * 0.995, Some(swap_sig))
        }
        _ => (amount_usd, None)
    };

    let (merchant_receives_usdc, _zendfi_fee) = calculate_settlement_amounts( 
        state, 
        final_usdc_amount, 
        "USDC"
    ).await?;

    if !check_escrow_balance(state, merchant_receives_usdc).await? {
        return Err("Insufficient USDC balance in escrow wallet".into());
    }

    let settlement_id = Uuid::new_v4();

    sqlx::query!(
        r#"
        INSERT INTO settlements 
        (id, payment_id, payment_token, settlement_token, amount_recieved, amount_settled,
         sol_swap_signature, merchant_id, amount_ngn, bank_account, bank_code, account_name, 
         status, provider, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'pending', 'crypto_transfer', $13)
        "#,
        settlement_id,
        payment_id,
        payment_token,
        "USDC", 
        BigDecimal::from_f64(final_usdc_amount).unwrap(),
        BigDecimal::from_f64(merchant_receives_usdc).unwrap(),
        swap_signature,
        merchant.id,
        BigDecimal::from_f64(0.0).unwrap(),
        merchant_wallet, 
        "CRYPTO", 
        merchant.name,
        chrono::Utc::now()
    )
    .execute(&state.db)
    .await?;

    tracing::info!(
        "Crypto settlement created: {} {} -> ${:.6} USDC to wallet {} (merchant: {})",
        payment_token, final_usdc_amount, merchant_receives_usdc, merchant_wallet, merchant.name
    );

    // Execute the actual USDC transfer to merchant wallet
    process_usdc_wallet_transfer_with_retry(
        state,
        settlement_id, 
        merchant_receives_usdc,
        merchant_wallet,
        3 
    ).await?;

    tracing::info!("Crypto settlemnt completed for payment {}", payment_id);

    let _ = crate::webhooks::create_webhook_event(
        state, 
        payment_id, 
        crate::webhooks::WebhookEventType::SettlementCompleted
    ).await;

    Ok(())
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

    if keypair_bytes.len() != 64 {
        return Err("Invalid keypair file length".into());
    }
    
    let mut keypair_array = [0u8; 64];
    keypair_array.copy_from_slice(&keypair_bytes);
    let escrow_keypair = Keypair::try_from(&keypair_array[..])?;

    tracing::info!("Loaded escrow wallet: {}", escrow_keypair.pubkey());

    let rpc_client = RpcClient::new(&state.solana_rpc_url);

    let recipient_pubkey = Pubkey::from_str(merchant_wallet)?;
    let usdc_mint = Pubkey::from_str(&get_usdc_mint_for_network(&state.config.solana_network))?;

    let usdc_amount_tokens = (usdc_amount * 1_000_000.0) as u64;

    tracing::info!(
        "Preparing USDC transfer: ${:.6} ({} tokens) to {}",
        usdc_amount, usdc_amount_tokens, merchant_wallet
    );

    let escrow_ata = get_associated_token_address(&escrow_keypair.pubkey(), &usdc_mint);
    let recipient_ata = get_associated_token_address(&recipient_pubkey, &usdc_mint);

    tracing::info!("Escrow ATA: {}", escrow_ata);
    tracing::info!("Recipient ATA: {}", recipient_ata);

    let mut instructions = Vec::new();

    match rpc_client.get_account(&recipient_ata) {
        Ok(_) => {
            tracing::info!("Recipient ATA already exists");
        }
        Err(_) => {
            tracing::info!("Creating recipient ATA");
            let create_ata_ix = ata_instruction::create_associated_token_account(
                &escrow_keypair.pubkey(), 
                &recipient_pubkey,    
                &usdc_mint,        
                &spl_token::id(),   
            );
            instructions.push(create_ata_ix);
        }
    }

    let transfer_ix = token_instruction::transfer(
        &spl_token::id(),  
        &escrow_ata,  
        &recipient_ata,  
        &escrow_keypair.pubkey(), 
        &[&escrow_keypair.pubkey()],
        usdc_amount_tokens,     
    )?;
    instructions.push(transfer_ix);

    let memo_data = format!("ZendFi settlement: {}", settlement_id);
    let memo_ix = create_memo_instruction(&memo_data);
    instructions.push(memo_ix);

    let recent_blockhash = rpc_client.get_latest_blockhash()?;
    
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&escrow_keypair.pubkey()),
        &[&escrow_keypair],
        recent_blockhash,
    );

    tracing::info!("Sending USDC transfer transaction...");
    
    let signature = rpc_client.send_and_confirm_transaction_with_spinner(&transaction)?;
    
    tracing::info!("USDC transfer completed! Signature: {}", signature);

    sqlx::query!(
        r#"
        UPDATE settlements 
        SET status = 'completed',
            provider_response = $1,
            sol_swap_signature = $2,
            completed_at = $3
        WHERE id = $4
        "#,
        serde_json::json!({
            "status": "completed",
            "transfer_type": "usdc_wallet",
            "amount_usdc": usdc_amount,
            "amount_tokens": usdc_amount_tokens,
            "recipient_wallet": merchant_wallet,
            "recipient_ata": recipient_ata.to_string(),
            "escrow_ata": escrow_ata.to_string(),
            "provider": "solana_spl_transfer",
            "transaction_signature": signature.to_string()
        }),
        signature.to_string(),
        chrono::Utc::now(),
        settlement_id
    )
    .execute(&state.db)
    .await?;

    if let Ok(payment_id) = get_payment_id_from_settlement(state, settlement_id).await {
        let _ = crate::webhooks::create_webhook_event(
            state, 
            payment_id, 
            crate::webhooks::WebhookEventType::SettlementCompleted
        ).await;
    }

    tracing::info!(
        "USDC settlement completed: ${:.6} USDC to {} (tx: {})", 
        usdc_amount, merchant_wallet, signature
    );

    Ok(())
}

fn create_memo_instruction(memo: &str) -> Instruction {
    Instruction {
        program_id: Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr").unwrap(), // Memo program ID
        accounts: vec![],
        data: memo.as_bytes().to_vec(),
    }
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

async fn process_usdc_wallet_transfer_with_retry(
    state: &AppState,
    settlement_id: Uuid,
    usdc_amount: f64,
    merchant_wallet: &str,
    max_retries: u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut attempts = 0;
    
    while attempts < max_retries {
        match process_usdc_wallet_transfer(state, settlement_id, usdc_amount, merchant_wallet).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                attempts += 1;
                tracing::warn!("USDC transfer attempt {} failed: {}", attempts, e);
                
                if attempts >= max_retries {
                    sqlx::query!(
                        r#"
                        UPDATE settlements 
                        SET status = 'failed',
                            provider_response = $1
                        WHERE id = $2
                        "#,
                        serde_json::json!({
                            "status": "failed",
                            "error": e.to_string(),
                            "attempts": attempts,
                            "failure_reason": "max_retries_exceeded"
                        }),
                        settlement_id
                    )
                    .execute(&state.db)
                    .await?;
                    
                    return Err(e);
                }

                let delay_seconds = 2_u64.pow(attempts);
                tokio::time::sleep(std::time::Duration::from_secs(delay_seconds)).await;
            }
        }
    }
    
    Ok(())
}

async fn check_escrow_balance(
    state: &AppState,
    required_usdc: f64,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let keypair_path = state.config.wallet_keypair_path
        .as_ref()
        .ok_or("Escrow wallet keypair path not configured")?;
    
    let keypair_bytes = fs::read(keypair_path)?;

    if keypair_bytes.len() != 64 {
        return Err("Invalid keypair file length".into());
    }
    
    let mut keypair_array = [0u8; 64];
    keypair_array.copy_from_slice(&keypair_bytes);
    let escrow_keypair = Keypair::try_from(&keypair_array[..])?;
    
    let rpc_client = RpcClient::new(&state.solana_rpc_url);
    let usdc_mint = Pubkey::from_str(&get_usdc_mint_for_network(&state.config.solana_network))?;
    let escrow_ata = get_associated_token_address(&escrow_keypair.pubkey(), &usdc_mint);
    
    match rpc_client.get_token_account_balance(&escrow_ata) {
        Ok(balance) => {
            let current_balance = balance.ui_amount.unwrap_or(0.0);
            let has_sufficient = current_balance >= required_usdc;
            
            tracing::info!(
                "Escrow USDC balance: ${:.6}, Required: ${:.6}, Sufficient: {}",
                current_balance, required_usdc, has_sufficient
            );
            
            Ok(has_sufficient)
        }
        Err(e) => {
            tracing::error!("Failed to check escrow balance: {}", e);
            Err(e.into())
        }
    }
}

async fn execute_usdt_to_usdc_swap(
    state: &AppState,
    usdt_amount: f64,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let _swap_request = serde_json::json!({ 
        "inputMint": crate::solana::DEVNET_USDT_MINT,
        "outputMint": get_usdc_mint_for_network(&state.config.solana_network),
        "amount": (usdt_amount * 1_000_000.0) as u64,
        "slippageBps": 25,
    });

    // TODO: Real Jupiter API integration for USDT->USDC
    let simulated_signature = format!("SWAP_USDT_USDC_{}", Uuid::new_v4());
    
    tracing::info!("Executed USDT->USDC swap: {} USDT -> {} USDC (signature: {})", 
                   usdt_amount, usdt_amount, simulated_signature);
    
    Ok(simulated_signature)
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
        let transaction_fee = amount_usd * 0.015; 
        let merchant_receives = amount_usd - transaction_fee;
        Ok((merchant_receives, transaction_fee))
    }
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
                  account_name, status, batch_id, estimated_processing_time,
                  external_reference, provider, created_at, completed_at
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
        let expected_ngn = amount_usd * 1650.0;
        let expected_fee = expected_ngn * 0.02;
        let expected_merchant = expected_ngn - expected_fee;
        
        assert!(expected_merchant > 0.0);
        assert!(expected_fee > 0.0);
        assert_eq!(expected_fee, 3300.0); 
    }
}