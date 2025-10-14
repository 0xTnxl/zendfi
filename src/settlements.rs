use uuid::Uuid;
use bigdecimal::ToPrimitive;
use crate::{AppState, models::*, key_manager::SecureKeyManager};
use solana_sdk::{
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
use base64::Engine;
use solana_sdk::signer::keypair::Keypair;
use solana_sdk::pubkey::Pubkey;
use bigdecimal::BigDecimal;
use bigdecimal::FromPrimitive;

pub async fn process_settlement(
    state: &AppState,
    payment_id: Uuid,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut db_tx = state.db.begin().await?;
    
    let payment = sqlx::query!(
        r#"SELECT p.id, p.merchant_id, p.amount_usd, 
                  p.status as "status: PaymentStatus", 
                  COALESCE(p.payment_token, 'USDC') as payment_token,
                  p.settlement_preference_override,
                  m.settlement_preference, m.wallet_address, m.name
           FROM payments p 
           JOIN merchants m ON p.merchant_id = m.id 
           WHERE p.id = $1
           FOR UPDATE"#,  
        payment_id
    )
    .fetch_one(&mut *db_tx)
    .await?;

    if !matches!(payment.status, PaymentStatus::Confirmed) {
        db_tx.rollback().await?;
        return Err("Payment not confirmed".into());
    }

    let existing_settlement = sqlx::query!(
        "SELECT id FROM settlements WHERE payment_id = $1",
        payment_id
    )
    .fetch_optional(&mut *db_tx)
    .await?;

    if existing_settlement.is_some() {
        db_tx.rollback().await?;
        tracing::info!("Settlement already exists for payment {}", payment_id);
        return Ok(());
    }

    let amount_usd = payment.amount_usd.to_f64().unwrap_or(0.0);
    let payment_token = payment.payment_token.as_deref().unwrap_or("USDC");
    let merchant_wallet = payment.wallet_address;

    let settlement_preference = payment.settlement_preference_override
        .as_deref()
        .or(payment.settlement_preference.as_deref())
        .unwrap_or("auto_usdc");

    // Process settlement based on preference
    let result = match settlement_preference {
        "direct_token" => {
            process_direct_token_settlement_atomic(
                &mut db_tx,
                state, 
                payment_id, 
                amount_usd, 
                payment_token, 
                payment.merchant_id,
                &merchant_wallet,
                &payment.name
            ).await
        }
        _ => {
            process_usdc_settlement_atomic(
                &mut db_tx,
                state,
                payment_id,
                amount_usd,
                payment_token,
                payment.merchant_id,
                &merchant_wallet,
                &payment.name
            ).await
        }
    };

    match result {
        Ok(_) => {
            db_tx.commit().await?;
            tracing::info!("Settlement completed atomically for payment {}", payment_id);
            Ok(())
        }
        Err(e) => {
            db_tx.rollback().await?;
            tracing::error!("Settlement failed for payment {}, rolled back: {}", payment_id, e);
            Err(e)
        }
    }
}

async fn process_direct_token_settlement_atomic(
    db_tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    state: &AppState,
    payment_id: Uuid,
    amount_usd: f64,
    payment_token: &str,
    merchant_id: Uuid,
    merchant_wallet: &str,
    merchant_name: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!("Processing atomic direct {} settlement: ${} to {} ({})", 
                   payment_token, amount_usd, merchant_wallet, merchant_name);

    let (merchant_receives, _solapay_fee) = calculate_settlement_amounts(amount_usd).await?;

    if !check_escrow_balance(state, merchant_receives, payment_token).await? {
        return Err(format!("Insufficient {} balance in escrow wallet", payment_token).into());
    }

    let settlement_id = Uuid::new_v4();

    sqlx::query!(
        r#"
        INSERT INTO settlements 
        (id, payment_id, payment_token, settlement_token, amount_recieved, amount_settled,
         settlement_currency, recipient_wallet, merchant_id, status, provider, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'processing', 'solapay_direct', $10)
        "#,
        settlement_id,
        payment_id,
        payment_token,
        payment_token, 
        BigDecimal::from_f64(amount_usd).unwrap(),
        BigDecimal::from_f64(merchant_receives).unwrap(),
        payment_token,
        merchant_wallet,
        merchant_id,
        chrono::Utc::now()
    )
    .execute(&mut **db_tx)
    .await?;

    // Execute the actual transfer (this is atomic with blockchain)
    execute_crypto_transfer(state, settlement_id, merchant_receives, payment_token, merchant_wallet).await?;

    tracing::info!("Direct {} settlement completed atomically: ${} to {}", 
                   payment_token, merchant_receives, merchant_name);

    // Webhook will be sent after transaction commits
    Ok(())
}

async fn process_usdc_settlement_atomic(
    db_tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    state: &AppState,
    payment_id: Uuid,
    amount_usd: f64,
    payment_token: &str,
    merchant_id: Uuid,
    merchant_wallet: &str,
    merchant_name: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!("Processing atomic USDC settlement: {} {} -> USDC to {} ({})", 
                   amount_usd, payment_token, merchant_wallet, merchant_name);

    let final_usdc_amount = if payment_token != "USDC" {
        tracing::info!("Swapping {} {} to USDC via Jupiter", amount_usd, payment_token);

        execute_jupiter_swap(state, payment_token, "USDC", amount_usd).await
            .map_err(|e| {
                tracing::error!("Jupiter swap failed for {} -> USDC: {}", payment_token, e);
                e
            })?
    } else {
        tracing::info!("Payment already in USDC, no swap needed");
        amount_usd
    };

    let (merchant_receives_usdc, solapay_fee) = calculate_settlement_amounts(final_usdc_amount).await?;
    
    tracing::info!("Settlement calculation: {} USDC received -> {} USDC to merchant (fee: {} USDC)", 
                   final_usdc_amount, merchant_receives_usdc, solapay_fee);

    if !check_escrow_balance(state, merchant_receives_usdc, "USDC").await? {
        return Err(format!(
            "Insufficient USDC balance in escrow wallet. Required: {}, check escrow funding", 
            merchant_receives_usdc
        ).into());
    }

    let settlement_id = Uuid::new_v4();
    
    sqlx::query!(
        r#"
        INSERT INTO settlements 
        (id, payment_id, payment_token, settlement_token, amount_recieved, amount_settled,
         settlement_currency, recipient_wallet, merchant_id, status, provider, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'processing', 'solapay_dex', $10)
        "#,
        settlement_id,
        payment_id,
        payment_token,
        "USDC", 
        BigDecimal::from_f64(amount_usd).unwrap(), 
        BigDecimal::from_f64(merchant_receives_usdc).unwrap(), 
        "USDC",
        merchant_wallet,
        merchant_id,
        chrono::Utc::now()
    )
    .execute(&mut **db_tx)
    .await
    .map_err(|e| {
        tracing::error!("Failed to insert settlement record: {}", e);
        format!("Database error during settlement creation: {}", e)
    })?;

    tracing::info!("Settlement record created with ID: {}", settlement_id);

    execute_crypto_transfer(state, settlement_id, merchant_receives_usdc, "USDC", merchant_wallet).await
        .map_err(|e| {
            tracing::error!("USDC transfer failed for settlement {}: {}", settlement_id, e);
            e
        })?;

    tracing::info!("Atomic USDC settlement completed successfully: {} USDC to {} ({})", 
                   merchant_receives_usdc, merchant_wallet, merchant_name);
 
    Ok(())
}

async fn execute_jupiter_swap(
    state: &AppState,
    from_token: &str,
    to_token: &str,
    amount: f64,
) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!("Executing Jupiter swap: {} {} -> {}", amount, from_token, to_token);

    let quote = get_jupiter_quote(from_token, to_token, amount).await?;

    let swap_signature = execute_jupiter_swap_transaction(state, &quote).await?;

    let output_amount = quote["outAmount"].as_str()
        .ok_or("Invalid Jupiter quote response")?
        .parse::<u64>()?;

    let output_amount_tokens = output_amount as f64 / 1_000_000.0;
    
    tracing::info!("Jupiter swap completed: {} -> {} (tx: {})", 
                   amount, output_amount_tokens, swap_signature);
    
    Ok(output_amount_tokens)
}

async fn get_jupiter_quote(
    from_token: &str,
    to_token: &str,
    amount: f64,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::new();

    let from_mint = get_token_mint_address(from_token)?;
    let to_mint = get_token_mint_address(to_token)?;

    let amount_lamports = (amount * get_token_decimals_multiplier(from_token)?) as u64;
    
    let url = format!(
        "https://quote-api.jup.ag/v6/quote?inputMint={}&outputMint={}&amount={}&slippageBps=50",
        from_mint, to_mint, amount_lamports
    );
    
    let response = client
        .get(&url)
        .send()
        .await?;
    
    if !response.status().is_success() {
        return Err(format!("Jupiter quote API error: {}", response.status()).into());
    }
    
    let quote: serde_json::Value = response.json().await?;
    Ok(quote)
}

async fn execute_jupiter_swap_transaction(
    state: &AppState,
    quote: &serde_json::Value,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::new();

    let keypair_path = state.config.wallet_keypair_path
        .as_ref()
        .ok_or("Escrow wallet keypair path not configured")?;
    
    let keypair_bytes = fs::read(keypair_path)?;
    let mut keypair_array = [0u8; 64];
    keypair_array.copy_from_slice(&keypair_bytes);
    let escrow_keypair = Keypair::try_from(&keypair_array[..])?;

    let swap_request = serde_json::json!({
        "quoteResponse": quote,
        "userPublicKey": escrow_keypair.pubkey().to_string(),
        "wrapAndUnwrapSol": true,
        "dynamicComputeUnitLimit": true,
        "prioritizationFeeLamports": "auto"
    });
    
    let response = client
        .post("https://quote-api.jup.ag/v6/swap")
        .json(&swap_request)
        .send()
        .await?;
    
    if !response.status().is_success() {
        return Err(format!("Jupiter swap API error: {}", response.status()).into());
    }
    
    let swap_response: serde_json::Value = response.json().await?;
    let swap_transaction = swap_response["swapTransaction"]
        .as_str()
        .ok_or("No swap transaction in response")?;

    let transaction_bytes = base64::engine::general_purpose::STANDARD.decode(swap_transaction)?;
    let mut transaction: Transaction = bincode::deserialize(&transaction_bytes)
        .map_err(|e| format!("Failed to deserialize transaction: {}", e))?;

    let rpc_client = RpcClient::new(&state.solana_rpc_url);
    let recent_blockhash = rpc_client.get_latest_blockhash()?;
    transaction.partial_sign(&[&escrow_keypair], recent_blockhash);

    let signature = rpc_client.send_and_confirm_transaction(&transaction)?;
    
    Ok(signature.to_string())
}

/// Fallback: Load keypair from filesystem (legacy method)
pub fn load_keypair_from_filesystem(state: &AppState) -> Result<Keypair, Box<dyn std::error::Error + Send + Sync>> {
    let keypair_path = state.config.wallet_keypair_path
        .as_ref()
        .ok_or("Escrow wallet keypair path not configured - check WALLET_KEYPAIR_PATH")?;

    if !std::path::Path::new(keypair_path).exists() {
        return Err(format!("Keypair file does not exist: {}", keypair_path).into());
    }
    
    let keypair_bytes = fs::read(keypair_path)
        .map_err(|e| format!("Failed to read keypair file {}: {}", keypair_path, e))?;

    if keypair_bytes.len() == 64 {
        let mut keypair_array = [0u8; 64];
        keypair_array.copy_from_slice(&keypair_bytes);
        Keypair::try_from(&keypair_array[..])
            .map_err(|e| format!("Failed to parse 64-byte keypair: {}", e).into())
    } else if keypair_bytes.len() == 32 {
        Keypair::try_from(&keypair_bytes[..])
            .map_err(|e| format!("Failed to parse 32-byte seed: {}", e).into())
    } else {
        let key_data: Vec<u8> = serde_json::from_slice(&keypair_bytes)
            .map_err(|e| format!("Invalid keypair format (not 32, 64 bytes, or JSON): {} bytes, error: {}", keypair_bytes.len(), e))?;
            
        if key_data.len() == 64 {
            let mut keypair_array = [0u8; 64];
            keypair_array.copy_from_slice(&key_data);
            Keypair::try_from(&keypair_array[..])
                .map_err(|e| format!("Failed to parse JSON keypair: {}", e).into())
        } else {
            Err(format!("JSON keypair has invalid length: {} (expected 64)", key_data.len()).into())
        }
    }
}

async fn execute_crypto_transfer(
    state: &AppState,
    settlement_id: Uuid,
    amount: f64,
    token: &str,
    recipient_wallet: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!("Executing {} transfer: ${} to {}", token, amount, recipient_wallet);
    
    // Try encrypted key manager first, fallback to filesystem
    let escrow_keypair = match SecureKeyManager::from_env() {
        Ok(key_manager) => {
            tracing::info!("Using encrypted key manager for escrow wallet");
            // System UUID for escrow wallet (not merchant-specific)
            let system_uuid = Uuid::parse_str("00000000-0000-0000-0000-000000000001")?;
            
            match key_manager.retrieve_keypair(state, "escrow_wallet", system_uuid).await {
                Ok(keypair) => {
                    tracing::info!("Successfully retrieved encrypted escrow keypair");
                    keypair
                }
                Err(e) => {
                    tracing::warn!("Encrypted key not found, falling back to filesystem: {}", e);
                    load_keypair_from_filesystem(state)?
                }
            }
        }
        Err(e) => {
            tracing::warn!("Encrypted key manager not configured, using filesystem: {}", e);
            load_keypair_from_filesystem(state)?
        }
    };

    let rpc_client = RpcClient::new(&state.solana_rpc_url);
    let recipient_pubkey = Pubkey::from_str(recipient_wallet)
        .map_err(|e| format!("Invalid recipient wallet address: {}", e))?;

    let signature = match token {
        "SOL" => {
            let lamports = (amount * 1_000_000_000.0) as u64;
            let transfer_ix = solana_sdk::system_instruction::transfer(
                &escrow_keypair.pubkey(),
                &recipient_pubkey,
                lamports,
            );
            
            let recent_blockhash = rpc_client.get_latest_blockhash()
                .map_err(|e| format!("Failed to get blockhash: {}", e))?;

            let transaction = Transaction::new_signed_with_payer(
                &[transfer_ix],
                Some(&escrow_keypair.pubkey()),
                &[&escrow_keypair],
                recent_blockhash,
            );
            
            rpc_client.send_and_confirm_transaction(&transaction)
                .map_err(|e| format!("SOL transfer failed: {}", e))?
        }
        "USDC" | "USDT" => {
            let mint_address = get_token_mint_address(token)?;
            let token_mint = Pubkey::from_str(mint_address)
                .map_err(|e| format!("Invalid token mint address: {}", e))?;
            let amount_tokens = (amount * get_token_decimals_multiplier(token)?) as u64;
            
            let escrow_ata = get_associated_token_address(&escrow_keypair.pubkey(), &token_mint);
            let recipient_ata = get_associated_token_address(&recipient_pubkey, &token_mint);
            
            let mut instructions = Vec::new();

            // Check if the recipient ATA exists
            if rpc_client.get_account(&recipient_ata).is_err() {
                tracing::info!("Creating ATA for recipient: {}", recipient_ata);
                let create_ata_ix = ata_instruction::create_associated_token_account(
                    &escrow_keypair.pubkey(),
                    &recipient_pubkey,
                    &token_mint,
                    &spl_token::id(),
                );
                instructions.push(create_ata_ix);
            }

            let transfer_ix = token_instruction::transfer(
                &spl_token::id(),
                &escrow_ata,
                &recipient_ata,
                &escrow_keypair.pubkey(),
                &[&escrow_keypair.pubkey()],
                amount_tokens,
            ).map_err(|e| format!("Failed to create transfer instruction: {}", e))?;
            instructions.push(transfer_ix);

            let memo_data = format!("Solapay settlement: {}", settlement_id);
            let memo_ix = create_memo_instruction(&memo_data);
            instructions.push(memo_ix);

            let recent_blockhash = rpc_client.get_latest_blockhash()
                .map_err(|e| format!("Failed to get blockhash: {}", e))?;

            let transaction = Transaction::new_signed_with_payer(
                &instructions,
                Some(&escrow_keypair.pubkey()),
                &[&escrow_keypair],
                recent_blockhash,
            );

            rpc_client.send_and_confirm_transaction(&transaction)
                .map_err(|e| format!("{} transfer failed: {}", token, e))?
        }
        _ => return Err(format!("Unsupported token: {}", token).into())
    };

    sqlx::query!(
        r#"UPDATE settlements 
           SET status = 'completed', transaction_signature = $1, completed_at = $2
           WHERE id = $3"#,
        signature.to_string(),
        chrono::Utc::now(),
        settlement_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| format!("Failed to update settlement status: {}", e))?;

    tracing::info!("{} transfer completed! Signature: {}", token, signature);
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
    required_amount: f64,
    token: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let keypair_path = state.config.wallet_keypair_path
        .as_ref()
        .ok_or("Escrow wallet keypair path not configured")?;
    
    let keypair_bytes = fs::read(keypair_path)?;
    let mut keypair_array = [0u8; 64];
    keypair_array.copy_from_slice(&keypair_bytes);
    let escrow_keypair = Keypair::try_from(&keypair_array[..])?;
    
    let rpc_client = RpcClient::new(&state.solana_rpc_url);
    
    match token {
        "SOL" => {
            let balance = rpc_client.get_balance(&escrow_keypair.pubkey())?;
            let balance_sol = balance as f64 / 1_000_000_000.0;
            tracing::info!("Escrow SOL balance: {}, required: {}", balance_sol, required_amount);
            Ok(balance_sol >= required_amount)
        }
        "USDC" | "USDT" => {
            let mint_address = get_token_mint_address(token)?;
            let token_mint = Pubkey::from_str(mint_address)?;
            let escrow_ata = get_associated_token_address(&escrow_keypair.pubkey(), &token_mint);
            
            match rpc_client.get_token_account_balance(&escrow_ata) {
                Ok(balance) => {
                    let current_balance = balance.ui_amount.unwrap_or(0.0);
                    tracing::info!("Escrow {} balance: {}, required: {}", token, current_balance, required_amount);
                    Ok(current_balance >= required_amount)
                }
                Err(e) => {
                    tracing::error!("Failed to get {} escrow balance: {}", token, e);
                    Ok(false)
                }
            }
        }
        _ => Ok(false)
    }
}

async fn calculate_settlement_amounts(
    amount: f64,
) -> Result<(f64, f64), Box<dyn std::error::Error + Send + Sync>> {
    let solapay_fee_rate = 0.029; // 2.9% fee
    let fee = amount * solapay_fee_rate;
    let merchant_receives = amount - fee;
    Ok((merchant_receives, fee))
}

fn get_token_mint_address(token: &str) -> Result<&'static str, Box<dyn std::error::Error + Send + Sync>> {
    match token.to_uppercase().as_str() {
        "USDC" => Ok("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"), 
        "USDT" => Ok("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"), 
        "SOL" => Ok("So11111111111111111111111111111111111111112"), 
        _ => Err(format!("Unsupported token: {}", token).into())
    }
}

fn get_token_decimals_multiplier(token: &str) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    match token.to_uppercase().as_str() {
        "USDC" | "USDT" => Ok(1_000_000.0),
        "SOL" => Ok(1_000_000_000.0),     
        _ => Err(format!("Unsupported token: {}", token).into())
    }
}