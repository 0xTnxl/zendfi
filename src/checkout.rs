use axum::{
    extract::{State, Path, Extension},
    http::StatusCode,
    Json, response::Html,
};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use crate::{AppState, auth::AuthenticatedMerchant};
use bigdecimal::{BigDecimal, FromPrimitive};

#[derive(Debug, Serialize, Deserialize)]
pub struct CreatePaymentLinkRequest {
    pub amount: f64,
    pub currency: String,
    pub token: Option<String>,
    pub description: Option<String>,
    pub max_uses: Option<i32>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaymentLinkResponse {
    pub id: Uuid,
    pub link_code: String,
    pub payment_url: String,
    pub hosted_page_url: String,
    pub amount: f64,
    pub currency: String,
    pub token: String,
    pub max_uses: Option<i32>,
    pub uses_count: i32,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostedCheckoutData {
    pub payment_id: Uuid,
    pub merchant_name: String,
    pub amount_usd: f64,
    pub currency: String,
    pub token: String,
    pub description: Option<String>,
    pub qr_code: String,
    pub payment_url: String,
    pub wallet_address: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub status: String,
}

pub async fn create_payment_link(
    State(state): State<AppState>,
    Extension(merchant): Extension<AuthenticatedMerchant>,
    Json(request): Json<CreatePaymentLinkRequest>,
) -> Result<Json<PaymentLinkResponse>, StatusCode> {
    if request.amount <= 0.0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Generate unique short code (8 characters)
    let link_code = generate_link_code();
    let link_id = Uuid::new_v4();
    let token = request.token.as_deref().unwrap_or("USDC").to_uppercase();

    let amount_bd = BigDecimal::from_f64(request.amount).unwrap();

    sqlx::query!(
        r#"
        INSERT INTO payment_links 
        (id, merchant_id, link_code, amount_usd, currency, token, description, metadata, max_uses, expires_at, is_active, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
        "#,
        link_id,
        merchant.merchant_id,
        link_code,
        amount_bd,
        request.currency,
        token,
        request.description,
        request.metadata.unwrap_or(serde_json::json!({})),
        request.max_uses,
        request.expires_at,
        true
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create payment link: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let frontend_url = &state.config.frontend_url;
    let payment_url = format!("{}/pay/link/{}", frontend_url, link_code);
    let hosted_page_url = format!("{}/checkout/{}", frontend_url, link_code);

    tracing::info!("Created payment link {} for merchant {}", link_code, merchant.merchant_id);

    Ok(Json(PaymentLinkResponse {
        id: link_id,
        link_code: link_code.clone(),
        payment_url,
        hosted_page_url,
        amount: request.amount,
        currency: request.currency,
        token,
        max_uses: request.max_uses,
        uses_count: 0,
        expires_at: request.expires_at,
        is_active: true,
        created_at: chrono::Utc::now(),
    }))
}

pub async fn get_payment_link(
    State(state): State<AppState>,
    Path(link_code): Path<String>,
) -> Result<Json<PaymentLinkResponse>, StatusCode> {
    let link = sqlx::query!(
        r#"
        SELECT id, merchant_id, link_code, amount_usd, currency, token, max_uses, uses_count, expires_at, is_active, created_at
        FROM payment_links
        WHERE link_code = $1
        "#,
        link_code
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    let frontend_url = &state.config.frontend_url;

    Ok(Json(PaymentLinkResponse {
        id: link.id,
        link_code: link.link_code.clone(),
        payment_url: format!("{}/pay/link/{}", frontend_url, link.link_code),
        hosted_page_url: format!("{}/checkout/{}", frontend_url, link.link_code),
        amount: link.amount_usd.to_string().parse().unwrap_or(0.0),
        currency: link.currency,
        token: link.token,
        max_uses: link.max_uses,
        uses_count: link.uses_count.unwrap_or(0),
        expires_at: link.expires_at,
        is_active: link.is_active.unwrap_or(true),
        created_at: link.created_at.unwrap_or_else(|| chrono::Utc::now()),
    }))
}

// Create payment from link (when customer clicks the link)
pub async fn create_payment_from_link(
    State(state): State<AppState>,
    Path(link_code): Path<String>,
) -> Result<Json<HostedCheckoutData>, StatusCode> {
    let link = sqlx::query!(
        r#"
        SELECT id, merchant_id, amount_usd, currency, token, description, max_uses, uses_count, expires_at, is_active
        FROM payment_links
        WHERE link_code = $1 AND is_active = TRUE
        "#,
        link_code
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    if let Some(expires_at) = link.expires_at {
        if expires_at < chrono::Utc::now() {
            return Err(StatusCode::GONE);
        }
    }

    if let Some(max_uses) = link.max_uses {
        if link.uses_count.unwrap_or(0) >= max_uses {
            return Err(StatusCode::GONE);
        }
    }

    let merchant = sqlx::query!(
        "SELECT name, wallet_address FROM merchants WHERE id = $1",
        link.merchant_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let payment_id = Uuid::new_v4();
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(15);
    let token_enum = match link.token.as_str() {
        "SOL" => crate::solana::SupportedToken::Sol,
        "USDT" => crate::solana::SupportedToken::Usdt,
        _ => crate::solana::SupportedToken::Usdc,
    };

    let amount_f64 = link.amount_usd.to_string().parse().unwrap_or(0.0);
    let qr_code = crate::solana::generate_payment_qr(
        &payment_id,
        amount_f64,
        &merchant.wallet_address,
        &state.config.solana_network,
        token_enum,
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let payment_metadata = serde_json::json!({
        "description": link.description,
        "qr_code": qr_code,
        "payment_link_code": link_code,
        "merchant_wallet": merchant.wallet_address
    });

    sqlx::query!(
        r#"
        INSERT INTO payments 
        (id, merchant_id, amount_usd, status, expires_at, payment_token, payment_link_id, metadata, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
        "#,
        payment_id,
        link.merchant_id,
        link.amount_usd,
        crate::models::PaymentStatus::Pending as crate::models::PaymentStatus,
        expires_at,
        link.token,
        link.id,
        payment_metadata
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create payment from link: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    sqlx::query!(
        "UPDATE payment_links SET uses_count = uses_count + 1 WHERE id = $1",
        link.id
    )
    .execute(&state.db)
    .await
    .ok();

    sqlx::query!(
        r#"
        INSERT INTO payment_link_uses (id, payment_link_id, payment_id, used_at)
        VALUES ($1, $2, $3, NOW())
        "#,
        Uuid::new_v4(),
        link.id,
        payment_id
    )
    .execute(&state.db)
    .await
    .ok();

    Ok(Json(HostedCheckoutData {
        payment_id,
        merchant_name: merchant.name,
        amount_usd: amount_f64,
        currency: link.currency,
        token: link.token,
        description: link.description,
        qr_code: qr_code.clone(),
        payment_url: format!("solana:{}", qr_code),
        wallet_address: merchant.wallet_address,
        expires_at,
        status: "pending".to_string(),
    }))
}

pub async fn get_hosted_checkout_page(
    State(state): State<AppState>,
    Path(link_code): Path<String>,
) -> Result<Html<String>, StatusCode> {
    let checkout_data = create_payment_from_link(State(state.clone()), Path(link_code.clone()))
        .await?
        .0;

    let html = render_checkout_page(&checkout_data, &state.config.frontend_url);
    Ok(Html(html))
}

pub async fn get_payment_page(
    State(state): State<AppState>,
    Path(payment_id): Path<Uuid>,
) -> Result<Html<String>, StatusCode> {
    let payment = sqlx::query!(
        r#"
        SELECT p.id, p.merchant_id, p.amount_usd, p.status as "status: crate::models::PaymentStatus", 
               p.expires_at, p.payment_token, p.metadata,
               m.name as merchant_name, m.wallet_address as merchant_wallet
        FROM payments p
        JOIN merchants m ON p.merchant_id = m.id
        WHERE p.id = $1
        "#,
        payment_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    let qr_code = payment.metadata.get("qr_code")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let checkout_data = HostedCheckoutData {
        payment_id: payment.id,
        merchant_name: payment.merchant_name,
        amount_usd: payment.amount_usd.to_string().parse().unwrap_or(0.0),
        currency: "USD".to_string(),
        token: payment.payment_token.unwrap_or_else(|| "USDC".to_string()),
        description: payment.metadata.get("description").and_then(|v| v.as_str()).map(String::from),
        qr_code: qr_code.clone(),
        payment_url: format!("solana:{}", qr_code),
        wallet_address: payment.merchant_wallet,
        expires_at: payment.expires_at,
        status: format!("{:?}", payment.status).to_lowercase(),
    };

    let html = render_checkout_page(&checkout_data, &state.config.frontend_url);
    Ok(Html(html))
}

pub fn generate_link_code() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    
    (0..8)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

fn render_checkout_page(data: &HostedCheckoutData, api_base: &str) -> String {
    format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pay {merchant_name} - ${amount} {token}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 500px;
            width: 100%;
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{ font-size: 24px; margin-bottom: 8px; }}
        .header p {{ opacity: 0.9; font-size: 14px; }}
        .content {{ padding: 30px; text-align: center; }}
        .amount {{
            font-size: 48px;
            font-weight: bold;
            color: #667eea;
            margin: 20px 0;
        }}
        .description {{
            color: #666;
            margin-bottom: 30px;
            font-size: 16px;
        }}
        .tabs {{
            display: flex;
            border-bottom: 2px solid #e0e0e0;
            margin-bottom: 20px;
        }}
        .tab {{
            flex: 1;
            padding: 12px;
            background: none;
            border: none;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            color: #666;
            transition: all 0.3s;
        }}
        .tab.active {{
            color: #667eea;
            border-bottom: 2px solid #667eea;
            margin-bottom: -2px;
        }}
        .tab-content {{
            display: none;
        }}
        .tab-content.active {{
            display: block;
        }}
        .qr-container {{
            background: #f8f9fa;
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
            display: inline-block;
        }}
        .qr-code {{
            width: 256px;
            height: 256px;
            background: white;
            padding: 10px;
            border-radius: 8px;
        }}
        .status {{
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 600;
            margin: 20px 0;
            display: inline-block;
        }}
        .status-pending {{ background: #fff3cd; color: #856404; }}
        .status-confirmed {{ background: #d4edda; color: #155724; }}
        .status-failed {{ background: #f8d7da; color: #721c24; }}
        .wallet-button {{
            background: #667eea;
            color: white;
            border: none;
            padding: 16px 32px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            margin: 10px 0;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }}
        .wallet-button:hover {{ background: #5568d3; transform: translateY(-2px); }}
        .wallet-button:disabled {{ background: #ccc; cursor: not-allowed; transform: none; }}
        .wallet-icon {{ width: 24px; height: 24px; }}
        .timer {{
            color: #666;
            font-size: 14px;
            margin-top: 20px;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 12px;
        }}
        .loading {{ display: none; }}
        .loading.active {{ display: inline-block; }}
        .error-message {{
            background: #f8d7da;
            color: #721c24;
            padding: 12px;
            border-radius: 8px;
            margin: 10px 0;
            display: none;
        }}
        .error-message.active {{ display: block; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{merchant_name}</h1>
            <p>Secure Crypto Payment</p>
        </div>
        
        <div class="content">
            <div class="amount">${amount} {token}</div>
            <div class="description">{description}</div>
            
            <div id="status" class="status status-pending">⏳ Awaiting Payment</div>
            
            <div class="tabs">
                <button class="tab active" onclick="switchTab('wallet')">Connect Wallet</button>
                <button class="tab" onclick="switchTab('qr')">QR Code</button>
            </div>
            
            <!-- Web3 Wallet Tab -->
            <div id="wallet-tab" class="tab-content active">
                <button id="connect-wallet-btn" class="wallet-button" onclick="connectWallet()">
                    <span>🔗 Connect Wallet</span>
                </button>
                <div id="wallet-connected" style="display: none;">
                    <button class="wallet-button" onclick="payWithWallet()">
                        💳 Pay ${amount} {token}
                    </button>
                    <button class="wallet-button" onclick="disconnectWallet()" style="background: #6c757d;">
                        🔌 Disconnect
                    </button>
                </div>
                <div id="error-message" class="error-message"></div>
                <p style="color: #999; font-size: 12px; margin-top: 20px;">
                    Supports: Phantom, Solflare, Backpack, and more
                </p>
            </div>
            
            <!-- QR Code Tab -->
            <div id="qr-tab" class="tab-content">
                <div class="qr-container">
                    <canvas id="qrcode" class="qr-code"></canvas>
                </div>
                
                <button class="wallet-button" onclick="openSolanaPay()" style="background: #14F195; color: #000;">
                    📱 Open in Wallet App
                </button>
                
                <button class="wallet-button" onclick="copyAddress()" style="background: #6c757d;">
                    📋 Copy Wallet Address
                </button>
            </div>
            
            <div class="timer" id="timer">Expires in 15:00</div>
        </div>
        
        <div class="footer">
            Powered by ZendFi • Secured by Solana
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/qrious@4/dist/qrious.min.js"></script>
    <script src="https://unpkg.com/@solana/web3.js@latest/lib/index.iife.min.js"></script>
    <script>
        
        const paymentId = '{payment_id}';
        const walletAddress = '{wallet_address}';
        const amount = {amount};
        const token = '{token}';
        const expiresAt = new Date('{expires_at}');
        let walletAdapter = null;
        let publicKey = null;
        
        // Generate QR code
        new QRious({{
            element: document.getElementById('qrcode'),
            value: '{payment_url}',
            size: 256
        }});
        
        // Tab switching
        function switchTab(tab) {{
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            if (tab === 'wallet') {{
                document.querySelectorAll('.tab')[0].classList.add('active');
                document.getElementById('wallet-tab').classList.add('active');
            }} else {{
                document.querySelectorAll('.tab')[1].classList.add('active');
                document.getElementById('qr-tab').classList.add('active');
            }}
        }}
        
        // Connect Solana wallet
        async function connectWallet() {{
            try {{
                showError('');
                
                if (typeof window.solana === 'undefined') {{
                    showError('No Solana wallet found. Please install Phantom, Solflare, or Backpack.');
                    return;
                }}
                
                const resp = await window.solana.connect();
                publicKey = resp.publicKey.toString();
                
                document.getElementById('connect-wallet-btn').style.display = 'none';
                document.getElementById('wallet-connected').style.display = 'block';
                
                console.log('Connected:', publicKey);
            }} catch (err) {{
                showError('Failed to connect wallet: ' + err.message);
            }}
        }}
        
        // Disconnect wallet
        function disconnectWallet() {{
            if (window.solana) {{
                window.solana.disconnect();
            }}
            publicKey = null;
            document.getElementById('connect-wallet-btn').style.display = 'block';
            document.getElementById('wallet-connected').style.display = 'none';
        }}
        
        // Pay with connected wallet
        async function payWithWallet() {{
            if (!publicKey) {{
                showError('Please connect your wallet first');
                return;
            }}
            
            try {{
                showError('');
                
                // Show loading state
                const payBtn = event.target;
                const originalText = payBtn.innerHTML;
                payBtn.innerHTML = '⏳ Processing...';
                payBtn.disabled = true;
                
                const connection = new solanaWeb3.Connection(
                    'https://api.devnet.solana.com',
                    'confirmed'
                );
                
                const recipientPubkey = new solanaWeb3.PublicKey(walletAddress);
                const senderPubkey = new solanaWeb3.PublicKey(publicKey);
                
                // Check SOL balance first
                const solBalance = await connection.getBalance(senderPubkey);
                const solBalanceInSol = solBalance / solanaWeb3.LAMPORTS_PER_SOL;
                
                console.log('SOL Balance:', solBalanceInSol);
                
                if (solBalanceInSol < 0.001) {{
                    throw new Error('Insufficient SOL for transaction fees. You need at least 0.001 SOL.');
                }}
                
                let transaction = new solanaWeb3.Transaction();
                
                if (token === 'SOL') {{
                    // SOL transfer
                    const lamports = amount * solanaWeb3.LAMPORTS_PER_SOL;
                    transaction.add(
                        solanaWeb3.SystemProgram.transfer({{
                            fromPubkey: senderPubkey,
                            toPubkey: recipientPubkey,
                            lamports: Math.floor(lamports),
                        }})
                    );
                }} else {{
                    // SPL Token transfer (USDC/USDT)
                    const TOKEN_PROGRAM_ID = new solanaWeb3.PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
                    const ASSOCIATED_TOKEN_PROGRAM_ID = new solanaWeb3.PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');
                    
                    // Token mint addresses
                    const mintAddresses = {{
                        'USDC': '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU', // devnet
                        'USDT': 'EgEHQxJ8aPe7bsrR88zG3w3Y9N5CZg3w8d1K1CZg3w8d'  // devnet
                    }};
                    
                    const mintPubkey = new solanaWeb3.PublicKey(mintAddresses[token] || mintAddresses.USDC);
                    
                    // Get associated token accounts
                    function getAssociatedTokenAddress(mint, owner) {{
                        const seeds = [
                            owner.toBytes(),
                            TOKEN_PROGRAM_ID.toBytes(),
                            mint.toBytes()
                        ];
                        const [address] = solanaWeb3.PublicKey.findProgramAddressSync(
                            seeds,
                            ASSOCIATED_TOKEN_PROGRAM_ID
                        );
                        return address;
                    }}
                    
                    const senderTokenAccount = getAssociatedTokenAddress(mintPubkey, senderPubkey);
                    const recipientTokenAccount = getAssociatedTokenAddress(mintPubkey, recipientPubkey);
                    
                    // Check if recipient token account exists, if not create it
                    const recipientAccountInfo = await connection.getAccountInfo(recipientTokenAccount);
                    
                    if (!recipientAccountInfo) {{
                        // Create associated token account for recipient
                        const createATAIx = solanaWeb3.SystemProgram.createAccount({{
                            fromPubkey: senderPubkey,
                            newAccountPubkey: recipientTokenAccount,
                            space: 165, // Token account space
                            lamports: await connection.getMinimumBalanceForRentExemption(165),
                            programId: TOKEN_PROGRAM_ID,
                        }});
                        
                        const initATAIx = new solanaWeb3.TransactionInstruction({{
                            keys: [
                                {{ pubkey: senderPubkey, isSigner: true, isWritable: true }},
                                {{ pubkey: recipientTokenAccount, isSigner: false, isWritable: true }},
                                {{ pubkey: recipientPubkey, isSigner: false, isWritable: false }},
                                {{ pubkey: mintPubkey, isSigner: false, isWritable: false }},
                                {{ pubkey: solanaWeb3.SystemProgram.programId, isSigner: false, isWritable: false }},
                                {{ pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false }},
                            ],
                            programId: ASSOCIATED_TOKEN_PROGRAM_ID,
                            data: new Uint8Array([1]), // InitializeAccount3
                        }});
                        
                        transaction.add(createATAIx, initATAIx);
                    }}
                    
                    // SPL Token transfer instruction
                    const decimals = token === 'USDC' ? 6 : 6; // Both USDC and USDT use 6 decimals
                    const transferAmount = Math.floor(amount * Math.pow(10, decimals));
                    
                    // Create transfer instruction data using Uint8Array
                    const transferData = new Uint8Array(9);
                    transferData[0] = 3; // Transfer instruction
                    // Write amount as little-endian u64
                    const amountBytes = new BigUint64Array([BigInt(transferAmount)]);
                    const amountView = new Uint8Array(amountBytes.buffer);
                    transferData.set(amountView, 1);
                    
                    const transferIx = new solanaWeb3.TransactionInstruction({{
                        keys: [
                            {{ pubkey: senderTokenAccount, isSigner: false, isWritable: true }},
                            {{ pubkey: recipientTokenAccount, isSigner: false, isWritable: true }},
                            {{ pubkey: senderPubkey, isSigner: true, isWritable: false }},
                        ],
                        programId: TOKEN_PROGRAM_ID,
                        data: transferData,
                    }});
                    
                    transaction.add(transferIx);
                }}
                
                // Add memo with payment reference
                const memoText = `Payment:${{paymentId}}`;
                const memoData = new TextEncoder().encode(memoText);
                const memoInstruction = new solanaWeb3.TransactionInstruction({{
                    keys: [],
                    programId: new solanaWeb3.PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'),
                    data: memoData,
                }});
                transaction.add(memoInstruction);
                
                // Set transaction properties
                transaction.feePayer = senderPubkey;
                transaction.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
                
                // Sign and send transaction
                const signed = await window.solana.signAndSendTransaction(transaction);
                console.log('Transaction sent:', signed.signature);
                
                // Update payment with signature
                await fetch(`{api_base}/api/v1/payments/${{paymentId}}/confirm`, {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ transaction_signature: signed.signature }})
                }});
                
                document.getElementById('status').className = 'status status-confirmed';
                document.getElementById('status').textContent = '✅ Payment Confirmed!';
                payBtn.innerHTML = '✅ Payment Sent!';
                
            }} catch (err) {{
                console.error('Payment error:', err);
            
                // Provide more specific error messages
                let errorMessage = 'Payment failed: ';
                
                if (err.message.includes('insufficient') || err.message.includes('Insufficient')) {{
                    errorMessage = '❌ Insufficient funds. Make sure you have enough ' + token + ' and SOL for transaction fees.';
                }} else if (err.message.includes('User rejected')) {{
                    errorMessage = '❌ Transaction was rejected in your wallet.';
                }} else if (err.message.includes('Blockhash not found')) {{
                    errorMessage = '❌ Transaction expired. Please try again.';
                }} else {{
                    errorMessage += err.message || 'Unknown error occurred';
                }}
                
                // Restore button
                const payBtn = event.target;
                if (payBtn) {{
                    payBtn.innerHTML = '💳 Pay $' + amount + ' ' + token;
                    payBtn.disabled = false;
                }}
            }}
        }}
        
        // Show error message
        function showError(msg) {{
            const errorEl = document.getElementById('error-message');
            if (msg) {{
                errorEl.textContent = msg;
                errorEl.classList.add('active');
            }} else {{
                errorEl.classList.remove('active');
            }}
        }}
        
        // Countdown timer
        function updateTimer() {{
            const now = new Date();
            const diff = expiresAt - now;
            
            if (diff <= 0) {{
                document.getElementById('timer').textContent = 'Payment expired';
                document.getElementById('status').className = 'status status-failed';
                document.getElementById('status').textContent = '⏰ Payment Expired';
                return;
            }}
            
            const minutes = Math.floor(diff / 60000);
            const seconds = Math.floor((diff % 60000) / 1000);
            document.getElementById('timer').textContent = 
                `Expires in ${{minutes}}:${{seconds.toString().padStart(2, '0')}}`;
        }}
        
        setInterval(updateTimer, 1000);
        updateTimer();
        
        // Poll payment status
        async function checkPaymentStatus() {{
            try {{
                const response = await fetch(`{api_base}/api/v1/payments/${{paymentId}}/status`);
                const data = await response.json();
                
                const statusEl = document.getElementById('status');
                if (data.status === 'confirmed') {{
                    statusEl.className = 'status status-confirmed';
                    statusEl.textContent = '✅ Payment Confirmed';
                }} else if (data.status === 'failed') {{
                    statusEl.className = 'status status-failed';
                    statusEl.textContent = '❌ Payment Failed';
                }}
            }} catch (e) {{
                console.error('Status check failed:', e);
            }}
        }}
        
        setInterval(checkPaymentStatus, 5000);
        
        // Open Solana Pay URL
        function openSolanaPay() {{
            window.location.href = '{payment_url}';
        }}
        
        // Copy address
        function copyAddress() {{
            navigator.clipboard.writeText(walletAddress);
            alert('Wallet address copied!');
        }}
    </script>
</body>
</html>
    "#,
        merchant_name = data.merchant_name,
        amount = data.amount_usd,
        token = data.token,
        description = data.description.as_deref().unwrap_or("Complete your payment"),
        payment_id = data.payment_id,
        wallet_address = data.wallet_address,
        payment_url = data.payment_url,
        expires_at = data.expires_at.to_rfc3339(),
        api_base = api_base
    )
}