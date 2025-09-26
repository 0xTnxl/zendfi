Zendfi is a solana-based payment gateway specifically engineered for african developers and merchants. The core design processes multiple token payements, including SOL, USDC and USDT with optional settlement to NGN or USDC, it also features batch processing, real-time monitoring and extensive security

System Architecture
Solapay employs a microservice architecture built on Rust/Axum with PostgreSQL persistence, designed for high availability and horizontal scaling:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Client SDK    │    │   Payment API    │    │  Settlement     │
│                 │───▶│                  │───▶│  Engine         │
│ • QR Generation │    │ • Auth/Rate      │    │ • Batch Proc    │
│ • Status Check  │    │ • Payment Mgmt   │    │ • Quidax Integ  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  Solana Client  │    │  Webhook System │
                       │                 │    │                 │
                       │ • Multi-RPC     │    │ • Retry Logic   │
                       │ • Failover      │    │ • HMAC Security │
                       │ • Monitoring    │    │ • Event Stream  │
                       └─────────────────┘    └─────────────────┘
```

**Multi-Token Payment Processing**
The payment system handles three distinct token types with unified processing logic

**Native SOL Transfers:**
```rust
// Direct lamport transfers using system instructions
let transfer_ix = solana_sdk::system_instruction::transfer(
    &payer_pubkey,
    &recipient_pubkey,
    lamports,
);
```

SPL Token Transfer (USDC/USDT):
```rust
// Associated Token Account management with automatic creation
let transfer_ix = token_instruction::transfer(
    &spl_token::id(),
    &sender_ata,
    &recipient_ata,
    &authority,
    &[&authority],
    amount_with_decimals,
)?;
```

The system automatically detects payments types and applies appropriate decimal scaling (9 decimals fo SOL, 6 for stablecoins), ensuring precise amount matching across different token standards

**Transaction Discovery and Confirmation**
Payment verification basically employs a multi-stage prcess:

1. Signature Polling: Monitors the escrow wallet for incoming transactions
2. Transaction Analysis: Parses transaction data for payment references and amounts
3. Confirmation Tracking: Validates transaction finality using commitment levels
4. Settlement Triggering: Initiates appropriate settlement workflows

The transaction discovery mechanism searches through recent signatures, decodes instruction data, and matches payment references embedded in transaction memos or instruction data.

**Resilient Solana RPC Architecture**
Network reliability is very critical for payment processing. Solapay implements a RPC client with automatic failover:

```rust
pub struct ResilientSolanaClient {
    endpoints: Vec<SolanaEndpoint>,
    current_primary: AtomicUsize,
    request_timeout: Duration,
    semaphore: Arc<Semaphore>,
}
```

**Endpoint Health Monitoring:**
- Tracks success rates, response times and consecutive failures in real time
- Implement exponential backoffs for failed endpoints
- Automatically promotes healthy backups endpoints to primary
- Provides real-time health metrics through system momitoring

**Request Distrubution:**
- Semaphore-based concurrency limiting prevents endpoint overhead
- Circuit breaker pattern isolates the unhealthy endpoints
- Weighted round-robin distrubition based on endpoint performace

**Settlement Engine Architecture**
The settlement engine aims to address the core business challenges: converting volatile crypto payments into stable value transfers. The system supports two primary settlement modes:

Direct USDC Settlement: For merchants that are very comfortable with crypto, ot they just prefer the exposure, payments are processed through on-chain transfers from the escrow wallet to merchant wallets. This path minimizes the fees and settlement delays, while maintaining full blockchain transparency

NGN Bank Settlement: For more traditional merchants, or merchants who require local currency, Solapay implements batch processing mechanism:

1. Non-USDC payments are swapped to USDC through Quidax integration 
2. Multiple settlements are grouped into 30-minute processing windows
3. Quidax withdrawals to Nigerian banks requirw manual dashboard confirmations for regulatory compliance
4. Merchants would recieve real-time updates on settlement status via webhook notifications

**Quidax Integration Layer**

The Quidax integration serves as the bridge between crypto and traditional banking, handling:

```rust
// Create temporary deposit addresses for non-USDC tokens
let quidax_address = quidax_client.create_payment_address(
    &from_currency.to_lowercase(),
    Some("solana"), // Solana network specification
).await?;

// Execute atomic swaps with confirmation monitoring
let quotation = quidax_client.create_swap_quotation(
    &from_currency,
    "usdc",
    amount
).await?;
```

Balance Verification: Real-time wallet balance monitoring ensures deposit confirmation before proceeding with swaps, preventing failed transactions and improving settlement reliability.

Withdrawal Management: The system can initiate crypto withdrawals directly to merchant wallets for USDC settlements, while NGN settlements require manual processing through the Quidax dashboard due to banking regulations.

Batch Processing and Settlement Windows
NGN settlements employ a sophisticated batching mechanism optimized for operational efficiency:

Time-Based Batching: Settlements are grouped into 30-minute windows aligned with business hours, reducing manual processing overhead while maintaining reasonable settlement speeds.

**Status Progression:**

``` 
pending_manual -> ready_for_manual_processing -> completed
```

Admin Interface: A dedicated admin API provides settlement management capabilities:

```rust
// SHA256-hashed keys with prefix identification
let api_key = format!("zfi_live_{}", hex::encode(key_bytes));
let key_hash = sha2::Sha256::digest(api_key.as_bytes());
```

Webhook Security: HMAC-SHA256 signatures prevent webhook tampering:

```rust
pub fn generate_webhook_signature(payload: &str, secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())?;
    mac.update(payload.as_bytes());
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}
```

**Real-Time Price Integration**

Solapay uses Jupiter's API as the primary source for accurate cross-currency settlements

```rust
async fn get_sol_price() -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    let url = "https://lite-api.jup.ag/price/v3?ids=So11111111111111111111111111111111111111112";
    // Price caching with 5-minute TTL
    // Fallback mechanisms for API failures
}
```

Exchange Rate Management: USD/NGN rates are fetched from Binance with CoinGecko fallback, cached for performance, and automatically refreshed to ensure accurate settlement calculations.

**Monitoring and Observability**
The system provides comprehensive monitoring across all components:

Health Endpoints:
```
GET /health - Basic service health
GET /system/health - Detailed component status
```

**Metrics Collection:**

- Payment volume and success rates
- Settlement processing times
- RPC endpoint performance
- Database connection health
- Webhook delivery statistics

Structured Logging: All operations generate structured logs with correlation IDs, enabling effective debugging and performance analysis.

**Database Schema Design**
The database schema is optimized for payment processing workflows:

**Payments Table**: Stores payment lifecycle with status tracking and settlement preferences.

**Settlements Table**: Manages settlement operations with batch processing metadata and external provider references.

**Webhook Events**: Implements reliable webhook delivery with retry logic and comprehensive audit trails.

**Merchants Table**: Centralizes merchant configuration including settlement preferences and banking details.

Error Handling and Recovery
The system implements comprehensive error handling:

**Transaction Failures**: Failed payments are marked with detailed error information, enabling manual review and potential recovery.

**Settlement Failures**: Failed settlements maintain state for retry operations, with detailed logging for operational investigation.

**Network Issues**: RPC failures trigger automatic failover with health monitoring ensuring minimal service disruption.

Performance Characteristics

**Payment Processing**
- Sub-30 second payment confirmation for finalized transactions
- Support for concurrent payment processing across multiple merchants
- Automatic scaling through connection pooling and async processing

**Settlement Processing**:

- Batch settlement processing minimizes operational overhead
- Direct USDC settlements complete within blockchain confirmation times
- NGN settlements process within defined batch windows

**System Throughput**:

- Database connection pooling supports high concurrent load
- Async processing prevents blocking operations
- Webhook delivery operates independently of payment processing

Conclusion
Solpay represents a prod-ready approach to cryptocurrency payment processing, specifically tailored for African/Nigerian markets. By combining robust blockchain infra with traditional banking integration, the system enables merchants accept crypto payments globally, without technical complexities, while maintaining business-appropriate settlement mechanisms.