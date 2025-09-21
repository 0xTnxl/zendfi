#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub solana_rpc_urls: Vec<String>, 
    pub recipient_wallet: String,
    pub wallet_keypair_path: Option<String>, 
    pub frontend_url: String,
    pub port: u16,
    pub usdc_mint: String,  
    pub solana_network: String,
    pub merchant_wallet_dir: String,
}

impl Config {
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();
        
        let solana_rpc_urls = if let Ok(urls) = std::env::var("SOLANA_RPC_URLS") {
            urls.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else if let Ok(single_url) = std::env::var("SOLANA_RPC_URL") {
            vec![single_url]
        } else {
            vec!["https://api.devnet.solana.com".to_string()]
        };
        
        let solana_network = std::env::var("SOLANA_NETWORK")
            .unwrap_or_else(|_| "devnet".to_string());
            
        let usdc_mint = std::env::var("USDC_MINT")
            .unwrap_or_else(|_| {
                if solana_network == "mainnet" {
                    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string()
                } else {
                    "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU".to_string()
                }
            });
        
        Self {
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgresql://localhost/zendfi".to_string()),
            solana_rpc_urls,
            recipient_wallet: std::env::var("RECIPIENT_WALLET")
                .expect("RECIPIENT_WALLET must be set"),
            wallet_keypair_path: std::env::var("WALLET_KEYPAIR_PATH").ok(),
            frontend_url: std::env::var("FRONTEND_URL")
                .unwrap_or_else(|_| "http://localhost:3001".to_string()),
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .expect("PORT must be a valid number"),
            usdc_mint,    
            solana_network, 
            merchant_wallet_dir: std::env::var("MERCHANT_WALLET_DIR")
                .unwrap_or_else(|_| "./secure/merchant_wallets".to_string()),
        }
    }
}