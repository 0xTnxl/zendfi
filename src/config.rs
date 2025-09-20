#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub solana_rpc_urls: Vec<String>, 
    pub recipient_wallet: String,
    pub frontend_url: String,
    pub port: u16,
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
            // Default
            vec!["https://api.devnet.solana.com".to_string()]
        };
        
        Self {
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgresql://localhost/zendfi".to_string()),
            solana_rpc_urls,
            recipient_wallet: std::env::var("RECIPIENT_WALLET")
                .expect("RECIPIENT_WALLET must be set"),
            frontend_url: std::env::var("FRONTEND_URL")
                .unwrap_or_else(|_| "http://localhost:3001".to_string()),
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .expect("PORT must be a valid number"),
        }
    }
}