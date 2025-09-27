use std::str::FromStr;
use solana_sdk::pubkey::Pubkey;

#[derive(Debug)]
pub enum ConfigError {
    MissingSeed,
    InvalidSeedLength,
    InvalidRecipientWallet,
    MissingRequiredEnvVar(String),
    InvalidUrl(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ConfigError::MissingSeed => write!(f, "SOLAPAY_MASTER_SEED is required"),
            ConfigError::InvalidSeedLength => write!(f, "SOLAPAY_MASTER_SEED must be at least 32 characters"),
            ConfigError::InvalidRecipientWallet => write!(f, "RECIPIENT_WALLET is not a valid Solana address"),
            ConfigError::MissingRequiredEnvVar(var) => write!(f, "Required environment variable {} is missing", var),
            ConfigError::InvalidUrl(url) => write!(f, "Invalid URL: {}", url),
        }
    }
}

impl std::error::Error for ConfigError {}

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
    pub fn from_env() -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();

        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| ConfigError::MissingRequiredEnvVar("DATABASE_URL".to_string()))?;
        
        let recipient_wallet = std::env::var("RECIPIENT_WALLET")
            .map_err(|_| ConfigError::MissingRequiredEnvVar("RECIPIENT_WALLET".to_string()))?;

        Pubkey::from_str(&recipient_wallet)
            .map_err(|_| ConfigError::InvalidRecipientWallet)?;
        
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
        
        let config = Self {
            database_url,
            solana_rpc_urls,
            recipient_wallet,
            wallet_keypair_path: std::env::var("WALLET_KEYPAIR_PATH").ok(),
            frontend_url: std::env::var("FRONTEND_URL")
                .unwrap_or_else(|_| "http://localhost:3001".to_string()),
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .map_err(|_| ConfigError::MissingRequiredEnvVar("PORT must be valid number".to_string()))?,
            usdc_mint,    
            solana_network, 
            merchant_wallet_dir: std::env::var("MERCHANT_WALLET_DIR")
                .unwrap_or_else(|_| "./secure/merchant_wallets".to_string()),
        };

        config.validate()?;
        
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        for url in &self.solana_rpc_urls {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(ConfigError::InvalidUrl(url.clone()));
            }
        }

        if self.recipient_wallet == "11111111111111111111111111111112" {
            return Err(ConfigError::InvalidRecipientWallet);
        }

        if let Ok(master_seed) = std::env::var("SOLAPAY_MASTER_SEED") {
            if master_seed.len() < 32 {
                return Err(ConfigError::InvalidSeedLength);
            }
        } else {
            tracing::warn!("SOLAPAY_MASTER_SEED not set - merchant wallet generation will fail");
        }
        
        Ok(())
    }
}