use serde::{Deserialize, Serialize};
use reqwest::Client;

#[derive(Debug, Clone)]
pub struct QuidaxClient {
    client: Client,
    api_key: String,
    base_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuidaxAddress {
    pub id: String,
    pub address: String,
    pub currency: String,
    pub network: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuidaxSwapQuotation {
    pub id: String,
    pub from_currency: String,
    pub to_currency: String,
    pub from_amount: String,
    pub to_amount: String,
    pub rate: String,
    pub valid_until: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuidaxWithdrawal {
    pub id: String,
    pub reference: Option<String>,
    pub currency: String,
    pub amount: String,
    pub fee: String,
    pub total: String,
    pub status: String,
    pub txid: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuidaxWallet {
    pub id: String,
    pub name: String,
    pub currency: String,
    pub balance: String,
    pub locked: String,
    pub staked: String,
    pub is_crypto: bool,
    pub deposit_address: Option<String>,
}

impl QuidaxClient {
    pub fn new(api_key: String, base_url: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
            base_url,
        }
    }

    pub async fn get_wallets(&self) -> Result<Vec<QuidaxWallet>, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v1/users/me/wallets", self.base_url);

        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("Failed to get wallets: {}", error_text).into());
        }

        let json_response: serde_json::Value = response.json().await?;
        
        if let Some(data) = json_response.get("data") {
            if let Some(wallets) = data.as_array() {
                let mut result = Vec::new();
                for wallet in wallets {
                    let quidax_wallet = QuidaxWallet {
                        id: wallet.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        name: wallet.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        currency: wallet.get("currency").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        balance: wallet.get("balance").and_then(|v| v.as_str()).unwrap_or("0.0").to_string(),
                        locked: wallet.get("locked").and_then(|v| v.as_str()).unwrap_or("0.0").to_string(),
                        staked: wallet.get("staked").and_then(|v| v.as_str()).unwrap_or("0.0").to_string(),
                        is_crypto: wallet.get("is_crypto").and_then(|v| v.as_bool()).unwrap_or(false),
                        deposit_address: wallet.get("deposit_address").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    };
                    result.push(quidax_wallet);
                }
                Ok(result)
            } else {
                Err("Invalid wallet data format".into())
            }
        } else {
            Err("Invalid response format from Quidax".into())
        }
    }

    pub async fn get_wallet_balance(&self, currency: &str) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
        let wallets = self.get_wallets().await?;
        
        for wallet in wallets {
            if wallet.currency.to_lowercase() == currency.to_lowercase() {
                let balance: f64 = wallet.balance.parse().unwrap_or(0.0);
                return Ok(balance);
            }
        }
        
        Err(format!("Wallet for {} not found", currency).into())
    }

    pub async fn get_swap_transaction(
        &self,
        swap_transaction_id: &str,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v1/users/me/swap_transactions/{}", self.base_url, swap_transaction_id);

        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("Failed to get swap transaction: {}", error_text).into());
        }

        Ok(response.json().await?)
    }

    pub async fn create_payment_address(
        &self,
        currency: &str,
        network: Option<&str>,
    ) -> Result<QuidaxAddress, Box<dyn std::error::Error + Send + Sync>> {
        let mut url = format!("{}/api/v1/users/me/wallets/{}/addresses", self.base_url, currency);
        
        if let Some(net) = network {
            url.push_str(&format!("?network={}", net));
        }

        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("Failed to create payment address: {}", error_text).into());
        }

        let json_response: serde_json::Value = response.json().await?;
        
        if let Some(data) = json_response.get("data") {
            let address = QuidaxAddress {
                id: data.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                address: data.get("address").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                currency: currency.to_string(),
                network: network.map(|s| s.to_string()),
                created_at: data.get("created_at").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            };
            Ok(address)
        } else {
            Err("Invalid response format from Quidax".into())
        }
    }

    pub async fn create_swap_quotation(
        &self,
        from_currency: &str,
        to_currency: &str,
        from_amount: f64,
    ) -> Result<QuidaxSwapQuotation, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v1/users/me/swap_quotation", self.base_url);
        
        let payload = serde_json::json!({
            "from_currency": from_currency,
            "to_currency": to_currency,
            "from_amount": from_amount.to_string()
        });

        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("Failed to create swap quotation: {}", error_text).into());
        }

        let json_response: serde_json::Value = response.json().await?;
        
        if let Some(data) = json_response.get("data") {
            let quotation = QuidaxSwapQuotation {
                id: data.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                from_currency: from_currency.to_string(),
                to_currency: to_currency.to_string(),
                from_amount: from_amount.to_string(),
                to_amount: data.get("to_amount").and_then(|v| v.as_str()).unwrap_or("0").to_string(),
                rate: data.get("rate").and_then(|v| v.as_str()).unwrap_or("0").to_string(),
                valid_until: data.get("valid_until").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            };
            Ok(quotation)
        } else {
            Err("Invalid swap quotation response".into())
        }
    }

    pub async fn confirm_swap(
        &self,
        quotation_id: &str,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v1/users/me/swap_quotation/{}/confirm", self.base_url, quotation_id);

        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("Failed to confirm swap: {}", error_text).into());
        }

        Ok(response.json().await?)
    }

    #[allow(dead_code)]
    pub async fn create_withdrawal(
        &self,
        currency: &str,
        amount: f64,
        fund_uid: &str, // wallet address
        transaction_note: Option<&str>,
        narration: Option<&str>,
        network: Option<&str>,
        reference: Option<&str>,
    ) -> Result<QuidaxWithdrawal, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v1/users/me/withdraws", self.base_url);
        
        let mut payload = serde_json::json!({
            "currency": currency,
            "amount": amount.to_string(),
            "fund_uid": fund_uid,
        });

        if let Some(note) = transaction_note {
            payload["transaction_note"] = serde_json::Value::String(note.to_string());
        }
        if let Some(narr) = narration {
            payload["narration"] = serde_json::Value::String(narr.to_string());
        }
        if let Some(net) = network {
            payload["network"] = serde_json::Value::String(net.to_string());
        }
        if let Some(ref_id) = reference {
            payload["reference"] = serde_json::Value::String(ref_id.to_string());
        }

        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("Failed to create withdrawal: {}", error_text).into());
        }

        let json_response: serde_json::Value = response.json().await?;
        
        if let Some(data) = json_response.get("data") {
            let withdrawal = QuidaxWithdrawal {
                id: data.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                reference: data.get("reference").and_then(|v| v.as_str()).map(|s| s.to_string()),
                currency: currency.to_string(),
                amount: data.get("amount").and_then(|v| v.as_str()).unwrap_or("0").to_string(),
                fee: data.get("fee").and_then(|v| v.as_str()).unwrap_or("0").to_string(),
                total: data.get("total").and_then(|v| v.as_str()).unwrap_or("0").to_string(),
                status: data.get("status").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                txid: data.get("txid").and_then(|v| v.as_str()).map(|s| s.to_string()),
                created_at: data.get("created_at").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            };
            Ok(withdrawal)
        } else {
            Err("Invalid withdrawal response".into())
        }
    }

    #[allow(dead_code)]
    pub async fn get_withdrawal(
        &self,
        withdrawal_id: &str,
    ) -> Result<QuidaxWithdrawal, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v1/users/me/withdraws/{}", self.base_url, withdrawal_id);

        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("Failed to get withdrawal: {}", error_text).into());
        }

        let json_response: serde_json::Value = response.json().await?;
        
        if let Some(data) = json_response.get("data") {
            let withdrawal = QuidaxWithdrawal {
                id: data.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                reference: data.get("reference").and_then(|v| v.as_str()).map(|s| s.to_string()),
                currency: data.get("currency").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                amount: data.get("amount").and_then(|v| v.as_str()).unwrap_or("0").to_string(),
                fee: data.get("fee").and_then(|v| v.as_str()).unwrap_or("0").to_string(),
                total: data.get("total").and_then(|v| v.as_str()).unwrap_or("0").to_string(),
                status: data.get("status").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                txid: data.get("txid").and_then(|v| v.as_str()).map(|s| s.to_string()),
                created_at: data.get("created_at").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            };
            Ok(withdrawal)
        } else {
            Err("Invalid withdrawal response".into())
        }
    }

    pub async fn validate_address(
        &self,
        currency: &str,
        address: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v1/{}/{}/validate_address", self.base_url, currency, address);

        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await?;

        if !response.status().is_success() {
            return Ok(false);
        }

        let json_response: serde_json::Value = response.json().await?;
        
        if let Some(data) = json_response.get("data") {
            Ok(data.get("valid").and_then(|v| v.as_bool()).unwrap_or(false))
        } else {
            Ok(false)
        }
    }
}

pub fn get_quidax_client(_state: &crate::AppState) -> QuidaxClient {
    QuidaxClient::new(
        std::env::var("QUIDAX_SECRET_KEY").expect("QUIDAX_SECRET_KEY must be set"),
        std::env::var("QUIDAX_BASE_URL").unwrap_or_else(|_| "https://app.quidax.io".to_string()),
    )
}