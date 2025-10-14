use axum::{
    extract::{State, Path, Extension},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use bigdecimal::{BigDecimal, FromPrimitive};
use crate::{AppState, auth::AuthenticatedMerchant};

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateInvoiceRequest {
    pub customer_email: String,
    pub customer_name: Option<String>,
    pub amount: f64,
    pub token: Option<String>,
    pub description: String,
    pub line_items: Option<Vec<LineItem>>,
    pub due_date: Option<chrono::DateTime<chrono::Utc>>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LineItem {
    pub description: String,
    pub quantity: i32,
    pub unit_price: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InvoiceResponse {
    pub id: Uuid,
    pub invoice_number: String,
    pub customer_email: String,
    pub customer_name: Option<String>,
    pub amount_usd: f64,
    pub token: String,
    pub description: String,
    pub status: String,
    pub payment_url: Option<String>,
    pub due_date: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub async fn create_invoice(
    State(state): State<AppState>,
    Extension(merchant): Extension<AuthenticatedMerchant>,
    Json(request): Json<CreateInvoiceRequest>,
) -> Result<Json<InvoiceResponse>, StatusCode> {
    if request.amount <= 0.0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    if !request.customer_email.contains('@') {
        return Err(StatusCode::BAD_REQUEST);
    }

    let invoice_id = Uuid::new_v4();
    let invoice_number = generate_invoice_number(&state, merchant.merchant_id).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let token = request.token.as_deref().unwrap_or("USDC").to_uppercase();
    let amount_bd = BigDecimal::from_f64(request.amount).unwrap();
    
    let line_items_json = request.line_items
        .as_ref()
        .map(|items| serde_json::to_value(items).unwrap())
        .unwrap_or(serde_json::json!([]));

    sqlx::query!(
        r#"
        INSERT INTO invoices
        (id, merchant_id, invoice_number, customer_email, customer_name, amount_usd, 
         currency, token, description, line_items, metadata, status, due_date, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
        "#,
        invoice_id,
        merchant.merchant_id,
        invoice_number,
        request.customer_email,
        request.customer_name,
        amount_bd,
        "USD",
        token,
        request.description,
        line_items_json,
        request.metadata.unwrap_or(serde_json::json!({})),
        "draft",
        request.due_date
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create invoice: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::info!("Created invoice {} for merchant {}", invoice_number, merchant.merchant_id);

    Ok(Json(InvoiceResponse {
        id: invoice_id,
        invoice_number: invoice_number.clone(),
        customer_email: request.customer_email,
        customer_name: request.customer_name,
        amount_usd: request.amount,
        token,
        description: request.description,
        status: "draft".to_string(),
        payment_url: None,
        due_date: request.due_date,
        created_at: chrono::Utc::now(),
    }))
}

pub async fn send_invoice(
    State(state): State<AppState>,
    Extension(merchant): Extension<AuthenticatedMerchant>,
    Path(invoice_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let invoice = sqlx::query!(
        r#"
        SELECT i.id, i.invoice_number, i.customer_email, i.customer_name, i.amount_usd, 
               i.token, i.description, i.line_items, i.status, i.due_date,
               m.name as merchant_name, m.email as merchant_email
        FROM invoices i
        JOIN merchants m ON i.merchant_id = m.id
        WHERE i.id = $1 AND i.merchant_id = $2
        "#,
        invoice_id,
        merchant.merchant_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    if invoice.status != "draft" && invoice.status != "sent" {
        return Err(StatusCode::BAD_REQUEST);
    }

    let payment_link_code = crate::checkout::generate_link_code();
    let payment_link_id = Uuid::new_v4();
    
    sqlx::query!(
        r#"
        INSERT INTO payment_links
        (id, merchant_id, link_code, amount_usd, currency, token, description, is_active, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
        "#,
        payment_link_id,
        merchant.merchant_id,
        payment_link_code,
        invoice.amount_usd,
        "USD",
        invoice.token,
        format!("Invoice Payment: {}", invoice.invoice_number),
        true
    )
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let payment_url = format!("{}/checkout/{}", state.config.frontend_url, payment_link_code);

    sqlx::query!(
        "UPDATE invoices SET status = $1, sent_at = NOW() WHERE id = $2",
        "sent",
        invoice_id
    )
    .execute(&state.db)
    .await
    .ok();

    // Send email
    send_invoice_email(
        &state,
        &invoice.customer_email,
        invoice.customer_name.as_deref(),
        &invoice.merchant_name,
        &invoice.invoice_number,
        invoice.amount_usd.to_string().parse().unwrap_or(0.0),
        &invoice.token,
        &invoice.description,
        &payment_url,
        invoice.due_date.as_ref(),
    ).await.map_err(|e| {
        tracing::error!("Failed to send invoice email: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::info!("Sent invoice {} to {}", invoice.invoice_number, invoice.customer_email);

    Ok(Json(serde_json::json!({
        "success": true,
        "invoice_id": invoice_id,
        "invoice_number": invoice.invoice_number,
        "sent_to": invoice.customer_email,
        "payment_url": payment_url,
        "status": "sent"
    })))
}

pub async fn get_invoice(
    State(state): State<AppState>,
    Extension(merchant): Extension<AuthenticatedMerchant>,
    Path(invoice_id): Path<Uuid>,
) -> Result<Json<InvoiceResponse>, StatusCode> {
    let invoice = sqlx::query!(
        r#"
        SELECT id, invoice_number, customer_email, customer_name, amount_usd, currency,
               token, description, status, due_date, created_at
        FROM invoices
        WHERE id = $1 AND merchant_id = $2
        "#,
        invoice_id,
        merchant.merchant_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(InvoiceResponse {
        id: invoice.id,
        invoice_number: invoice.invoice_number,
        customer_email: invoice.customer_email,
        customer_name: invoice.customer_name,
        amount_usd: invoice.amount_usd.to_string().parse().unwrap_or(0.0),
        token: invoice.token,
        description: invoice.description,
        status: invoice.status,
        payment_url: None,
        due_date: invoice.due_date,
        created_at: invoice.created_at.unwrap_or_else(|| chrono::Utc::now()),
    }))
}

pub async fn list_invoices(
    State(state): State<AppState>,
    Extension(merchant): Extension<AuthenticatedMerchant>,
) -> Result<Json<Vec<InvoiceResponse>>, StatusCode> {
    let invoices = sqlx::query!(
        r#"
        SELECT id, invoice_number, customer_email, customer_name, amount_usd,
               token, description, status, due_date, created_at
        FROM invoices
        WHERE merchant_id = $1
        ORDER BY created_at DESC
        LIMIT 100
        "#,
        merchant.merchant_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let response: Vec<InvoiceResponse> = invoices
        .into_iter()
        .map(|inv| InvoiceResponse {
            id: inv.id,
            invoice_number: inv.invoice_number,
            customer_email: inv.customer_email,
            customer_name: inv.customer_name,
            amount_usd: inv.amount_usd.to_string().parse().unwrap_or(0.0),
            token: inv.token,
            description: inv.description,
            status: inv.status,
            payment_url: None,
            due_date: inv.due_date,
            created_at: inv.created_at.unwrap_or_else(|| chrono::Utc::now()),
        })
        .collect();

    Ok(Json(response))
}

async fn generate_invoice_number(
    state: &AppState,
    merchant_id: Uuid,
) -> Result<String, Box<dyn std::error::Error>> {
    let count = sqlx::query!(
        "SELECT COUNT(*) as count FROM invoices WHERE merchant_id = $1",
        merchant_id
    )
    .fetch_one(&state.db)
    .await?;

    let number = count.count.unwrap_or(0) + 1;
    let year = chrono::Utc::now().format("%Y");
    
    Ok(format!("INV-{}-{:05}", year, number))
}

async fn send_invoice_email(
    _state: &AppState,
    to_email: &str,
    customer_name: Option<&str>,
    merchant_name: &str,
    invoice_number: &str,
    amount: f64,
    token: &str,
    description: &str,
    payment_url: &str,
    due_date: Option<&chrono::DateTime<chrono::Utc>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let smtp_host = std::env::var("SMTP_HOST").ok();
    let smtp_username = std::env::var("SMTP_USERNAME").ok();
    let smtp_password = std::env::var("SMTP_PASSWORD").ok();
    let from_email = std::env::var("FROM_EMAIL").unwrap_or_else(|_| "noreply@zendfi.com".to_string());

    if smtp_host.is_none() || smtp_username.is_none() || smtp_password.is_none() {
        tracing::warn!("SMTP not configured. Skipping email send. Invoice URL: {}", payment_url);
        tracing::info!("To enable emails, set SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, FROM_EMAIL");
        return Ok(()); 
    }

    let customer_display = customer_name.unwrap_or("Customer");
    let due_date_str = due_date
        .map(|d| d.format("%B %d, %Y").to_string())
        .unwrap_or_else(|| "Upon receipt".to_string());

    let _email_body = format!(
        r#"
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px; text-align: center;">
                <h1 style="color: white; margin: 0;">Invoice from {}</h1>
            </div>
            
            <div style="padding: 40px; background: #f8f9fa;">
                <p>Dear {},</p>
                
                <p>You have received an invoice from <strong>{}</strong>.</p>
                
                <div style="background: white; padding: 30px; border-radius: 8px; margin: 20px 0;">
                    <h2 style="color: #667eea; margin-top: 0;">Invoice Details</h2>
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <td style="padding: 10px; border-bottom: 1px solid #e0e0e0;"><strong>Invoice Number:</strong></td>
                            <td style="padding: 10px; border-bottom: 1px solid #e0e0e0;">{}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px; border-bottom: 1px solid #e0e0e0;"><strong>Amount:</strong></td>
                            <td style="padding: 10px; border-bottom: 1px solid #e0e0e0;">${} {}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px; border-bottom: 1px solid #e0e0e0;"><strong>Description:</strong></td>
                            <td style="padding: 10px; border-bottom: 1px solid #e0e0e0;">{}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px;"><strong>Due Date:</strong></td>
                            <td style="padding: 10px;">{}</td>
                        </tr>
                    </table>
                </div>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{}" style="background: #667eea; color: white; padding: 16px 32px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: 600;">
                        Pay Invoice
                    </a>
                </div>
                
                <p style="color: #666; font-size: 12px; text-align: center; margin-top: 40px;">
                    Powered by ZenFi • Secured by Solana<br>
                    If you have any questions, please contact {}.
                </p>
            </div>
        </body>
        </html>
        "#,
        merchant_name,
        customer_display,
        merchant_name,
        invoice_number,
        amount,
        token,
        description,
        due_date_str,
        payment_url,
        merchant_name
    );

    tracing::info!("Sending invoice email to {} (SMTP configured)", to_email);
    
    // TODO: Implement actual SMTP sending with lettre crate
    // For now, just log the email content
    tracing::info!("Email would be sent to: {}", to_email);
    tracing::info!("From: {}", from_email);
    tracing::info!("Payment URL: {}", payment_url);

    Ok(())
}

#[allow(unused_imports)]
pub use crate::checkout::generate_link_code;
