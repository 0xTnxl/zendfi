use axum::{
    routing::{get, post},
    Router,
    middleware::{self, Next}, 
    http::{header, StatusCode, Method},
    response::Response,
    extract::Request,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod auth;
mod models;
mod handlers;
mod solana;
mod sol_client;
mod database;
mod exchange;
mod config;
mod webhooks;

use handlers::*;
use config::Config;
use std::sync::Arc;


#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub solana_rpc_url: String,
    pub solana_client: Arc<sol_client::ResilientSolanaClient>,
    pub config: Config,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zendfi=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting ZendFi Payment Gateway");
    
    let config = Config::from_env();
    
    // Database connection
    let db = database::initialize_database(&config.database_url).await?;
    
    // ✅ CREATE RESILIENT SOLANA CLIENT
    let solana_client = Arc::new(sol_client::ResilientSolanaClient::new(
        config.solana_rpc_urls.clone()
    ));
    
    // ✅ START ENDPOINT MONITORING
    let monitor_client = solana_client.clone();
    tokio::spawn(sol_client::start_endpoint_monitor(monitor_client));
    
    let state = AppState {
        db,
        solana_rpc_url: config.solana_rpc_urls.first()
            .unwrap_or(&"https://api.devnet.solana.com".to_string())
            .clone(),
        solana_client: solana_client.clone(),
        config: config.clone(),
    };

    match test_solana_connection(&state.solana_rpc_url).await {
        Ok(_) => tracing::info!("Connected to Solana RPC"),
        Err(e) => tracing::warn!("Solana RPC connection issue: {}", e),
    }

    let webhook_state = state.clone();
    tokio::spawn(webhooks::webhook_retry_worker(webhook_state));

    let monitor_state = state.clone();
    tokio::spawn(solana::start_payment_monitor(monitor_state));
    
    // Public routes (no authentication required)
    let public_routes = Router::new()
        .route("/health", get(health_check))
        .route("/system/health", get(system_health)) 
        .route("/", get(root_handler))
        .route("/api/v1/merchants", post(create_merchant))
        .route("/api/v1/rates", get(get_exchange_rates))
        // Webhook endpoints (external) - also public
        .route("/api/v1/webhooks/:payment_id", post(handle_webhook))
        .with_state(state.clone());
    
    // Protected routes (require API key authentication)
    let protected_routes = Router::new()
        .route("/api/v1/payments", post(create_payment))
        .route("/api/v1/payments/:id", get(get_payment))
        .route("/api/v1/payments/:id/status", get(get_payment_status))
        .route("/api/v1/payments/:id/confirm", post(confirm_payment))
        .route("/api/v1/dashboard", get(get_merchant_dashboard))
        .route("/api/v1/webhooks", get(webhooks::list_webhook_events))
        .route("/api/v1/webhooks/:id/retry", post(webhooks::retry_webhook))
        .with_state(state.clone())
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::authenticate_merchant));
    
    // Combine the routers
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(middleware::from_fn(cors_layer));
    
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", config.port))
        .await?;
        
    tracing::info!("ZendFi API running on http://0.0.0.0:{}", config.port);
    tracing::info!("API Documentation: http://0.0.0.0:{}/", config.port);
    
    axum::serve(listener, app).await?;
    
    Ok(())
}

async fn test_solana_connection(rpc_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response: serde_json::Value = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getHealth"
        }))
        .send()
        .await?
        .json()
        .await?;
    
    if response["result"].as_str() == Some("ok") {
        Ok(())
    } else {
        Err("Solana RPC not healthy".into())
    }
}

async fn root_handler() -> &'static str {
    r#"
People rarely visit, but since you're here...
    "#
}

async fn cors_layer(request: Request, next: Next) -> Result<Response, StatusCode> {
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    
    if request.method() == Method::OPTIONS {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body("".into())
            .unwrap();
        
        let headers = response.headers_mut();
        add_cors_headers(headers, &origin);
        return Ok(response);
    }

    let mut response = next.run(request).await;
    add_cors_headers(response.headers_mut(), &origin);
    Ok(response)
}

fn add_cors_headers(headers: &mut axum::http::HeaderMap, origin: &str) {
    let allowed_origins = [
        "http://localhost:3000",    // React dev server
        "http://localhost:5173",    // Vite dev server  
        "http://localhost:8080",    // Alternative dev port
        "https://your-frontend-domain.com", // I'll replace this with the original URL once it is ready
    ];
    
    if allowed_origins.contains(&origin) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.parse().unwrap());
        headers.insert(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".parse().unwrap());
    } else if origin.is_empty() {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
    }
    
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS, 
        "GET, POST, PUT, DELETE, OPTIONS".parse().unwrap()
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS, 
        "Content-Type, Authorization, X-Requested-With".parse().unwrap()
    );
    headers.insert(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".parse().unwrap());
    headers.insert(header::ACCESS_CONTROL_MAX_AGE, "86400".parse().unwrap());
}