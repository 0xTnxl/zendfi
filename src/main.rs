use axum::{
    routing::{get, post},
    Router,
    middleware::{self, Next}, 
    http::{header, StatusCode, Method},
    response::Response,
    extract::Request,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;
use tracing::Instrument;
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::time::Instant;
use axum::extract::{DefaultBodyLimit, State};
use axum::Extension;
use axum::response::{Json as AxumJson, IntoResponse};
use crate::rate_limiter::PersistentRateLimiter;
use axum::http::HeaderValue;
use std::net::SocketAddr;
use axum::extract::ConnectInfo;

mod auth;
mod models;
mod handlers;
mod solana;
mod sol_client;
mod settlements;
mod rate_limiter;
mod database;
mod config;
mod webhooks;

use handlers::*;
use config::Config;
use std::sync::Arc;

#[derive(Clone)]
pub struct RateLimiter {
    requests: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    max_requests: usize,
    window_seconds: u64,
}

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub solana_rpc_url: String,
    pub solana_client: Arc<sol_client::ResilientSolanaClient>,
    pub config: Config,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window_seconds: u64) -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window_seconds,
        }
    }

    pub async fn is_allowed(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut requests = self.requests.write().await;
        
        let entry = requests.entry(key.to_string()).or_insert_with(Vec::new);
        
        // Remove old requests outside the window
        entry.retain(|&timestamp| now.duration_since(timestamp).as_secs() < self.window_seconds);
        
        if entry.len() >= self.max_requests {
            false
        } else {
            entry.push(now);
            true
        }
    }
}


async fn error_handler_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let correlation_id = request
        .headers()
        .get("x-correlation-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let result = next.run(request).await;

    if result.status().is_client_error() || result.status().is_server_error() {
        let status = result.status();

        tracing::error!(
            "Request failed with status {}: {} {}",
            status,
            method,
            uri
        );

        let error_message = match status {
            StatusCode::BAD_REQUEST => "Bad request - check your input parameters",
            StatusCode::UNAUTHORIZED => "Unauthorized - invalid or missing API key",
            StatusCode::NOT_FOUND => "Resource not found",
            StatusCode::TOO_MANY_REQUESTS => "Rate limit exceeded - slow down your requests",
            StatusCode::INTERNAL_SERVER_ERROR => "Internal server error - please try again",
            _ => "An error occurred",
        };

        let detailed_error = if std::env::var("ENVIRONMENT").unwrap_or_default() == "development" {
            format!("{} (check server logs for details)", error_message)
        } else {
            error_message.to_string()
        };

        let error_json = serde_json::json!({
            "error": {
                "code": status.as_u16(),
                "message": detailed_error,
                "timestamp": chrono::Utc::now(),
                "request_id": correlation_id,
            }
        });

        let mut response = AxumJson(error_json).into_response();
        *response.status_mut() = status;
        return Ok(response);
    }

    Ok(result)
}


async fn rate_limiting_middleware(
    State(state): State<AppState>,
    Extension(merchant): Extension<crate::auth::AuthenticatedMerchant>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let (max_requests, window_seconds, rate_limit_key) = match request.uri().path() {
        path if path.starts_with("/api/v1/payments") => {
            (50, 3600, format!("payments_merchant_{}", merchant.merchant_id))
        }
        path if path.starts_with("/api/v1/dashboard") => {
            (200, 3600, format!("dashboard_merchant_{}", merchant.merchant_id))
        }
        _ => {
            (100, 3600, format!("api_merchant_{}", merchant.merchant_id))
        }
    };

    let rate_limiter = PersistentRateLimiter::new(max_requests, window_seconds);
    
    let rate_limit_result = rate_limiter
        .check_rate_limit(&state, &rate_limit_key, Some(merchant.api_key_id))
        .await
        .map_err(|e| {
            tracing::error!("Rate limiter error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if !rate_limit_result.allowed {
        tracing::warn!(
            "Rate limit exceeded for merchant {} (key: {})", 
            merchant.merchant_id, 
            rate_limit_key
        );

        let response = axum::response::Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("X-RateLimit-Limit", max_requests.to_string())
            .header("X-RateLimit-Remaining", "0")
            .header("X-RateLimit-Reset", rate_limit_result.reset_time.to_string())
            .header("Retry-After", rate_limit_result.retry_after.unwrap_or(60).to_string())
            .body(axum::body::Body::from(serde_json::json!({
                "error": {
                    "code": 429,
                    "message": "Rate limit exceeded",
                    "limit": max_requests,
                    "window_seconds": window_seconds,
                    "reset_time": rate_limit_result.reset_time,
                    "retry_after": rate_limit_result.retry_after
                }
            }).to_string()))
            .unwrap();

        return Ok(response);
    }

    request.extensions_mut().insert(rate_limit_result.clone());

    let response = next.run(request).await; 

    let mut response = response;
    response.headers_mut().insert(
        "X-RateLimit-Limit", 
        HeaderValue::from_str(&max_requests.to_string()).unwrap()
    );
    response.headers_mut().insert(
        "X-RateLimit-Remaining", 
        HeaderValue::from_str(&rate_limit_result.remaining.to_string()).unwrap()
    );
    response.headers_mut().insert(
        "X-RateLimit-Reset", 
        HeaderValue::from_str(&rate_limit_result.reset_time.to_string()).unwrap()
    );

    Ok(response)
}

async fn public_rate_limiting_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let state = request.extensions().get::<AppState>().unwrap().clone();

    let ip_hash = {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(addr.ip().to_string().as_bytes());
        hex::encode(hasher.finalize())[..16].to_string() 
    };

    let rate_limit_key = format!("public_ip_{}", ip_hash);
    let rate_limiter = PersistentRateLimiter::new(10, 3600); 

    let rate_limit_result = rate_limiter
        .check_rate_limit(&state, &rate_limit_key, None)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !rate_limit_result.allowed {
        tracing::warn!("Public rate limit exceeded for IP: {}", addr.ip());
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(request).await)
}

async fn correlation_id_middleware(mut request: Request, next: Next) -> Result<Response, StatusCode> {
    let correlation_id = Uuid::new_v4().to_string();
    request.headers_mut().insert(
        "x-correlation-id",
        correlation_id.parse().unwrap()
    );

    let span = tracing::info_span!(
        "request",
        correlation_id = &correlation_id,
        method = %request.method(),
        path = %request.uri().path()
    );

    let response = next.run(request).instrument(span).await;
    Ok(response)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zendfi=info,sqlx=warn,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Solpay Payment Gateway");
    
    let config = match Config::from_env() {
        Ok(config) => {
            tracing::info!("Configuration loaded successfully");
            config
        },
        Err(e) => {
            tracing::error!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    let db = database::initialize_database(&config.database_url).await
        .map_err(|e| {
            tracing::error!("Database initialization failed: {}", e);
            e
        })?;
    
    let solana_client = Arc::new(sol_client::ResilientSolanaClient::new(
        config.solana_rpc_urls.clone()
    ));

    let state = AppState {
        db: db.clone(),
        solana_rpc_url: config.solana_rpc_urls.first()
            .unwrap_or(&"https://api.devnet.solana.com".to_string())
            .clone(),
        solana_client: solana_client.clone(),
        config: config.clone(),
    };

    let cleanup_state = state.clone();
    tokio::spawn(rate_limiter::start_rate_limit_cleanup_worker(cleanup_state));
    
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
        Ok(_) => tracing::info!("Solana RPC connection verified"),
        Err(e) => {
            tracing::error!("Solana RPC connection failed: {}", e);
            // Don't exit, we'll let it try to recover
        }
    }

    let webhook_state = state.clone();
    tokio::spawn(webhooks::webhook_retry_worker(webhook_state));

    let monitor_state = state.clone();
    tokio::spawn(solana::start_payment_monitor(monitor_state));


    let public_routes = Router::new()
        .route("/health", get(health_check))
        .route("/system/health", get(system_health))
        .route("/", get(root_handler))
        .route("/api/v1/merchants", post(create_merchant))
        .route_layer(middleware::from_fn(public_rate_limiting_middleware)) 
        .with_state(state.clone());

    let protected_routes = Router::new()
        .route("/api/v1/payments", post(create_payment))
        .route("/api/v1/payments/:id", get(get_payment))
        .route("/api/v1/payments/:id/status", get(get_payment_status))
        .route("/api/v1/payments/:id/confirm", post(confirm_payment))
        .route("/api/v1/dashboard", get(get_merchant_dashboard))
        .route("/api/v1/webhooks", get(webhooks::list_webhook_events))
        .route("/api/v1/webhooks/:id/retry", post(webhooks::retry_webhook))
        .with_state(state.clone())
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limiting_middleware))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::authenticate_merchant));
    
    // Combine the routers
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn(error_handler_middleware))
        .layer(middleware::from_fn(correlation_id_middleware))
        .layer(middleware::from_fn(cors_layer));
    
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", config.port))
        .await?;
        
    tracing::info!("Solapay API running on http://0.0.0.0:{}", config.port);
    tracing::info!("Health endpoint: http://0.0.0.0:{}/system/health", config.port);
    tracing::info!("API Documentation: http://0.0.0.0:{}/", config.port);
    
    // And yes! A graceful shutdown
    let shutdown = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
        tracing::info!("Recieved shutdown signal, gracefully shutting down...");
    };
    
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    
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
        "http://localhost:3000",  
        "http://localhost:5173",   
        "http://localhost:8080",  
        "https://your-frontend-domain.com", 
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