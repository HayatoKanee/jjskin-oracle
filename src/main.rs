mod attestation;
mod axum_websocket;
mod config;
mod inspect;
mod proxy;
mod settlement;
mod verifier;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use axum_websocket::{WebSocket, WebSocketUpgrade};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tower_http::cors::CorsLayer;
use tracing::{error, info};
use uuid::Uuid;
use ws_stream_tungstenite::WsStream;

use tlsn::{config::verifier::VerifierConfig, webpki::RootCertStore};

use config::Config;
use settlement::{ChainReader, OracleSigner};

// ============================================================================
// Application State
// ============================================================================

/// Maximum concurrent sessions (prevents memory exhaustion DoS).
const MAX_SESSIONS: usize = 100;

/// Stored session data.
struct SessionData {
    asset_id: u64,
}

/// Shared application state.
struct AppState {
    sessions: Mutex<HashMap<String, SessionData>>,
    config: Config,
    oracle_signer: Arc<OracleSigner>,
    chain_reader: ChainReader,
}

// ============================================================================
// CLI Args
// ============================================================================

#[derive(Parser, Debug)]
#[command(name = "tlsn-server", version, about = "TLSNotary Verifier + Oracle Server")]
struct Args {
    /// Path to the configuration YAML file.
    #[arg(short, long, default_value = "config.yaml")]
    config: String,
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
struct SessionRequest {
    /// Asset ID for on-chain escrow lookup (required).
    /// Accepts both string and number to avoid JS precision loss for large IDs.
    #[serde(rename = "assetId", deserialize_with = "deserialize_string_or_number")]
    asset_id: u64,
}

/// Deserialize a u64 from either a JSON string ("123") or number (123).
/// Extension sends assetId as string to avoid JS float64 precision loss.
fn deserialize_string_or_number<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrNumber {
        String(String),
        Number(u64),
    }

    match StringOrNumber::deserialize(deserializer)? {
        StringOrNumber::String(s) => s.parse().map_err(de::Error::custom),
        StringOrNumber::Number(n) => Ok(n),
    }
}

#[derive(Debug, Serialize)]
struct SessionResponse {
    #[serde(rename = "sessionId")]
    session_id: String,
}

#[derive(Debug, Serialize)]
struct InfoResponse {
    version: &'static str,
    #[serde(rename = "gitHash")]
    git_hash: String,
    #[serde(rename = "oracleAddress")]
    oracle_address: String,
    #[serde(rename = "tdxEnabled")]
    tdx_enabled: bool,
    #[serde(rename = "tdxBackend")]
    tdx_backend: String,
}

#[derive(Debug, Deserialize)]
struct NotarizeQuery {
    #[serde(rename = "sessionId")]
    session_id: String,
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Install ring crypto provider before any rustls usage
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_target(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_thread_ids(true)
        .with_line_number(true)
        .init();

    let args = Args::parse();
    let config = Config::load(Path::new(&args.config));

    info!("Configuration loaded:");
    info!("  host: {}", config.host);
    info!("  port: {}", config.port);
    info!("  max_sent_data: {}", config.notarization.max_sent_data);
    info!("  max_recv_data: {}", config.notarization.max_recv_data);
    info!("  timeout: {}s", config.notarization.timeout);

    // Validate contract addresses are configured (zero-address = silent settlement failure).
    const ZERO_ADDR: &str = "0x0000000000000000000000000000000000000000";
    if config.oracle.contract_address == ZERO_ADDR {
        eprintln!("FATAL: oracle.contract_address is not configured (zero address)");
        std::process::exit(1);
    }
    if config.oracle.steam_factory_address == ZERO_ADDR {
        eprintln!("FATAL: oracle.steam_factory_address is not configured (zero address)");
        std::process::exit(1);
    }

    // Initialize oracle signer (required — single verifier path).
    let oracle_signer = OracleSigner::from_config(&config.oracle).await?;
    info!("Oracle signer: address={}", oracle_signer.address());

    // Initialize chain reader for on-chain escrow reads.
    let jjskin_address = config
        .oracle
        .contract_address
        .parse()
        .map_err(|e| eyre::eyre!("Invalid contract_address: {e}"))?;
    let factory_address = config
        .oracle
        .steam_factory_address
        .parse()
        .map_err(|e| eyre::eyre!("Invalid steam_factory_address: {e}"))?;
    let chain_reader = ChainReader::new(
        config.oracle.rpc_url.clone(),
        jjskin_address,
        factory_address,
    );
    info!(
        "Chain reader: rpc={}, contract={}, factory={}",
        config.oracle.rpc_url, config.oracle.contract_address, config.oracle.steam_factory_address
    );

    // Bind oracle address for TDX attestation (no-op outside TDX).
    attestation::bind_oracle_address(oracle_signer.address());

    // Wrap oracle signer in Arc for sharing between AppState and InspectState.
    let oracle_signer = Arc::new(oracle_signer);

    // Initialize CS2 inspect bot pool (if enabled).
    let inspect_enabled = config.inspect.enabled;
    let inspect_state: Option<Arc<inspect::InspectState>> = if inspect_enabled {
        info!("Inspect module enabled, initializing bot pool...");
        match inspect::bot_pool::BotPool::new(&config.inspect).await {
            Ok(pool) => {
                let cache = inspect::cache::InspectCache::new(
                    100_000,
                    Duration::from_secs(3600),
                );
                info!("Bot pool ready: {} bots, inspect cache: 100k cap / 1h TTL", pool.bot_count());
                Some(Arc::new(inspect::InspectState {
                    pool,
                    signer: oracle_signer.clone(),
                    cache,
                }))
            }
            Err(e) => {
                error!("Failed to initialize bot pool: {} — inspect disabled", e);
                None
            }
        }
    } else {
        info!("Inspect module disabled");
        None
    };

    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .expect("Invalid host:port");

    let tls_config = config.tls.clone();

    let app_state = Arc::new(AppState {
        sessions: Mutex::new(HashMap::new()),
        config,
        oracle_signer,
        chain_reader,
    });

    // Build main routes (oracle / MPC-TLS).
    let main_routes = Router::new()
        .route("/health", get(health_handler))
        .route("/info", get(info_handler))
        .route("/attestation", get(attestation::attestation_handler))
        .route("/session", post(session_handler))
        .route("/notarize", get(notarize_ws_handler))
        .route("/proxy", get(proxy::proxy_ws_handler))
        .with_state(app_state);

    // Conditionally add inspect routes (separate state: Arc<InspectState>).
    let app = if let Some(inspect_state) = inspect_state {
        let inspect_routes = Router::new()
            .route("/", get(inspect::inspect_handler))
            .route("/bulk", post(inspect::bulk_handler))
            .with_state(inspect_state);
        main_routes.nest("/inspect", inspect_routes)
    } else {
        main_routes
    };

    let app = app.layer(CorsLayer::permissive());

    let tls_enabled = tls_config.enabled;
    info!(
        "TLSNotary Verifier Server starting on {} (TLS: {})",
        addr,
        if tls_enabled { "enabled" } else { "disabled" }
    );
    info!("  GET  /health              - Health check");
    info!("  GET  /info                - Server info + oracle address");
    info!("  GET  /attestation         - TDX DCAP quote (for oracle registration)");
    info!("  POST /session             - Create session (assetId required)");
    info!("  GET  /notarize?sessionId= - WebSocket MPC-TLS + settlement");
    info!("  GET  /proxy?token=        - WebSocket-to-TCP proxy");
    if inspect_enabled {
        info!("  GET  /inspect?url=        - CS2 item inspection (single)");
        info!("  POST /inspect/bulk        - CS2 item inspection (batch)");
    }

    if tls_enabled {
        let cert_path = tls_config
            .certificate_path
            .as_ref()
            .expect("tls.certificate_path is required when tls.enabled = true");
        let key_path = tls_config
            .private_key_path
            .as_ref()
            .expect("tls.private_key_path is required when tls.enabled = true");

        let rustls_config = RustlsConfig::from_pem_file(cert_path, key_path).await?;
        info!("TLS enabled: cert={}, key={}", cert_path, key_path);
        axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).tcp_nodelay(true).await?;
    }

    Ok(())
}

// ============================================================================
// Route Handlers
// ============================================================================

/// GET /health
async fn health_handler() -> impl IntoResponse {
    "ok"
}

/// GET /info — server version and oracle address.
async fn info_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let git_hash = std::env::var("GIT_HASH").unwrap_or_else(|_| "dev".to_string());
    let tdx_available = attestation::is_tdx_available();

    Json(InfoResponse {
        version: env!("CARGO_PKG_VERSION"),
        git_hash,
        oracle_address: format!("{}", state.oracle_signer.address()),
        tdx_enabled: tdx_available,
        tdx_backend: if tdx_available { "Dstack".to_string() } else { "None".to_string() },
    })
}

/// POST /session — create a new MPC-TLS session.
///
/// Extension provides `assetId` as a lookup hint. Escrow data is read
/// from on-chain by ChainReader during settlement (not from extension).
async fn session_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SessionRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Atomic check-and-insert under a single lock to prevent TOCTOU race.
    let session_id = Uuid::new_v4().to_string();
    {
        let mut sessions = state.sessions.lock().await;
        if sessions.len() >= MAX_SESSIONS {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                format!("Server at capacity ({MAX_SESSIONS} concurrent sessions)"),
            ));
        }
        sessions.insert(
            session_id.clone(),
            SessionData {
                asset_id: body.asset_id,
            },
        );
    }
    info!(
        "[{}] Session created: assetId={}",
        session_id, body.asset_id
    );

    // Spawn a timeout task to clean up stale sessions.
    let state_clone = state.clone();
    let session_id_clone = session_id.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let mut sessions = state_clone.sessions.lock().await;
        if sessions.remove(&session_id_clone).is_some() {
            info!(
                "[{}] Session expired (no WebSocket connection within 30s)",
                session_id_clone
            );
        }
    });

    Ok(Json(SessionResponse { session_id }))
}

/// GET /notarize?sessionId=xxx — WebSocket upgrade for MPC-TLS + settlement.
async fn notarize_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Query(query): Query<NotarizeQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let session_id = query.session_id;

    // Look up and remove the session.
    let session_data = {
        let mut sessions = state.sessions.lock().await;
        sessions.remove(&session_id)
    };

    match session_data {
        Some(session_data) => {
            info!("[{}] WebSocket upgrade for MPC-TLS + settlement", session_id);
            Ok(ws.on_upgrade(move |socket| {
                handle_notarize_websocket(socket, session_id, session_data, state)
            }))
        }
        None => {
            error!("[{}] Session not found or already used", session_id);
            Err((
                StatusCode::NOT_FOUND,
                format!("Session not found: {}", session_id),
            ))
        }
    }
}

/// Handle the WebSocket MPC-TLS + settlement connection.
async fn handle_notarize_websocket(
    socket: WebSocket,
    session_id: String,
    session_data: SessionData,
    state: Arc<AppState>,
) {
    info!("[{}] WebSocket connected, starting MPC-TLS", session_id);

    let ws_stream = WsStream::new(socket.into_inner());

    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore::mozilla())
        .build()
        .expect("Failed to build verifier config");

    let timeout_duration = Duration::from_secs(state.config.notarization.timeout);

    match timeout(timeout_duration, async {
        // Step 1: Run MPC-TLS
        let (mpc, mut socket) = verifier::run_mpc_tls(ws_stream, verifier_config).await?;

        // Step 2: Read escrow from on-chain (trustless source)
        info!("[{}] Reading escrow from chain for asset_id={}", session_id, session_data.asset_id);
        let t_chain = Instant::now();
        let escrow = state
            .chain_reader
            .read_escrow(session_data.asset_id)
            .await
            .map_err(|e| eyre::eyre!("Chain read failed: {e}"))?;
        info!("[{}] [TIMING] chain read: {:?}", session_id, t_chain.elapsed());

        // Step 3: Settlement — use MPC-verified plaintext + on-chain escrow, sign EIP-712
        info!("[{}] Running oracle settlement", session_id);
        let t_settle = Instant::now();

        verifier::handle_post_protocol(
            &mpc,
            &mut socket,
            &escrow,
            &state.oracle_signer,
        )
        .await?;
        info!("[{}] [TIMING] settlement (decide+sign+send): {:?}", session_id, t_settle.elapsed());

        Ok::<(), eyre::Report>(())
    })
    .await
    {
        Ok(Ok(())) => {
            info!("[{}] MPC-TLS + settlement completed successfully", session_id);
        }
        Ok(Err(e)) => {
            error!("[{}] MPC-TLS + settlement failed: {}", session_id, e);
        }
        Err(_) => {
            error!(
                "[{}] MPC-TLS + settlement timed out after {:?}",
                session_id, timeout_duration
            );
        }
    }
}
