mod attestation;
mod axum_websocket;
mod config;
mod inventory_attestation;
mod item_detail;
mod observability;
mod proxy;
mod settlement;
mod steam_inventory;
mod verifier;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};
use std::time::{Duration, Instant};

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use axum_server::tls_rustls::RustlsConfig;
use axum_websocket::{WebSocket, WebSocketUpgrade};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::time::{Instant as TokioInstant, MissedTickBehavior};
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};
use uuid::Uuid;
use ws_stream_tungstenite::WsStream;

use tlsn::{config::verifier::VerifierConfig, webpki::RootCertStore};

use config::Config;
use observability::{
    OracleRuntimeMetrics, current_loadavg_1m, current_process_cpu_sample, current_rss_bytes,
    current_thread_count, process_cpu_percent,
};
use settlement::{ChainReader, OracleSigner};
use verifier::{MpcTlsError, MpcTlsRuntimeLimits};

// ============================================================================
// Application State
// ============================================================================

const TLSN_PROTOCOL_VERSION: &str = "tlsn/0.1.0-alpha.15";

type SettlementOutcome = Result<settlement::SettlementResult, String>;

/// Stored one-time session data shared by the verifier and result endpoint.
struct SessionData {
    asset_id: u64,
    verifier_claimed: AtomicBool,
    result_sender: Mutex<Option<oneshot::Sender<SettlementOutcome>>>,
    result_receiver: Mutex<Option<oneshot::Receiver<SettlementOutcome>>>,
}

#[derive(Default)]
struct SessionCounters {
    created: AtomicU64,
    expired: AtomicU64,
    upgraded: AtomicU64,
    rejected_at_capacity: AtomicU64,
}

fn session_token_ttl(timeout_seconds: u64) -> Duration {
    Duration::from_secs(timeout_seconds.saturating_add(30).max(30))
}

fn remaining_deadline(deadline: TokioInstant) -> Option<Duration> {
    deadline.checked_duration_since(TokioInstant::now())
}

fn spawn_resource_heartbeat(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let cpu_count = std::thread::available_parallelism()
            .map(|parallelism| parallelism.get())
            .unwrap_or(1);
        let mut previous_cpu_sample = current_process_cpu_sample();

        loop {
            interval.tick().await;

            let pending_sessions = state.sessions.lock().await.len();
            let current_cpu_sample = current_process_cpu_sample();
            let process_cpu_pct = previous_cpu_sample
                .zip(current_cpu_sample)
                .and_then(|(previous, current)| process_cpu_percent(previous, current, cpu_count));
            previous_cpu_sample = current_cpu_sample;

            let rss_bytes = current_rss_bytes();
            let loadavg_1m = current_loadavg_1m();
            let thread_count = current_thread_count();

            info!(
                stage = "resource_heartbeat",
                cpu_count,
                pending_sessions,
                active_notarizations = state.metrics.active_notarizations(),
                available_active_permits = state.active_notarization_permits.available_permits(),
                sessions_created = state.session_counters.created.load(Ordering::Relaxed),
                sessions_expired = state.session_counters.expired.load(Ordering::Relaxed),
                sessions_upgraded = state.session_counters.upgraded.load(Ordering::Relaxed),
                sessions_rejected_at_capacity = state
                    .session_counters
                    .rejected_at_capacity
                    .load(Ordering::Relaxed),
                inventory_cache_hits = state.metrics.inventory_attestation_cache_hits(),
                inventory_cache_misses = state.metrics.inventory_attestation_cache_misses(),
                mpc_tls_timeouts = state.metrics.mpc_tls_timeouts(),
                rss_bytes = rss_bytes.unwrap_or_default(),
                rss_available = rss_bytes.is_some(),
                process_cpu_pct = process_cpu_pct.unwrap_or_default(),
                process_cpu_available = process_cpu_pct.is_some(),
                loadavg_1m = loadavg_1m.unwrap_or_default(),
                loadavg_available = loadavg_1m.is_some(),
                thread_count = thread_count.unwrap_or_default(),
                thread_count_available = thread_count.is_some(),
                "Oracle resource heartbeat"
            );
        }
    });
}

/// Shared application state.
struct AppState {
    sessions: Mutex<HashMap<String, Arc<SessionData>>>,
    config: Config,
    oracle_signer: Arc<OracleSigner>,
    chain_reader: ChainReader,
    metrics: Arc<OracleRuntimeMetrics>,
    active_notarization_permits: Arc<Semaphore>,
    session_counters: SessionCounters,
}

// ============================================================================
// CLI Args
// ============================================================================

#[derive(Parser, Debug)]
#[command(
    name = "tlsn-server",
    version,
    about = "TLSNotary Verifier + Oracle Server"
)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Start the server (default when no subcommand given).
    Serve {
        /// Path to the configuration YAML file.
        #[arg(short, long, default_value = "config.yaml")]
        config: String,
    },
    /// Run oracle decide() on JSON from stdin (for e2e testing).
    ///
    /// Reads a JSON object from stdin with fields:
    ///   server_name, sent_bytes_hex, recv_bytes_hex, escrow, proof_timestamp
    /// Outputs JSON: { "ok": { ... } } or { "error": "..." }
    TestDecide,
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
    #[serde(rename = "maxSentData")]
    max_sent_data: usize,
    #[serde(rename = "maxRecvData")]
    max_recv_data: usize,
    #[serde(rename = "protocolVersion")]
    protocol_version: String,
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
    #[serde(rename = "protocolVersion")]
    protocol_version: &'static str,
}

#[derive(Debug, Serialize)]
struct SettlementResultResponse {
    signature: String,
    #[serde(rename = "assetId")]
    asset_id: String,
    decision: u8,
    #[serde(rename = "refundReason")]
    refund_reason: u8,
    #[serde(rename = "protocolVersion")]
    protocol_version: &'static str,
}

impl From<settlement::SettlementResult> for SettlementResultResponse {
    fn from(result: settlement::SettlementResult) -> Self {
        Self {
            signature: format!("0x{}", hex::encode(result.signature)),
            asset_id: result.asset_id.to_string(),
            decision: result.decision,
            refund_reason: result.refund_reason,
            protocol_version: TLSN_PROTOCOL_VERSION,
        }
    }
}

#[derive(Debug, Serialize)]
struct InfoResponse {
    version: &'static str,
    #[serde(rename = "protocolVersion")]
    protocol_version: &'static str,
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

#[derive(Debug, Deserialize)]
struct SessionResultQuery {
    #[serde(rename = "sessionId")]
    session_id: String,
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = Args::parse();

    // Default to Serve if no subcommand given (backwards compatible).
    let command = args.command.unwrap_or(Command::Serve {
        config: "config.yaml".to_string(),
    });

    match command {
        Command::TestDecide => return run_test_decide(),
        Command::Serve {
            config: config_path,
        } => {
            return run_serve(&config_path).await;
        }
    }
}

/// test-decide: read JSON from stdin, call decide(), output JSON to stdout.
fn run_test_decide() -> eyre::Result<()> {
    use settlement::oracle;

    #[derive(serde::Deserialize)]
    struct TestDecideInput {
        server_name: String,
        sent_bytes_hex: String,
        recv_bytes_hex: String,
        escrow: settlement::EscrowSnapshot,
        proof_timestamp: u64,
    }

    let input: TestDecideInput = serde_json::from_reader(std::io::stdin())
        .map_err(|e| eyre::eyre!("Failed to parse stdin JSON: {e}"))?;

    let sent_bytes = hex::decode(&input.sent_bytes_hex)
        .map_err(|e| eyre::eyre!("Invalid sent_bytes_hex: {e}"))?;
    let recv_bytes = hex::decode(&input.recv_bytes_hex)
        .map_err(|e| eyre::eyre!("Invalid recv_bytes_hex: {e}"))?;

    let result = oracle::decide(
        &input.server_name,
        &sent_bytes,
        &recv_bytes,
        &input.escrow,
        input.proof_timestamp,
    );

    match result {
        Ok(settlement) => {
            let output = serde_json::json!({
                "ok": {
                    "asset_id": settlement.asset_id,
                    "trade_offer_id": settlement.trade_offer_id,
                    "decision": settlement.decision as u8,
                    "refund_reason": settlement.refund_reason as u8,
                }
            });
            println!("{}", serde_json::to_string(&output)?);
        }
        Err(e) => {
            let output = serde_json::json!({ "error": format!("{e}") });
            println!("{}", serde_json::to_string(&output)?);
        }
    }

    Ok(())
}

async fn run_serve(config_path: &str) -> eyre::Result<()> {
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

    let config = Config::load(Path::new(config_path));

    info!("Configuration loaded:");
    info!("  host: {}", config.host);
    info!("  port: {}", config.port);
    info!("  max_sent_data: {}", config.notarization.max_sent_data);
    info!("  max_recv_data: {}", config.notarization.max_recv_data);
    info!(
        "  max_pending_sessions: {}",
        config.notarization.max_pending_sessions
    );
    info!(
        "  max_active_sessions: {}",
        config.notarization.max_active_sessions
    );
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

    // Wrap oracle signer in Arc for sharing between AppState and inventory attestation state.
    let oracle_signer = Arc::new(oracle_signer);
    let metrics = Arc::new(OracleRuntimeMetrics::default());
    let active_notarization_permits =
        Arc::new(Semaphore::new(config.notarization.max_active_sessions));

    let inventory_attestation_state = Arc::new(inventory_attestation::InventoryAttestationState {
        inventory: steam_inventory::InventoryClient::new(),
        resolver: inventory_attestation::catalog::CatalogResolver::load()?,
        signer: oracle_signer.clone(),
        cache: inventory_attestation::cache::InventoryAttestationCache::new(
            inventory_attestation::DEFAULT_CACHE_CAPACITY,
            Duration::from_secs(inventory_attestation::DEFAULT_CACHE_TTL_SECONDS),
        ),
        metrics: metrics.clone(),
    });

    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .expect("Invalid host:port");

    let tls_config = config.tls.clone();

    let app_state = Arc::new(AppState {
        sessions: Mutex::new(HashMap::new()),
        config,
        oracle_signer,
        chain_reader,
        metrics,
        active_notarization_permits,
        session_counters: SessionCounters::default(),
    });

    spawn_resource_heartbeat(app_state.clone());

    let inventory_attestation_routes = Router::new()
        .route("/attest", post(inventory_attestation::attest_handler))
        .with_state(inventory_attestation_state);

    // Build main routes (oracle / MPC-TLS).
    let main_routes = Router::new()
        .route("/health", get(health_handler))
        .route("/info", get(info_handler))
        .route("/attestation", get(attestation::attestation_handler))
        .route("/session", post(session_handler))
        .route("/session/result", get(session_result_handler))
        .route("/notarize", get(notarize_ws_handler))
        .route("/proxy", get(proxy::proxy_ws_handler))
        .nest("/inventory", inventory_attestation_routes)
        .with_state(app_state);

    let app = main_routes.layer(CorsLayer::permissive());

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
    info!("  GET  /session/result      - Consume one-time settlement result");
    info!("  GET  /notarize?sessionId= - WebSocket MPC-TLS + settlement");
    info!("  GET  /proxy?token=        - WebSocket-to-TCP proxy");
    info!("  POST /inventory/attest    - Inventory-backed item attestation");

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
        protocol_version: TLSN_PROTOCOL_VERSION,
        git_hash,
        oracle_address: format!("{}", state.oracle_signer.address()),
        tdx_enabled: tdx_available,
        tdx_backend: if tdx_available {
            "Dstack".to_string()
        } else {
            "None".to_string()
        },
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
    if body.protocol_version != TLSN_PROTOCOL_VERSION {
        return Err((
            StatusCode::UPGRADE_REQUIRED,
            format!(
                "TLSNotary protocol mismatch: expected {}, received {}",
                TLSN_PROTOCOL_VERSION, body.protocol_version
            ),
        ));
    }
    if body.max_sent_data == 0
        || body.max_recv_data == 0
        || body.max_sent_data > state.config.notarization.max_sent_data
        || body.max_recv_data > state.config.notarization.max_recv_data
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid transcript limits: sent={}/{}, recv={}/{}",
                body.max_sent_data,
                state.config.notarization.max_sent_data,
                body.max_recv_data,
                state.config.notarization.max_recv_data,
            ),
        ));
    }

    // Atomic check-and-insert under a single lock to prevent TOCTOU race.
    let session_id = Uuid::new_v4().to_string();
    let (result_sender, result_receiver) = oneshot::channel();
    let session_data = Arc::new(SessionData {
        asset_id: body.asset_id,
        verifier_claimed: AtomicBool::new(false),
        result_sender: Mutex::new(Some(result_sender)),
        result_receiver: Mutex::new(Some(result_receiver)),
    });
    let pending_sessions = {
        let mut sessions = state.sessions.lock().await;
        if sessions.len() >= state.config.notarization.max_pending_sessions {
            let rejected_at_capacity = state
                .session_counters
                .rejected_at_capacity
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            let rss_bytes = current_rss_bytes();
            warn!(
                session_id,
                asset_id = body.asset_id,
                pending_sessions = sessions.len(),
                active_notarizations = state.metrics.active_notarizations(),
                available_active_permits = state.active_notarization_permits.available_permits(),
                rejected_at_capacity,
                rss_bytes = rss_bytes.unwrap_or_default(),
                rss_available = rss_bytes.is_some(),
                "Rejected session at pending-session capacity"
            );
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "Server at pending-session capacity ({})",
                    state.config.notarization.max_pending_sessions
                ),
            ));
        }
        sessions.insert(session_id.clone(), session_data);
        sessions.len()
    };
    let sessions_created = state
        .session_counters
        .created
        .fetch_add(1, Ordering::Relaxed)
        + 1;
    let rss_bytes = current_rss_bytes();
    info!(
        session_id,
        asset_id = body.asset_id,
        pending_sessions,
        active_notarizations = state.metrics.active_notarizations(),
        available_active_permits = state.active_notarization_permits.available_permits(),
        sessions_created,
        rss_bytes = rss_bytes.unwrap_or_default(),
        rss_available = rss_bytes.is_some(),
        "Session created"
    );

    // Spawn a timeout task to clean up stale sessions.
    let state_clone = state.clone();
    let session_id_clone = session_id.clone();
    let session_ttl = session_token_ttl(state.config.notarization.timeout);
    tokio::spawn(async move {
        tokio::time::sleep(session_ttl).await;
        let mut sessions = state_clone.sessions.lock().await;
        if sessions.remove(&session_id_clone).is_some() {
            let pending_sessions = sessions.len();
            let sessions_expired = state_clone
                .session_counters
                .expired
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            let rss_bytes = current_rss_bytes();
            info!(
                session_id = session_id_clone,
                pending_sessions,
                active_notarizations = state_clone.metrics.active_notarizations(),
                available_active_permits = state_clone.active_notarization_permits.available_permits(),
                session_ttl_ms = session_ttl.as_millis() as u64,
                sessions_expired,
                rss_bytes = rss_bytes.unwrap_or_default(),
                rss_available = rss_bytes.is_some(),
                "Session expired before WebSocket upgrade"
            );
        }
    });

    Ok(Json(SessionResponse {
        session_id,
        protocol_version: TLSN_PROTOCOL_VERSION,
    }))
}

/// GET /session/result?sessionId=xxx — consume a one-time settlement result.
async fn session_result_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionResultQuery>,
) -> Result<Json<SettlementResultResponse>, (StatusCode, String)> {
    let session_data = {
        let sessions = state.sessions.lock().await;
        sessions.get(&query.session_id).cloned()
    }
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("Session not found: {}", query.session_id),
        )
    })?;

    let receiver = session_data
        .result_receiver
        .lock()
        .await
        .take()
        .ok_or_else(|| {
            (
                StatusCode::CONFLICT,
                format!("Session result already claimed: {}", query.session_id),
            )
        })?;

    let wait_timeout = Duration::from_secs(state.config.notarization.timeout);
    let outcome = tokio::time::timeout(wait_timeout, receiver).await;
    state.sessions.lock().await.remove(&query.session_id);

    match outcome {
        Ok(Ok(Ok(settlement))) => Ok(Json(settlement.into())),
        Ok(Ok(Err(error))) => Err((StatusCode::UNPROCESSABLE_ENTITY, error)),
        Ok(Err(_)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Settlement result channel closed unexpectedly".to_string(),
        )),
        Err(_) => Err((
            StatusCode::GATEWAY_TIMEOUT,
            format!(
                "Settlement result timed out after {}ms",
                wait_timeout.as_millis()
            ),
        )),
    }
}

/// GET /notarize?sessionId=xxx — WebSocket upgrade for MPC-TLS + settlement.
async fn notarize_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Query(query): Query<NotarizeQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let session_id = query.session_id;

    let permit = match state
        .active_notarization_permits
        .clone()
        .try_acquire_owned()
    {
        Ok(permit) => permit,
        Err(_) => {
            let pending_sessions = state.sessions.lock().await.len();
            let rss_bytes = current_rss_bytes();
            warn!(
                session_id,
                pending_sessions,
                active_notarizations = state.metrics.active_notarizations(),
                available_active_permits = state.active_notarization_permits.available_permits(),
                max_active_sessions = state.config.notarization.max_active_sessions,
                rss_bytes = rss_bytes.unwrap_or_default(),
                rss_available = rss_bytes.is_some(),
                "Rejected WebSocket upgrade at active MPC-TLS capacity"
            );
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "Server busy: active MPC-TLS capacity reached ({})",
                    state.config.notarization.max_active_sessions
                ),
            ));
        }
    };

    // Look up the session only after securing an active-work permit. It stays in
    // the map until the result endpoint consumes it or the TTL expires.
    let (session_data, pending_sessions) = {
        let sessions = state.sessions.lock().await;
        let session_data = sessions.get(&session_id).cloned();
        (session_data, sessions.len())
    };

    match session_data {
        Some(session_data) => {
            if session_data
                .verifier_claimed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err((
                    StatusCode::CONFLICT,
                    format!("Session verifier already claimed: {}", session_id),
                ));
            }

            let sessions_upgraded = state
                .session_counters
                .upgraded
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            let rss_bytes = current_rss_bytes();
            info!(
                session_id,
                asset_id = session_data.asset_id,
                pending_sessions,
                active_notarizations = state.metrics.active_notarizations(),
                available_active_permits = state.active_notarization_permits.available_permits(),
                sessions_upgraded,
                rss_bytes = rss_bytes.unwrap_or_default(),
                rss_available = rss_bytes.is_some(),
                "WebSocket upgrade for MPC-TLS + settlement"
            );
            Ok(ws.on_upgrade(move |socket| {
                handle_notarize_websocket(socket, session_id, session_data, state, permit)
            }))
        }
        None => {
            let rss_bytes = current_rss_bytes();
            error!(
                session_id,
                pending_sessions,
                active_notarizations = state.metrics.active_notarizations(),
                available_active_permits = state.active_notarization_permits.available_permits(),
                rss_bytes = rss_bytes.unwrap_or_default(),
                rss_available = rss_bytes.is_some(),
                "Session not found or already used"
            );
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
    session_data: Arc<SessionData>,
    state: Arc<AppState>,
    _permit: OwnedSemaphorePermit,
) {
    let started_at = Instant::now();
    let active_notarizations = state.metrics.increment_active_notarizations();
    let pending_sessions = state.sessions.lock().await.len();
    let rss_bytes = current_rss_bytes();
    info!(
        session_id,
        asset_id = session_data.asset_id,
        active_notarizations,
        pending_sessions,
        available_active_permits = state.active_notarization_permits.available_permits(),
        mpc_tls_timeouts = state.metrics.mpc_tls_timeouts(),
        rss_bytes = rss_bytes.unwrap_or_default(),
        rss_available = rss_bytes.is_some(),
        "WebSocket connected, starting MPC-TLS"
    );

    let ws_stream = WsStream::new(socket.into_inner());

    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore::mozilla())
        .build()
        .expect("Failed to build verifier config");
    let runtime_limits = MpcTlsRuntimeLimits {
        max_sent_data: state.config.notarization.max_sent_data,
        max_recv_data: state.config.notarization.max_recv_data,
    };

    let timeout_duration = Duration::from_secs(state.config.notarization.timeout);
    let overall_deadline = TokioInstant::now() + timeout_duration;

    let mut timed_out = false;

    match async {
        // Step 1: Run MPC-TLS
        let mpc = match verifier::run_mpc_tls(
            &session_id,
            ws_stream,
            verifier_config,
            runtime_limits,
            timeout_duration,
        )
        .await {
            Ok(result) => result,
            Err(MpcTlsError::Timeout { timeout }) => {
                timed_out = true;
                return Err(eyre::eyre!(
                    "MPC-TLS session timed out after {}ms",
                    timeout.as_millis()
                ));
            }
            Err(MpcTlsError::Session(error)) => return Err(error),
        };
        let rss_bytes = current_rss_bytes();
        info!(
            session_id,
            asset_id = session_data.asset_id,
            ciphertext_sent_bytes = mpc.ciphertext_sent_bytes,
            ciphertext_recv_bytes = mpc.ciphertext_recv_bytes,
            plaintext_sent_bytes = mpc.sent_bytes.len(),
            plaintext_recv_bytes = mpc.recv_bytes.len(),
            active_notarizations = state.metrics.active_notarizations(),
            available_active_permits = state.active_notarization_permits.available_permits(),
            rss_bytes = rss_bytes.unwrap_or_default(),
            rss_available = rss_bytes.is_some(),
            "MPC-TLS stage completed"
        );

        // Step 2: Read escrow from on-chain (trustless source)
        info!(
            session_id,
            asset_id = session_data.asset_id,
            "Reading escrow from chain"
        );
        let t_chain = Instant::now();
        let chain_read_timeout = remaining_deadline(overall_deadline).ok_or_else(|| {
            timed_out = true;
            eyre::eyre!("Notarization deadline exceeded before chain read")
        })?;
        let escrow = match tokio::time::timeout(
            chain_read_timeout,
            state.chain_reader.read_escrow(session_data.asset_id),
        )
        .await
        {
            Ok(result) => result.map_err(|e| eyre::eyre!("Chain read failed: {e}"))?,
            Err(_) => {
                timed_out = true;
                return Err(eyre::eyre!(
                    "Notarization timed out during chain read after {}ms",
                    timeout_duration.as_millis()
                ));
            }
        };
        info!(
            session_id,
            asset_id = session_data.asset_id,
            stage = "chain_read",
            duration_ms = t_chain.elapsed().as_millis() as u64,
            "[TIMING] chain read"
        );

        // Step 3: Settlement — use MPC-verified plaintext + on-chain escrow, sign EIP-712
        info!(session_id, asset_id = session_data.asset_id, "Running oracle settlement");
        let t_settle = Instant::now();

        let settlement_timeout = remaining_deadline(overall_deadline).ok_or_else(|| {
            timed_out = true;
            eyre::eyre!("Notarization deadline exceeded before settlement")
        })?;
        let settlement = match tokio::time::timeout(
            settlement_timeout,
            verifier::create_settlement_result(
                &session_id,
                &mpc,
                &escrow,
                &state.oracle_signer,
            ),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                timed_out = true;
                return Err(eyre::eyre!(
                    "Notarization timed out during settlement after {}ms",
                    timeout_duration.as_millis()
                ));
            }
        };
        info!(
            session_id,
            asset_id = session_data.asset_id,
            stage = "settlement",
            duration_ms = t_settle.elapsed().as_millis() as u64,
            "[TIMING] settlement (decide+sign+send)"
        );

        Ok::<settlement::SettlementResult, eyre::Report>(settlement)
    }
    .await
    {
        Ok(settlement) => {
            let remaining_active = state.metrics.decrement_active_notarizations();
            let rss_bytes = current_rss_bytes();
            info!(
                session_id,
                asset_id = session_data.asset_id,
                total_duration_ms = started_at.elapsed().as_millis() as u64,
                active_notarizations = remaining_active,
                available_active_permits = state.active_notarization_permits.available_permits(),
                mpc_tls_timeouts = state.metrics.mpc_tls_timeouts(),
                rss_bytes = rss_bytes.unwrap_or_default(),
                rss_available = rss_bytes.is_some(),
                "MPC-TLS + settlement completed successfully"
            );
            publish_settlement_outcome(&session_data, Ok(settlement)).await;
        }
        Err(error) => {
            let timeout_count = if timed_out {
                Some(state.metrics.record_mpc_tls_timeout())
            } else {
                None
            };
            let remaining_active = state.metrics.decrement_active_notarizations();
            let rss_bytes = current_rss_bytes();
            if let Some(timeout_count) = timeout_count {
                error!(
                    session_id,
                    asset_id = session_data.asset_id,
                    timeout_ms = timeout_duration.as_millis() as u64,
                    total_duration_ms = started_at.elapsed().as_millis() as u64,
                    active_notarizations = remaining_active,
                    available_active_permits = state.active_notarization_permits.available_permits(),
                    mpc_tls_timeouts = timeout_count,
                    rss_bytes = rss_bytes.unwrap_or_default(),
                    rss_available = rss_bytes.is_some(),
                    "MPC-TLS + settlement timed out"
                );
            } else {
                error!(
                    session_id,
                    asset_id = session_data.asset_id,
                    total_duration_ms = started_at.elapsed().as_millis() as u64,
                    active_notarizations = remaining_active,
                    available_active_permits = state.active_notarization_permits.available_permits(),
                    mpc_tls_timeouts = state.metrics.mpc_tls_timeouts(),
                    rss_bytes = rss_bytes.unwrap_or_default(),
                    rss_available = rss_bytes.is_some(),
                    error = %error,
                    "MPC-TLS + settlement failed"
                );
            }
            publish_settlement_outcome(&session_data, Err(error.to_string())).await;
        }
    }
}

async fn publish_settlement_outcome(
    session_data: &SessionData,
    outcome: SettlementOutcome,
) {
    if let Some(sender) = session_data.result_sender.lock().await.take() {
        let _ = sender.send(outcome);
    }
}

#[cfg(test)]
mod alpha15_session_tests {
    use super::*;

    fn session_data(asset_id: u64) -> (Arc<SessionData>, oneshot::Receiver<SettlementOutcome>) {
        let (sender, receiver) = oneshot::channel();
        (
            Arc::new(SessionData {
                asset_id,
                verifier_claimed: AtomicBool::new(false),
                result_sender: Mutex::new(Some(sender)),
                result_receiver: Mutex::new(None),
            }),
            receiver,
        )
    }

    #[test]
    fn session_request_requires_exact_alpha15_protocol_and_preserves_uint64_asset() {
        let request: SessionRequest = serde_json::from_value(serde_json::json!({
            "assetId": "18446744073709551615",
            "maxSentData": 1024,
            "maxRecvData": 2048,
            "protocolVersion": TLSN_PROTOCOL_VERSION,
        }))
        .unwrap();

        assert_eq!(request.asset_id, u64::MAX);
        assert_eq!(request.protocol_version, TLSN_PROTOCOL_VERSION);
    }

    #[test]
    fn settlement_response_serializes_asset_as_string_and_signature_as_hex() {
        let response = SettlementResultResponse::from(settlement::SettlementResult {
            signature: vec![0xab; 65],
            asset_id: u64::MAX,
            decision: 1,
            refund_reason: 12,
        });
        let json = serde_json::to_value(response).unwrap();

        assert_eq!(json["assetId"], u64::MAX.to_string());
        assert_eq!(json["signature"], format!("0x{}", "ab".repeat(65)));
        assert_eq!(json["protocolVersion"], TLSN_PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn settlement_result_is_published_only_once() {
        let (session, receiver) = session_data(42);
        let first = settlement::SettlementResult {
            signature: vec![1; 65],
            asset_id: 42,
            decision: 0,
            refund_reason: 0,
        };

        publish_settlement_outcome(&session, Ok(first.clone())).await;
        publish_settlement_outcome(&session, Err("duplicate".to_string())).await;

        let received = receiver.await.unwrap().unwrap();
        assert_eq!(received.asset_id, first.asset_id);
        assert!(session.result_sender.lock().await.is_none());
    }
}
