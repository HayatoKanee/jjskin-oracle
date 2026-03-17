use std::path::Path;

use serde::Deserialize;
use tracing::info;

/// Server configuration loaded from YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub notarization: NotarizationConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub oracle: OracleConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NotarizationConfig {
    /// Maximum pending `/session` tokens waiting for WebSocket upgrade.
    #[serde(default = "default_max_pending_sessions")]
    pub max_pending_sessions: usize,
    /// Maximum active MPC-TLS notarizations admitted concurrently.
    #[serde(default = "default_max_active_sessions")]
    pub max_active_sessions: usize,
    /// Maximum bytes the prover can send through TLS.
    #[serde(default = "default_max_sent_data")]
    pub max_sent_data: usize,
    /// Maximum bytes the prover can receive through TLS.
    #[serde(default = "default_max_recv_data")]
    pub max_recv_data: usize,
    /// Timeout for the MPC-TLS session in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    pub private_key_path: Option<String>,
    pub certificate_path: Option<String>,
}

/// Oracle settlement configuration (always enabled — single verifier path).
#[derive(Debug, Clone, Deserialize)]
pub struct OracleConfig {
    /// Path to oracle Ethereum private key (hex format).
    /// Can also be set via ORACLE_SIGNING_KEY env var.
    pub signing_key_path: Option<String>,
    /// JJSKIN contract address (required for EIP-712 domain separator + escrow reads).
    #[serde(default = "default_contract_address")]
    pub contract_address: String,
    /// Chain ID (default: 42161 for Arbitrum One).
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,
    /// Arbitrum RPC URL for on-chain escrow reads.
    #[serde(default = "default_rpc_url")]
    pub rpc_url: String,
    /// SteamAccountFactory contract address (for Steam ID ↔ wallet mapping).
    #[serde(default = "default_contract_address")]
    pub steam_factory_address: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            notarization: NotarizationConfig::default(),
            tls: TlsConfig::default(),
            oracle: OracleConfig::default(),
        }
    }
}

impl Default for NotarizationConfig {
    fn default() -> Self {
        Self {
            max_pending_sessions: default_max_pending_sessions(),
            max_active_sessions: default_max_active_sessions(),
            max_sent_data: default_max_sent_data(),
            max_recv_data: default_max_recv_data(),
            timeout: default_timeout(),
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            private_key_path: None,
            certificate_path: None,
        }
    }
}

impl Default for OracleConfig {
    fn default() -> Self {
        Self {
            signing_key_path: None,
            contract_address: default_contract_address(),
            chain_id: default_chain_id(),
            rpc_url: default_rpc_url(),
            steam_factory_address: default_contract_address(),
        }
    }
}

impl Config {
    /// Load configuration from a YAML file.
    ///
    /// - Missing file → defaults (acceptable for dev).
    /// - Parse error → fatal exit (prevents running with zero-address contracts).
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(contents) => match serde_yaml::from_str(&contents) {
                Ok(config) => {
                    info!("Loaded config from {:?}", path);
                    config
                }
                Err(e) => {
                    eprintln!("FATAL: Failed to parse config file {:?}: {}", path, e);
                    std::process::exit(1);
                }
            },
            Err(_) => {
                info!("No config file found at {:?}, using defaults", path);
                Self::default()
            }
        }
    }
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    7047
}

fn default_max_pending_sessions() -> usize {
    100
}

fn default_max_active_sessions() -> usize {
    2
}

fn default_max_sent_data() -> usize {
    4096
}

fn default_max_recv_data() -> usize {
    16384
}

fn default_timeout() -> u64 {
    120
}

fn default_chain_id() -> u64 {
    42161 // Arbitrum One
}

fn default_rpc_url() -> String {
    "https://arb1.arbitrum.io/rpc".to_string()
}

fn default_contract_address() -> String {
    "0x0000000000000000000000000000000000000000".to_string()
}
