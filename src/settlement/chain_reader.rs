//! On-chain escrow reader.
//!
//! Reads escrow data directly from JJSKIN contract + SteamAccountFactory
//! via `eth_call`. Replaces extension-provided escrow data (untrusted).
//!
//! Security: Oracle consumes ONLY cryptographically verified inputs:
//! - MPC-TLS transcript (garbled circuits prove Steam response authenticity)
//! - On-chain state (blockchain consensus — trustless)
//!
//! The extension provides `assetId` as a lookup hint. Even a malicious assetId
//! cannot cause incorrect settlement because tradeOfferId binding (committed
//! on-chain by seller) prevents mismatch.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use alloy::primitives::Address;
use alloy::sol;
use alloy::sol_types::SolCall;
use eyre::{Result, eyre};
use tracing::{info, warn};

use super::types::EscrowSnapshot;

// ABI definitions for on-chain reads (function selectors + encoding/decoding).
// These match the auto-generated getters for public mappings in Solidity.
sol! {
    // JJSKIN.sol: mapping(AssetId => Purchase) public purchases;
    // AssetId is `type AssetId is uint64` → ABI uses uint64
    function purchases(uint64 assetId) external view returns (
        address buyer,
        uint40 purchaseTime,
        uint8 status,
        uint48 tradeOfferId
    );

    // JJSKIN.sol: mapping(AssetId => Listing) public listings;
    function listings(uint64 assetId) external view returns (
        address seller,
        uint56 price,
        bool exists,
        uint32 reserved
    );

    // SteamAccountFactory.sol: getSteamIdByWallet(address) → uint256
    function getSteamIdByWallet(address wallet) external view returns (uint256 steamId);
}

/// Reads escrow data from on-chain contracts via `eth_call`.
///
/// Stateless: each call is an independent query against current chain state.
/// No caching, no stored state — `f(assetId) → EscrowSnapshot`.
pub struct ChainReader {
    client: reqwest::Client,
    rpc_url: String,
    jjskin_address: Address,
    factory_address: Address,
    next_rpc_id: AtomicU64,
}

impl ChainReader {
    pub fn new(
        rpc_url: String,
        jjskin_address: Address,
        factory_address: Address,
    ) -> Self {
        Self {
            client: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to build RPC HTTP client"),
            rpc_url,
            jjskin_address,
            factory_address,
            next_rpc_id: AtomicU64::new(1),
        }
    }

    /// Read escrow data from on-chain for a given asset ID.
    ///
    /// Makes 4 `eth_call` requests (2 parallel batches):
    /// 1. JJSKIN.purchases(assetId) + JJSKIN.listings(assetId)  [parallel]
    /// 2. SteamAccountFactory.getSteamIdByWallet(seller) + ...(buyer)  [parallel]
    pub async fn read_escrow(&self, asset_id: u64) -> Result<EscrowSnapshot> {
        // Batch 1: Read purchase and listing in parallel
        let purchase_calldata = purchasesCall { assetId: asset_id }.abi_encode();
        let listing_calldata = listingsCall { assetId: asset_id }.abi_encode();

        let (purchase_result, listing_result) = tokio::join!(
            self.eth_call(self.jjskin_address, &purchase_calldata),
            self.eth_call(self.jjskin_address, &listing_calldata),
        );

        let purchase_bytes = purchase_result?;
        let listing_bytes = listing_result?;

        let purchase = purchasesCall::abi_decode_returns(&purchase_bytes)
            .map_err(|e| eyre!("Failed to decode purchases({}): {e}", asset_id))?;
        let listing = listingsCall::abi_decode_returns(&listing_bytes)
            .map_err(|e| eyre!("Failed to decode listings({}): {e}", asset_id))?;

        // Validate purchase exists and is active
        if purchase.buyer == Address::ZERO {
            return Err(eyre!("No purchase exists for asset {}", asset_id));
        }
        if purchase.status != 0 {
            return Err(eyre!(
                "Purchase not active for asset {} (status={})",
                asset_id,
                purchase.status
            ));
        }
        if !listing.exists {
            return Err(eyre!("No listing exists for asset {}", asset_id));
        }

        // Safe: uint56, uint48, uint40 always fit in u64.
        // tradeOfferId is uint48 on-chain. Steam IDs are 64-bit but currently
        // fit in 48 bits. If Steam exceeds 2^48, the contract needs updating.
        let price: u64 = listing.price.as_limbs()[0];
        let trade_offer_id: u64 = purchase.tradeOfferId.as_limbs()[0];
        let purchase_time: u64 = purchase.purchaseTime.as_limbs()[0];

        info!(
            "On-chain: asset_id={}, buyer={}, seller={}, price={}, tradeOfferId={}, purchaseTime={}",
            asset_id, purchase.buyer, listing.seller, price, trade_offer_id, purchase_time,
        );

        // Batch 2: Read Steam IDs for both parties in parallel
        let seller_steam_calldata =
            getSteamIdByWalletCall { wallet: listing.seller }.abi_encode();
        let buyer_steam_calldata =
            getSteamIdByWalletCall { wallet: purchase.buyer }.abi_encode();

        let (seller_steam_result, buyer_steam_result) = tokio::join!(
            self.eth_call(self.factory_address, &seller_steam_calldata),
            self.eth_call(self.factory_address, &buyer_steam_calldata),
        );

        let seller_steam_bytes = seller_steam_result?;
        let buyer_steam_bytes = buyer_steam_result?;

        let seller_steam_u256 = getSteamIdByWalletCall::abi_decode_returns(&seller_steam_bytes)
            .map_err(|e| eyre!("Failed to decode seller steam ID: {e}"))?;
        let buyer_steam_u256 = getSteamIdByWalletCall::abi_decode_returns(&buyer_steam_bytes)
            .map_err(|e| eyre!("Failed to decode buyer steam ID: {e}"))?;

        // Steam64 IDs are ~17 digits (~7.6e16) — fits in u64 (max ~1.8e19)
        // Single return value: abi_decode_returns yields U256 directly
        let seller_steam_id: u64 = seller_steam_u256.as_limbs()[0];
        let buyer_steam_id: u64 = buyer_steam_u256.as_limbs()[0];

        if seller_steam_id == 0 {
            return Err(eyre!(
                "Seller {} not registered in SteamAccountFactory",
                listing.seller
            ));
        }
        if buyer_steam_id == 0 {
            return Err(eyre!(
                "Buyer {} not registered in SteamAccountFactory",
                purchase.buyer
            ));
        }

        info!(
            "Steam IDs: seller={}, buyer={}",
            seller_steam_id, buyer_steam_id
        );

        Ok(EscrowSnapshot {
            asset_id,
            trade_offer_id,
            seller_steam_id,
            buyer_steam_id,
            seller: listing.seller.0 .0,
            buyer: purchase.buyer.0 .0,
            amount: price,
            purchase_time,
        })
    }

    /// Make a raw `eth_call` JSON-RPC request with retry on transient failures.
    ///
    /// Retries up to 3 times with exponential backoff (200ms, 600ms, 1800ms)
    /// for network errors and HTTP 429/5xx. Non-retryable errors (RPC-level
    /// revert, decode failure) fail immediately.
    async fn eth_call(&self, to: Address, data: &[u8]) -> Result<Vec<u8>> {
        const MAX_RETRIES: u32 = 3;
        const BASE_DELAY_MS: u64 = 200;

        let mut last_err = eyre!("eth_call failed");

        for attempt in 0..MAX_RETRIES {
            let rpc_id = self.next_rpc_id.fetch_add(1, Ordering::Relaxed);
            let send_result = self
                .client
                .post(&self.rpc_url)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "eth_call",
                    "params": [{
                        "to": format!("{to}"),
                        "data": format!("0x{}", hex::encode(data))
                    }, "latest"],
                    "id": rpc_id
                }))
                .send()
                .await;

            let response = match send_result {
                Ok(r) => r,
                Err(e) => {
                    last_err = eyre!("RPC request failed: {e}");
                    if attempt + 1 < MAX_RETRIES {
                        let delay = BASE_DELAY_MS * 3u64.pow(attempt);
                        warn!(attempt = attempt + 1, delay_ms = delay, "RPC send failed, retrying");
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }
                    continue;
                }
            };

            // Retry on 429/5xx
            let status = response.status();
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS
                || status.is_server_error()
            {
                last_err = eyre!("RPC HTTP {}", status);
                if attempt + 1 < MAX_RETRIES {
                    let delay = BASE_DELAY_MS * 3u64.pow(attempt);
                    warn!(attempt = attempt + 1, status = %status, delay_ms = delay, "RPC HTTP error, retrying");
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                continue;
            }

            let json: serde_json::Value = response
                .json()
                .await
                .map_err(|e| eyre!("RPC response parse failed: {e}"))?;

            if let Some(error) = json.get("error") {
                return Err(eyre!("RPC error: {}", error));
            }

            let result = json["result"]
                .as_str()
                .ok_or_else(|| eyre!("Missing 'result' in RPC response"))?;

            return hex::decode(result.trim_start_matches("0x"))
                .map_err(|e| eyre!("Failed to decode hex result: {e}"));
        }

        Err(last_err)
    }
}
