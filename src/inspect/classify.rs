use std::collections::HashMap;
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use tracing::{debug, error, info, warn};

use super::cs2_schema::Cs2Schema;
use super::cache::InspectCache;
use super::inventory::{InventoryClient, InventoryError};
use super::types::{InspectData, SingleResponse, BulkItemResponse, BulkResponse};
use crate::settlement::OracleSigner;

/// Maximum items per bulk classify request.
const MAX_BULK_ITEMS: usize = 100;

/// Shared state for classify routes.
pub struct ClassifyState {
    pub schema: Cs2Schema,
    pub inventory: InventoryClient,
    pub signer: Arc<OracleSigner>,
    pub cache: InspectCache,
}

// ============================================================================
// Request types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ClassifyRequest {
    #[serde(rename = "assetId", deserialize_with = "deserialize_string_or_number")]
    asset_id: u64,
    #[serde(rename = "steamId", deserialize_with = "deserialize_string_or_number")]
    steam_id: u64,
}

#[derive(Debug, Deserialize)]
pub struct BulkClassifyRequest {
    pub items: Vec<BulkClassifyItem>,
}

#[derive(Debug, Deserialize)]
pub struct BulkClassifyItem {
    #[serde(rename = "assetId", deserialize_with = "deserialize_string_or_number")]
    pub asset_id: u64,
    #[serde(rename = "steamId", deserialize_with = "deserialize_string_or_number")]
    pub steam_id: u64,
}

/// Deserialize a u64 from either a JSON string ("123") or number (123).
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

// ============================================================================
// Route handlers
// ============================================================================

/// POST /inspect/classify
///
/// Classify a single non-inspectable item (case, key) by looking up its
/// market_hash_name in the Steam inventory and mapping to a defindex.
/// Returns the same response format as /inspect.
pub async fn classify_handler(
    State(state): State<Arc<ClassifyState>>,
    Json(body): Json<ClassifyRequest>,
) -> Result<Json<SingleResponse>, (StatusCode, Json<SingleResponse>)> {
    let cache_key = format!("classify:{}:{}", body.steam_id, body.asset_id);

    // Check cache first
    if let Some(cached) = state.cache.get(&cache_key) {
        debug!(asset_id = body.asset_id, "Classify cache hit");
        return Ok(Json(SingleResponse {
            iteminfo: Some(cached.data),
            error: None,
            item_detail: cached.item_detail,
            oracle_signature: cached.oracle_signature,
        }));
    }

    // Look up asset in Steam inventory
    let inv_item = state
        .inventory
        .find_asset(body.steam_id, body.asset_id)
        .await
        .map_err(|e| {
            let (status, msg) = match &e {
                InventoryError::PrivateInventory => {
                    (StatusCode::BAD_REQUEST, "Steam inventory is private".to_string())
                }
                InventoryError::AssetNotFound(_) => {
                    (StatusCode::NOT_FOUND, format!("Asset {} not found in inventory", body.asset_id))
                }
                InventoryError::SteamApiError(msg) => {
                    error!(error = %msg, "Steam API error during classify");
                    (StatusCode::BAD_GATEWAY, "Steam API error, please retry".to_string())
                }
                InventoryError::RequestFailed(msg) => {
                    error!(error = %msg, "Request failed during classify");
                    (StatusCode::BAD_GATEWAY, "Failed to reach Steam, please retry".to_string())
                }
            };
            (status, Json(SingleResponse {
                iteminfo: None,
                error: Some(msg),
                item_detail: None,
                oracle_signature: None,
            }))
        })?;

    // Look up defindex + ItemDetail from schema
    let (defindex, item_detail) = state
        .schema
        .lookup(&inv_item.market_hash_name)
        .ok_or_else(|| {
            warn!(
                name = inv_item.market_hash_name,
                asset_id = body.asset_id,
                "Item not in schema (not a case/key)"
            );
            (
                StatusCode::BAD_REQUEST,
                Json(SingleResponse {
                    iteminfo: None,
                    error: Some(format!(
                        "Item '{}' is not a supported case or key",
                        inv_item.market_hash_name
                    )),
                    item_detail: None,
                    oracle_signature: None,
                }),
            )
        })?;

    // Build InspectData (mimics GC response format for non-inspectable items)
    let data = build_classify_inspect_data(body.asset_id, body.steam_id, defindex);

    // Sign attestation
    let (item_detail_str, oracle_signature) =
        sign_classify(body.asset_id, item_detail, &state.signer).await;

    // Cache with short TTL (cache is shared, keyed by classify:{steamId}:{assetId})
    state.cache.insert(
        cache_key,
        data.clone(),
        item_detail_str.clone(),
        oracle_signature.clone(),
    );

    info!(
        asset_id = body.asset_id,
        defindex,
        name = inv_item.market_hash_name,
        "Classify success"
    );

    Ok(Json(SingleResponse {
        iteminfo: Some(data),
        error: None,
        item_detail: item_detail_str,
        oracle_signature,
    }))
}

/// POST /inspect/classify/bulk
///
/// Classify multiple non-inspectable items. Groups by steamId for efficient
/// inventory fetches.
pub async fn bulk_classify_handler(
    State(state): State<Arc<ClassifyState>>,
    Json(body): Json<BulkClassifyRequest>,
) -> Result<Json<BulkResponse>, (StatusCode, String)> {
    let total = body.items.len();
    if total > MAX_BULK_ITEMS {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Too many items: {total} exceeds limit of {MAX_BULK_ITEMS}"),
        ));
    }
    info!(total, "Processing bulk classify request");

    let mut response = BulkResponse::new();
    let mut cache_hits = 0u32;

    // Separate cache hits from misses, grouping misses by steamId
    let mut misses_by_steam: HashMap<u64, Vec<u64>> = HashMap::new();
    for item in &body.items {
        let cache_key = format!("classify:{}:{}", item.steam_id, item.asset_id);
        if let Some(cached) = state.cache.get(&cache_key) {
            response.insert(
                item.asset_id.to_string(),
                BulkItemResponse::Success {
                    iteminfo: cached.data,
                    item_detail: cached.item_detail,
                    oracle_signature: cached.oracle_signature,
                },
            );
            cache_hits += 1;
        } else {
            misses_by_steam
                .entry(item.steam_id)
                .or_default()
                .push(item.asset_id);
        }
    }

    if cache_hits > 0 {
        info!(hits = cache_hits, total, "Bulk classify cache hits");
    }

    // Process misses grouped by steamId (one inventory fetch per steamId)
    for (steam_id, asset_ids) in &misses_by_steam {
        // Fetch full inventory for this steamId
        let inventory = match state.inventory.fetch_inventory(*steam_id).await {
            Ok(inv) => inv,
            Err(e) => {
                let msg = match &e {
                    InventoryError::PrivateInventory => "Steam inventory is private",
                    _ => "Failed to fetch inventory",
                };
                for asset_id in asset_ids {
                    response.insert(
                        asset_id.to_string(),
                        BulkItemResponse::Error {
                            error: msg.to_string(),
                        },
                    );
                }
                continue;
            }
        };

        // Build asset_id -> InventoryItem lookup
        let inv_map: HashMap<u64, &super::inventory::InventoryItem> =
            inventory.iter().map(|i| (i.asset_id, i)).collect();

        for asset_id in asset_ids {
            let key = asset_id.to_string();

            let inv_item = match inv_map.get(asset_id) {
                Some(item) => item,
                None => {
                    response.insert(
                        key,
                        BulkItemResponse::Error {
                            error: format!("Asset {asset_id} not found in inventory"),
                        },
                    );
                    continue;
                }
            };

            let (defindex, item_detail) = match state.schema.lookup(&inv_item.market_hash_name) {
                Some(v) => v,
                None => {
                    response.insert(
                        key,
                        BulkItemResponse::Error {
                            error: format!(
                                "Item '{}' is not a supported case or key",
                                inv_item.market_hash_name
                            ),
                        },
                    );
                    continue;
                }
            };

            let data = build_classify_inspect_data(*asset_id, *steam_id, defindex);
            let (item_detail_str, oracle_signature) =
                sign_classify(*asset_id, item_detail, &state.signer).await;

            // Cache
            let cache_key = format!("classify:{steam_id}:{asset_id}");
            state.cache.insert(
                cache_key,
                data.clone(),
                item_detail_str.clone(),
                oracle_signature.clone(),
            );

            response.insert(
                key,
                BulkItemResponse::Success {
                    iteminfo: data,
                    item_detail: item_detail_str,
                    oracle_signature: oracle_signature,
                },
            );
        }
    }

    let success_count = response
        .values()
        .filter(|v| matches!(v, BulkItemResponse::Success { .. }))
        .count();

    info!(
        total,
        success = success_count,
        errors = response.len() - success_count,
        cache_hits,
        "Bulk classify complete"
    );

    Ok(Json(response))
}

// ============================================================================
// Helpers
// ============================================================================

/// Build an InspectData struct for a classified (non-inspectable) item.
/// Cases/keys have no float, paint, seed — only defindex matters.
fn build_classify_inspect_data(asset_id: u64, steam_id: u64, defindex: u32) -> InspectData {
    InspectData {
        accountid: None,
        itemid: asset_id.to_string(),
        defindex,
        paintindex: 0,
        rarity: 0,
        quality: 4, // Normal
        paintwear: None,
        paintseed: 0,
        killeaterscoretype: None,
        killeatervalue: None,
        customname: None,
        stickers: vec![],
        inventory: None,
        origin: 0,
        questid: None,
        dropreason: None,
        musicindex: None,
        s: Some(steam_id.to_string()),
        a: asset_id.to_string(),
        d: "0".to_string(),
        m: None,
        floatvalue: 0.0,
    }
}

/// Sign item attestation and return (item_detail_string, oracle_signature_hex).
async fn sign_classify(
    asset_id: u64,
    item_detail: u64,
    signer: &OracleSigner,
) -> (Option<String>, Option<String>) {
    match signer.sign_item_attestation(asset_id, item_detail).await {
        Ok(sig_bytes) => {
            let sig_hex = format!("0x{}", hex::encode(&sig_bytes));
            (Some(item_detail.to_string()), Some(sig_hex))
        }
        Err(e) => {
            error!(asset_id, error = %e, "Failed to sign classify attestation");
            (None, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_classify_inspect_data() {
        let data = build_classify_inspect_data(12345, 76561198012345678, 4001);

        assert_eq!(data.itemid, "12345");
        assert_eq!(data.defindex, 4001);
        assert_eq!(data.paintindex, 0);
        assert_eq!(data.quality, 4);
        assert_eq!(data.paintseed, 0);
        assert_eq!(data.floatvalue, 0.0);
        assert_eq!(data.a, "12345");
        assert_eq!(data.s.as_deref(), Some("76561198012345678"));
        assert!(data.stickers.is_empty());
    }

    #[test]
    fn test_deserialize_classify_request_strings() {
        let json = r#"{"assetId": "38988024803", "steamId": "76561198012345678"}"#;
        let req: ClassifyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.asset_id, 38988024803);
        assert_eq!(req.steam_id, 76561198012345678);
    }

    #[test]
    fn test_deserialize_classify_request_numbers() {
        let json = r#"{"assetId": 38988024803, "steamId": 76561198012345678}"#;
        let req: ClassifyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.asset_id, 38988024803);
        assert_eq!(req.steam_id, 76561198012345678);
    }

    #[test]
    fn test_deserialize_bulk_classify_request() {
        let json = r#"{"items": [
            {"assetId": "100", "steamId": "200"},
            {"assetId": 300, "steamId": 400}
        ]}"#;
        let req: BulkClassifyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.items.len(), 2);
        assert_eq!(req.items[0].asset_id, 100);
        assert_eq!(req.items[1].steam_id, 400);
    }
}
