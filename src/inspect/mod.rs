pub mod bot_pool;
pub mod cache;
pub mod classify;
pub mod cs2_schema;
pub mod gc_client;
pub mod inventory;
pub mod item_detail;
pub mod link_parser;
pub mod types;

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use tracing::{debug, error, info, warn};

use bot_pool::BotPool;
use cache::InspectCache;
use futures_util::stream::{self, StreamExt as _};
use item_detail::encode_item_detail;
use link_parser::parse_inspect_link;
use types::{BulkItemResponse, BulkRequest, BulkResponse, InspectData, SingleResponse};

/// Maximum items per bulk request (prevents bot pool exhaustion).
const MAX_BULK_ITEMS: usize = 100;

/// Maximum concurrent GC requests per bulk call.
const BULK_CONCURRENCY: usize = 10;

use crate::settlement::OracleSigner;

// ============================================================================
// State
// ============================================================================

/// Shared state for inspect routes: bot pool + oracle signer + LRU cache.
pub struct InspectState {
    pub pool: BotPool,
    pub signer: Arc<OracleSigner>,
    pub cache: InspectCache,
}

// ============================================================================
// Query types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct InspectQuery {
    pub url: String,
}

// ============================================================================
// Route handlers
// ============================================================================

/// Sign item attestation for inspect data, returning (item_detail, oracle_signature).
async fn sign_inspect_data(
    signer: &OracleSigner,
    asset_id: u64,
    data: &InspectData,
) -> (Option<String>, Option<String>) {
    let item_detail = encode_item_detail(
        data.paintindex,
        data.floatvalue,
        data.defindex,
        data.paintseed,
        data.quality,
        // tint_id: use first sticker's tint_id if present and no paint (graffiti),
        // otherwise 0
        if data.paintindex == 0 {
            data.stickers.first().and_then(|s| s.tint_id).unwrap_or(0)
        } else {
            0
        },
    );

    match signer.sign_item_attestation(asset_id, item_detail).await {
        Ok(sig_bytes) => {
            let sig_hex = format!("0x{}", hex::encode(&sig_bytes));
            (Some(item_detail.to_string()), Some(sig_hex))
        }
        Err(e) => {
            error!(a = asset_id, error = %e, "Failed to sign item attestation");
            (None, None)
        }
    }
}

/// GET /inspect?url={inspect_link}
///
/// Single item inspection — matches CSFloat's `GET /?url=` response format.
/// Includes `item_detail` and `oracle_signature` when signing succeeds.
/// Results are cached by inspect link; cache hits skip GC entirely.
pub async fn inspect_handler(
    State(state): State<Arc<InspectState>>,
    Query(params): Query<InspectQuery>,
) -> Result<Json<SingleResponse>, (StatusCode, Json<SingleResponse>)> {
    let link_params = parse_inspect_link(&params.url).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(SingleResponse {
                iteminfo: None,
                error: Some("Invalid inspect link".to_string()),
                item_detail: None,
                oracle_signature: None,
            }),
        )
    })?;

    // Check cache first.
    if let Some(cached) = state.cache.get(&params.url) {
        debug!(a = link_params.a, "Cache hit");
        return Ok(Json(SingleResponse {
            iteminfo: Some(cached.data),
            error: None,
            item_detail: cached.item_detail,
            oracle_signature: cached.oracle_signature,
        }));
    }

    debug!(a = link_params.a, "Cache miss, inspecting item");

    match state.pool.inspect(&link_params).await {
        Ok(data) => {
            info!(a = link_params.a, float = data.floatvalue, "Inspect success");

            let (item_detail, oracle_signature) =
                sign_inspect_data(&state.signer, link_params.a, &data).await;

            // Populate cache.
            state.cache.insert(
                params.url.clone(),
                data.clone(),
                item_detail.clone(),
                oracle_signature.clone(),
            );

            Ok(Json(SingleResponse {
                iteminfo: Some(data),
                error: None,
                item_detail,
                oracle_signature,
            }))
        }
        Err(e) => {
            error!(a = link_params.a, error = %e, "Inspect failed");
            let client_msg = match &e {
                gc_client::InspectError::Timeout => "Inspection timed out, please retry",
                gc_client::InspectError::NoBots => "Service temporarily unavailable",
                _ => "Inspection failed, please retry",
            };
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SingleResponse {
                    iteminfo: None,
                    error: Some(client_msg.to_string()),
                    item_detail: None,
                    oracle_signature: None,
                }),
            ))
        }
    }
}

/// POST /inspect/bulk
///
/// Batch item inspection — matches CSFloat's `POST /bulk` response format.
/// Response is keyed by asset ID (the `a` parameter from inspect links).
/// Each successful item includes `item_detail` and `oracle_signature`.
/// Cache hits are served immediately; only misses hit the GC bot pool.
pub async fn bulk_handler(
    State(state): State<Arc<InspectState>>,
    Json(body): Json<BulkRequest>,
) -> Result<Json<BulkResponse>, (StatusCode, String)> {
    let total = body.links.len();
    if total > MAX_BULK_ITEMS {
        warn!(total, max = MAX_BULK_ITEMS, "Bulk request exceeds limit");
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Too many items: {total} exceeds limit of {MAX_BULK_ITEMS}"),
        ));
    }
    info!(total, "Processing bulk inspect request");

    let mut response = BulkResponse::new();
    let mut cache_hits = 0u32;

    // Separate cache hits from misses.
    let mut misses: Vec<String> = Vec::new();
    for link_item in &body.links {
        let link = &link_item.link;
        if let Some(cached) = state.cache.get(link) {
            let params = match parse_inspect_link(link) {
                Some(p) => p,
                None => {
                    response.insert(
                        link.clone(),
                        BulkItemResponse::Error {
                            error: "Invalid inspect link".to_string(),
                        },
                    );
                    continue;
                }
            };
            response.insert(
                params.a.to_string(),
                BulkItemResponse::Success {
                    iteminfo: cached.data,
                    item_detail: cached.item_detail,
                    oracle_signature: cached.oracle_signature,
                },
            );
            cache_hits += 1;
        } else {
            misses.push(link.clone());
        }
    }

    if cache_hits > 0 {
        info!(
            hits = cache_hits,
            total,
            "Bulk cache hits"
        );
    }

    // Inspect cache misses via bot pool (bounded concurrency).
    if !misses.is_empty() {
        let results: Vec<_> = stream::iter(misses.into_iter().map(|link| {
            let state = Arc::clone(&state);
            async move {
                let params = match parse_inspect_link(&link) {
                    Some(p) => p,
                    None => return (link, None, Err("Invalid inspect link".to_string())),
                };
                let asset_id_num = params.a;
                let asset_id_key = params.a.to_string();
                match state.pool.inspect(&params).await {
                    Ok(data) => {
                        let (item_detail, oracle_signature) =
                            sign_inspect_data(&state.signer, asset_id_num, &data).await;
                        (asset_id_key, Some(link), Ok((data, item_detail, oracle_signature)))
                    }
                    Err(e) => {
                        error!(a = asset_id_num, error = %e, "Bulk inspect item failed");
                        let msg = match &e {
                            gc_client::InspectError::Timeout => "Inspection timed out",
                            gc_client::InspectError::NoBots => "Service temporarily unavailable",
                            _ => "Inspection failed",
                        };
                        (asset_id_key, Some(link), Err(msg.to_string()))
                    }
                }
            }
        }))
        .buffer_unordered(BULK_CONCURRENCY)
        .collect()
        .await;

        for (key, link, result) in results {
            match result {
                Ok((data, item_detail, oracle_signature)) => {
                    // Populate cache for this miss.
                    if let Some(link) = link {
                        state.cache.insert(
                            link,
                            data.clone(),
                            item_detail.clone(),
                            oracle_signature.clone(),
                        );
                    }
                    response.insert(
                        key,
                        BulkItemResponse::Success {
                            iteminfo: data,
                            item_detail,
                            oracle_signature,
                        },
                    );
                }
                Err(e) => {
                    response.insert(key, BulkItemResponse::Error { error: e });
                }
            }
        }
    }

    let success_count = response.values().filter(|v| matches!(v, BulkItemResponse::Success { .. })).count();
    let error_count = response.len() - success_count;

    info!(
        total,
        success = success_count,
        errors = error_count,
        cache_hits,
        "Bulk inspect complete"
    );

    Ok(Json(response))
}
