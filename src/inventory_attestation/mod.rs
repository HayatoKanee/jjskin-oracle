pub mod cache;
pub mod catalog;

use std::sync::Arc;
use std::time::Instant;

use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::item_detail::encode_item_detail_with_flags;
use crate::observability::{OracleRuntimeMetrics, current_rss_bytes};
use crate::settlement::OracleSigner;
use crate::steam_inventory::{InventoryClient, InventoryError};

use self::catalog::{CatalogResolveError, CatalogResolver, ResolvedCatalogIdentity};

pub const DEFAULT_CACHE_CAPACITY: usize = 10_000;
pub const DEFAULT_CACHE_TTL_SECONDS: u64 = 120;

pub struct InventoryAttestationState {
    pub inventory: InventoryClient,
    pub resolver: CatalogResolver,
    pub signer: Arc<OracleSigner>,
    pub cache: cache::InventoryAttestationCache,
    pub metrics: Arc<OracleRuntimeMetrics>,
}

#[derive(Debug, Deserialize)]
pub struct InventoryAttestationRequest {
    #[serde(rename = "assetId", deserialize_with = "deserialize_string_or_number")]
    asset_id: u64,
    #[serde(rename = "steamId", deserialize_with = "deserialize_string_or_number")]
    steam_id: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryAttestationSuccess {
    pub asset_id: String,
    pub item_detail: String,
    pub oracle_attestation: String,
    pub evidence_summary: EvidenceSummary,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceSummary {
    pub market_hash_name: String,
    pub defindex: u32,
    pub paintindex: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tint_id: Option<u32>,
    pub item_type: String,
    pub quality: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub floatvalue: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paintseed: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_catalog: Option<u32>,
    pub pattern_tier: u32,
    pub is_slab: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryAttestationErrorResponse {
    pub error_code: String,
    pub message: String,
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

pub async fn attest_handler(
    State(state): State<Arc<InventoryAttestationState>>,
    Json(body): Json<InventoryAttestationRequest>,
) -> Result<Json<InventoryAttestationSuccess>, (StatusCode, Json<InventoryAttestationErrorResponse>)>
{
    let request_id = Uuid::new_v4().to_string();
    let request_started_at = Instant::now();
    let cache_key = format!("{}:{}", body.steam_id, body.asset_id);

    if let Some(cached) = state.cache.get(&cache_key) {
        let cache_hits = state.metrics.record_inventory_attestation_cache_hit();
        let rss_bytes = current_rss_bytes();
        info!(
            request_id,
            steam_id = body.steam_id,
            asset_id = body.asset_id,
            stage = "cache_hit",
            cache_hits,
            cache_misses = state.metrics.inventory_attestation_cache_misses(),
            rss_bytes = rss_bytes.unwrap_or_default(),
            rss_available = rss_bytes.is_some(),
            "Inventory attestation cache hit"
        );
        return Ok(Json(cached));
    }

    let cache_misses = state.metrics.record_inventory_attestation_cache_miss();
    let rss_bytes = current_rss_bytes();
    info!(
        request_id,
        steam_id = body.steam_id,
        asset_id = body.asset_id,
        stage = "inventory_fetch_start",
        cache_hits = state.metrics.inventory_attestation_cache_hits(),
        cache_misses,
        rss_bytes = rss_bytes.unwrap_or_default(),
        rss_available = rss_bytes.is_some(),
        "Inventory attestation started"
    );

    let fetch_started_at = Instant::now();
    let inventory_item = match state
        .inventory
        .find_asset(body.steam_id, body.asset_id)
        .await
    {
        Ok(item) => item,
        Err(error) => {
            let (error_code, status, message) = describe_inventory_error(&error);
            warn!(
                request_id,
                steam_id = body.steam_id,
                asset_id = body.asset_id,
                stage = "attestation_failed",
                total_duration_ms = request_started_at.elapsed().as_millis() as u64,
                duration_ms = fetch_started_at.elapsed().as_millis() as u64,
                cache_hits = state.metrics.inventory_attestation_cache_hits(),
                cache_misses = state.metrics.inventory_attestation_cache_misses(),
                error_code,
                error = %error,
                "Inventory attestation failed during inventory fetch"
            );
            return Err((
                status,
                Json(InventoryAttestationErrorResponse {
                    error_code: error_code.to_string(),
                    message,
                }),
            ));
        }
    };

    info!(
        request_id,
        steam_id = body.steam_id,
        asset_id = body.asset_id,
        stage = "inventory_fetch_ok",
        duration_ms = fetch_started_at.elapsed().as_millis() as u64,
        cache_hits = state.metrics.inventory_attestation_cache_hits(),
        cache_misses = state.metrics.inventory_attestation_cache_misses(),
        market_hash_name = inventory_item.market_hash_name.as_str(),
        "Inventory item fetched"
    );

    let resolve_started_at = Instant::now();
    let resolved = match state.resolver.resolve(&inventory_item) {
        Ok(resolved) => resolved,
        Err(error) => {
            let (error_code, status, message) = describe_catalog_error(&error);
            warn!(
                request_id,
                steam_id = body.steam_id,
                asset_id = body.asset_id,
                stage = "attestation_failed",
                total_duration_ms = request_started_at.elapsed().as_millis() as u64,
                duration_ms = resolve_started_at.elapsed().as_millis() as u64,
                cache_hits = state.metrics.inventory_attestation_cache_hits(),
                cache_misses = state.metrics.inventory_attestation_cache_misses(),
                error_code,
                error = %error,
                "Inventory attestation failed during catalog resolution"
            );
            return Err((
                status,
                Json(InventoryAttestationErrorResponse {
                    error_code: error_code.to_string(),
                    message,
                }),
            ));
        }
    };

    info!(
        request_id,
        steam_id = body.steam_id,
        asset_id = body.asset_id,
        stage = "catalog_resolve_ok",
        duration_ms = resolve_started_at.elapsed().as_millis() as u64,
        cache_hits = state.metrics.inventory_attestation_cache_hits(),
        cache_misses = state.metrics.inventory_attestation_cache_misses(),
        item_type = resolved.item_type.as_str(),
        defindex = resolved.defindex,
        paintindex = resolved.paintindex,
        pattern_tier = resolved.pattern_tier,
        "Catalog identity resolved"
    );

    let sign_started_at = Instant::now();
    let response = match build_attestation_response(&state.signer, body.asset_id, &resolved).await {
        Ok(response) => response,
        Err(error) => {
            error!(
                request_id,
                steam_id = body.steam_id,
                asset_id = body.asset_id,
                stage = "attestation_failed",
                total_duration_ms = request_started_at.elapsed().as_millis() as u64,
                duration_ms = sign_started_at.elapsed().as_millis() as u64,
                cache_hits = state.metrics.inventory_attestation_cache_hits(),
                cache_misses = state.metrics.inventory_attestation_cache_misses(),
                error_code = "SIGNING_FAILED",
                error = %error,
                "Failed to sign inventory attestation"
            );
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(InventoryAttestationErrorResponse {
                    error_code: "SIGNING_FAILED".to_string(),
                    message: "Failed to sign item attestation".to_string(),
                }),
            ));
        }
    };

    info!(
        request_id,
        steam_id = body.steam_id,
        asset_id = body.asset_id,
        stage = "attestation_signed",
        total_duration_ms = request_started_at.elapsed().as_millis() as u64,
        duration_ms = sign_started_at.elapsed().as_millis() as u64,
        cache_hits = state.metrics.inventory_attestation_cache_hits(),
        cache_misses = state.metrics.inventory_attestation_cache_misses(),
        item_detail = response.item_detail.as_str(),
        "Inventory attestation signed"
    );

    state.cache.insert(cache_key, response.clone());

    Ok(Json(response))
}

async fn build_attestation_response(
    signer: &OracleSigner,
    asset_id: u64,
    resolved: &ResolvedCatalogIdentity,
) -> eyre::Result<InventoryAttestationSuccess> {
    let item_detail = encode_resolved_item_detail(resolved);
    let oracle_attestation = signer.sign_item_attestation(asset_id, item_detail).await?;

    Ok(InventoryAttestationSuccess {
        asset_id: asset_id.to_string(),
        item_detail: item_detail.to_string(),
        oracle_attestation: format!("0x{}", hex::encode(oracle_attestation)),
        evidence_summary: EvidenceSummary {
            market_hash_name: resolved.market_hash_name.clone(),
            defindex: resolved.defindex,
            paintindex: resolved.paintindex,
            tint_id: (resolved.tint_id > 0).then_some(resolved.tint_id),
            item_type: resolved.item_type.clone(),
            quality: resolved.quality,
            floatvalue: (resolved.paintindex > 0).then_some(resolved.floatvalue),
            paintseed: (resolved.paintindex > 0).then_some(resolved.paintseed),
            finish_catalog: resolved.finish_catalog,
            pattern_tier: resolved.pattern_tier,
            is_slab: resolved.is_slab,
        },
    })
}

pub(crate) fn encode_resolved_item_detail(resolved: &ResolvedCatalogIdentity) -> u64 {
    encode_item_detail_with_flags(
        resolved.paintindex,
        resolved.floatvalue,
        resolved.defindex,
        resolved.paintseed,
        resolved.quality,
        resolved.tint_id,
        resolved.pattern_tier,
        resolved.is_slab,
    )
}

fn describe_inventory_error(error: &InventoryError) -> (&'static str, StatusCode, String) {
    match error {
        InventoryError::PrivateInventory => (
            "PRIVATE_INVENTORY",
            StatusCode::BAD_REQUEST,
            "Steam inventory is private".to_string(),
        ),
        InventoryError::AssetNotFound(asset_id) => (
            "ASSET_NOT_FOUND",
            StatusCode::NOT_FOUND,
            format!("Asset {asset_id} not found in inventory"),
        ),
        InventoryError::SteamApiError(message) => (
            "INVENTORY_FETCH_FAILED",
            StatusCode::BAD_GATEWAY,
            format!("Steam inventory API error: {message}"),
        ),
        InventoryError::RequestFailed(message) => (
            "INVENTORY_FETCH_FAILED",
            StatusCode::BAD_GATEWAY,
            format!("Failed to fetch Steam inventory: {message}"),
        ),
    }
}

fn describe_catalog_error(error: &CatalogResolveError) -> (&'static str, StatusCode, String) {
    match error {
        CatalogResolveError::CatalogMiss { .. } => {
            ("CATALOG_MISS", StatusCode::BAD_REQUEST, error.to_string())
        }
        CatalogResolveError::UnsupportedFinishCatalog { .. } => (
            "UNSUPPORTED_FINISH_CATALOG",
            StatusCode::BAD_REQUEST,
            error.to_string(),
        ),
        CatalogResolveError::AmbiguousCatalogIdentity { .. } => (
            "AMBIGUOUS_IDENTITY",
            StatusCode::BAD_REQUEST,
            error.to_string(),
        ),
        CatalogResolveError::MissingDefindex { .. }
        | CatalogResolveError::MissingTintId { .. }
        | CatalogResolveError::MissingFloatvalue { .. }
        | CatalogResolveError::MissingPaintseed { .. } => (
            "EVIDENCE_INCOMPLETE",
            StatusCode::UNPROCESSABLE_ENTITY,
            error.to_string(),
        ),
        CatalogResolveError::UnrepresentableItemDetail { .. } => (
            "UNSUPPORTED_ITEM_DETAIL",
            StatusCode::UNPROCESSABLE_ENTITY,
            error.to_string(),
        ),
    }
}
