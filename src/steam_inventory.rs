use std::collections::HashMap;
use std::fmt;
use std::fs::read_to_string;
use std::sync::Mutex;
use std::time::Duration;

use reqwest::header::{ACCEPT, HeaderMap, HeaderValue, USER_AGENT};
use serde::Deserialize;
use tracing::{debug, info, warn};

const CS2_APP_ID: u32 = 730;
const CS2_CONTEXT_ID: u32 = 2;
const ITEMS_PER_PAGE: usize = 2_000;
const REQUEST_TIMEOUT_SECONDS: u64 = 30;
const MAX_ITEMS_SCANNED: usize = 100_000;
const MAX_PAGES: usize = (MAX_ITEMS_SCANNED + ITEMS_PER_PAGE - 1) / ITEMS_PER_PAGE;

/// Steam inventory API client for querying public CS2 inventories.
pub struct InventoryClient {
    direct_http: reqwest::Client,
    proxy_pool: Option<InventoryProxyPool>,
}

struct InventoryProxyPool {
    clients: Vec<reqwest::Client>,
    current_index: Mutex<usize>,
}

/// Mutable per-asset Steam evidence extracted from inventory payload.
#[derive(Debug, Clone, Default)]
pub struct SteamAssetEvidence {
    pub floatvalue: Option<f32>,
    pub paintseed: Option<u32>,
    pub finish_catalog: Option<u32>,
    pub item_certificate: Option<String>,
}

/// A single item found in a Steam inventory.
#[derive(Debug, Clone)]
pub struct InventoryItem {
    pub market_hash_name: String,
    pub exterior: Option<String>,
    pub is_stattrak: bool,
    pub is_souvenir: bool,
    pub steam_evidence: Option<SteamAssetEvidence>,
}

/// Errors from inventory lookups.
#[derive(Debug)]
pub enum InventoryError {
    /// Inventory is private or friends-only.
    PrivateInventory,
    /// The asset ID was not found in the inventory.
    AssetNotFound(u64),
    /// Steam API returned an error or unexpected response.
    SteamApiError(String),
    /// HTTP request failed.
    RequestFailed(String),
}

impl fmt::Display for InventoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrivateInventory => write!(f, "Inventory is private"),
            Self::AssetNotFound(id) => write!(f, "Asset {id} not found in inventory"),
            Self::SteamApiError(msg) => write!(f, "Steam API error: {msg}"),
            Self::RequestFailed(msg) => write!(f, "Request failed: {msg}"),
        }
    }
}

impl std::error::Error for InventoryError {}

// ============================================================================
// Steam inventory API response types
// ============================================================================

#[derive(Deserialize)]
struct InventoryResponse {
    #[serde(default)]
    assets: Vec<AssetEntry>,
    #[serde(default)]
    descriptions: Vec<DescriptionEntry>,
    #[serde(default)]
    asset_properties: Vec<AssetPropertiesEntry>,
    #[serde(default)]
    #[allow(dead_code)]
    total_inventory_count: u32,
    /// If true, more items are available (paginate with last_assetid).
    #[serde(default)]
    more_items: Option<u32>,
    /// Last asset ID for pagination cursor.
    #[serde(default)]
    last_assetid: Option<String>,
}

#[derive(Deserialize)]
struct AssetEntry {
    assetid: String,
    classid: String,
    #[serde(default)]
    instanceid: String,
}

#[derive(Deserialize)]
struct DescriptionEntry {
    classid: String,
    #[serde(default)]
    instanceid: String,
    #[serde(default)]
    market_hash_name: Option<String>,
    #[serde(default)]
    tags: Vec<TagEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct TagEntry {
    category: String,
    localized_tag_name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct AssetPropertiesEntry {
    assetid: String,
    #[serde(default)]
    asset_properties: Vec<AssetPropertyValue>,
}

#[derive(Debug, Clone, Deserialize)]
struct AssetPropertyValue {
    propertyid: u32,
    #[serde(default)]
    int_value: Option<String>,
    #[serde(default)]
    float_value: Option<String>,
    #[serde(default)]
    string_value: Option<String>,
}

impl InventoryClient {
    pub fn new() -> Self {
        let direct_http =
            build_http_client(None).expect("Failed to build direct Steam inventory client");
        let proxy_pool = InventoryProxyPool::from_env();

        Self {
            direct_http,
            proxy_pool,
        }
    }

    /// Find a specific asset in a Steam user's CS2 inventory.
    ///
    /// Queries the public inventory API, paginates if needed, and joins
    /// assets with descriptions to get the market_hash_name and per-asset evidence.
    pub async fn find_asset(
        &self,
        steam_id: u64,
        asset_id: u64,
    ) -> Result<InventoryItem, InventoryError> {
        let asset_id_str = asset_id.to_string();
        let mut start_assetid: Option<String> = None;
        let mut page = 0;

        loop {
            page += 1;
            if page > MAX_PAGES {
                return Err(InventoryError::SteamApiError(
                    "Inventory pagination exceeded limit".into(),
                ));
            }
            let mut url = format!(
                "https://steamcommunity.com/inventory/{steam_id}/{CS2_APP_ID}/{CS2_CONTEXT_ID}?l=english&count={ITEMS_PER_PAGE}"
            );
            if let Some(ref cursor) = start_assetid {
                url.push_str(&format!("&start_assetid={cursor}"));
            }

            debug!(steam_id, asset_id, page = ?start_assetid, "Fetching inventory page");

            let inv = self.fetch_inventory_response(&url).await?;
            let desc_map = build_description_map(&inv.descriptions);
            let property_map = build_asset_property_map(&inv.asset_properties);

            for asset in &inv.assets {
                if asset.assetid == asset_id_str {
                    let desc = desc_map
                        .get(&(asset.classid.as_str(), asset.instanceid.as_str()))
                        .ok_or_else(|| {
                            InventoryError::SteamApiError(
                                "Asset found but no matching description".to_string(),
                            )
                        })?;

                    return Ok(build_inventory_item(desc, property_map.get(&asset.assetid)));
                }
            }

            // Paginate if more items available
            if inv.more_items == Some(1) {
                if let Some(last) = inv.last_assetid {
                    start_assetid = Some(last);
                    continue;
                }
            }

            // Not found after exhausting all pages
            return Err(InventoryError::AssetNotFound(asset_id));
        }
    }

    async fn fetch_inventory_response(
        &self,
        url: &str,
    ) -> Result<InventoryResponse, InventoryError> {
        const MAX_RETRIES_WITHOUT_PROXY: usize = 3;
        const MAX_PROXY_ATTEMPTS: usize = 10;

        let max_attempts = self
            .proxy_pool
            .as_ref()
            .map(|proxy_pool| 1 + proxy_pool.len().min(MAX_PROXY_ATTEMPTS))
            .unwrap_or(MAX_RETRIES_WITHOUT_PROXY);
        let mut last_error: Option<InventoryError> = None;

        for attempt in 0..max_attempts {
            let use_proxy = self.proxy_pool.is_some() && attempt > 0;
            let via = if use_proxy { "proxy" } else { "direct" };
            let client = if use_proxy {
                self.proxy_pool
                    .as_ref()
                    .expect("proxy pool must exist when use_proxy is true")
                    .next()
            } else {
                self.direct_http.clone()
            };

            let response = client.get(url).send().await;
            let response = match response {
                Ok(response) => response,
                Err(error) => {
                    last_error = Some(InventoryError::RequestFailed(error.to_string()));

                    warn!(
                        attempt = attempt + 1,
                        max_attempts,
                        via,
                        error = %error,
                        "Steam inventory request attempt failed"
                    );

                    if attempt < max_attempts - 1 {
                        let wait_ms = if self.proxy_pool.is_some() {
                            1_000
                        } else {
                            (1_000usize * 2usize.saturating_pow(attempt as u32)).min(5_000)
                        };
                        tokio::time::sleep(Duration::from_millis(wait_ms as u64)).await;
                    }
                    continue;
                }
            };

            if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
                && attempt < max_attempts - 1
            {
                let wait_ms = if self.proxy_pool.is_some() {
                    500
                } else {
                    (1_000usize * 2usize.saturating_pow(attempt as u32)).min(5_000)
                };
                warn!(
                    attempt = attempt + 1,
                    max_attempts,
                    via,
                    wait_ms,
                    "Steam inventory request rate limited (429), retrying"
                );
                tokio::time::sleep(Duration::from_millis(wait_ms as u64)).await;
                continue;
            }

            return parse_inventory_response(response).await;
        }

        Err(last_error.unwrap_or_else(|| {
            InventoryError::RequestFailed("All Steam inventory attempts failed".to_string())
        }))
    }
}

impl InventoryProxyPool {
    fn from_env() -> Option<Self> {
        let proxy_urls = load_proxy_urls();
        if proxy_urls.is_empty() {
            return None;
        }

        let clients: Vec<reqwest::Client> = proxy_urls
            .into_iter()
            .filter_map(|proxy_url| match build_http_client(Some(&proxy_url)) {
                Ok(client) => Some(client),
                Err(error) => {
                    warn!(
                        proxy_url,
                        error = %error,
                        "Skipping invalid Steam inventory proxy"
                    );
                    None
                }
            })
            .collect();

        if clients.is_empty() {
            return None;
        }

        info!(
            count = clients.len(),
            "Steam inventory proxy pool initialized"
        );

        Some(Self {
            clients,
            current_index: Mutex::new(0),
        })
    }

    fn len(&self) -> usize {
        self.clients.len()
    }

    fn next(&self) -> reqwest::Client {
        let mut current_index = self
            .current_index
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let client = self.clients[*current_index].clone();
        *current_index = (*current_index + 1) % self.clients.len();
        client
    }
}

fn load_proxy_urls() -> Vec<String> {
    if let Ok(file_path) = std::env::var("STEAM_SOCKS_PROXIES_FILE") {
        let file_path = file_path.trim();
        if !file_path.is_empty() {
            match read_to_string(file_path) {
                Ok(contents) => {
                    let proxy_urls: Vec<String> = contents
                        .lines()
                        .map(str::trim)
                        .filter(|line| !line.is_empty() && !line.starts_with('#'))
                        .map(str::to_string)
                        .collect();

                    if !proxy_urls.is_empty() {
                        info!(
                            file_path,
                            count = proxy_urls.len(),
                            "Loaded Steam inventory proxies from file"
                        );
                        return proxy_urls;
                    }
                }
                Err(error) => {
                    warn!(
                        file_path,
                        error = %error,
                        "Failed to read STEAM_SOCKS_PROXIES_FILE"
                    );
                }
            }
        }
    }

    if let Ok(proxy_csv) = std::env::var("STEAM_SOCKS_PROXIES") {
        let proxy_urls: Vec<String> = proxy_csv
            .split(',')
            .map(str::trim)
            .filter(|proxy| !proxy.is_empty())
            .map(str::to_string)
            .collect();

        if !proxy_urls.is_empty() {
            info!(
                count = proxy_urls.len(),
                "Loaded Steam inventory proxies from STEAM_SOCKS_PROXIES"
            );
            return proxy_urls;
        }
    }

    if let Ok(proxy_url) = std::env::var("STEAM_INVENTORY_PROXY_URL") {
        let proxy_url = proxy_url.trim();
        if !proxy_url.is_empty() {
            return vec![proxy_url.to_string()];
        }
    }

    Vec::new()
}

fn build_http_client(proxy_url: Option<&str>) -> Result<reqwest::Client, reqwest::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        ),
    );

    let mut builder = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECONDS));

    if let Some(proxy_url) = proxy_url {
        builder = builder.proxy(reqwest::Proxy::all(proxy_url)?);
    }

    builder.build()
}

async fn parse_inventory_response(
    resp: reqwest::Response,
) -> Result<InventoryResponse, InventoryError> {
    let status = resp.status();

    if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(InventoryError::PrivateInventory);
    }

    if !status.is_success() {
        // Steam returns null/empty JSON body for private inventories sometimes
        return Err(InventoryError::SteamApiError(format!("HTTP {status}")));
    }

    let body = resp
        .text()
        .await
        .map_err(|e| InventoryError::RequestFailed(e.to_string()))?;

    // Steam returns `null` for private inventories
    if body.trim() == "null" || body.is_empty() {
        return Err(InventoryError::PrivateInventory);
    }

    serde_json::from_str(&body)
        .map_err(|e| InventoryError::SteamApiError(format!("Failed to parse response: {e}")))
}

fn build_description_map<'a>(
    descriptions: &'a [DescriptionEntry],
) -> HashMap<(&'a str, &'a str), &'a DescriptionEntry> {
    descriptions
        .iter()
        .map(|description| {
            (
                (
                    description.classid.as_str(),
                    description.instanceid.as_str(),
                ),
                description,
            )
        })
        .collect()
}

fn build_asset_property_map(
    assets: &[AssetPropertiesEntry],
) -> HashMap<String, HashMap<u32, AssetPropertyValue>> {
    let mut asset_property_map = HashMap::new();

    for asset in assets {
        if asset.asset_properties.is_empty() {
            continue;
        }

        asset_property_map.insert(
            asset.assetid.clone(),
            asset
                .asset_properties
                .iter()
                .cloned()
                .map(|property| (property.propertyid, property))
                .collect(),
        );
    }

    asset_property_map
}

fn build_inventory_item(
    desc: &DescriptionEntry,
    properties: Option<&HashMap<u32, AssetPropertyValue>>,
) -> InventoryItem {
    let market_hash_name = desc.market_hash_name.clone().unwrap_or_default();

    InventoryItem {
        market_hash_name: market_hash_name.clone(),
        exterior: extract_exterior(&desc.tags),
        is_stattrak: market_hash_name.starts_with("StatTrak™ ")
            || has_quality_tag(&desc.tags, "StatTrak™"),
        is_souvenir: market_hash_name.starts_with("Souvenir ")
            || has_quality_tag(&desc.tags, "Souvenir"),
        steam_evidence: extract_steam_evidence(properties),
    }
}

fn extract_exterior(tags: &[TagEntry]) -> Option<String> {
    tags.iter()
        .find(|tag| tag.category == "Exterior")
        .map(|tag| tag.localized_tag_name.clone())
}

fn has_quality_tag(tags: &[TagEntry], localized_tag_name: &str) -> bool {
    tags.iter()
        .any(|tag| tag.localized_tag_name == localized_tag_name)
}

fn parse_optional_u32(value: Option<&String>) -> Option<u32> {
    value.and_then(|raw| raw.parse::<u32>().ok())
}

fn parse_optional_f32(value: Option<&String>) -> Option<f32> {
    value.and_then(|raw| raw.parse::<f32>().ok())
}

fn extract_steam_evidence(
    properties: Option<&HashMap<u32, AssetPropertyValue>>,
) -> Option<SteamAssetEvidence> {
    let properties = properties?;

    let float_property = properties.get(&2);
    let paint_seed_property = properties.get(&1);
    let finish_catalog_property = properties.get(&7);
    let certificate_property = properties.get(&6);

    let evidence = SteamAssetEvidence {
        floatvalue: parse_optional_f32(float_property.and_then(|value| value.float_value.as_ref())),
        paintseed: parse_optional_u32(
            paint_seed_property.and_then(|value| value.int_value.as_ref()),
        ),
        finish_catalog: parse_optional_u32(
            finish_catalog_property.and_then(|value| value.int_value.as_ref()),
        ),
        item_certificate: certificate_property.and_then(|value| value.string_value.clone()),
    };

    if evidence.floatvalue.is_some()
        || evidence.paintseed.is_some()
        || evidence.finish_catalog.is_some()
        || evidence.item_certificate.is_some()
    {
        Some(evidence)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_INVENTORY: &str = r#"{
        "assets": [
            {"appid": 730, "contextid": "2", "assetid": "38988024803", "classid": "310776560", "instanceid": "302028390", "amount": "1"},
            {"appid": 730, "contextid": "2", "assetid": "38988024804", "classid": "4849782580", "instanceid": "302028390", "amount": "1"},
            {"appid": 730, "contextid": "2", "assetid": "38988024805", "classid": "310776561", "instanceid": "0", "amount": "1"}
        ],
        "descriptions": [
            {
                "appid": 730,
                "classid": "310776560",
                "instanceid": "302028390",
                "market_hash_name": "StatTrak™ MP9 | Nexus (Field-Tested)",
                "tradable": 1,
                "tags": [
                    {"category": "Quality", "localized_tag_name": "StatTrak™"},
                    {"category": "Exterior", "localized_tag_name": "Field-Tested"}
                ]
            },
            {
                "appid": 730,
                "classid": "4849782580",
                "instanceid": "302028390",
                "market_hash_name": "Operation Bravo Case",
                "tradable": 1,
                "tags": []
            },
            {
                "appid": 730,
                "classid": "310776561",
                "instanceid": "0",
                "market_hash_name": "Souvenir CS:GO Case Key",
                "tradable": 0,
                "tags": [
                    {"category": "Quality", "localized_tag_name": "Souvenir"}
                ]
            }
        ],
        "asset_properties": [
            {
                "appid": 730,
                "contextid": "2",
                "assetid": "38988024803",
                "asset_properties": [
                    {"propertyid": 1, "int_value": "766"},
                    {"propertyid": 2, "float_value": "0.256801605224609375"},
                    {"propertyid": 6, "string_value": "CERT"}
                ]
            }
        ],
        "total_inventory_count": 3
    }"#;

    #[test]
    fn test_parse_inventory_response() {
        let inv: InventoryResponse = serde_json::from_str(SAMPLE_INVENTORY).unwrap();
        assert_eq!(inv.assets.len(), 3);
        assert_eq!(inv.descriptions.len(), 3);
        assert_eq!(inv.asset_properties.len(), 1);
        assert_eq!(inv.total_inventory_count, 3);
    }

    #[test]
    fn test_join_assets_descriptions() {
        let inv: InventoryResponse = serde_json::from_str(SAMPLE_INVENTORY).unwrap();

        let desc_map = build_description_map(&inv.descriptions);

        // First asset should match the StatTrak item
        let asset = &inv.assets[0];
        let desc = desc_map
            .get(&(asset.classid.as_str(), asset.instanceid.as_str()))
            .unwrap();
        assert_eq!(
            desc.market_hash_name.as_deref(),
            Some("StatTrak™ MP9 | Nexus (Field-Tested)")
        );

        // Third asset (souvenir key, instanceid "0") should match
        let asset = &inv.assets[2];
        let desc = desc_map
            .get(&(asset.classid.as_str(), asset.instanceid.as_str()))
            .unwrap();
        assert_eq!(
            desc.market_hash_name.as_deref(),
            Some("Souvenir CS:GO Case Key")
        );
    }

    #[test]
    fn test_build_inventory_item_extracts_variant_flags_and_evidence() {
        let inv: InventoryResponse = serde_json::from_str(SAMPLE_INVENTORY).unwrap();
        let desc_map = build_description_map(&inv.descriptions);
        let property_map = build_asset_property_map(&inv.asset_properties);

        let asset = &inv.assets[0];
        let desc = desc_map
            .get(&(asset.classid.as_str(), asset.instanceid.as_str()))
            .unwrap();
        let item = build_inventory_item(desc, property_map.get(&asset.assetid));

        assert_eq!(
            item.market_hash_name,
            "StatTrak™ MP9 | Nexus (Field-Tested)"
        );
        assert_eq!(item.exterior.as_deref(), Some("Field-Tested"));
        assert!(item.is_stattrak);
        assert!(!item.is_souvenir);

        let evidence = item.steam_evidence.expect("expected steam evidence");
        assert_eq!(evidence.paintseed, Some(766));
        assert_eq!(evidence.floatvalue, Some(0.2568016));
        assert_eq!(evidence.item_certificate.as_deref(), Some("CERT"));
    }

    #[test]
    fn test_find_asset_in_parsed_response() {
        let inv: InventoryResponse = serde_json::from_str(SAMPLE_INVENTORY).unwrap();
        let target_asset_id = "38988024804";

        let desc_map = build_description_map(&inv.descriptions);

        let found = inv.assets.iter().find(|a| a.assetid == target_asset_id);
        assert!(found.is_some());

        let asset = found.unwrap();
        let desc = desc_map
            .get(&(asset.classid.as_str(), asset.instanceid.as_str()))
            .unwrap();
        assert_eq!(
            desc.market_hash_name.as_deref(),
            Some("Operation Bravo Case")
        );
    }

    #[test]
    fn test_private_inventory_null_body() {
        // Steam returns literal "null" for private inventories
        let result: Result<InventoryResponse, _> = serde_json::from_str("null");
        assert!(result.is_err());
    }

    #[test]
    fn test_paginated_response() {
        let json = r#"{
            "assets": [{"appid": 730, "contextid": "2", "assetid": "100", "classid": "1", "instanceid": "0", "amount": "1"}],
            "descriptions": [{"appid": 730, "classid": "1", "instanceid": "0", "market_hash_name": "Test Item", "tradable": 1}],
            "total_inventory_count": 6000,
            "more_items": 1,
            "last_assetid": "100"
        }"#;

        let inv: InventoryResponse = serde_json::from_str(json).unwrap();
        assert_eq!(inv.more_items, Some(1));
        assert_eq!(inv.last_assetid.as_deref(), Some("100"));
        assert_eq!(inv.total_inventory_count, 6000);
    }

    #[test]
    fn test_pagination_cursor_advances() {
        // Verify pagination response has the cursor for next page
        let page1 = r#"{
            "assets": [{"appid": 730, "contextid": "2", "assetid": "100", "classid": "1", "instanceid": "0"}],
            "descriptions": [{"appid": 730, "classid": "1", "instanceid": "0", "market_hash_name": "Item", "tradable": 1}],
            "total_inventory_count": 10000,
            "more_items": 1,
            "last_assetid": "100"
        }"#;
        let page2 = r#"{
            "assets": [{"appid": 730, "contextid": "2", "assetid": "200", "classid": "1", "instanceid": "0"}],
            "descriptions": [{"appid": 730, "classid": "1", "instanceid": "0", "market_hash_name": "Item", "tradable": 1}],
            "total_inventory_count": 10000
        }"#;

        let inv1: InventoryResponse = serde_json::from_str(page1).unwrap();
        assert_eq!(inv1.more_items, Some(1));
        assert_eq!(inv1.last_assetid.as_deref(), Some("100"));

        let inv2: InventoryResponse = serde_json::from_str(page2).unwrap();
        assert_eq!(inv2.more_items, None);
        assert!(inv2.last_assetid.is_none());
    }
}
