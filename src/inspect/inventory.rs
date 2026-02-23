use std::collections::HashMap;
use std::fmt;

use serde::Deserialize;
use tracing::debug;

/// Steam inventory API client for querying public CS2 inventories.
pub struct InventoryClient {
    http: reqwest::Client,
}

/// A single item found in a Steam inventory.
pub struct InventoryItem {
    pub asset_id: u64,
    pub classid: String,
    pub market_hash_name: String,
    pub tradable: bool,
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
    tradable: u8,
}

impl InventoryClient {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to build reqwest client");
        Self { http }
    }

    /// Find a specific asset in a Steam user's CS2 inventory.
    ///
    /// Queries the public inventory API, paginates if needed, and joins
    /// assets with descriptions to get the market_hash_name.
    pub async fn find_asset(
        &self,
        steam_id: u64,
        asset_id: u64,
    ) -> Result<InventoryItem, InventoryError> {
        let asset_id_str = asset_id.to_string();
        let mut start_assetid: Option<String> = None;

        loop {
            let mut url = format!(
                "https://steamcommunity.com/inventory/{steam_id}/730/2?l=english&count=5000"
            );
            if let Some(ref cursor) = start_assetid {
                url.push_str(&format!("&start_assetid={cursor}"));
            }

            debug!(steam_id, asset_id, page = ?start_assetid, "Fetching inventory page");

            let resp = self
                .http
                .get(&url)
                .send()
                .await
                .map_err(|e| InventoryError::RequestFailed(e.to_string()))?;

            let status = resp.status();

            if status == reqwest::StatusCode::FORBIDDEN
                || status == reqwest::StatusCode::UNAUTHORIZED
            {
                return Err(InventoryError::PrivateInventory);
            }

            if !status.is_success() {
                // Steam returns null/empty JSON body for private inventories sometimes
                return Err(InventoryError::SteamApiError(format!(
                    "HTTP {status}"
                )));
            }

            let body = resp
                .text()
                .await
                .map_err(|e| InventoryError::RequestFailed(e.to_string()))?;

            // Steam returns `null` for private inventories
            if body.trim() == "null" || body.is_empty() {
                return Err(InventoryError::PrivateInventory);
            }

            let inv: InventoryResponse = serde_json::from_str(&body).map_err(|e| {
                InventoryError::SteamApiError(format!("Failed to parse response: {e}"))
            })?;

            // Build classid+instanceid -> description lookup
            let desc_map: HashMap<(&str, &str), &DescriptionEntry> = inv
                .descriptions
                .iter()
                .map(|d| ((d.classid.as_str(), d.instanceid.as_str()), d))
                .collect();

            // Search for our asset
            for asset in &inv.assets {
                if asset.assetid == asset_id_str {
                    let desc = desc_map
                        .get(&(asset.classid.as_str(), asset.instanceid.as_str()))
                        .ok_or_else(|| {
                            InventoryError::SteamApiError(
                                "Asset found but no matching description".to_string(),
                            )
                        })?;

                    let market_hash_name = desc
                        .market_hash_name
                        .clone()
                        .unwrap_or_default();

                    return Ok(InventoryItem {
                        asset_id,
                        classid: asset.classid.clone(),
                        market_hash_name,
                        tradable: desc.tradable == 1,
                    });
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

    /// Fetch the full inventory for a Steam user (for bulk operations).
    /// Returns all items in the inventory.
    pub async fn fetch_inventory(
        &self,
        steam_id: u64,
    ) -> Result<Vec<InventoryItem>, InventoryError> {
        let mut all_items = Vec::new();
        let mut start_assetid: Option<String> = None;

        loop {
            let mut url = format!(
                "https://steamcommunity.com/inventory/{steam_id}/730/2?l=english&count=5000"
            );
            if let Some(ref cursor) = start_assetid {
                url.push_str(&format!("&start_assetid={cursor}"));
            }

            let resp = self
                .http
                .get(&url)
                .send()
                .await
                .map_err(|e| InventoryError::RequestFailed(e.to_string()))?;

            let status = resp.status();
            if status == reqwest::StatusCode::FORBIDDEN
                || status == reqwest::StatusCode::UNAUTHORIZED
            {
                return Err(InventoryError::PrivateInventory);
            }
            if !status.is_success() {
                return Err(InventoryError::SteamApiError(format!("HTTP {status}")));
            }

            let body = resp
                .text()
                .await
                .map_err(|e| InventoryError::RequestFailed(e.to_string()))?;

            if body.trim() == "null" || body.is_empty() {
                return Err(InventoryError::PrivateInventory);
            }

            let inv: InventoryResponse = serde_json::from_str(&body).map_err(|e| {
                InventoryError::SteamApiError(format!("Failed to parse response: {e}"))
            })?;

            let desc_map: HashMap<(&str, &str), &DescriptionEntry> = inv
                .descriptions
                .iter()
                .map(|d| ((d.classid.as_str(), d.instanceid.as_str()), d))
                .collect();

            for asset in &inv.assets {
                if let Some(desc) = desc_map.get(&(asset.classid.as_str(), asset.instanceid.as_str())) {
                    let asset_id = asset.assetid.parse::<u64>().unwrap_or(0);
                    all_items.push(InventoryItem {
                        asset_id,
                        classid: asset.classid.clone(),
                        market_hash_name: desc.market_hash_name.clone().unwrap_or_default(),
                        tradable: desc.tradable == 1,
                    });
                }
            }

            if inv.more_items == Some(1) {
                if let Some(last) = inv.last_assetid {
                    start_assetid = Some(last);
                    continue;
                }
            }

            break;
        }

        debug!(count = all_items.len(), "Fetched full inventory");
        Ok(all_items)
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
                "market_hash_name": "CS:GO Weapon Case",
                "tradable": 1,
                "marketable": 1
            },
            {
                "appid": 730,
                "classid": "4849782580",
                "instanceid": "302028390",
                "market_hash_name": "Operation Bravo Case",
                "tradable": 1,
                "marketable": 1
            },
            {
                "appid": 730,
                "classid": "310776561",
                "instanceid": "0",
                "market_hash_name": "CS:GO Case Key",
                "tradable": 0,
                "marketable": 0
            }
        ],
        "total_inventory_count": 3
    }"#;

    #[test]
    fn test_parse_inventory_response() {
        let inv: InventoryResponse = serde_json::from_str(SAMPLE_INVENTORY).unwrap();
        assert_eq!(inv.assets.len(), 3);
        assert_eq!(inv.descriptions.len(), 3);
        assert_eq!(inv.total_inventory_count, 3);
    }

    #[test]
    fn test_join_assets_descriptions() {
        let inv: InventoryResponse = serde_json::from_str(SAMPLE_INVENTORY).unwrap();

        let desc_map: HashMap<(&str, &str), &DescriptionEntry> = inv
            .descriptions
            .iter()
            .map(|d| ((d.classid.as_str(), d.instanceid.as_str()), d))
            .collect();

        // First asset should match "CS:GO Weapon Case"
        let asset = &inv.assets[0];
        let desc = desc_map
            .get(&(asset.classid.as_str(), asset.instanceid.as_str()))
            .unwrap();
        assert_eq!(
            desc.market_hash_name.as_deref(),
            Some("CS:GO Weapon Case")
        );
        assert_eq!(desc.tradable, 1);

        // Third asset (key, instanceid "0") should match
        let asset = &inv.assets[2];
        let desc = desc_map
            .get(&(asset.classid.as_str(), asset.instanceid.as_str()))
            .unwrap();
        assert_eq!(
            desc.market_hash_name.as_deref(),
            Some("CS:GO Case Key")
        );
        assert_eq!(desc.tradable, 0);
    }

    #[test]
    fn test_find_asset_in_parsed_response() {
        let inv: InventoryResponse = serde_json::from_str(SAMPLE_INVENTORY).unwrap();
        let target_asset_id = "38988024804";

        let desc_map: HashMap<(&str, &str), &DescriptionEntry> = inv
            .descriptions
            .iter()
            .map(|d| ((d.classid.as_str(), d.instanceid.as_str()), d))
            .collect();

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
}
