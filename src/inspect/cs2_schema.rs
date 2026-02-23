use std::collections::HashMap;

use eyre::{Result, eyre};
use tracing::{info, warn};

use super::item_detail::encode_item_detail;

/// Pre-loaded CS2 item schema for non-inspectable items (cases, keys).
///
/// Built at startup from CSGO-API GitHub data. Maps `market_hash_name` to
/// defindex and pre-computes the deterministic `ItemDetail` (packed u64)
/// for each item type.
pub struct Cs2Schema {
    /// market_hash_name -> defindex (e.g., "CS:GO Weapon Case" -> 4001)
    name_to_defindex: HashMap<String, u32>,
    /// defindex -> pre-computed ItemDetail (u64, packed)
    item_details: HashMap<u32, u64>,
}

/// Raw JSON entry from CSGO-API crates.json / keys.json.
#[derive(serde::Deserialize)]
struct CsgoApiItem {
    #[serde(default)]
    market_hash_name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_defindex")]
    def_index: Option<u32>,
}

/// Deserialize def_index which comes as a string in CSGO-API JSON.
fn deserialize_defindex<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    let opt: Option<serde_json::Value> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(serde_json::Value::String(s)) => s
            .parse::<u32>()
            .map(Some)
            .map_err(serde::de::Error::custom),
        Some(serde_json::Value::Number(n)) => Ok(n.as_u64().map(|v| v as u32)),
        Some(_) => Ok(None),
    }
}

const CRATES_URL: &str =
    "https://raw.githubusercontent.com/ByMykel/CSGO-API/main/public/api/en/crates.json";
const KEYS_URL: &str =
    "https://raw.githubusercontent.com/ByMykel/CSGO-API/main/public/api/en/keys.json";

impl Cs2Schema {
    /// Download crates.json + keys.json from CSGO-API and build the schema.
    pub async fn load() -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| eyre!("Failed to build HTTP client: {e}"))?;

        let (crates_resp, keys_resp) =
            tokio::try_join!(client.get(CRATES_URL).send(), client.get(KEYS_URL).send(),)
                .map_err(|e| eyre!("Failed to fetch CSGO-API data: {e}"))?;

        let crates_json: Vec<CsgoApiItem> = crates_resp
            .json()
            .await
            .map_err(|e| eyre!("Failed to parse crates.json: {e}"))?;
        let keys_json: Vec<CsgoApiItem> = keys_resp
            .json()
            .await
            .map_err(|e| eyre!("Failed to parse keys.json: {e}"))?;

        Self::from_items(&crates_json, &keys_json)
    }

    /// Build schema from parsed items (used by load() and tests).
    fn from_items(crates: &[CsgoApiItem], keys: &[CsgoApiItem]) -> Result<Self> {
        let mut name_to_defindex = HashMap::new();
        let mut item_details = HashMap::new();

        let mut skipped = 0u32;
        for item in crates.iter().chain(keys.iter()) {
            let (name, defindex) = match (&item.market_hash_name, item.def_index) {
                (Some(name), Some(def)) if !name.is_empty() => (name.clone(), def),
                _ => {
                    skipped += 1;
                    continue;
                }
            };

            // Cases/keys: paintindex=0, floatvalue=0.0, paintseed=0, quality=4 (Normal), tint_id=0
            let detail = encode_item_detail(0, 0.0, defindex, 0, 4, 0);
            name_to_defindex.insert(name, defindex);
            item_details.insert(defindex, detail);
        }

        if skipped > 0 {
            warn!(skipped, "Skipped items with null market_hash_name or def_index");
        }

        info!(
            items = name_to_defindex.len(),
            "CS2 schema loaded (cases + keys)"
        );

        if name_to_defindex.is_empty() {
            return Err(eyre!("CS2 schema is empty — no valid items found"));
        }

        Ok(Self {
            name_to_defindex,
            item_details,
        })
    }

    /// Look up defindex by market_hash_name.
    pub fn defindex(&self, market_hash_name: &str) -> Option<u32> {
        self.name_to_defindex.get(market_hash_name).copied()
    }

    /// Get pre-computed ItemDetail for a defindex.
    pub fn item_detail(&self, defindex: u32) -> Option<u64> {
        self.item_details.get(&defindex).copied()
    }

    /// Look up both defindex and ItemDetail by market_hash_name.
    pub fn lookup(&self, market_hash_name: &str) -> Option<(u32, u64)> {
        let defindex = self.defindex(market_hash_name)?;
        let detail = self.item_detail(defindex)?;
        Some((defindex, detail))
    }

    /// Number of items in the schema.
    pub fn len(&self) -> usize {
        self.name_to_defindex.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_items() -> (Vec<CsgoApiItem>, Vec<CsgoApiItem>) {
        let crates_json = r#"[
            {"id": "crate-4001", "name": "CS:GO Weapon Case", "def_index": "4001", "market_hash_name": "CS:GO Weapon Case"},
            {"id": "crate-4233", "name": "Operation Bravo Case", "def_index": "4233", "market_hash_name": "Operation Bravo Case"},
            {"id": "crate-null", "name": "Some Untraded Crate", "def_index": "9999", "market_hash_name": null}
        ]"#;
        let keys_json = r#"[
            {"id": "key-1203", "name": "CS:GO Case Key", "def_index": "1203", "market_hash_name": "CS:GO Case Key"},
            {"id": "key-7008", "name": "Prisma 2 Case Key", "def_index": "7008", "market_hash_name": "Prisma 2 Case Key"}
        ]"#;

        let crates: Vec<CsgoApiItem> = serde_json::from_str(crates_json).unwrap();
        let keys: Vec<CsgoApiItem> = serde_json::from_str(keys_json).unwrap();
        (crates, keys)
    }

    #[test]
    fn test_schema_from_items() {
        let (crates, keys) = sample_items();
        let schema = Cs2Schema::from_items(&crates, &keys).unwrap();

        // 2 crates + 2 keys = 4 (null market_hash_name skipped)
        assert_eq!(schema.len(), 4);

        assert_eq!(schema.defindex("CS:GO Weapon Case"), Some(4001));
        assert_eq!(schema.defindex("Operation Bravo Case"), Some(4233));
        assert_eq!(schema.defindex("CS:GO Case Key"), Some(1203));
        assert_eq!(schema.defindex("Prisma 2 Case Key"), Some(7008));
        assert_eq!(schema.defindex("Nonexistent Item"), None);
    }

    #[test]
    fn test_item_detail_matches_encode() {
        let (crates, keys) = sample_items();
        let schema = Cs2Schema::from_items(&crates, &keys).unwrap();

        // For cases/keys: encode_item_detail(0, 0.0, defindex, 0, 4, 0) = defindex << 15
        for defindex in [4001u32, 4233, 1203, 7008] {
            let expected = encode_item_detail(0, 0.0, defindex, 0, 4, 0);
            assert_eq!(expected, (defindex as u64) << 15);
            assert_eq!(schema.item_detail(defindex), Some(expected));
        }
    }

    #[test]
    fn test_lookup_returns_both() {
        let (crates, keys) = sample_items();
        let schema = Cs2Schema::from_items(&crates, &keys).unwrap();

        let (defindex, detail) = schema.lookup("CS:GO Weapon Case").unwrap();
        assert_eq!(defindex, 4001);
        assert_eq!(detail, 4001u64 << 15);

        assert!(schema.lookup("Not A Real Item").is_none());
    }

    #[test]
    fn test_null_market_hash_name_skipped() {
        let crates_json = r#"[
            {"id": "crate-1", "def_index": "100", "market_hash_name": null},
            {"id": "crate-2", "def_index": "200", "market_hash_name": ""},
            {"id": "crate-3", "def_index": "300", "market_hash_name": "Valid Item"}
        ]"#;
        let crates: Vec<CsgoApiItem> = serde_json::from_str(crates_json).unwrap();
        let schema = Cs2Schema::from_items(&crates, &[]).unwrap();

        // Only "Valid Item" should be included (null and empty are skipped)
        assert_eq!(schema.len(), 1);
        assert_eq!(schema.defindex("Valid Item"), Some(300));
    }

    #[test]
    fn test_empty_schema_errors() {
        let crates: Vec<CsgoApiItem> = vec![];
        let result = Cs2Schema::from_items(&crates, &[]);
        assert!(result.is_err());
    }
}
