use std::collections::HashMap;
use std::fmt;

use eyre::{Context, Result};
use serde::Deserialize;
use tracing::info;

use crate::item_detail::encode_item_detail_with_flags;
use crate::steam_inventory::InventoryItem;

const CATALOG_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/buy-order-attestation-catalog.json"
));
const MAX_DEFINDEX_STANDARD: u32 = 0x1FFF;

#[derive(Debug, Clone)]
pub struct ResolvedCatalogIdentity {
    pub market_hash_name: String,
    pub defindex: u32,
    pub paintindex: u32,
    pub tint_id: u32,
    pub item_type: String,
    pub quality: u32,
    pub floatvalue: f32,
    pub paintseed: u32,
    pub pattern_tier: u32,
    pub is_slab: bool,
    pub finish_catalog: Option<u32>,
}

#[derive(Debug, Clone)]
pub enum CatalogResolveError {
    CatalogMiss {
        market_hash_name: String,
    },
    UnsupportedFinishCatalog {
        market_hash_name: String,
        finish_catalog: u32,
    },
    AmbiguousCatalogIdentity {
        market_hash_name: String,
        candidate_count: usize,
    },
    MissingDefindex {
        market_hash_name: String,
    },
    MissingTintId {
        market_hash_name: String,
    },
    MissingFloatvalue {
        market_hash_name: String,
    },
    MissingPaintseed {
        market_hash_name: String,
    },
    UnrepresentableItemDetail {
        market_hash_name: String,
        conflicting_count: usize,
    },
}

impl fmt::Display for CatalogResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CatalogMiss { market_hash_name } => {
                write!(f, "No catalog identity found for '{market_hash_name}'")
            }
            Self::UnsupportedFinishCatalog {
                market_hash_name,
                finish_catalog,
            } => write!(
                f,
                "Unsupported finish_catalog {finish_catalog} for '{market_hash_name}'"
            ),
            Self::AmbiguousCatalogIdentity {
                market_hash_name,
                candidate_count,
            } => write!(
                f,
                "Catalog identity for '{market_hash_name}' is ambiguous ({candidate_count} candidates)"
            ),
            Self::MissingDefindex { market_hash_name } => {
                write!(
                    f,
                    "Catalog item for '{market_hash_name}' is missing defindex"
                )
            }
            Self::MissingTintId { market_hash_name } => {
                write!(f, "Catalog item for '{market_hash_name}' is missing tintId")
            }
            Self::MissingFloatvalue { market_hash_name } => {
                write!(
                    f,
                    "Missing floatvalue for painted item '{market_hash_name}'"
                )
            }
            Self::MissingPaintseed { market_hash_name } => {
                write!(f, "Missing paintseed for painted item '{market_hash_name}'")
            }
            Self::UnrepresentableItemDetail {
                market_hash_name,
                conflicting_count,
            } => write!(
                f,
                "Current itemDetail v1 cannot uniquely represent '{market_hash_name}' ({conflicting_count} conflicting catalog items)"
            ),
        }
    }
}

impl std::error::Error for CatalogResolveError {}

pub struct CatalogResolver {
    catalog: CatalogArtifact,
    exact_index: HashMap<String, Vec<usize>>,
    family_index: HashMap<FamilyKey, Vec<usize>>,
    static_attestation_key_counts: HashMap<u64, usize>,
}

impl CatalogResolver {
    pub fn load() -> Result<Self> {
        let catalog: CatalogArtifact = serde_json::from_str(CATALOG_JSON)
            .context("failed to parse embedded attestation catalog")?;

        let mut exact_index: HashMap<String, Vec<usize>> = HashMap::new();
        let mut family_index: HashMap<FamilyKey, Vec<usize>> = HashMap::new();
        let mut static_attestation_key_counts: HashMap<u64, usize> = HashMap::new();

        for (index, item) in catalog.items.iter().enumerate() {
            exact_index
                .entry(item.market_hash_name.clone())
                .or_default()
                .push(index);

            if let Some(key) = FamilyKey::from_catalog_item(item) {
                family_index.entry(key).or_default().push(index);
            }

            if let Some(attestation_key) = static_attestation_key_for_catalog_item(item) {
                *static_attestation_key_counts
                    .entry(attestation_key)
                    .or_insert(0) += 1;
            }
        }

        info!(
            schema_version = catalog.schema_version.as_str(),
            classification_version = catalog
                .special_classification
                .classification_version
                .as_str(),
            item_count = catalog.items.len(),
            "Inventory attestation catalog loaded"
        );

        Ok(Self {
            catalog,
            exact_index,
            family_index,
            static_attestation_key_counts,
        })
    }

    pub fn resolve(
        &self,
        inventory_item: &InventoryItem,
    ) -> Result<ResolvedCatalogIdentity, CatalogResolveError> {
        let finish_catalog = inventory_item
            .steam_evidence
            .as_ref()
            .and_then(|evidence| evidence.finish_catalog);
        let catalog_item = self.resolve_catalog_item(inventory_item, finish_catalog)?;
        let defindex =
            catalog_item
                .defindex
                .ok_or_else(|| CatalogResolveError::MissingDefindex {
                    market_hash_name: inventory_item.market_hash_name.clone(),
                })?;
        let paintindex = catalog_item.paintindex.unwrap_or(0);
        let tint_id = if catalog_item.item_type == "graffiti" {
            catalog_item
                .tint_id
                .ok_or_else(|| CatalogResolveError::MissingTintId {
                    market_hash_name: inventory_item.market_hash_name.clone(),
                })?
        } else {
            0
        };
        let floatvalue = if paintindex > 0 {
            inventory_item
                .steam_evidence
                .as_ref()
                .and_then(|evidence| evidence.floatvalue)
                .ok_or_else(|| CatalogResolveError::MissingFloatvalue {
                    market_hash_name: inventory_item.market_hash_name.clone(),
                })?
        } else {
            0.0
        };
        let paintseed = if paintindex > 0 {
            inventory_item
                .steam_evidence
                .as_ref()
                .and_then(|evidence| evidence.paintseed)
                .ok_or_else(|| CatalogResolveError::MissingPaintseed {
                    market_hash_name: inventory_item.market_hash_name.clone(),
                })?
        } else {
            0
        };
        ensure_representable_item_detail(catalog_item, &self.static_attestation_key_counts)?;

        Ok(ResolvedCatalogIdentity {
            market_hash_name: inventory_item.market_hash_name.clone(),
            defindex,
            paintindex,
            tint_id,
            item_type: catalog_item.item_type.clone(),
            quality: quality_from_inventory_item(inventory_item),
            floatvalue,
            paintseed,
            pattern_tier: classify_special_pattern_tier(
                &self.catalog.special_classification,
                &inventory_item.market_hash_name,
                defindex,
                paintindex,
                paintseed,
            ),
            is_slab: catalog_item.item_type == "sticker_slab",
            finish_catalog,
        })
    }

    fn resolve_catalog_item<'a>(
        &'a self,
        inventory_item: &InventoryItem,
        finish_catalog: Option<u32>,
    ) -> Result<&'a CatalogItem, CatalogResolveError> {
        let exact_candidates = self
            .exact_index
            .get(&inventory_item.market_hash_name)
            .cloned()
            .unwrap_or_default();

        if let Some(finish_catalog) = finish_catalog {
            if !exact_candidates.is_empty() {
                if let Some(candidate_index) =
                    exact_candidates.iter().copied().find(|candidate_index| {
                        self.catalog.items[*candidate_index].paintindex == Some(finish_catalog)
                    })
                {
                    return Ok(&self.catalog.items[candidate_index]);
                }

                return Err(CatalogResolveError::UnsupportedFinishCatalog {
                    market_hash_name: inventory_item.market_hash_name.clone(),
                    finish_catalog,
                });
            }

            let Some(family_key) = FamilyKey::from_inventory_item(inventory_item) else {
                return Err(CatalogResolveError::CatalogMiss {
                    market_hash_name: inventory_item.market_hash_name.clone(),
                });
            };
            let Some(family_candidates) = self.family_index.get(&family_key) else {
                return Err(CatalogResolveError::CatalogMiss {
                    market_hash_name: inventory_item.market_hash_name.clone(),
                });
            };

            let matching_candidates: Vec<usize> = family_candidates
                .iter()
                .copied()
                .filter(|candidate_index| {
                    self.catalog.items[*candidate_index].paintindex == Some(finish_catalog)
                })
                .collect();

            return match matching_candidates.as_slice() {
                [candidate_index] => Ok(&self.catalog.items[*candidate_index]),
                [] => Err(CatalogResolveError::UnsupportedFinishCatalog {
                    market_hash_name: inventory_item.market_hash_name.clone(),
                    finish_catalog,
                }),
                many => Err(CatalogResolveError::AmbiguousCatalogIdentity {
                    market_hash_name: inventory_item.market_hash_name.clone(),
                    candidate_count: many.len(),
                }),
            };
        }

        match exact_candidates.as_slice() {
            [candidate_index] => Ok(&self.catalog.items[*candidate_index]),
            [] => Err(CatalogResolveError::CatalogMiss {
                market_hash_name: inventory_item.market_hash_name.clone(),
            }),
            many => Err(CatalogResolveError::AmbiguousCatalogIdentity {
                market_hash_name: inventory_item.market_hash_name.clone(),
                candidate_count: many.len(),
            }),
        }
    }
}

fn quality_from_inventory_item(item: &InventoryItem) -> u32 {
    if item.is_souvenir {
        12
    } else if item.is_stattrak {
        9
    } else {
        4
    }
}

fn quality_from_catalog_item(item: &CatalogItem) -> u32 {
    if item.souvenir {
        12
    } else if item.stat_trak {
        9
    } else {
        4
    }
}

fn static_attestation_key_for_catalog_item(item: &CatalogItem) -> Option<u64> {
    let defindex = item.defindex?;
    let paintindex = item.paintindex.unwrap_or(0);
    if paintindex > 0 {
        return None;
    }

    Some(encode_item_detail_with_flags(
        paintindex,
        0.0,
        defindex,
        0,
        quality_from_catalog_item(item),
        item.tint_id.unwrap_or(0),
        0,
        item.item_type == "sticker_slab",
    ))
}

fn ensure_representable_item_detail(
    catalog_item: &CatalogItem,
    static_attestation_key_counts: &HashMap<u64, usize>,
) -> Result<(), CatalogResolveError> {
    let Some(attestation_key) = static_attestation_key_for_catalog_item(catalog_item) else {
        return Ok(());
    };

    let use_extended_mode = catalog_item.defindex.unwrap_or(0) > MAX_DEFINDEX_STANDARD
        || catalog_item.tint_id.unwrap_or(0) > 0;
    if use_extended_mode {
        return Ok(());
    }

    let conflicting_count = static_attestation_key_counts
        .get(&attestation_key)
        .copied()
        .unwrap_or(0);
    if conflicting_count > 1 {
        return Err(CatalogResolveError::UnrepresentableItemDetail {
            market_hash_name: catalog_item.market_hash_name.clone(),
            conflicting_count,
        });
    }

    Ok(())
}

fn classify_special_pattern_tier(
    taxonomy: &SpecialClassificationTaxonomy,
    market_hash_name: &str,
    defindex: u32,
    paint_index: u32,
    paint_seed: u32,
) -> u32 {
    let catalog_key = to_catalog_key(market_hash_name);
    let Some(family) = taxonomy.families.iter().find(|family| {
        family
            .catalog_matchers
            .iter()
            .any(|matcher| matches_catalog_matcher(&catalog_key, matcher))
    }) else {
        return 0;
    };

    let bucket_key = match &family.classifier {
        SpecialClassifierSource::PaintIndexMap { rules } => rules
            .iter()
            .find(|rule| rule.paint_indexes.contains(&paint_index))
            .map(|rule| rule.bucket_key.clone()),
        SpecialClassifierSource::PaintSeedMap { items } => {
            let item_rule = items.iter().find(|rule| {
                matches_paint_seed_item_rule(rule, &catalog_key, defindex, paint_index)
            });

            item_rule.and_then(|rule| {
                rule.rules
                    .iter()
                    .find(|candidate| matches_seed_rule(candidate, paint_seed))
                    .map(|candidate| candidate.bucket_key.clone())
            })
        }
    };

    bucket_key
        .and_then(|bucket_key| {
            family
                .buckets
                .iter()
                .find(|bucket| bucket.key == bucket_key)
                .map(|bucket| bucket.pattern_tier)
        })
        .unwrap_or(0)
}

fn matches_paint_seed_item_rule(
    rule: &PaintSeedMapItemRuleSource,
    catalog_key: &str,
    defindex: u32,
    paint_index: u32,
) -> bool {
    if !rule.catalog_matchers.is_empty()
        && !rule
            .catalog_matchers
            .iter()
            .any(|matcher| matches_catalog_matcher(catalog_key, matcher))
    {
        return false;
    }

    if !rule.defindexes.is_empty() && !rule.defindexes.contains(&defindex) {
        return false;
    }

    if let Some(expected_paint_index) = rule.paint_index {
        if expected_paint_index != paint_index {
            return false;
        }
    }

    true
}

fn matches_seed_rule(rule: &PaintSeedRuleSourceDefinition, paint_seed: u32) -> bool {
    if rule.seeds.contains(&paint_seed) {
        return true;
    }

    rule.seed_ranges
        .iter()
        .any(|range| paint_seed >= range.min && paint_seed <= range.max)
}

fn matches_catalog_matcher(catalog_key: &str, matcher: &SpecialCatalogMatcher) -> bool {
    match matcher {
        SpecialCatalogMatcher::Exact { value } => catalog_key == value,
        SpecialCatalogMatcher::Suffix { value } => catalog_key.ends_with(value),
    }
}

fn to_catalog_key(market_hash_name: &str) -> String {
    collapse_spaces(strip_variant_prefixes(strip_trailing_exterior(market_hash_name)).trim())
}

fn parse_family_from_market_hash_name(market_hash_name: &str) -> Option<(String, String)> {
    let normalized = strip_variant_prefixes(strip_trailing_exterior(market_hash_name)).trim();
    let parts: Vec<&str> = normalized.split(" | ").collect();
    if parts.len() < 2 {
        return None;
    }

    let weapon_name = parts[0].trim().trim_start_matches("★ ").trim().to_string();
    let pattern_name = parts[1..].join(" | ").trim().to_string();

    Some((weapon_name, pattern_name))
}

fn strip_trailing_exterior(value: &str) -> &str {
    if value.ends_with(')') {
        if let Some(index) = value.rfind(" (") {
            return &value[..index];
        }
    }

    value
}

fn strip_variant_prefixes(mut value: &str) -> &str {
    if let Some(stripped) = value.strip_prefix("StatTrak™ ") {
        value = stripped;
    }

    if let Some(stripped) = value.strip_prefix("Souvenir ") {
        value = stripped;
    }

    value
}

fn collapse_spaces(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FamilyKey {
    weapon_type: String,
    pattern_name: String,
    exterior: String,
    stat_trak: bool,
    souvenir: bool,
}

impl FamilyKey {
    fn from_catalog_item(item: &CatalogItem) -> Option<Self> {
        Some(Self {
            weapon_type: item.weapon_type.clone()?,
            pattern_name: item.pattern_name.clone()?,
            exterior: item.exterior.clone()?,
            stat_trak: item.stat_trak,
            souvenir: item.souvenir,
        })
    }

    fn from_inventory_item(item: &InventoryItem) -> Option<Self> {
        let (weapon_type, pattern_name) =
            parse_family_from_market_hash_name(&item.market_hash_name)?;
        let exterior = item.exterior.clone()?;

        Some(Self {
            weapon_type,
            pattern_name,
            exterior,
            stat_trak: item.is_stattrak,
            souvenir: item.is_souvenir,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CatalogArtifact {
    schema_version: String,
    items: Vec<CatalogItem>,
    special_classification: SpecialClassificationTaxonomy,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CatalogItem {
    market_hash_name: String,
    defindex: Option<u32>,
    paintindex: Option<u32>,
    tint_id: Option<u32>,
    item_type: String,
    weapon_type: Option<String>,
    pattern_name: Option<String>,
    exterior: Option<String>,
    stat_trak: bool,
    souvenir: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpecialClassificationTaxonomy {
    classification_version: String,
    families: Vec<SpecialFamilyConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpecialFamilyConfig {
    catalog_matchers: Vec<SpecialCatalogMatcher>,
    buckets: Vec<SpecialClassificationBucketDefinition>,
    classifier: SpecialClassifierSource,
}

#[derive(Debug, Clone, Deserialize)]
struct SpecialClassificationBucketDefinition {
    key: String,
    #[serde(rename = "patternTier")]
    pattern_tier: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind")]
enum SpecialCatalogMatcher {
    #[serde(rename = "exact")]
    Exact { value: String },
    #[serde(rename = "suffix")]
    Suffix { value: String },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind")]
enum SpecialClassifierSource {
    #[serde(rename = "paint_index_map")]
    PaintIndexMap { rules: Vec<PaintIndexMapRuleSource> },
    #[serde(rename = "paint_seed_map")]
    PaintSeedMap {
        items: Vec<PaintSeedMapItemRuleSource>,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PaintIndexMapRuleSource {
    bucket_key: String,
    paint_indexes: Vec<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PaintSeedMapItemRuleSource {
    #[serde(default)]
    catalog_matchers: Vec<SpecialCatalogMatcher>,
    #[serde(default)]
    defindexes: Vec<u32>,
    paint_index: Option<u32>,
    rules: Vec<PaintSeedRuleSourceDefinition>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PaintSeedRuleSourceDefinition {
    bucket_key: String,
    #[serde(default)]
    seeds: Vec<u32>,
    #[serde(default)]
    seed_ranges: Vec<SeedRange>,
}

#[derive(Debug, Clone, Deserialize)]
struct SeedRange {
    min: u32,
    max: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item_detail::encode_item_detail_with_flags;
    use crate::steam_inventory::SteamAssetEvidence;

    fn inventory_item(
        market_hash_name: &str,
        exterior: Option<&str>,
        is_stattrak: bool,
        is_souvenir: bool,
        steam_evidence: Option<SteamAssetEvidence>,
    ) -> InventoryItem {
        InventoryItem {
            market_hash_name: market_hash_name.to_string(),
            exterior: exterior.map(str::to_string),
            is_stattrak,
            is_souvenir,
            steam_evidence,
        }
    }

    #[test]
    fn resolves_painted_item_from_exact_market_hash_name() {
        let resolver = CatalogResolver::load().unwrap();
        let item = inventory_item(
            "StatTrak™ MP9 | Nexus (Field-Tested)",
            Some("Field-Tested"),
            true,
            false,
            Some(SteamAssetEvidence {
                floatvalue: Some(0.2568016),
                paintseed: Some(766),
                finish_catalog: None,
                item_certificate: None,
            }),
        );

        let resolved = resolver.resolve(&item).unwrap();
        let item_detail = encode_item_detail_with_flags(
            resolved.paintindex,
            resolved.floatvalue,
            resolved.defindex,
            resolved.paintseed,
            resolved.quality,
            resolved.tint_id,
            resolved.pattern_tier,
            resolved.is_slab,
        );

        assert_eq!(resolved.defindex, 34);
        assert_eq!(resolved.paintindex, 1193);
        assert_eq!(resolved.pattern_tier, 0);
        assert_eq!(item_detail, 335868581978922945);
    }

    #[test]
    fn uses_finish_catalog_to_resolve_gamma_doppler_phase() {
        let resolver = CatalogResolver::load().unwrap();
        let item = inventory_item(
            "Glock-18 | Gamma Doppler (Factory New)",
            Some("Factory New"),
            false,
            false,
            Some(SteamAssetEvidence {
                floatvalue: Some(0.06596978),
                paintseed: Some(135),
                finish_catalog: Some(1119),
                item_certificate: None,
            }),
        );

        let resolved = resolver.resolve(&item).unwrap();
        let item_detail = encode_item_detail_with_flags(
            resolved.paintindex,
            resolved.floatvalue,
            resolved.defindex,
            resolved.paintseed,
            resolved.quality,
            resolved.tint_id,
            resolved.pattern_tier,
            resolved.is_slab,
        );

        assert_eq!(resolved.defindex, 4);
        assert_eq!(resolved.paintindex, 1119);
        assert_eq!(resolved.pattern_tier, 1);
        assert_eq!(item_detail, 314988207626391780);
    }

    #[test]
    fn resolves_graffiti_tint_from_catalog() {
        let resolver = CatalogResolver::load().unwrap();
        let item = inventory_item(
            "Sealed Graffiti | Toasted (Desert Amber)",
            None,
            false,
            false,
            None,
        );

        let resolved = resolver.resolve(&item).unwrap();
        let item_detail = encode_item_detail_with_flags(
            resolved.paintindex,
            resolved.floatvalue,
            resolved.defindex,
            resolved.paintseed,
            resolved.quality,
            resolved.tint_id,
            resolved.pattern_tier,
            resolved.is_slab,
        );

        assert_eq!(resolved.defindex, 1727);
        assert_eq!(resolved.tint_id, 5);
        assert_eq!(item_detail, 43980521734112);
    }

    #[test]
    fn resolves_sticker_slab_flag() {
        let resolver = CatalogResolver::load().unwrap();
        let item = inventory_item(
            "Sticker Slab | 1eeR | Austin 2025",
            None,
            false,
            false,
            None,
        );

        let resolved = resolver.resolve(&item).unwrap();
        let item_detail = encode_item_detail_with_flags(
            resolved.paintindex,
            resolved.floatvalue,
            resolved.defindex,
            resolved.paintseed,
            resolved.quality,
            resolved.tint_id,
            resolved.pattern_tier,
            resolved.is_slab,
        );

        let paintseed = (item_detail >> 5) & 0x3FF;

        assert_eq!(resolved.defindex, 9139);
        assert!(resolved.is_slab);
        assert_eq!(paintseed, 0x3FF);
    }

    #[test]
    fn rejects_ambiguous_phase_item_without_finish_catalog() {
        let resolver = CatalogResolver::load().unwrap();
        let item = inventory_item(
            "Glock-18 | Gamma Doppler (Factory New)",
            Some("Factory New"),
            false,
            false,
            Some(SteamAssetEvidence {
                floatvalue: Some(0.06596978),
                paintseed: Some(135),
                finish_catalog: None,
                item_certificate: None,
            }),
        );

        let error = resolver.resolve(&item).unwrap_err();
        assert!(matches!(
            error,
            CatalogResolveError::AmbiguousCatalogIdentity { .. }
        ));
    }

    #[test]
    fn rejects_unknown_finish_catalog_for_phase_item() {
        let resolver = CatalogResolver::load().unwrap();
        let item = inventory_item(
            "Glock-18 | Gamma Doppler (Factory New)",
            Some("Factory New"),
            false,
            false,
            Some(SteamAssetEvidence {
                floatvalue: Some(0.06596978),
                paintseed: Some(135),
                finish_catalog: Some(999_999),
                item_certificate: None,
            }),
        );

        let error = resolver.resolve(&item).unwrap_err();
        assert!(matches!(
            error,
            CatalogResolveError::UnsupportedFinishCatalog { .. }
        ));
    }

    #[test]
    fn rejects_non_painted_item_that_collides_under_item_detail_v1() {
        let resolver = CatalogResolver::load().unwrap();
        let item = inventory_item("Sticker | Ork Waaagh!", None, false, false, None);

        let error = resolver.resolve(&item).unwrap_err();
        assert!(matches!(
            error,
            CatalogResolveError::UnrepresentableItemDetail { .. }
        ));
    }
}
