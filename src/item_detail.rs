/// ItemDetail encoder — packs CS2 item attributes into a uint64.
///
/// Port of `encodeItemDetail()` from `packages/jjskin-kernel/src/value-objects/ItemDetail.ts`.
/// MUST MATCH: JJSKIN.sol ItemDetailLib encoding.
///
/// Bit layout (standard mode):
///   bits 63-48: paintindex (16 bits)
///   bits 47-28: floatvalue (20 bits, ×1,000,000)
///   bits 27-15: defindex (13 bits)
///   bits 14-5:  paintseed (10 bits)
///   bits 4-2:   patternTier (3 bits)
///   bits 1-0:   quality (2 bits)

const FLOAT_PRECISION: f64 = 1_000_000.0;
const MAX_DEFINDEX_STANDARD: u32 = 0x1FFF; // 8191
const MAX_PAINTSEED: u32 = 1000;
const MAX_PATTERN_TIER: u32 = 0x7;
const MAX_TINT_ID: u32 = 0x1F; // 31
const EXTENDED_MODE_PAINTSEED: u64 = 0x3FF; // 1023

/// Map Steam quality (4=Normal, 9=StatTrak, 12=Souvenir) to 2-bit encoding.
fn encode_quality(steam_quality: u32) -> u32 {
    match steam_quality {
        9 => 1,  // StatTrak
        12 => 2, // Souvenir
        _ => 0,  // Normal (Steam quality 4 and anything else)
    }
}

#[cfg(test)]
/// Backwards-compatible wrapper for focused encoder tests that do not provide
/// `pattern_tier` or `is_slab`.
pub fn encode_item_detail(
    paintindex: u32,
    floatvalue: f32,
    defindex: u32,
    paintseed: u32,
    quality: u32,
    tint_id: u32,
) -> u64 {
    encode_item_detail_with_flags(
        paintindex, floatvalue, defindex, paintseed, quality, tint_id, 0, false,
    )
}

/// Encode CS2 item attributes into a packed uint64.
///
/// Auto-detects mode:
/// - defindex > 8191 OR tint_id > 0 → extended mode
/// - otherwise → standard mode
///
/// `quality` is the Steam raw value (4=Normal, 9=StatTrak, 12=Souvenir).
/// `tint_id` is the graffiti color (0 for weapons).
pub fn encode_item_detail_with_flags(
    paintindex: u32,
    floatvalue: f32,
    defindex: u32,
    paintseed: u32,
    quality: u32,
    tint_id: u32,
    pattern_tier: u32,
    is_slab: bool,
) -> u64 {
    let quality_encoded = encode_quality(quality) & 0x3;
    let use_extended = defindex > MAX_DEFINDEX_STANDARD || tint_id > 0;

    if use_extended {
        // Extended mode: 28-bit defindex, tintId, quality, and slab bit.
        let defindex_upper = ((defindex >> 13) & 0x7FFF) as u64;
        let defindex_lower = (defindex & 0x1FFF) as u64;
        let tint = (tint_id.min(MAX_TINT_ID) & 0x1F) as u64;
        let slab = if is_slab { 1u64 } else { 0u64 };

        (tint << 43)
            | (defindex_upper << 28)
            | (defindex_lower << 15)
            | (EXTENDED_MODE_PAINTSEED << 5)
            | (slab << 4)
            | (quality_encoded as u64)
    } else {
        // Standard mode
        let float_scaled = (floatvalue as f64 * FLOAT_PRECISION).round() as u64;
        let paint = (paintindex as u64) & 0xFFFF;
        let float_bits = float_scaled & 0xFFFFF;
        let def = (defindex as u64) & 0x1FFF;
        let seed = (paintseed.min(MAX_PAINTSEED) as u64) & 0x3FF;
        let pattern_bits = (pattern_tier.min(MAX_PATTERN_TIER) as u64) & 0x7;
        let quality_bits = quality_encoded as u64;

        (paint << 48)
            | (float_bits << 28)
            | (def << 15)
            | (seed << 5)
            | (pattern_bits << 2)
            | quality_bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_mode_basic() {
        // AK-47 Redline (paintindex=44), float=0.25, defindex=7, seed=500, Normal
        let result = encode_item_detail(44, 0.25, 7, 500, 4, 0);

        // Verify by decoding
        let paintindex = (result >> 48) & 0xFFFF;
        let float_scaled = (result >> 28) & 0xFFFFF;
        let defindex = (result >> 15) & 0x1FFF;
        let paintseed = (result >> 5) & 0x3FF;
        let pattern_tier = (result >> 2) & 0x7;
        let quality = result & 0x3;

        assert_eq!(paintindex, 44);
        assert_eq!(float_scaled, 250000); // 0.25 * 1_000_000
        assert_eq!(defindex, 7);
        assert_eq!(paintseed, 500);
        assert_eq!(pattern_tier, 0);
        assert_eq!(quality, 0); // Normal
    }

    #[test]
    fn test_standard_mode_stattrak() {
        let result = encode_item_detail(44, 0.123456, 7, 100, 9, 0);
        let quality = result & 0x3;
        assert_eq!(quality, 1); // StatTrak
    }

    #[test]
    fn test_standard_mode_souvenir() {
        let result = encode_item_detail(44, 0.5, 7, 200, 12, 0);
        let quality = result & 0x3;
        assert_eq!(quality, 2); // Souvenir
    }

    #[test]
    fn test_standard_mode_pattern_tier() {
        let result = encode_item_detail_with_flags(44, 0.25, 7, 500, 4, 0, 3, false);
        let pattern_tier = (result >> 2) & 0x7;
        assert_eq!(pattern_tier, 3);
    }

    #[test]
    fn test_extended_mode_high_defindex() {
        // Sticker with defindex > 8191 → extended mode
        let result = encode_item_detail(0, 0.0, 10000, 0, 4, 0);

        // Verify paintseed marker = 1023
        let paintseed = (result >> 5) & 0x3FF;
        assert_eq!(paintseed, EXTENDED_MODE_PAINTSEED);

        // Decode defindex
        let defindex_lower = (result >> 15) & 0x1FFF;
        let float_bits = (result >> 28) & 0xFFFFF;
        let defindex_upper = float_bits & 0x7FFF;
        let decoded_defindex = ((defindex_upper << 13) | defindex_lower) as u32;
        assert_eq!(decoded_defindex, 10000);
    }

    #[test]
    fn test_extended_mode_tint_id() {
        // Graffiti with tint_id > 0 → extended mode
        let result = encode_item_detail(0, 0.0, 100, 0, 4, 5);

        let paintseed = (result >> 5) & 0x3FF;
        assert_eq!(paintseed, EXTENDED_MODE_PAINTSEED);

        // Decode tint_id
        let float_bits = (result >> 28) & 0xFFFFF;
        let tint_id = (float_bits >> 15) & 0x1F;
        assert_eq!(tint_id, 5);
    }

    #[test]
    fn test_extended_mode_sets_slab_flag_when_already_extended() {
        let result = encode_item_detail_with_flags(0, 0.0, 10000, 0, 4, 0, 0, true);

        let paintseed = (result >> 5) & 0x3FF;
        let slab = (result >> 4) & 0x1;

        assert_eq!(paintseed, EXTENDED_MODE_PAINTSEED);
        assert_eq!(slab, 1);
    }

    #[test]
    fn test_sticker_slab_low_defindex_matches_typescript_standard_mode() {
        let result = encode_item_detail_with_flags(0, 0.0, 6026, 0, 4, 0, 0, true);
        assert_eq!(result, 197459968);
    }

    #[test]
    fn test_cross_check_with_typescript() {
        // Cross-check: AK-47 Redline, float=0.5, defindex=7, seed=500, Normal
        // TypeScript: encodeItemDetail({paintindex:44, floatvalue:0.5, defindex:7, paintseed:500, patternTier:0, tintId:0, quality:0})
        // = (44n << 48n) | (500000n << 28n) | (7n << 15n) | (500n << 5n) = 12384935286046720
        let result = encode_item_detail(44, 0.5, 7, 500, 4, 0);

        let paint = (result >> 48) & 0xFFFF;
        let float_scaled = (result >> 28) & 0xFFFFF;
        let def = (result >> 15) & 0x1FFF;
        let seed = (result >> 5) & 0x3FF;
        let qual = result & 0x3;

        assert_eq!(paint, 44);
        assert_eq!(float_scaled, 500000);
        assert_eq!(def, 7);
        assert_eq!(seed, 500);
        assert_eq!(qual, 0);

        // Reconstruct expected value
        let expected: u64 = (44u64 << 48) | (500000u64 << 28) | (7u64 << 15) | (500u64 << 5);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_gamma_doppler_cross_check_with_typescript() {
        let result =
            encode_item_detail_with_flags(1119, 0.06596978008747101_f32, 4, 135, 4, 0, 1, false);
        assert_eq!(result, 314988207626391780);
    }

    #[test]
    fn test_float_precision() {
        // 0.123456 → 123456 (exact at 6 decimals)
        let result = encode_item_detail(1, 0.123456, 7, 0, 4, 0);
        let float_scaled = (result >> 28) & 0xFFFFF;
        assert_eq!(float_scaled, 123456);
    }

    #[test]
    fn test_quality_mapping() {
        assert_eq!(encode_quality(4), 0); // Normal
        assert_eq!(encode_quality(9), 1); // StatTrak
        assert_eq!(encode_quality(12), 2); // Souvenir
        assert_eq!(encode_quality(0), 0); // Unknown → Normal
        assert_eq!(encode_quality(99), 0); // Unknown → Normal
    }
}
