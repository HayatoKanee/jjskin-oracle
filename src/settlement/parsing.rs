//! HTTP response parsing and Steam data extraction
//!
//! Adapted from jjskin-oracle/common/src/parsing.rs for std environment.
//! Uses serde_json for JSON parsing (std available) while keeping
//! manual byte-level parsing for HTTP headers and HTML.

use serde::Deserialize;

use super::types::{CommunityProofData, ProofSource, TradeOfferData, TradeStatusData, STEAM64_OFFSET};
use miniz_oxide::inflate::decompress_to_vec;

/// Error type for parsing operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    NoJsonBody,
    InvalidGzip,
    UnsupportedCompression,
    InvalidGzipHeader,
    InvalidGzipData,
    DecompressionFailed,
    DecompressedTooLarge,
    InvalidUtf8,
    MissingTradeOfferId,
    MissingCookie,
    InvalidCookieFormat,
    NumberOverflow,
    ResponseTooLarge,
    TradeNotFound,
    CommunityTradeExists,
    JsonParse(String),
}

/// Maximum decompressed size (10MB)
pub const MAX_DECOMPRESSED_SIZE: usize = 10 * 1024 * 1024;

/// Maximum raw response size (50MB)
pub const MAX_RAW_RESPONSE_SIZE: usize = 50 * 1024 * 1024;

impl ParseError {
    pub fn as_str(&self) -> &str {
        match self {
            ParseError::NoJsonBody => "No JSON body found",
            ParseError::InvalidGzip => "Not a valid gzip stream",
            ParseError::UnsupportedCompression => "Unsupported compression method",
            ParseError::InvalidGzipHeader => "Invalid gzip header",
            ParseError::InvalidGzipData => "Invalid gzip data",
            ParseError::DecompressionFailed => "Failed to decompress",
            ParseError::DecompressedTooLarge => "Decompressed data exceeds size limit",
            ParseError::InvalidUtf8 => "Invalid UTF-8",
            ParseError::MissingTradeOfferId => "Could not find tradeofferid",
            ParseError::MissingCookie => "No steamLoginSecure cookie found",
            ParseError::InvalidCookieFormat => "Invalid steamLoginSecure cookie format",
            ParseError::NumberOverflow => "Number too large to parse",
            ParseError::ResponseTooLarge => "Response exceeds size limit",
            ParseError::TradeNotFound => "Trade not found - empty response from Steam",
            ParseError::CommunityTradeExists => "Community proof invalid - trade exists for this user",
            ParseError::JsonParse(msg) => msg.as_str(),
        }
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::error::Error for ParseError {}

// ============================================================================
// Serde deserialization types (internal)
// ============================================================================

#[derive(Deserialize)]
struct GetTradeOfferResponse {
    response: GetTradeOfferInner,
}

#[derive(Deserialize)]
struct GetTradeOfferInner {
    offer: Option<TradeOffer>,
}

#[derive(Deserialize)]
struct TradeOffer {
    tradeofferid: String,
    trade_offer_state: u32,
    accountid_other: u64,
    items_to_give: Option<Vec<TradeItem>>,
    items_to_receive: Option<Vec<TradeItem>>,
    #[serde(default)]
    is_our_offer: Option<bool>,
}

#[derive(Deserialize)]
struct TradeItem {
    appid: u32,
    assetid: String,
}

#[derive(Deserialize)]
struct GetTradeStatusResponse {
    response: GetTradeStatusInner,
}

#[derive(Deserialize)]
struct GetTradeStatusInner {
    trades: Option<Vec<TradeStatusEntry>>,
}

#[derive(Deserialize)]
struct TradeStatusEntry {
    #[serde(default)]
    status: u32,
    #[serde(default)]
    steamid_other: Option<String>,
    assets_given: Option<Vec<TradeStatusAsset>>,
    assets_received: Option<Vec<TradeStatusAsset>>,
    #[serde(default)]
    time_settlement: Option<u64>,
}

#[derive(Deserialize)]
struct TradeStatusAsset {
    appid: u32,
    assetid: String,
}

// ============================================================================
// HTTP Response Parsing
// ============================================================================

/// Find the start of body in HTTP response (after \r\n\r\n)
pub fn find_json_start(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if data[i..i + 4] == [0x0d, 0x0a, 0x0d, 0x0a] {
            return Some(i + 4);
        }
    }
    None
}

/// Extract and decompress HTTP response body
pub fn extract_http_body(response: &[u8]) -> Result<String, ParseError> {
    if response.len() > MAX_RAW_RESPONSE_SIZE {
        return Err(ParseError::ResponseTooLarge);
    }

    let body_start = find_json_start(response).ok_or(ParseError::NoJsonBody)?;
    let json_bytes = &response[body_start..];

    if json_bytes.len() >= 2 && json_bytes[0] == 0x1f && json_bytes[1] == 0x8b {
        let decompressed = decompress_gzip(json_bytes)?;
        String::from_utf8(decompressed).map_err(|_| ParseError::InvalidUtf8)
    } else {
        std::str::from_utf8(json_bytes)
            .map_err(|_| ParseError::InvalidUtf8)
            .map(String::from)
    }
}

// ============================================================================
// Gzip Decompression
// ============================================================================

pub fn decompress_gzip(gzip_bytes: &[u8]) -> Result<Vec<u8>, ParseError> {
    if gzip_bytes.len() < 18 || gzip_bytes[0] != 0x1f || gzip_bytes[1] != 0x8b {
        return Err(ParseError::InvalidGzip);
    }

    if gzip_bytes[2] != 8 {
        return Err(ParseError::UnsupportedCompression);
    }

    let flags = gzip_bytes[3];
    let mut offset = 10;

    if flags & 0x04 != 0 {
        if offset + 2 > gzip_bytes.len() {
            return Err(ParseError::InvalidGzipHeader);
        }
        let xlen = u16::from_le_bytes([gzip_bytes[offset], gzip_bytes[offset + 1]]) as usize;
        offset += 2 + xlen;
    }

    if flags & 0x08 != 0 {
        while offset < gzip_bytes.len() && gzip_bytes[offset] != 0 {
            offset += 1;
        }
        offset += 1;
    }

    if flags & 0x10 != 0 {
        while offset < gzip_bytes.len() && gzip_bytes[offset] != 0 {
            offset += 1;
        }
        offset += 1;
    }

    if flags & 0x02 != 0 {
        offset += 2;
    }

    if offset >= gzip_bytes.len() {
        return Err(ParseError::InvalidGzipData);
    }

    let compressed_end = gzip_bytes.len().saturating_sub(8);
    let compressed_data = &gzip_bytes[offset..compressed_end];

    let decompressed =
        decompress_to_vec(compressed_data).map_err(|_| ParseError::DecompressionFailed)?;

    if decompressed.len() > MAX_DECOMPRESSED_SIZE {
        return Err(ParseError::DecompressedTooLarge);
    }

    Ok(decompressed)
}

// ============================================================================
// Steam JSON Parsing (serde_json)
// ============================================================================

/// Detect proof source from HTTP request URL.
///
/// Scans full request bytes (not just the URL line). This is safe because:
/// 1. `server_name` cross-validation in `oracle::decide()` rejects mismatches
///    (e.g. "GetTradeOffer" in a cookie on a community request)
/// 2. Even if misclassified, the JSON parse step rejects wrong response structures
pub fn detect_proof_source(request: &[u8]) -> Option<ProofSource> {
    if let Some(pos) = find_pattern(request, b"GetTrade") {
        let next_pos = pos + 8;
        if next_pos < request.len() {
            match request[next_pos] {
                b'O' => return Some(ProofSource::TradeOffer),
                b'S' => return Some(ProofSource::TradeStatus),
                _ => return None,
            }
        }
        return None;
    }

    if find_pattern(request, b"steamcommunity.com").is_some() {
        return Some(ProofSource::Community);
    }

    None
}

/// Extract first CS2 (appid=730) assetid from a list of TradeItems
fn first_cs2_assetid(items: &Option<Vec<TradeItem>>) -> Option<u64> {
    items.as_ref()?.iter().find_map(|item| {
        if item.appid == 730 {
            item.assetid.parse().ok()
        } else {
            None
        }
    })
}

/// Extract first CS2 (appid=730) assetid from a list of TradeStatusAssets
fn first_cs2_status_assetid(items: &Option<Vec<TradeStatusAsset>>) -> Option<u64> {
    items.as_ref()?.iter().find_map(|item| {
        if item.appid == 730 {
            item.assetid.parse().ok()
        } else {
            None
        }
    })
}

/// Parse GetTradeOffer JSON response
pub fn parse_trade_offer(json: &str) -> Result<TradeOfferData, ParseError> {
    let resp: GetTradeOfferResponse = serde_json::from_str(json)
        .map_err(|e| ParseError::JsonParse(format!("GetTradeOffer JSON: {e}")))?;

    let offer = resp.response.offer.ok_or(ParseError::TradeNotFound)?;

    let trade_offer_id: u64 = offer.tradeofferid.parse()
        .map_err(|_| ParseError::MissingTradeOfferId)?;

    let partner_steam_id = offer.accountid_other + STEAM64_OFFSET;

    let asset_to_give = first_cs2_assetid(&offer.items_to_give);
    let asset_to_receive = first_cs2_assetid(&offer.items_to_receive);

    let is_our_offer = offer.is_our_offer.unwrap_or(false);

    Ok(TradeOfferData {
        state: offer.trade_offer_state,
        trade_offer_id,
        partner_steam_id,
        asset_to_give,
        asset_to_receive,
        is_our_offer,
    })
}

/// Parse GetTradeStatus JSON response
pub fn parse_trade_status(json: &str) -> Result<TradeStatusData, ParseError> {
    let resp: GetTradeStatusResponse = serde_json::from_str(json)
        .map_err(|e| ParseError::JsonParse(format!("GetTradeStatus JSON: {e}")))?;

    let trades = resp.response.trades.ok_or(ParseError::TradeNotFound)?;
    let trade = trades.into_iter().next().ok_or(ParseError::TradeNotFound)?;

    let partner_steam_id = trade.steamid_other
        .and_then(|s| s.parse::<u64>().ok());

    let asset_id_given = first_cs2_status_assetid(&trade.assets_given);
    let asset_id = first_cs2_status_assetid(&trade.assets_received)
        .or(asset_id_given);

    Ok(TradeStatusData {
        status: trade.status,
        partner_steam_id,
        asset_id_given,
        asset_id,
        time_settlement: trade.time_settlement,
    })
}

// ============================================================================
// Steam Community HTML Parsing (manual — HTML is not JSON)
// ============================================================================

/// Parse Steam Community HTML response for fraud detection
pub fn parse_community_html(
    request: &[u8],
    response: &[u8],
) -> Result<CommunityProofData, ParseError> {
    let html = extract_http_body(response)?;
    let html_bytes = html.as_bytes();

    let prover_steam_id = extract_steam_id_from_cookie(request)?;
    let trade_offer_id = extract_trade_offer_id_from_url(request)
        .ok_or(ParseError::MissingTradeOfferId)?;

    let mut is_error_page = false;
    let mut has_not_found = false;
    let mut has_sign_in = false;
    let mut has_steam_id = false;

    const ERROR_TITLE: &[u8] = b"Steam Community :: Error";
    const NOT_EXIST: &[u8] = b"trade offer does not exist";
    const BELONGS_OTHER: &[u8] = b"belongs to another user";
    const SIGN_IN: &[u8] = b"Sign In";
    const STEAM_ID: &[u8] = b"g_steamID";

    let len = html_bytes.len();
    let mut i = 0;
    while i < len {
        let c = html_bytes[i];
        match c {
            b'S' => {
                if !is_error_page && i + ERROR_TITLE.len() <= len
                    && &html_bytes[i..i + ERROR_TITLE.len()] == ERROR_TITLE
                {
                    is_error_page = true;
                } else if !has_sign_in && i + SIGN_IN.len() <= len
                    && &html_bytes[i..i + SIGN_IN.len()] == SIGN_IN
                {
                    has_sign_in = true;
                }
            }
            b't' => {
                if !has_not_found && i + NOT_EXIST.len() <= len
                    && &html_bytes[i..i + NOT_EXIST.len()] == NOT_EXIST
                {
                    has_not_found = true;
                }
            }
            b'b' => {
                if !has_not_found && i + BELONGS_OTHER.len() <= len
                    && &html_bytes[i..i + BELONGS_OTHER.len()] == BELONGS_OTHER
                {
                    has_not_found = true;
                }
            }
            b'g' => {
                if !has_steam_id && i + STEAM_ID.len() <= len
                    && &html_bytes[i..i + STEAM_ID.len()] == STEAM_ID
                {
                    has_steam_id = true;
                }
            }
            _ => {}
        }
        i += 1;
    }

    let is_sign_in_page = has_sign_in && !has_steam_id;
    if is_sign_in_page {
        return Err(ParseError::MissingCookie);
    }

    let trade_not_found = is_error_page && has_not_found;
    if !trade_not_found {
        // Covers both "trade exists" (normal page) and unrecognized responses
        // (Steam outage, captcha, etc). Conservative: if we can't confirm the
        // trade doesn't exist, don't sign a refund. Prover can retry later.
        return Err(ParseError::CommunityTradeExists);
    }

    Ok(CommunityProofData {
        prover_steam_id,
        trade_offer_id,
        trade_not_found,
    })
}

/// Extract Steam ID from steamLoginSecure cookie.
///
/// Restricts search to `Cookie:` header line to prevent injection via URL query params.
pub fn extract_steam_id_from_cookie(request: &[u8]) -> Result<u64, ParseError> {
    // Find the Cookie header line (not URL/body)
    let cookie_header_pos = find_pattern(request, b"\r\nCookie:")
        .ok_or(ParseError::MissingCookie)?;
    let header_start = cookie_header_pos + 2; // skip \r\n
    let header_end = find_pattern(&request[header_start..], b"\r\n")
        .map(|pos| header_start + pos)
        .unwrap_or(request.len());
    let cookie_line = &request[header_start..header_end];

    let cookie_start = find_pattern(cookie_line, b"steamLoginSecure=")
        .ok_or(ParseError::MissingCookie)?;

    let value_start = cookie_start + b"steamLoginSecure=".len();

    let mut steam_id: u64 = 0;
    let mut i = value_start;
    let mut digit_count = 0;

    while i < cookie_line.len() && cookie_line[i].is_ascii_digit() {
        digit_count += 1;
        if digit_count > 20 {
            return Err(ParseError::NumberOverflow);
        }
        let digit = (cookie_line[i] - b'0') as u64;
        steam_id = steam_id.checked_mul(10)
            .and_then(|n| n.checked_add(digit))
            .ok_or(ParseError::NumberOverflow)?;
        i += 1;
    }

    if !(15..=18).contains(&digit_count) {
        return Err(ParseError::InvalidCookieFormat);
    }

    let has_delimiter = (i + 6 <= cookie_line.len() && &cookie_line[i..i+6] == b"%7C%7C")
        || (i + 2 <= cookie_line.len() && &cookie_line[i..i+2] == b"||");

    if !has_delimiter {
        return Err(ParseError::InvalidCookieFormat);
    }

    Ok(steam_id)
}

/// Extract trade_offer_id from Community URL path
pub fn extract_trade_offer_id_from_url(request: &[u8]) -> Option<u64> {
    let pattern_pos = find_pattern(request, b"/tradeoffer/")?;
    let start = pattern_pos + b"/tradeoffer/".len();

    let mut trade_id: u64 = 0;
    let mut i = start;
    let mut digit_count = 0;

    while i < request.len() && request[i].is_ascii_digit() {
        digit_count += 1;
        if digit_count > 20 {
            return None;
        }
        let digit = (request[i] - b'0') as u64;
        trade_id = trade_id.checked_mul(10).and_then(|n| n.checked_add(digit))?;
        i += 1;
    }

    if digit_count > 0 {
        Some(trade_id)
    } else {
        None
    }
}

/// Extract trade_offer_id from HTTP request URL query parameter
pub fn extract_trade_offer_id_from_request(request: &[u8]) -> Option<u64> {
    extract_number_after_pattern(request, b"tradeofferid=")
        .or_else(|| extract_number_after_pattern(request, b"tradeOfferid="))
        .or_else(|| extract_number_after_pattern(request, b"TradeOfferId="))
}

// ============================================================================
// Pattern Matching Utilities (for HTTP-level byte parsing)
// ============================================================================

pub fn find_pattern(data: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.is_empty() || data.len() < pattern.len() {
        return None;
    }
    (0..=data.len() - pattern.len()).find(|&i| &data[i..i + pattern.len()] == pattern)
}

/// Extract a number following a pattern in bytes (for HTTP query params, cookies)
fn extract_number_after_pattern(data: &[u8], pattern: &[u8]) -> Option<u64> {
    let pos = find_pattern(data, pattern)?;
    let start = pos + pattern.len();

    let mut i = start;
    while i < data.len() && (data[i] == b' ' || data[i] == b'"') {
        i += 1;
    }

    let mut num: u64 = 0;
    let mut digit_count = 0;
    const MAX_DIGITS: usize = 20;

    while i < data.len() && data[i].is_ascii_digit() {
        digit_count += 1;
        if digit_count > MAX_DIGITS {
            return None;
        }
        let digit = (data[i] - b'0') as u64;
        num = num.checked_mul(10).and_then(|n| n.checked_add(digit))?;
        i += 1;
    }

    if digit_count > 0 {
        Some(num)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_json_start() {
        let http = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"test\": true}";
        assert_eq!(find_json_start(http), Some(51));
    }

    #[test]
    fn test_detect_proof_source() {
        let trade_offer = b"GET /IEconService/GetTradeOffer/v1/?tradeofferid=123 HTTP/1.1";
        assert_eq!(detect_proof_source(trade_offer), Some(ProofSource::TradeOffer));

        let trade_status = b"GET /IEconService/GetTradeStatus/v1/?tradeid=123 HTTP/1.1";
        assert_eq!(detect_proof_source(trade_status), Some(ProofSource::TradeStatus));

        let community = b"GET /tradeoffer/8735365249 HTTP/1.1\r\nHost: steamcommunity.com";
        assert_eq!(detect_proof_source(community), Some(ProofSource::Community));
    }

    #[test]
    fn test_parse_trade_offer() {
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":3,"accountid_other":444017009,"items_to_receive":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let result = parse_trade_offer(json).unwrap();
        assert_eq!(result.trade_offer_id, 8653813160);
        assert_eq!(result.state, 3);
        assert_eq!(result.partner_steam_id, 76561198404282737);
        assert_eq!(result.asset_to_receive, Some(40964044588));
        assert_eq!(result.asset_to_give, None);
    }

    #[test]
    fn test_parse_trade_offer_empty() {
        let json = r#"{"response":{}}"#;
        assert!(matches!(parse_trade_offer(json), Err(ParseError::TradeNotFound)));
    }

    #[test]
    fn test_parse_trade_offer_with_is_our_offer() {
        let json = r#"{"response":{"offer":{"tradeofferid":"123","trade_offer_state":5,"accountid_other":100,"is_our_offer":true,"items_to_give":[{"appid":730,"assetid":"999"}]}}}"#;
        let result = parse_trade_offer(json).unwrap();
        assert!(result.is_our_offer);
        assert_eq!(result.asset_to_give, Some(999));
    }

    #[test]
    fn test_parse_trade_offer_non_cs2_items() {
        let json = r#"{"response":{"offer":{"tradeofferid":"123","trade_offer_state":3,"accountid_other":100,"items_to_receive":[{"appid":440,"assetid":"111"},{"appid":730,"assetid":"222"}]}}}"#;
        let result = parse_trade_offer(json).unwrap();
        assert_eq!(result.asset_to_receive, Some(222));
    }

    #[test]
    fn test_parse_trade_status() {
        let json = r#"{"response":{"trades":[{"tradeid":"698750883296824050","steamid_other":"76561198404282737","status":3,"assets_given":[{"appid":730,"assetid":"44815125678"}],"time_settlement":1766476800}]}}"#;
        let result = parse_trade_status(json).unwrap();
        assert_eq!(result.status, 3);
        assert_eq!(result.partner_steam_id, Some(76561198404282737));
        assert_eq!(result.asset_id_given, Some(44815125678));
        assert_eq!(result.time_settlement, Some(1766476800));
    }

    #[test]
    fn test_parse_trade_status_empty() {
        let json = r#"{"response":{}}"#;
        assert!(matches!(parse_trade_status(json), Err(ParseError::TradeNotFound)));
    }

    #[test]
    fn test_extract_steam_id_from_cookie() {
        let request = b"GET /tradeoffer/123 HTTP/1.1\r\nCookie: steamLoginSecure=76561198366018280%7C%7CeyToken";
        assert_eq!(extract_steam_id_from_cookie(request).unwrap(), 76561198366018280);
    }

    #[test]
    fn test_extract_trade_offer_id_from_url() {
        let request = b"GET /tradeoffer/8735365249 HTTP/1.1";
        assert_eq!(extract_trade_offer_id_from_url(request), Some(8735365249));
    }

    #[test]
    fn test_extract_trade_offer_id_from_request() {
        let request = b"GET /IEconService/GetTradeOffer/v1/?tradeofferid=8653813160 HTTP/1.1";
        assert_eq!(extract_trade_offer_id_from_request(request), Some(8653813160));
    }

    #[test]
    fn test_parse_community_html_not_found() {
        let request = b"GET /tradeoffer/8735365249 HTTP/1.1\r\nCookie: steamLoginSecure=76561198366018280%7C%7CeyToken";
        let response = b"HTTP/1.1 200 OK\r\n\r\n<title>Steam Community :: Error</title>The trade offer does not exist, or the trade offer belongs to another user.";
        let result = parse_community_html(request, response).unwrap();
        assert_eq!(result.trade_offer_id, 8735365249);
        assert_eq!(result.prover_steam_id, 76561198366018280);
        assert!(result.trade_not_found);
    }

    #[test]
    fn test_parse_community_html_trade_exists() {
        // Normal trade page (trade exists) → refund rejected
        let request = b"GET /tradeoffer/123 HTTP/1.1\r\nCookie: steamLoginSecure=76561198366018280%7C%7CeyToken";
        let response = b"HTTP/1.1 200 OK\r\n\r\n<html><script>var g_steamID = '76561198366018280';</script><div>Trade Offer</div></html>";
        let result = parse_community_html(request, response);
        assert!(matches!(result, Err(ParseError::CommunityTradeExists)));
    }

    #[test]
    fn test_parse_community_html_unrecognized_response_is_conservative() {
        // Unrecognized response (Steam outage, captcha, etc.) → also rejects
        // Conservative: "can't confirm trade doesn't exist → don't sign refund"
        let request = b"GET /tradeoffer/123 HTTP/1.1\r\nCookie: steamLoginSecure=76561198366018280%7C%7CeyToken";
        let response = b"HTTP/1.1 200 OK\r\n\r\n<html>Something unexpected</html>";
        let result = parse_community_html(request, response);
        assert!(matches!(result, Err(ParseError::CommunityTradeExists)));
    }

    #[test]
    fn test_parse_community_html_sign_in_page() {
        // Sign-in page = prover not logged in → MissingCookie
        let request = b"GET /tradeoffer/123 HTTP/1.1\r\nCookie: steamLoginSecure=76561198366018280%7C%7CeyToken";
        let response = b"HTTP/1.1 200 OK\r\n\r\n<html>Sign In</html>";
        let result = parse_community_html(request, response);
        assert!(matches!(result, Err(ParseError::MissingCookie)));
    }

    #[test]
    fn test_detect_proof_source_pattern_in_cookie_still_detects() {
        // "GetTradeOffer" in a cookie — detect_proof_source will find it.
        // This is safe because oracle::decide() cross-validates server_name from TLS SNI.
        let request = b"GET /some/other/endpoint HTTP/1.1\r\nCookie: ref=GetTradeOffer\r\n\r\n";
        // Pattern found in cookie → classified as TradeOffer
        assert_eq!(detect_proof_source(request), Some(ProofSource::TradeOffer));
        // But oracle::decide() would reject this if server_name != "api.steampowered.com"
    }

    #[test]
    fn test_detect_proof_source_no_match() {
        let request = b"GET /some/random/path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(detect_proof_source(request), None);
    }
}
