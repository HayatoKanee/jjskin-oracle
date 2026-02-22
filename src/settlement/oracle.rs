//! Core settlement decision engine.
//!
//! Takes MPC-TLS plaintext (server_name, sent/recv bytes) + escrow snapshot,
//! validates the Steam response, and determines Release or Refund.

use super::decision;
use super::parsing::{
    self, ParseError, detect_proof_source, extract_http_body, extract_trade_offer_id_from_request,
};
use super::types::{Decision, EscrowSnapshot, ProofSource, RefundReason, Settlement};

/// Steam API server hostname
const STEAM_API_HOST: &str = "api.steampowered.com";

/// Steam Community server hostname
const STEAM_COMMUNITY_HOST: &str = "steamcommunity.com";

#[derive(Debug)]
pub enum SettlementError {
    InvalidServer(String),
    UnknownProofSource,
    ParseFailed(ParseError),
    TradeOfferIdMismatch { expected: u64, got: u64 },
    AssetIdMismatch { expected: u64, got: Option<u64> },
    PartnerMismatch { expected: u64, got: u64 },
    NonTerminalState(u32),
    /// Too early to claim trade abandonment (must wait 24h from purchase)
    TooEarlyForAbandonment {
        proof_timestamp: u64,
        deadline: u64,
    },
    /// Release proof invalid: assetId not in assets_given
    InvalidReleaseProof { asset_id: u64 },
    /// time_settlement missing from GetTradeStatus (cannot verify escrow)
    MissingTimeSettlement,
    /// Escrow period not yet passed
    EscrowNotPassed {
        time_settlement: u64,
        proof_timestamp: u64,
    },
}

impl std::fmt::Display for SettlementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SettlementError::InvalidServer(s) => write!(f, "Invalid server: {s}"),
            SettlementError::UnknownProofSource => write!(f, "Unknown proof source from request URL"),
            SettlementError::ParseFailed(e) => write!(f, "Parse error: {e}"),
            SettlementError::TradeOfferIdMismatch { expected, got } => {
                write!(f, "TradeOfferId mismatch: expected {expected}, got {got}")
            }
            SettlementError::AssetIdMismatch { expected, got } => {
                write!(f, "AssetId mismatch: expected {expected}, got {got:?}")
            }
            SettlementError::PartnerMismatch { expected, got } => {
                write!(f, "Partner SteamId mismatch: expected {expected}, got {got}")
            }
            SettlementError::NonTerminalState(s) => {
                write!(f, "Non-terminal trade state: {s}")
            }
            SettlementError::TooEarlyForAbandonment { proof_timestamp, deadline } => {
                write!(f, "Too early to claim abandonment: proof_time={proof_timestamp}, deadline={deadline}")
            }
            SettlementError::InvalidReleaseProof { asset_id } => {
                write!(f, "Invalid Release proof: assetId {asset_id} not in assets_given")
            }
            SettlementError::MissingTimeSettlement => {
                write!(f, "time_settlement missing — cannot verify escrow period")
            }
            SettlementError::EscrowNotPassed { time_settlement, proof_timestamp } => {
                write!(f, "Escrow not passed: time_settlement={time_settlement} > proof_timestamp={proof_timestamp}")
            }
        }
    }
}

impl std::error::Error for SettlementError {}

/// Core decision function: parse MPC-TLS plaintext + validate against escrow.
///
/// # Arguments
/// * `server_name` - TLS server name from VerifierOutput (e.g. "api.steampowered.com")
/// * `sent_bytes` - Raw HTTP request bytes from MPC-TLS transcript
/// * `recv_bytes` - Raw HTTP response bytes from MPC-TLS transcript
/// * `escrow` - On-chain escrow snapshot from the extension
///
/// # Returns
/// * `Ok(Settlement)` - Decision to release or refund
/// * `Err(SettlementError)` - Validation failed
pub fn decide(
    server_name: &str,
    sent_bytes: &[u8],
    recv_bytes: &[u8],
    escrow: &EscrowSnapshot,
    proof_timestamp: u64,
) -> Result<Settlement, SettlementError> {
    // 1. Validate server is a Steam server
    if server_name != STEAM_API_HOST && server_name != STEAM_COMMUNITY_HOST {
        return Err(SettlementError::InvalidServer(server_name.to_string()));
    }

    // 2. Detect proof source from request URL, cross-validated with server_name
    let proof_source = detect_proof_source(sent_bytes)
        .ok_or(SettlementError::UnknownProofSource)?;

    // Cross-validate: API proof sources must come from API host, community from community host
    match proof_source {
        ProofSource::TradeOffer | ProofSource::TradeStatus if server_name != STEAM_API_HOST => {
            return Err(SettlementError::InvalidServer(format!(
                "API proof source {:?} from non-API host: {}", proof_source, server_name
            )));
        }
        ProofSource::Community if server_name != STEAM_COMMUNITY_HOST => {
            return Err(SettlementError::InvalidServer(format!(
                "Community proof from non-community host: {}", server_name
            )));
        }
        _ => {}
    }

    // 3. Extract HTTP body and parse
    let body = extract_http_body(recv_bytes)
        .map_err(SettlementError::ParseFailed)?;

    match proof_source {
        ProofSource::TradeOffer => decide_trade_offer(sent_bytes, &body, escrow),
        ProofSource::TradeStatus => decide_trade_status(&body, escrow, proof_timestamp),
        ProofSource::Community => decide_community(sent_bytes, recv_bytes, escrow, proof_timestamp),
    }
}

/// Decide based on GetTradeOffer response (refund path ONLY, never Release)
///
/// GetTradeOffer state 3 = "Accepted" (offer accepted, NOT completed).
/// Release ONLY comes from GetTradeStatus status 3 = "Complete" (items exchanged).
///
/// Matches zkVM oracle: decide_trade_offer in methods/guest/src/main.rs
fn decide_trade_offer(
    sent_bytes: &[u8],
    json: &str,
    escrow: &EscrowSnapshot,
) -> Result<Settlement, SettlementError> {
    let data = parsing::parse_trade_offer(json)
        .map_err(SettlementError::ParseFailed)?;

    // ① Validate tradeOfferId from REQUEST URL matches escrow
    // (defense in depth: verify both request URL and response body)
    if let Some(request_trade_offer_id) = extract_trade_offer_id_from_request(sent_bytes) {
        if request_trade_offer_id != escrow.trade_offer_id {
            return Err(SettlementError::TradeOfferIdMismatch {
                expected: escrow.trade_offer_id,
                got: request_trade_offer_id,
            });
        }
    }

    // Also validate tradeOfferId from response
    if data.trade_offer_id != escrow.trade_offer_id {
        return Err(SettlementError::TradeOfferIdMismatch {
            expected: escrow.trade_offer_id,
            got: data.trade_offer_id,
        });
    }

    // ② accountid_other must be seller or buyer
    if data.partner_steam_id != escrow.seller_steam_id
        && data.partner_steam_id != escrow.buyer_steam_id
    {
        return Ok(Settlement {
            asset_id: escrow.asset_id,
            trade_offer_id: escrow.trade_offer_id,
            decision: Decision::Refund,
            refund_reason: RefundReason::WrongParties,
        });
    }

    // ③ Determine capturer identity
    // If partner is buyer, capturer is seller. If partner is seller, capturer is buyer.
    let capturer_is_seller = data.partner_steam_id == escrow.buyer_steam_id;

    // ④ Validate CS2 asset in the CORRECT array based on capturer
    // Seller captures → item in items_to_give (seller sends item)
    // Buyer captures → item in items_to_receive (buyer receives item)
    let proof_asset_id = if capturer_is_seller {
        data.asset_to_give
    } else {
        data.asset_to_receive
    };

    let Some(proof_asset_id) = proof_asset_id else {
        return Ok(Settlement {
            asset_id: escrow.asset_id,
            trade_offer_id: escrow.trade_offer_id,
            decision: Decision::Refund,
            refund_reason: RefundReason::NotCS2Item,
        });
    };

    // ⑤ assetId must match escrow
    if proof_asset_id != escrow.asset_id {
        return Ok(Settlement {
            asset_id: escrow.asset_id,
            trade_offer_id: escrow.trade_offer_id,
            decision: Decision::Refund,
            refund_reason: RefundReason::WrongAsset,
        });
    }

    // ⑥ Determine who created the offer (for fault attribution)
    let seller_created_offer = decision::determine_seller_created_offer(
        capturer_is_seller,
        data.is_our_offer,
    );

    // ⑦ trade_offer_state determines refund reason with fault attribution
    // Terminal failure states only: 5=Expired, 6=Canceled, 7=Declined, 8=InvalidItems, 10=Canceled2FA
    // ALL other states (including 3=Accepted) are non-terminal → error
    let refund_reason = match data.state {
        5 => decision::fault_for_expired(seller_created_offer),
        6 => decision::fault_for_canceled(seller_created_offer),
        7 => decision::fault_for_declined(seller_created_offer),
        8 => RefundReason::InvalidItems,
        10 => RefundReason::Canceled2FA,
        // State 3 = Accepted is NOT terminal for GetTradeOffer.
        // Release comes from GetTradeStatus status 3 = Complete.
        _ => return Err(SettlementError::NonTerminalState(data.state)),
    };

    Ok(Settlement {
        asset_id: escrow.asset_id,
        trade_offer_id: escrow.trade_offer_id,
        decision: Decision::Refund,
        refund_reason,
    })
}

/// Decide based on GetTradeStatus response (release + rollback paths)
///
/// Matches zkVM oracle: decide_trade_status in methods/guest/src/main.rs
///
/// - status=3 → Release (trade completed, requires asset_id_given + partner=buyer + time_settlement)
/// - status=4-9,11 → Refund(DeprecatedRollback) — deprecated rollback states
/// - status=12 → Refund(TradeRollback) — current rollback state
/// - Other → NonTerminalState error (includes 0,1,2,10 and unknown)
fn decide_trade_status(
    json: &str,
    escrow: &EscrowSnapshot,
    proof_timestamp: u64,
) -> Result<Settlement, SettlementError> {
    let data = parsing::parse_trade_status(json)
        .map_err(SettlementError::ParseFailed)?;

    match data.status {
        // RELEASE PATH (status == 3 Complete)
        3 => {
            // ① assetId must be in assets_given (seller sent the CS2 item)
            // Use asset_id_given, NOT asset_id — verifies seller actually SENT the item
            if data.asset_id_given != Some(escrow.asset_id) {
                return Err(SettlementError::InvalidReleaseProof {
                    asset_id: escrow.asset_id,
                });
            }

            // ② steamid_other must be buyer (required for Release)
            let partner_steam_id = data.partner_steam_id
                .ok_or(SettlementError::ParseFailed(ParseError::JsonParse(
                    "Missing steamid_other in completed trade".into()
                )))?;
            if partner_steam_id != escrow.buyer_steam_id {
                return Ok(Settlement {
                    asset_id: escrow.asset_id,
                    trade_offer_id: escrow.trade_offer_id,
                    decision: Decision::Refund,
                    refund_reason: RefundReason::WrongRecipient,
                });
            }

            // ③ time_settlement MUST exist and have passed
            let time_settlement = data.time_settlement
                .ok_or(SettlementError::MissingTimeSettlement)?;
            if time_settlement > proof_timestamp {
                return Err(SettlementError::EscrowNotPassed {
                    time_settlement,
                    proof_timestamp,
                });
            }

            // All checks passed — RELEASE
            Ok(Settlement {
                asset_id: escrow.asset_id,
                trade_offer_id: escrow.trade_offer_id,
                decision: Decision::Release,
                refund_reason: RefundReason::None,
            })
        }

        // REFUND PATH: Deprecated rollback states (4-9, 11)
        4 | 5 | 6 | 7 | 8 | 9 | 11 => {
            // Validate asset is in trade
            if data.asset_id != Some(escrow.asset_id) {
                return Err(SettlementError::AssetIdMismatch {
                    expected: escrow.asset_id,
                    got: data.asset_id,
                });
            }

            Ok(Settlement {
                asset_id: escrow.asset_id,
                trade_offer_id: escrow.trade_offer_id,
                decision: Decision::Refund,
                refund_reason: RefundReason::DeprecatedRollback,
            })
        }

        // REFUND PATH (status == 12 Rollback)
        12 => {
            // Validate asset is in trade
            if data.asset_id != Some(escrow.asset_id) {
                return Err(SettlementError::AssetIdMismatch {
                    expected: escrow.asset_id,
                    got: data.asset_id,
                });
            }

            Ok(Settlement {
                asset_id: escrow.asset_id,
                trade_offer_id: escrow.trade_offer_id,
                decision: Decision::Refund,
                refund_reason: RefundReason::TradeRollback,
            })
        }

        // Other statuses — non-terminal or unsupported
        // Includes: 0 (Init), 1 (PreCommitted), 2 (Committed), 10, and unknown
        status => Err(SettlementError::NonTerminalState(status)),
    }
}

/// Decide based on Community HTML page (trade-not-found proof → refund)
///
/// Matches zkVM oracle: decide_community in methods/guest/src/main.rs
///
/// Checks:
/// 1. tradeOfferId in URL matches escrow
/// 2. Prover (from cookie) must be buyer or seller
/// 3. HTML must show "trade does not exist"
/// 4. Must wait 24h from purchase before claiming abandonment
///    (trade may be invisible while seller confirms on mobile)
fn decide_community(
    sent_bytes: &[u8],
    recv_bytes: &[u8],
    escrow: &EscrowSnapshot,
    proof_timestamp: u64,
) -> Result<Settlement, SettlementError> {
    let data = parsing::parse_community_html(sent_bytes, recv_bytes)
        .map_err(SettlementError::ParseFailed)?;

    // ① Validate trade offer ID
    if data.trade_offer_id != escrow.trade_offer_id {
        return Err(SettlementError::TradeOfferIdMismatch {
            expected: escrow.trade_offer_id,
            got: data.trade_offer_id,
        });
    }

    // ② Prover (cookie steamid) must be buyer or seller
    if data.prover_steam_id != escrow.seller_steam_id
        && data.prover_steam_id != escrow.buyer_steam_id
    {
        return Err(SettlementError::PartnerMismatch {
            expected: escrow.buyer_steam_id,
            got: data.prover_steam_id,
        });
    }

    // ③ HTML must show "trade does not exist"
    if !data.trade_not_found {
        return Err(SettlementError::ParseFailed(ParseError::CommunityTradeExists));
    }

    // ④ Time check: must wait 24 hours from purchase before claiming abandonment
    // Trade may be invisible to buyer while seller confirms on mobile.
    // Must match the on-chain abandonedWindow (default 24h, owner-adjustable 12h-72h).
    // If the contract owner changes abandonedWindow, update this value to match.
    const ABANDONED_WINDOW_SECS: u64 = 24 * 60 * 60; // 24 hours
    let abandonment_deadline = escrow.purchase_time + ABANDONED_WINDOW_SECS;

    if proof_timestamp < abandonment_deadline {
        return Err(SettlementError::TooEarlyForAbandonment {
            proof_timestamp,
            deadline: abandonment_deadline,
        });
    }

    Ok(Settlement {
        asset_id: escrow.asset_id,
        trade_offer_id: escrow.trade_offer_id,
        decision: Decision::Refund,
        refund_reason: RefundReason::TradeNotExist,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Default proof timestamp: well after purchase_time + 24h
    const NOW: u64 = 1700200000;

    fn test_escrow() -> EscrowSnapshot {
        EscrowSnapshot {
            asset_id: 40964044588,
            trade_offer_id: 8653813160,
            seller_steam_id: 76561198366018280,
            buyer_steam_id: 76561198404282737,
            seller: [0; 20],
            buyer: [0; 20],
            amount: 1000000,
            purchase_time: 1700000000,
        }
    }

    fn make_http_response(json: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{json}").into_bytes()
    }

    fn make_trade_offer_request(capturer_steam_id: u64) -> Vec<u8> {
        format!(
            "GET /IEconService/GetTradeOffer/v1/?tradeofferid=8653813160 HTTP/1.1\r\n\
             Host: api.steampowered.com\r\n\
             Cookie: steamLoginSecure={capturer_steam_id}%7C%7CeyToken\r\n\r\n"
        ).into_bytes()
    }

    fn make_trade_status_request() -> Vec<u8> {
        b"GET /IEconService/GetTradeStatus/v1/?tradeid=123 HTTP/1.1\r\n\
          Host: api.steampowered.com\r\n\r\n".to_vec()
    }

    /// Helper: API access token request (no steamLoginSecure cookie)
    fn make_trade_offer_request_api_token() -> Vec<u8> {
        b"GET /IEconService/GetTradeOffer/v1/?format=json&get_descriptions=false&tradeofferid=8653813160&access_token=SECRET HTTP/1.1\r\n\
          Host: api.steampowered.com\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n".to_vec()
    }

    // ========================================================================
    // GetTradeOffer tests (refund path only, NEVER Release)
    // ========================================================================

    #[test]
    fn test_trade_offer_state3_is_non_terminal() {
        // State 3 = Accepted in GetTradeOffer — NOT terminal.
        // Release comes from GetTradeStatus status 3 = Complete.
        let escrow = test_escrow();
        let sent = make_trade_offer_request(escrow.seller_steam_id);
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":3,"accountid_other":444017009,"items_to_give":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW);
        assert!(matches!(result, Err(SettlementError::NonTerminalState(3))));
    }

    #[test]
    fn test_trade_offer_expired_seller_created() {
        let escrow = test_escrow();
        // Seller captures → partner=buyer(444017009), is_our_offer=true → seller created → BuyerExpired
        // Seller captures → asset must be in items_to_give
        let sent = make_trade_offer_request(escrow.seller_steam_id);
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":5,"accountid_other":444017009,"is_our_offer":true,"items_to_give":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW).unwrap();
        assert_eq!(result.decision, Decision::Refund);
        assert_eq!(result.refund_reason, RefundReason::BuyerExpired);
    }

    #[test]
    fn test_trade_offer_expired_buyer_created() {
        let escrow = test_escrow();
        // Buyer captures → partner=seller, is_our_offer=true → buyer created → SellerExpired
        // Buyer captures → asset in items_to_receive
        let sent = make_trade_offer_request(escrow.buyer_steam_id);
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":5,"accountid_other":405752552,"is_our_offer":true,"items_to_receive":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW).unwrap();
        assert_eq!(result.decision, Decision::Refund);
        assert_eq!(result.refund_reason, RefundReason::SellerExpired);
    }

    #[test]
    fn test_trade_offer_canceled_by_2fa() {
        let escrow = test_escrow();
        // Seller captures → asset in items_to_give
        let sent = make_trade_offer_request(escrow.seller_steam_id);
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":10,"accountid_other":444017009,"items_to_give":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW).unwrap();
        assert_eq!(result.decision, Decision::Refund);
        assert_eq!(result.refund_reason, RefundReason::Canceled2FA);
    }

    #[test]
    fn test_trade_offer_wrong_parties() {
        let escrow = test_escrow();
        let sent = make_trade_offer_request_api_token();
        // accountid_other=999 → neither buyer nor seller → WrongParties refund
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":5,"accountid_other":999,"items_to_receive":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW).unwrap();
        assert_eq!(result.decision, Decision::Refund);
        assert_eq!(result.refund_reason, RefundReason::WrongParties);
    }

    #[test]
    fn test_trade_offer_not_cs2_item() {
        let escrow = test_escrow();
        // Seller captures → should check items_to_give, but no CS2 asset there
        let sent = make_trade_offer_request(escrow.seller_steam_id);
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":5,"accountid_other":444017009,"items_to_receive":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW).unwrap();
        assert_eq!(result.decision, Decision::Refund);
        assert_eq!(result.refund_reason, RefundReason::NotCS2Item);
    }

    #[test]
    fn test_trade_offer_wrong_asset() {
        let escrow = test_escrow();
        // Seller captures → items_to_give has wrong assetId
        let sent = make_trade_offer_request(escrow.seller_steam_id);
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":5,"accountid_other":444017009,"items_to_give":[{"appid":730,"assetid":"99999999"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW).unwrap();
        assert_eq!(result.decision, Decision::Refund);
        assert_eq!(result.refund_reason, RefundReason::WrongAsset);
    }

    #[test]
    fn test_trade_offer_id_mismatch() {
        let escrow = test_escrow();
        let sent = make_trade_offer_request(escrow.seller_steam_id);
        let json = r#"{"response":{"offer":{"tradeofferid":"999999","trade_offer_state":5,"accountid_other":444017009,"items_to_give":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW);
        assert!(matches!(result, Err(SettlementError::TradeOfferIdMismatch { .. })));
    }

    #[test]
    fn test_trade_offer_non_terminal_state() {
        let escrow = test_escrow();
        let sent = make_trade_offer_request(escrow.seller_steam_id);
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":2,"accountid_other":444017009,"items_to_give":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW);
        assert!(matches!(result, Err(SettlementError::NonTerminalState(2))));
    }

    #[test]
    fn test_trade_offer_api_token_expired() {
        let escrow = test_escrow();
        let sent = make_trade_offer_request_api_token();
        // No cookie → partner=buyer(444017009) → capturer=seller
        // Seller captures → items_to_give
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":5,"accountid_other":444017009,"is_our_offer":true,"items_to_give":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW).unwrap();
        assert_eq!(result.decision, Decision::Refund);
        assert_eq!(result.refund_reason, RefundReason::BuyerExpired);
    }

    // ========================================================================
    // GetTradeStatus tests (release + rollback paths)
    // ========================================================================

    #[test]
    fn test_trade_status_complete_release() {
        let escrow = test_escrow();
        let sent = make_trade_status_request();
        let json = r#"{"response":{"trades":[{"tradeid":"698750883296824050","steamid_other":"76561198404282737","status":3,"assets_given":[{"appid":730,"assetid":"40964044588"}],"time_settlement":1700100000}]}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW).unwrap();
        assert_eq!(result.decision, Decision::Release);
        assert_eq!(result.refund_reason, RefundReason::None);
    }

    #[test]
    fn test_trade_status_complete_wrong_recipient() {
        let escrow = test_escrow();
        let sent = make_trade_status_request();
        // steamid_other is seller, not buyer → WrongRecipient
        let json = r#"{"response":{"trades":[{"tradeid":"123","steamid_other":"76561198366018280","status":3,"assets_given":[{"appid":730,"assetid":"40964044588"}],"time_settlement":1700100000}]}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW).unwrap();
        assert_eq!(result.decision, Decision::Refund);
        assert_eq!(result.refund_reason, RefundReason::WrongRecipient);
    }

    #[test]
    fn test_trade_status_complete_missing_asset_given() {
        let escrow = test_escrow();
        let sent = make_trade_status_request();
        // No assets_given → InvalidReleaseProof
        let json = r#"{"response":{"trades":[{"tradeid":"123","steamid_other":"76561198404282737","status":3,"time_settlement":1700100000}]}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW);
        assert!(matches!(result, Err(SettlementError::InvalidReleaseProof { .. })));
    }

    #[test]
    fn test_trade_status_complete_escrow_not_passed() {
        let escrow = test_escrow();
        let sent = make_trade_status_request();
        // time_settlement is in the future relative to proof_timestamp
        let json = r#"{"response":{"trades":[{"tradeid":"123","steamid_other":"76561198404282737","status":3,"assets_given":[{"appid":730,"assetid":"40964044588"}],"time_settlement":1700300000}]}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW);
        assert!(matches!(result, Err(SettlementError::EscrowNotPassed { .. })));
    }

    #[test]
    fn test_trade_status_complete_missing_time_settlement() {
        let escrow = test_escrow();
        let sent = make_trade_status_request();
        let json = r#"{"response":{"trades":[{"tradeid":"123","steamid_other":"76561198404282737","status":3,"assets_given":[{"appid":730,"assetid":"40964044588"}]}]}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW);
        assert!(matches!(result, Err(SettlementError::MissingTimeSettlement)));
    }

    #[test]
    fn test_trade_status_rollback_refund() {
        let escrow = test_escrow();
        let sent = make_trade_status_request();
        let json = r#"{"response":{"trades":[{"tradeid":"123","steamid_other":"76561198404282737","status":12,"assets_received":[{"appid":730,"assetid":"40964044588"}]}]}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW).unwrap();
        assert_eq!(result.decision, Decision::Refund);
        assert_eq!(result.refund_reason, RefundReason::TradeRollback);
    }

    #[test]
    fn test_trade_status_deprecated_rollback() {
        let escrow = test_escrow();
        let sent = make_trade_status_request();
        // Status 4 = deprecated rollback
        let json = r#"{"response":{"trades":[{"tradeid":"123","steamid_other":"76561198404282737","status":4,"assets_received":[{"appid":730,"assetid":"40964044588"}]}]}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW).unwrap();
        assert_eq!(result.decision, Decision::Refund);
        assert_eq!(result.refund_reason, RefundReason::DeprecatedRollback);
    }

    #[test]
    fn test_trade_status_non_terminal() {
        let escrow = test_escrow();
        let sent = make_trade_status_request();
        // Status 1 = PreCommitted → non-terminal
        let json = r#"{"response":{"trades":[{"tradeid":"123","steamid_other":"76561198404282737","status":1}]}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW);
        assert!(matches!(result, Err(SettlementError::NonTerminalState(1))));
    }

    // ========================================================================
    // Community HTML tests (trade-not-found → refund)
    // ========================================================================

    #[test]
    fn test_community_trade_not_found_refund() {
        let escrow = test_escrow();
        let request = b"GET /tradeoffer/8653813160 HTTP/1.1\r\nHost: steamcommunity.com\r\nCookie: steamLoginSecure=76561198404282737%7C%7CeyToken\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\n\r\n<title>Steam Community :: Error</title>The trade offer does not exist, or the trade offer belongs to another user.";

        let result = decide(STEAM_COMMUNITY_HOST, request, response, &escrow, NOW).unwrap();
        assert_eq!(result.decision, Decision::Refund);
        assert_eq!(result.refund_reason, RefundReason::TradeNotExist);
    }

    #[test]
    fn test_community_wrong_prover() {
        let escrow = test_escrow();
        // Prover steam ID is neither buyer nor seller
        let request = b"GET /tradeoffer/8653813160 HTTP/1.1\r\nHost: steamcommunity.com\r\nCookie: steamLoginSecure=76561198000000000%7C%7CeyToken\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\n\r\n<title>Steam Community :: Error</title>The trade offer does not exist.";

        let result = decide(STEAM_COMMUNITY_HOST, request, response, &escrow, NOW);
        assert!(matches!(result, Err(SettlementError::PartnerMismatch { .. })));
    }

    #[test]
    fn test_community_too_early_for_abandonment() {
        let escrow = test_escrow();
        let request = b"GET /tradeoffer/8653813160 HTTP/1.1\r\nHost: steamcommunity.com\r\nCookie: steamLoginSecure=76561198404282737%7C%7CeyToken\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\n\r\n<title>Steam Community :: Error</title>The trade offer does not exist.";

        // proof_timestamp = purchase_time + 1 hour (too early, need 24h)
        let too_early = escrow.purchase_time + 3600;
        let result = decide(STEAM_COMMUNITY_HOST, request, response, &escrow, too_early);
        assert!(matches!(result, Err(SettlementError::TooEarlyForAbandonment { .. })));
    }

    #[test]
    fn test_community_after_24h_ok() {
        let escrow = test_escrow();
        let request = b"GET /tradeoffer/8653813160 HTTP/1.1\r\nHost: steamcommunity.com\r\nCookie: steamLoginSecure=76561198366018280%7C%7CeyToken\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\n\r\n<title>Steam Community :: Error</title>The trade offer does not exist, or the trade offer belongs to another user.";

        // proof_timestamp = purchase_time + 25 hours (past 24h deadline)
        let after_24h = escrow.purchase_time + 25 * 3600;
        let result = decide(STEAM_COMMUNITY_HOST, request, response, &escrow, after_24h).unwrap();
        assert_eq!(result.decision, Decision::Refund);
        assert_eq!(result.refund_reason, RefundReason::TradeNotExist);
    }

    // ========================================================================
    // GetTradeOffer: All trade_offer_state values (exhaustive)
    // ========================================================================

    #[test]
    fn test_trade_offer_all_non_terminal_states() {
        let escrow = test_escrow();
        // States 1,2,3,4,9,11 are all non-terminal for GetTradeOffer
        for state in [1, 2, 3, 4, 9, 11] {
            let sent = make_trade_offer_request(escrow.seller_steam_id);
            let json = format!(
                r#"{{"response":{{"offer":{{"tradeofferid":"8653813160","trade_offer_state":{state},"accountid_other":444017009,"items_to_give":[{{"appid":730,"assetid":"40964044588"}}]}}}}}}"#
            );
            let recv = make_http_response(&json);
            let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW);
            assert!(
                matches!(result, Err(SettlementError::NonTerminalState(s)) if s == state),
                "State {state} should be NonTerminalState"
            );
        }
    }

    #[test]
    fn test_trade_offer_all_terminal_states() {
        let escrow = test_escrow();
        // States 5,6,7,8,10 are terminal refund states
        let expected_reasons = [
            (5, RefundReason::BuyerExpired),   // seller captured, seller created
            (6, RefundReason::SellerCanceled),  // seller captured, seller created
            (7, RefundReason::BuyerDeclined),   // seller captured, seller created
            (8, RefundReason::InvalidItems),
            (10, RefundReason::Canceled2FA),
        ];
        for (state, expected_reason) in expected_reasons {
            let sent = make_trade_offer_request(escrow.seller_steam_id);
            let json = format!(
                r#"{{"response":{{"offer":{{"tradeofferid":"8653813160","trade_offer_state":{state},"accountid_other":444017009,"is_our_offer":true,"items_to_give":[{{"appid":730,"assetid":"40964044588"}}]}}}}}}"#
            );
            let recv = make_http_response(&json);
            let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW).unwrap();
            assert_eq!(result.decision, Decision::Refund, "State {state} should be Refund");
            assert_eq!(result.refund_reason, expected_reason, "State {state} wrong reason");
        }
    }

    // ========================================================================
    // GetTradeOffer: Capturer identity (buyer vs seller captures proof)
    // ========================================================================

    #[test]
    fn test_trade_offer_buyer_captures_seller_created() {
        let escrow = test_escrow();
        // Buyer captures → partner=seller(405752552), is_our_offer=false → seller created
        // Buyer captures → asset in items_to_receive
        let sent = make_trade_offer_request(escrow.buyer_steam_id);
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":5,"accountid_other":405752552,"is_our_offer":false,"items_to_receive":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW).unwrap();
        assert_eq!(result.refund_reason, RefundReason::BuyerExpired); // seller created → buyer at fault
    }

    #[test]
    fn test_trade_offer_buyer_captures_buyer_created() {
        let escrow = test_escrow();
        // Buyer captures → partner=seller, is_our_offer=true → buyer created
        let sent = make_trade_offer_request(escrow.buyer_steam_id);
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":5,"accountid_other":405752552,"is_our_offer":true,"items_to_receive":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW).unwrap();
        assert_eq!(result.refund_reason, RefundReason::SellerExpired); // buyer created → seller at fault
    }

    #[test]
    fn test_trade_offer_canceled_fault_attribution() {
        let escrow = test_escrow();
        // Seller captures, seller created, cancels own offer → SellerCanceled
        let sent = make_trade_offer_request(escrow.seller_steam_id);
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":6,"accountid_other":444017009,"is_our_offer":true,"items_to_give":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW).unwrap();
        assert_eq!(result.refund_reason, RefundReason::SellerCanceled);
    }

    #[test]
    fn test_trade_offer_declined_fault_attribution() {
        let escrow = test_escrow();
        // Buyer captures, seller created, buyer declines → BuyerDeclined
        let sent = make_trade_offer_request(escrow.buyer_steam_id);
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":7,"accountid_other":405752552,"is_our_offer":false,"items_to_receive":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW).unwrap();
        assert_eq!(result.refund_reason, RefundReason::BuyerDeclined);
    }

    // ========================================================================
    // GetTradeOffer: Third-party / collusion attack vectors
    // ========================================================================

    #[test]
    fn test_trade_offer_third_party_colluded_with_seller() {
        // Attack: Malicious seller colludes with third party (not buyer).
        // Third party captures proof via API token. Partner = seller.
        // Since partner is seller, capturer is inferred as buyer.
        // But capturer is actually a third party, not buyer.
        //
        // Defense: Even if third party captures, the trade must contain
        // the correct assetId. Third party can only trigger REFUND (not release).
        // Triggering refund doesn't benefit the attacker — seller loses item + payment.
        let escrow = test_escrow();
        let sent = make_trade_offer_request_api_token();
        // Partner = seller → capturer inferred as buyer
        // items_to_receive must have asset (buyer direction)
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":5,"accountid_other":405752552,"is_our_offer":false,"items_to_receive":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW).unwrap();
        // Third party triggers refund — but refund goes to REAL buyer, not third party
        assert_eq!(result.decision, Decision::Refund);
        assert_eq!(result.refund_reason, RefundReason::BuyerExpired);
    }

    #[test]
    fn test_trade_offer_third_party_wrong_asset() {
        // Attack: Third party tries to use a different trade (wrong assetId)
        let escrow = test_escrow();
        let sent = make_trade_offer_request_api_token();
        // Partner = seller, but trade contains a different asset
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":5,"accountid_other":405752552,"items_to_receive":[{"appid":730,"assetid":"99999999"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW).unwrap();
        assert_eq!(result.decision, Decision::Refund);
        assert_eq!(result.refund_reason, RefundReason::WrongAsset);
    }

    #[test]
    fn test_trade_offer_third_party_unrelated_partner() {
        // Attack: Third party submits proof of a trade between two strangers
        // Neither partner is buyer nor seller
        let escrow = test_escrow();
        let sent = make_trade_offer_request_api_token();
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":5,"accountid_other":12345,"items_to_receive":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW).unwrap();
        assert_eq!(result.decision, Decision::Refund);
        assert_eq!(result.refund_reason, RefundReason::WrongParties);
    }

    // ========================================================================
    // GetTradeStatus: All status values (exhaustive)
    // ========================================================================

    #[test]
    fn test_trade_status_all_deprecated_rollback_states() {
        let escrow = test_escrow();
        // Status 4-9, 11 are all deprecated rollback states
        for status in [4, 5, 6, 7, 8, 9, 11] {
            let sent = make_trade_status_request();
            let json = format!(
                r#"{{"response":{{"trades":[{{"tradeid":"123","steamid_other":"76561198404282737","status":{status},"assets_received":[{{"appid":730,"assetid":"40964044588"}}]}}]}}}}"#
            );
            let recv = make_http_response(&json);
            let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW).unwrap();
            assert_eq!(result.decision, Decision::Refund, "Status {status} should refund");
            assert_eq!(result.refund_reason, RefundReason::DeprecatedRollback, "Status {status}");
        }
    }

    #[test]
    fn test_trade_status_all_non_terminal_states() {
        let escrow = test_escrow();
        // Status 0, 1, 2, 10 are non-terminal
        for status in [0, 1, 2, 10] {
            let sent = make_trade_status_request();
            let json = format!(
                r#"{{"response":{{"trades":[{{"tradeid":"123","steamid_other":"76561198404282737","status":{status}}}]}}}}"#
            );
            let recv = make_http_response(&json);
            let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW);
            assert!(
                matches!(result, Err(SettlementError::NonTerminalState(s)) if s == status),
                "Status {status} should be NonTerminalState"
            );
        }
    }

    #[test]
    fn test_trade_status_rollback_wrong_asset() {
        let escrow = test_escrow();
        let sent = make_trade_status_request();
        // Status 12 but wrong assetId
        let json = r#"{"response":{"trades":[{"tradeid":"123","steamid_other":"76561198404282737","status":12,"assets_received":[{"appid":730,"assetid":"99999999"}]}]}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW);
        assert!(matches!(result, Err(SettlementError::AssetIdMismatch { .. })));
    }

    #[test]
    fn test_trade_status_release_time_settlement_exact_boundary() {
        let escrow = test_escrow();
        let sent = make_trade_status_request();
        // time_settlement == proof_timestamp (exactly at boundary, should pass)
        let json = format!(
            r#"{{"response":{{"trades":[{{"tradeid":"123","steamid_other":"76561198404282737","status":3,"assets_given":[{{"appid":730,"assetid":"40964044588"}}],"time_settlement":{NOW}}}]}}}}"#
        );
        let recv = make_http_response(&json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow, NOW).unwrap();
        assert_eq!(result.decision, Decision::Release);
    }

    // ========================================================================
    // Community: Buyer vs seller as prover
    // ========================================================================

    #[test]
    fn test_community_seller_as_prover() {
        let escrow = test_escrow();
        // Seller proves trade doesn't exist
        let request = b"GET /tradeoffer/8653813160 HTTP/1.1\r\nHost: steamcommunity.com\r\nCookie: steamLoginSecure=76561198366018280%7C%7CeyToken\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\n\r\n<title>Steam Community :: Error</title>The trade offer does not exist, or the trade offer belongs to another user.";

        let result = decide(STEAM_COMMUNITY_HOST, request, response, &escrow, NOW).unwrap();
        assert_eq!(result.decision, Decision::Refund);
        assert_eq!(result.refund_reason, RefundReason::TradeNotExist);
    }

    #[test]
    fn test_community_buyer_as_prover() {
        let escrow = test_escrow();
        // Buyer proves trade doesn't exist
        let request = b"GET /tradeoffer/8653813160 HTTP/1.1\r\nHost: steamcommunity.com\r\nCookie: steamLoginSecure=76561198404282737%7C%7CeyToken\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\n\r\n<title>Steam Community :: Error</title>The trade offer does not exist, or the trade offer belongs to another user.";

        let result = decide(STEAM_COMMUNITY_HOST, request, response, &escrow, NOW).unwrap();
        assert_eq!(result.decision, Decision::Refund);
        assert_eq!(result.refund_reason, RefundReason::TradeNotExist);
    }

    #[test]
    fn test_community_24h_exact_boundary() {
        let escrow = test_escrow();
        let request = b"GET /tradeoffer/8653813160 HTTP/1.1\r\nHost: steamcommunity.com\r\nCookie: steamLoginSecure=76561198404282737%7C%7CeyToken\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\n\r\n<title>Steam Community :: Error</title>The trade offer does not exist, or the trade offer belongs to another user.";

        // Exactly at 24h boundary (should pass)
        let exactly_24h = escrow.purchase_time + 24 * 3600;
        let result = decide(STEAM_COMMUNITY_HOST, request, response, &escrow, exactly_24h).unwrap();
        assert_eq!(result.decision, Decision::Refund);
        assert_eq!(result.refund_reason, RefundReason::TradeNotExist);
    }

    #[test]
    fn test_community_trade_offer_id_mismatch() {
        let escrow = test_escrow();
        // URL has different tradeofferId
        let request = b"GET /tradeoffer/999999 HTTP/1.1\r\nHost: steamcommunity.com\r\nCookie: steamLoginSecure=76561198404282737%7C%7CeyToken\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\n\r\n<title>Steam Community :: Error</title>The trade offer does not exist.";

        let result = decide(STEAM_COMMUNITY_HOST, request, response, &escrow, NOW);
        assert!(matches!(result, Err(SettlementError::TradeOfferIdMismatch { .. })));
    }

    // ========================================================================
    // General tests
    // ========================================================================

    #[test]
    fn test_invalid_server() {
        let escrow = test_escrow();
        let result = decide("evil.com", b"GET /", b"HTTP/1.1 200\r\n\r\n{}", &escrow, NOW);
        assert!(matches!(result, Err(SettlementError::InvalidServer(_))));
    }
}
