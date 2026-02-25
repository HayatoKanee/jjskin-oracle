use serde::{Deserialize, Serialize};

// ============================================================================
// Constants
// ============================================================================

/// Steam64 base offset for converting Steam32 IDs to Steam64 format
/// Steam64 = Steam32 + STEAM64_OFFSET
pub const STEAM64_OFFSET: u64 = 76561197960265728;

// ============================================================================
// EscrowSnapshot (read from on-chain by ChainReader)
// ============================================================================

/// On-chain escrow data read from JJSKIN contract + SteamAccountFactory.
///
/// Constructed by `ChainReader::read_escrow()` from trustless on-chain state.
/// Extension only provides `assetId` as a lookup hint.
#[derive(Serialize, Debug, Clone)]
pub struct EscrowSnapshot {
    /// Steam asset ID being traded
    pub asset_id: u64,
    /// Trade offer ID committed by seller (from Purchase.tradeOfferId)
    pub trade_offer_id: u64,
    /// Seller's Steam64 ID (from SteamAccountFactory)
    pub seller_steam_id: u64,
    /// Buyer's Steam64 ID (from SteamAccountFactory)
    pub buyer_steam_id: u64,
    /// Seller's wallet address (from Listing.seller)
    pub seller: [u8; 20],
    /// Buyer's wallet address (from Purchase.buyer)
    pub buyer: [u8; 20],
    /// USDC amount (from Listing.price, 6 decimals)
    pub amount: u64,
    /// Purchase timestamp (from Purchase.purchaseTime, Unix seconds)
    pub purchase_time: u64,
    /// Abandoned window in seconds (from JJSKIN.abandonedWindow, default 24h)
    pub abandoned_window: u64,
}

// ============================================================================
// Decision Types
// ============================================================================

/// Settlement decision
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Decision {
    Release = 0,
    Refund = 1,
}

/// Refund reason (matches Solidity RefundReason enum)
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RefundReason {
    None = 0,
    Timeout = 1,
    NotCS2Item = 2,
    WrongAsset = 3,
    WrongParties = 4,
    InvalidItems = 5,
    Canceled2FA = 6,
    BuyerExpired = 7,
    SellerExpired = 8,
    BuyerCanceled = 9,
    SellerCanceled = 10,
    BuyerDeclined = 11,
    SellerDeclined = 12,
    WrongRecipient = 13,
    TradeRollback = 14,
    DeprecatedRollback = 15,
    TradeNotExist = 16,
}

/// Single settlement result
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Settlement {
    pub asset_id: u64,
    /// Trade offer ID from on-chain escrow (included in EIP-712 signature as uint48)
    pub trade_offer_id: u64,
    pub decision: Decision,
    pub refund_reason: RefundReason,
}

// ============================================================================
// Steam API Types (Internal parsing)
// ============================================================================

/// Proof source type - determines extraction logic
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofSource {
    TradeOffer,
    TradeStatus,
    Community,
}

/// GetTradeOffer parsed data
#[derive(Debug, Clone)]
pub struct TradeOfferData {
    pub state: u32,
    pub trade_offer_id: u64,
    pub partner_steam_id: u64,
    pub asset_to_give: Option<u64>,
    pub asset_to_receive: Option<u64>,
    pub is_our_offer: bool,
}

/// GetTradeStatus parsed data
#[derive(Debug, Clone)]
pub struct TradeStatusData {
    pub status: u32,
    pub partner_steam_id: Option<u64>,
    pub asset_id_given: Option<u64>,
    pub asset_id: Option<u64>,
    pub time_settlement: Option<u64>,
}

/// Parsed Community proof data (HTML)
#[derive(Debug, Clone)]
pub struct CommunityProofData {
    pub prover_steam_id: u64,
    pub trade_offer_id: u64,
    pub trade_not_found: bool,
}

// ============================================================================
// Wire Type: SettlementResult (sent from verifier to prover)
// ============================================================================

/// Result sent over the wire from verifier to prover after settlement.
/// Both verifier and WASM prover define this independently (no shared dep).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SettlementResult {
    pub signature: Vec<u8>,  // 65 bytes: r || s || v (EIP-712)
    pub asset_id: u64,
    pub decision: u8,       // 0=Release, 1=Refund
    pub refund_reason: u8,  // RefundReason enum value
}
