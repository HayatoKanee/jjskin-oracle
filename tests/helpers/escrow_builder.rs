//! Build test `EscrowSnapshot` values for integration tests.
//!
//! Hand-built escrow snapshots (no Anvil needed for Phase 4).

use tlsn_server::settlement::EscrowSnapshot;

/// Steam64 base offset for converting Steam32 IDs.
const STEAM64_OFFSET: u64 = 76561197960265728;

/// Default test parameters matching the oracle.rs unit test fixtures.
pub struct TestParams {
    pub asset_id: u64,
    pub trade_offer_id: u64,
    pub trade_id: u64,
    pub seller_steam_id: u64,
    pub buyer_steam_id: u64,
    pub seller_account_id: u64,
    pub buyer_account_id: u64,
    pub price_usdc: u64,
    pub purchase_time: u64,
}

impl Default for TestParams {
    fn default() -> Self {
        let seller_steam_id: u64 = 76561198366018280;
        let buyer_steam_id: u64 = 76561198404282737;
        Self {
            asset_id: 40964044588,
            trade_offer_id: 8653813160,
            trade_id: 6300000000,
            seller_steam_id,
            buyer_steam_id,
            seller_account_id: seller_steam_id - STEAM64_OFFSET,
            buyer_account_id: buyer_steam_id - STEAM64_OFFSET,
            price_usdc: 10_000_000, // 10 USDC
            purchase_time: 1700000000,
        }
    }
}

/// Build an `EscrowSnapshot` for testing.
///
/// `purchase_time` is set to 1700000000 (well in the past) so that
/// settlement period checks pass with the current system clock.
pub fn build_test_escrow(params: &TestParams) -> EscrowSnapshot {
    EscrowSnapshot {
        asset_id: params.asset_id,
        trade_offer_id: params.trade_offer_id,
        seller_steam_id: params.seller_steam_id,
        buyer_steam_id: params.buyer_steam_id,
        seller: [0u8; 20], // Wallet addresses not used in decide()
        buyer: [0u8; 20],
        amount: params.price_usdc,
        purchase_time: params.purchase_time,
        abandoned_window: 24 * 60 * 60, // 24 hours
    }
}
