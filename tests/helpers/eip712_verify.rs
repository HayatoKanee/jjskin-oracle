//! EIP-712 ecrecover verification for integration tests.
//!
//! Reimplements the EIP-712 encoding from signer.rs to verify signatures
//! without importing private functions. This ensures the test verification
//! is independent of the production signing code.

use alloy::primitives::{keccak256, Address, B256, FixedBytes};

/// EIP-712 type hashes (must match signer.rs / JJSKIN.sol).
fn settlement_typehash() -> B256 {
    keccak256(b"Settlement(uint64 assetId,uint48 tradeOfferId,uint8 decision,uint8 refundReason)")
}

fn eip712_domain_typehash() -> B256 {
    keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
}

/// Compute the EIP-712 domain separator.
pub fn compute_domain_separator(chain_id: u64, contract_address: Address) -> B256 {
    let name_hash = keccak256(b"JJSKIN");
    let version_hash = keccak256(b"1");

    let mut encoded = Vec::with_capacity(5 * 32);
    encoded.extend_from_slice(eip712_domain_typehash().as_ref());
    encoded.extend_from_slice(name_hash.as_ref());
    encoded.extend_from_slice(version_hash.as_ref());
    encoded.extend_from_slice(&FixedBytes::<32>::left_padding_from(&chain_id.to_be_bytes()).0);
    encoded.extend_from_slice(&FixedBytes::<32>::left_padding_from(contract_address.as_ref()).0);

    keccak256(&encoded)
}

/// Compute the EIP-712 struct hash for a settlement.
pub fn compute_struct_hash(
    asset_id: u64,
    trade_offer_id: u64,
    decision: u8,
    refund_reason: u8,
) -> B256 {
    let mut encoded = Vec::with_capacity(5 * 32);
    encoded.extend_from_slice(settlement_typehash().as_ref());
    encoded.extend_from_slice(&FixedBytes::<32>::left_padding_from(&asset_id.to_be_bytes()).0);
    encoded
        .extend_from_slice(&FixedBytes::<32>::left_padding_from(&trade_offer_id.to_be_bytes()).0);
    encoded.extend_from_slice(&FixedBytes::<32>::left_padding_from(&[decision]).0);
    encoded.extend_from_slice(&FixedBytes::<32>::left_padding_from(&[refund_reason]).0);

    keccak256(&encoded)
}

/// Compute EIP-712 digest: keccak256("\x19\x01" || domainSeparator || structHash).
pub fn compute_eip712_digest(domain_separator: B256, struct_hash: B256) -> B256 {
    let mut data = Vec::with_capacity(2 + 32 + 32);
    data.extend_from_slice(&[0x19, 0x01]);
    data.extend_from_slice(domain_separator.as_ref());
    data.extend_from_slice(struct_hash.as_ref());
    keccak256(&data)
}

/// Verify that an EIP-712 settlement signature was produced by the expected oracle address.
///
/// Returns the recovered address on success.
pub fn verify_settlement_signature(
    sig_bytes: &[u8],
    asset_id: u64,
    trade_offer_id: u64,
    decision: u8,
    refund_reason: u8,
    chain_id: u64,
    contract_address: Address,
) -> Address {
    assert_eq!(sig_bytes.len(), 65, "signature must be 65 bytes");

    let domain_separator = compute_domain_separator(chain_id, contract_address);
    let struct_hash = compute_struct_hash(asset_id, trade_offer_id, decision, refund_reason);
    let digest = compute_eip712_digest(domain_separator, struct_hash);

    let v = sig_bytes[64];
    let sig = alloy::primitives::Signature::from_bytes_and_parity(
        &sig_bytes[..64],
        v != 27,
    );
    sig.recover_address_from_prehash(&digest)
        .expect("ecrecover failed")
}
