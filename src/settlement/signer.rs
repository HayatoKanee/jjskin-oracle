use std::path::Path;
use std::sync::LazyLock;

use alloy::primitives::{keccak256, Address, FixedBytes, B256};
use alloy::signers::{local::PrivateKeySigner, Signer};
use eyre::{Result, eyre};
use tracing::info;

use super::types::Settlement;
use crate::config::OracleConfig;

/// EIP-712 type hash: must match JJSKIN.sol SETTLEMENT_TYPEHASH
static SETTLEMENT_TYPEHASH: LazyLock<B256> = LazyLock::new(|| {
    keccak256(b"Settlement(uint64 assetId,uint48 tradeOfferId,uint8 decision,uint8 refundReason)")
});

/// EIP-712 type hash: must match JJSKIN.sol ITEM_ATTESTATION_TYPEHASH
static ITEM_ATTESTATION_TYPEHASH: LazyLock<B256> = LazyLock::new(|| {
    keccak256(b"ItemAttestation(uint64 assetId,uint64 itemDetail)")
});

/// EIP-712 domain separator type hash
static EIP712_DOMAIN_TYPEHASH: LazyLock<B256> = LazyLock::new(|| {
    keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    )
});

/// Oracle signer for EIP-712 settlement signatures.
///
/// Replaces OracleWallet — no on-chain calls, just signing.
/// The signed message is submitted to the contract by a relayer.
pub struct OracleSigner {
    signer: PrivateKeySigner,
    domain_separator: B256,
}

impl OracleSigner {
    /// Create from OracleConfig.
    ///
    /// Key resolution order:
    /// 1. `ORACLE_SIGNING_KEY` env var (dev/test mode only — operator knows key)
    /// 2. `signing_key_path` config (dev/test mode only)
    /// 3. dstack `derive_key` (production — deterministic key bound to compose-hash)
    /// 4. Fresh random key (fallback TEE mode — requires registerOracle() on every reboot)
    ///
    /// In dstack production mode, the key is derived deterministically from the TEE
    /// identity. Same Docker image = same key across reboots. Different image = different key.
    pub async fn from_config(config: &OracleConfig) -> Result<Self> {
        let signer = if let Ok(hex_key) = std::env::var("ORACLE_SIGNING_KEY") {
            // Dev/test mode: operator-provided key
            let hex_key = hex_key.trim();
            let s = hex_key
                .parse::<PrivateKeySigner>()
                .map_err(|e| eyre!("ORACLE_SIGNING_KEY invalid: {e}"))?;
            info!("Oracle key loaded from env (dev/test mode)");
            s
        } else if let Some(path) = &config.signing_key_path {
            // Dev/test mode: key from file
            let data = std::fs::read_to_string(path)
                .map_err(|e| eyre!("Failed to read oracle key file '{path}': {e}"))?;
            let data = data.trim();
            let s = data
                .parse::<PrivateKeySigner>()
                .map_err(|e| eyre!("Invalid oracle key in '{path}': {e}"))?;
            info!("Oracle key loaded from file (dev/test mode)");
            s
        } else if Path::new("/var/run/dstack.sock").exists()
            || Path::new("/var/run/tappd.sock").exists()
        {
            // dstack production mode: derive deterministic key from TEE identity
            derive_key_from_dstack().await?
        } else {
            // Fallback TEE mode: fresh random key (requires registerOracle on each boot)
            let s = PrivateKeySigner::random();
            info!(
                "Oracle key generated randomly (address={}). \
                 Register via /attestation quote.",
                s.address()
            );
            s
        };

        let contract_address: Address = config
            .contract_address
            .parse()
            .map_err(|e| eyre!("Invalid contract address: {e}"))?;

        let domain_separator = compute_domain_separator(config.chain_id, contract_address);

        info!(
            "Oracle signer initialized: address={}, contract={}, chain_id={}",
            signer.address(),
            contract_address,
            config.chain_id
        );

        Ok(Self {
            signer,
            domain_separator,
        })
    }

    /// Get the oracle's Ethereum address.
    pub fn address(&self) -> Address {
        self.signer.address()
    }

    /// Sign a settlement decision using EIP-712.
    ///
    /// Returns 65 bytes: r (32) || s (32) || v (1).
    /// Matches Solidity: `ECDSA.recover(_hashTypedDataV4(structHash), oracleSignature)`
    pub async fn sign_settlement(&self, settlement: &Settlement) -> Result<Vec<u8>> {
        let struct_hash = compute_struct_hash(settlement);
        let digest = compute_eip712_digest(self.domain_separator, struct_hash);

        let signature = self
            .signer
            .sign_hash(&digest)
            .await
            .map_err(|e| eyre!("Failed to sign settlement: {e}"))?;

        // as_bytes() returns [u8; 65]: r (32) || s (32) || v (1, 27 or 28)
        Ok(signature.as_bytes().to_vec())
    }

    /// Sign an item attestation using EIP-712.
    ///
    /// Attests that `assetId` has the given `itemDetail` (packed uint64).
    /// Returns 65 bytes: r (32) || s (32) || v (1).
    pub async fn sign_item_attestation(&self, asset_id: u64, item_detail: u64) -> Result<Vec<u8>> {
        let struct_hash = compute_item_attestation_struct_hash(asset_id, item_detail);
        let digest = compute_eip712_digest(self.domain_separator, struct_hash);

        let signature = self
            .signer
            .sign_hash(&digest)
            .await
            .map_err(|e| eyre!("Failed to sign item attestation: {e}"))?;

        Ok(signature.as_bytes().to_vec())
    }
}

/// Compute EIP-712 domain separator.
///
/// Matches OpenZeppelin's EIP712("JJSKIN", "1"):
/// ```text
/// keccak256(abi.encode(
///     EIP712_DOMAIN_TYPEHASH,
///     keccak256("JJSKIN"),
///     keccak256("1"),
///     chainId,
///     verifyingContract
/// ))
/// ```
fn compute_domain_separator(chain_id: u64, contract_address: Address) -> B256 {
    let name_hash = keccak256(b"JJSKIN");
    let version_hash = keccak256(b"1");

    let mut encoded = Vec::with_capacity(5 * 32);
    encoded.extend_from_slice((*EIP712_DOMAIN_TYPEHASH).as_ref());
    encoded.extend_from_slice(name_hash.as_ref());
    encoded.extend_from_slice(version_hash.as_ref());
    // chainId as uint256 (left-padded to 32 bytes)
    encoded.extend_from_slice(&FixedBytes::<32>::left_padding_from(&chain_id.to_be_bytes()).0);
    // address as bytes32 (left-padded to 32 bytes)
    encoded.extend_from_slice(&FixedBytes::<32>::left_padding_from(contract_address.as_ref()).0);

    keccak256(&encoded)
}

/// Compute struct hash for Settlement.
///
/// Matches Solidity (JJSKIN.sol):
/// ```text
/// keccak256(abi.encode(SETTLEMENT_TYPEHASH, assetId, uint48(tradeOfferId), decision, refundReason))
/// ```
///
/// abi.encode pads each value to 32 bytes.
fn compute_struct_hash(settlement: &Settlement) -> B256 {
    let mut encoded = Vec::with_capacity(5 * 32);
    encoded.extend_from_slice((*SETTLEMENT_TYPEHASH).as_ref());
    // uint64 assetId → uint256 (left-padded to 32 bytes)
    encoded
        .extend_from_slice(&FixedBytes::<32>::left_padding_from(&settlement.asset_id.to_be_bytes()).0);
    // uint48 tradeOfferId → uint256 (left-padded to 32 bytes)
    // Stored as u64 in Rust but ABI-encoded as uint48 (Solidity casts to uint48).
    // NOTE: Steam trade offer IDs are 64-bit but currently fit well within 48 bits
    // (~10 trillion max observed). If Steam ever exceeds 2^48, both the contract
    // (silent truncation in commitTradeOffer) and this encoding would need updating.
    encoded.extend_from_slice(
        &FixedBytes::<32>::left_padding_from(&settlement.trade_offer_id.to_be_bytes()).0,
    );
    // uint8 decision → uint256 (left-padded to 32 bytes)
    encoded
        .extend_from_slice(&FixedBytes::<32>::left_padding_from(&[settlement.decision as u8]).0);
    // uint8 refundReason → uint256 (left-padded to 32 bytes)
    encoded.extend_from_slice(
        &FixedBytes::<32>::left_padding_from(&[settlement.refund_reason as u8]).0,
    );

    keccak256(&encoded)
}

/// Compute struct hash for ItemAttestation.
///
/// Matches Solidity (JJSKIN.sol):
/// ```text
/// keccak256(abi.encode(ITEM_ATTESTATION_TYPEHASH, assetId, itemDetail))
/// ```
fn compute_item_attestation_struct_hash(asset_id: u64, item_detail: u64) -> B256 {
    let mut encoded = Vec::with_capacity(3 * 32);
    encoded.extend_from_slice((*ITEM_ATTESTATION_TYPEHASH).as_ref());
    // uint64 assetId → uint256 (left-padded to 32 bytes)
    encoded.extend_from_slice(&FixedBytes::<32>::left_padding_from(&asset_id.to_be_bytes()).0);
    // uint64 itemDetail → uint256 (left-padded to 32 bytes)
    encoded.extend_from_slice(&FixedBytes::<32>::left_padding_from(&item_detail.to_be_bytes()).0);

    keccak256(&encoded)
}

/// Derive a deterministic oracle signing key from dstack TEE identity.
///
/// Uses dstack's `derive_key` API which produces a key bound to the compose-hash.
/// Same Docker image = same key. Different image = different key.
/// The raw P-256 private key bytes (32 bytes) are used as a secp256k1 private key.
async fn derive_key_from_dstack() -> Result<PrivateKeySigner> {
    use dstack_sdk::tappd_client::TappdClient;

    let client = TappdClient::new(None);
    let resp = client
        .derive_key("oracle/signing/v1")
        .await
        .map_err(|e| eyre!("dstack derive_key failed: {e}"))?;

    let key_bytes = resp
        .decode_key()
        .map_err(|e| eyre!("Failed to decode dstack derived key: {e}"))?;

    if key_bytes.len() < 32 {
        return Err(eyre!(
            "dstack derived key too short ({} bytes, need 32)",
            key_bytes.len()
        ));
    }

    let key = B256::from_slice(&key_bytes[..32]);
    let signer = PrivateKeySigner::from_bytes(&key)
        .map_err(|e| eyre!("Invalid secp256k1 key from dstack derivation: {e}"))?;

    info!(
        "Oracle key derived via dstack (address={}). \
         Deterministic — survives reboots, changes on image update.",
        signer.address()
    );
    Ok(signer)
}

/// Compute EIP-712 digest: keccak256("\x19\x01" || domainSeparator || structHash)
fn compute_eip712_digest(domain_separator: B256, struct_hash: B256) -> B256 {
    let mut data = Vec::with_capacity(2 + 32 + 32);
    data.extend_from_slice(&[0x19, 0x01]);
    data.extend_from_slice(domain_separator.as_ref());
    data.extend_from_slice(struct_hash.as_ref());
    keccak256(&data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settlement::types::{Decision, RefundReason};

    /// Test that EIP-712 signing produces a valid 65-byte signature
    /// and ecrecover yields the expected signer address.
    #[tokio::test]
    async fn test_sign_and_recover() {
        // Known private key for deterministic testing
        let key_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let signer: PrivateKeySigner = key_hex.parse().unwrap();
        let expected_address = signer.address();

        // Use Arbitrum chain ID and a dummy contract address
        let chain_id = 42161u64;
        let contract_address: Address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
            .parse()
            .unwrap();

        let domain_separator = compute_domain_separator(chain_id, contract_address);

        let oracle_signer = OracleSigner {
            signer,
            domain_separator,
        };

        let settlement = Settlement {
            asset_id: 12345,
            trade_offer_id: 67890,
            decision: Decision::Release,
            refund_reason: RefundReason::None,
        };

        let sig_bytes = oracle_signer.sign_settlement(&settlement).await.unwrap();
        assert_eq!(sig_bytes.len(), 65, "signature must be 65 bytes");

        // Verify ecrecover matches expected address
        let struct_hash = compute_struct_hash(&settlement);
        let digest = compute_eip712_digest(domain_separator, struct_hash);

        let v = sig_bytes[64];
        let sig = alloy::primitives::Signature::from_bytes_and_parity(&sig_bytes[..64], v != 27);
        let recovered = sig.recover_address_from_prehash(&digest).unwrap();
        assert_eq!(recovered, expected_address, "ecrecover must match signer address");
    }

    /// Test domain separator matches expected value for known inputs.
    #[test]
    fn test_domain_separator_deterministic() {
        let chain_id = 42161u64;
        let contract_address: Address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
            .parse()
            .unwrap();

        let sep1 = compute_domain_separator(chain_id, contract_address);
        let sep2 = compute_domain_separator(chain_id, contract_address);
        assert_eq!(sep1, sep2);

        // Different chain ID → different separator
        let sep3 = compute_domain_separator(1, contract_address);
        assert_ne!(sep1, sep3);
    }

    /// Test struct hash matches expected encoding.
    #[test]
    fn test_struct_hash_deterministic() {
        let s1 = Settlement {
            asset_id: 12345,
            trade_offer_id: 67890,
            decision: Decision::Release,
            refund_reason: RefundReason::None,
        };
        let s2 = Settlement {
            asset_id: 12345,
            trade_offer_id: 67890,
            decision: Decision::Refund,
            refund_reason: RefundReason::BuyerExpired,
        };

        let h1 = compute_struct_hash(&s1);
        let h2 = compute_struct_hash(&s2);
        assert_ne!(h1, h2, "different settlements must produce different hashes");

        // Same input → same hash
        let h3 = compute_struct_hash(&s1);
        assert_eq!(h1, h3);
    }

    /// Test item attestation sign + ecrecover roundtrip.
    #[tokio::test]
    async fn test_sign_item_attestation_and_recover() {
        let key_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let signer: PrivateKeySigner = key_hex.parse().unwrap();
        let expected_address = signer.address();

        let chain_id = 42161u64;
        let contract_address: Address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
            .parse()
            .unwrap();

        let domain_separator = compute_domain_separator(chain_id, contract_address);
        let oracle_signer = OracleSigner {
            signer,
            domain_separator,
        };

        let asset_id = 39388024803u64;
        let item_detail = 12345678901234u64;

        let sig_bytes = oracle_signer
            .sign_item_attestation(asset_id, item_detail)
            .await
            .unwrap();
        assert_eq!(sig_bytes.len(), 65);

        // Verify ecrecover
        let struct_hash = compute_item_attestation_struct_hash(asset_id, item_detail);
        let digest = compute_eip712_digest(domain_separator, struct_hash);

        let v = sig_bytes[64];
        let sig = alloy::primitives::Signature::from_bytes_and_parity(&sig_bytes[..64], v != 27);
        let recovered = sig.recover_address_from_prehash(&digest).unwrap();
        assert_eq!(recovered, expected_address);
    }

    /// Test item attestation struct hash is deterministic and varies with inputs.
    #[test]
    fn test_item_attestation_struct_hash() {
        let h1 = compute_item_attestation_struct_hash(100, 200);
        let h2 = compute_item_attestation_struct_hash(100, 201);
        let h3 = compute_item_attestation_struct_hash(101, 200);
        let h4 = compute_item_attestation_struct_hash(100, 200);

        assert_ne!(h1, h2, "different itemDetail → different hash");
        assert_ne!(h1, h3, "different assetId → different hash");
        assert_eq!(h1, h4, "same inputs → same hash");
    }
}
