//! Cross-chain atomic swap primitives (HTLC) for LofSwap.
//!
//! LofSwap settles the *local* leg of a cross-chain swap in a hashed
//! timelock contract (HTLC) that lives directly in the chain state:
//!
//! * `SwapLock` moves coins from the maker into a deterministic escrow address
//!   that nobody holds a key for.
//! * `SwapClaim` spends the escrow to the agreed recipient by revealing the
//!   32-byte preimage of the hashlock.
//! * `SwapRefund` returns the escrow to the maker once the timelock expired.
//!
//! Because the preimage becomes public on LofSwap the moment the claim is
//! mined, the same hashlock can be used to unlock the counter-leg on any
//! foreign chain that supports SHA-256 HTLCs (Ethereum contracts, Solana
//! programs, ...). The foreign leg of the trade is committed to in
//! [`ForeignLeg`] so the full trade is auditable from the LofSwap chain even
//! though LofSwap never has custody of the foreign asset.
//!
//! Nothing in this module trusts a bridge operator: either both legs settle
//! (the secret is revealed) or both legs refund after their timelocks.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::pubkey_to_address;

/// Version of the swap sub-protocol encoded in the commitment preimages.
pub const SWAP_PROTOCOL: &str = "lofswap-swap-v1";
/// Transaction version that carries a [`SwapPayload`].
pub const SWAP_TX_VERSION: u8 = 4;
/// Hashlocks are SHA-256 digests, hex encoded.
pub const SWAP_HASHLOCK_HEX_LEN: usize = 64;
/// Preimages ("secrets") are exactly 32 bytes, hex encoded.
pub const SWAP_SECRET_HEX_LEN: usize = 64;
/// Shortest lifetime of a lock, measured from the tx timestamp.
pub const SWAP_MIN_LOCK_SECS: i64 = 30 * 60;
/// Longest lifetime of a lock, measured from the tx timestamp.
pub const SWAP_MAX_LOCK_SECS: i64 = 30 * 24 * 60 * 60;
/// Upper bound for every free-form foreign-leg field (anti-bloat).
pub const SWAP_MAX_FIELD_LEN: usize = 128;

/// Descriptor of the counter-leg that settles on a foreign chain.
///
/// The node cannot verify these fields — no LofSwap node reads Ethereum or
/// Solana state — but committing to them makes the intended trade public and
/// binds it to the hashlock, so a maker cannot later claim different terms.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct ForeignLeg {
    /// CAIP-2 style chain identifier, e.g. `eip155:1` or `solana:mainnet`.
    pub chain: String,
    /// Asset identifier: symbol, ERC-20 contract or SPL mint.
    pub asset: String,
    /// Amount in the foreign asset's base units, as a decimal string.
    pub amount: String,
    /// Address that receives the foreign asset when the swap settles.
    pub beneficiary: String,
    /// Optional pointer to the foreign HTLC (contract address / tx hash).
    #[serde(default)]
    pub htlc_ref: String,
}

impl ForeignLeg {
    /// Canonical digest used inside the swap commitment.
    pub fn digest(&self) -> String {
        sha256_hex(
            format!(
                "{}|{}|{}|{}|{}",
                self.chain, self.asset, self.amount, self.beneficiary, self.htlc_ref
            )
            .as_bytes(),
        )
    }

    fn fields(&self) -> [&str; 5] {
        [
            &self.chain,
            &self.asset,
            &self.amount,
            &self.beneficiary,
            &self.htlc_ref,
        ]
    }

    /// Rejects oversized or non-printable fields before they reach the chain.
    pub fn validate(&self) -> Result<(), String> {
        if self.chain.is_empty()
            || self.asset.is_empty()
            || self.amount.is_empty()
            || self.beneficiary.is_empty()
        {
            return Err("foreign leg is missing chain/asset/amount/beneficiary".to_string());
        }
        for field in self.fields() {
            if field.len() > SWAP_MAX_FIELD_LEN {
                return Err(format!(
                    "foreign leg field longer than {} bytes",
                    SWAP_MAX_FIELD_LEN
                ));
            }
            if !field.chars().all(|c| c.is_ascii_graphic() || c == ' ') || field.contains('|') {
                return Err("foreign leg field has illegal characters".to_string());
            }
        }
        if !self.amount.chars().all(|c| c.is_ascii_digit()) {
            return Err("foreign leg amount must be a base-unit integer".to_string());
        }
        Ok(())
    }
}

/// HTLC data carried by every swap transaction.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct SwapPayload {
    /// Deterministic swap identifier, see [`swap_id`].
    pub swap_id: String,
    /// `sha256(secret)` in lowercase hex.
    pub hashlock: String,
    /// Absolute UNIX timestamp after which a refund becomes possible.
    pub timelock: i64,
    /// Address entitled to claim the escrow (set on the lock).
    #[serde(default)]
    pub recipient: String,
    /// Revealed 32-byte preimage, hex encoded (set on the claim).
    #[serde(default)]
    pub secret: String,
    /// Counter-leg description (set on the lock).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foreign: Option<ForeignLeg>,
}

impl SwapPayload {
    /// Digest folded into the txid and signature preimages of v4 transactions,
    /// so every swap field is covered by the maker's / claimer's signature.
    pub fn digest(&self) -> String {
        sha256_hex(
            format!(
                "{}|{}|{}|{}|{}|{}",
                self.swap_id,
                self.hashlock,
                self.timelock,
                self.recipient,
                self.secret,
                self.foreign
                    .as_ref()
                    .map(|f| f.digest())
                    .unwrap_or_else(|| "none".to_string()),
            )
            .as_bytes(),
        )
    }
}

/// Hex-encoded SHA-256 of arbitrary bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// True for a lowercase hex string of exactly `len` characters.
pub fn is_hex_of_len(value: &str, len: usize) -> bool {
    value.len() == len
        && value.bytes().all(|b| b.is_ascii_hexdigit())
        && value == value.to_lowercase()
}

/// Hashlock for a 32-byte secret given in hex.
///
/// The digest is taken over the decoded *bytes*, which is what Ethereum's
/// `sha256(bytes32)` and Solana's `hashv` produce for the same secret, so the
/// identical secret unlocks all legs of the swap.
pub fn hashlock_for_secret_hex(secret_hex: &str) -> Option<String> {
    let bytes = decode_secret_hex(secret_hex)?;
    Some(sha256_hex(&bytes))
}

/// Decodes a 32-byte secret from hex, rejecting anything of the wrong size.
pub fn decode_secret_hex(secret_hex: &str) -> Option<Vec<u8>> {
    if !is_hex_of_len(secret_hex, SWAP_SECRET_HEX_LEN) {
        return None;
    }
    hex::decode(secret_hex).ok()
}

/// Deterministic identifier of a swap.
///
/// The id is derived from the full terms *plus* the maker's nonce, so it is
/// unique per maker and known before the lock is signed (unlike a txid, which
/// would be circular because the escrow address is part of the transaction).
#[allow(clippy::too_many_arguments)]
pub fn swap_id(
    chain_id: &str,
    maker: &str,
    recipient: &str,
    amount: u64,
    hashlock: &str,
    timelock: i64,
    nonce: u64,
    foreign: Option<&ForeignLeg>,
) -> String {
    let foreign_digest = foreign
        .map(|f| f.digest())
        .unwrap_or_else(|| "none".to_string());
    sha256_hex(
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            SWAP_PROTOCOL,
            chain_id,
            maker,
            recipient,
            amount,
            hashlock,
            timelock,
            nonce,
            foreign_digest
        )
        .as_bytes(),
    )
}

/// Escrow address holding the locked coins of a swap.
///
/// It is a syntactically valid `LFS` address derived from the swap id, so the
/// existing balance machinery, explorers and wallets treat it like any other
/// account — but no private key exists for it: only the HTLC rules can move
/// its funds.
pub fn swap_escrow_address(swap_id: &str) -> String {
    // `pubkey_to_address` is a plain domain-separated hash-to-address helper.
    pubkey_to_address(&format!("{}-escrow|{}", SWAP_PROTOCOL, swap_id))
}

/// Address of the account authorised to sign a claim/refund, derived from the
/// pubkey attached to the transaction.
pub fn signer_address(pubkey: &str) -> String {
    pubkey_to_address(pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashlock_matches_sha256_of_secret_bytes() {
        let secret = "00".repeat(32);
        let expected = sha256_hex(&[0u8; 32]);
        assert_eq!(hashlock_for_secret_hex(&secret).unwrap(), expected);
    }

    #[test]
    fn secret_must_be_32_bytes() {
        assert!(hashlock_for_secret_hex("abcd").is_none());
        assert!(hashlock_for_secret_hex(&"ab".repeat(31)).is_none());
        assert!(hashlock_for_secret_hex(&"AB".repeat(32)).is_none());
    }

    #[test]
    fn swap_id_changes_with_every_term() {
        let base = swap_id("c", "maker", "recipient", 10, "aa", 100, 0, None);
        assert_ne!(
            base,
            swap_id("c", "maker", "recipient", 11, "aa", 100, 0, None)
        );
        assert_ne!(
            base,
            swap_id("c", "maker", "recipient", 10, "ab", 100, 0, None)
        );
        assert_ne!(
            base,
            swap_id("c", "maker", "recipient", 10, "aa", 101, 0, None)
        );
        assert_ne!(
            base,
            swap_id("c", "maker", "recipient", 10, "aa", 100, 1, None)
        );
        let foreign = ForeignLeg {
            chain: "eip155:1".into(),
            asset: "USDC".into(),
            amount: "1000000".into(),
            beneficiary: "0xabc".into(),
            htlc_ref: String::new(),
        };
        assert_ne!(
            base,
            swap_id("c", "maker", "recipient", 10, "aa", 100, 0, Some(&foreign))
        );
    }

    #[test]
    fn escrow_address_is_a_valid_lfs_address() {
        let addr = swap_escrow_address(&swap_id("c", "m", "r", 1, "aa", 1, 0, None));
        assert!(addr.starts_with("LFS"));
        let payload = bs58::decode(&addr[3..]).into_vec().unwrap();
        assert_eq!(payload.len(), 20);
    }

    #[test]
    fn foreign_leg_rejects_bloat_and_separators() {
        let mut leg = ForeignLeg {
            chain: "eip155:1".into(),
            asset: "USDC".into(),
            amount: "1000000".into(),
            beneficiary: "0xabc".into(),
            htlc_ref: String::new(),
        };
        assert!(leg.validate().is_ok());
        leg.asset = "a|b".into();
        assert!(leg.validate().is_err());
        leg.asset = "x".repeat(SWAP_MAX_FIELD_LEN + 1);
        assert!(leg.validate().is_err());
        leg.asset = "USDC".into();
        leg.amount = "12.5".into();
        assert!(leg.validate().is_err());
    }
}
