//! Consensus rules and chain state for hashed-timelock (HTLC) swaps.
//!
//! A swap has exactly three possible histories on LofSwap:
//!
//! ```text
//! SwapLock ──(secret revealed before timelock)──> SwapClaim   -> recipient paid
//!          ──(timelock expired, no secret)──────> SwapRefund  -> maker paid back
//!          ──(nothing yet)────────────────────── Open
//! ```
//!
//! Locked coins sit at a deterministic escrow address that has no private key,
//! so the only way to move them is a claim or a refund that satisfies the
//! rules below. Every time comparison uses the median-time-past (MTP) of the
//! chain rather than the block timestamp, so a miner cannot fast-forward the
//! clock to steal a refund, nor stall it to block one.

use std::collections::HashMap;

use blockchain_core::{
    Block, ForeignLeg, SwapPayload, Transaction, TxKind,
    swap::{
        SWAP_HASHLOCK_HEX_LEN, SWAP_MAX_LOCK_SECS, SWAP_MIN_LOCK_SECS, SWAP_TX_VERSION,
        decode_secret_hex, is_hex_of_len, sha256_hex, swap_escrow_address, swap_id,
    },
};
use serde::{Deserialize, Serialize};

use crate::{chain::MIN_TX_FEE, errors::NodeError};

/// Height from which swap transactions are accepted by consensus.
///
/// Swap transactions are a hard fork: nodes older than this feature reject
/// blocks that contain them. On the public testnet the feature is active from
/// the genesis block; when forking an already running network, set this to a
/// height far enough in the future for every node to upgrade first.
pub const SWAP_ACTIVATION_HEIGHT: u64 = 0;

fn invalid(msg: impl Into<String>) -> NodeError {
    NodeError::ValidationError(msg.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SwapStatus {
    Open,
    Claimed,
    Refunded,
}

impl SwapStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SwapStatus::Open => "open",
            SwapStatus::Claimed => "claimed",
            SwapStatus::Refunded => "refunded",
        }
    }
}

/// Chain view of a single swap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapRecord {
    pub swap_id: String,
    pub escrow: String,
    pub maker: String,
    pub recipient: String,
    /// Coins held by the escrow, i.e. the amount the lock moved there.
    pub amount: u64,
    pub hashlock: String,
    pub timelock: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub foreign: Option<ForeignLeg>,
    pub status: SwapStatus,
    pub lock_txid: String,
    pub lock_height: u64,
    pub lock_time: i64,
    /// Preimage, published by the claim that settled the swap.
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub settle_txid: String,
    #[serde(default)]
    pub settle_height: Option<u64>,
    /// Coins actually paid out on settlement (`amount` minus the settle fee).
    #[serde(default)]
    pub payout: u64,
}

impl SwapRecord {
    pub fn is_open(&self) -> bool {
        self.status == SwapStatus::Open
    }
}

/// All swaps derived from a chain, keyed by swap id.
#[derive(Debug, Clone, Default)]
pub struct SwapIndex {
    by_id: HashMap<String, SwapRecord>,
    by_escrow: HashMap<String, String>,
}

impl SwapIndex {
    /// Replays every block and folds swap transactions into swap records.
    pub fn build(chain: &[Block]) -> Self {
        let mut index = SwapIndex::default();
        for block in chain {
            for tx in &block.transactions {
                index.apply(tx, block.index);
            }
        }
        index
    }

    /// Folds one already-validated transaction into the index.
    ///
    /// Invalid swap transactions are ignored here: consensus validation runs
    /// before a block is accepted, so anything reaching this point is either
    /// valid or from a block that will be rejected anyway.
    pub fn apply(&mut self, tx: &Transaction, height: u64) {
        let Some(payload) = tx.swap.as_ref() else {
            return;
        };
        match tx.kind {
            TxKind::SwapLock => {
                if self.by_id.contains_key(&payload.swap_id) {
                    return;
                }
                let escrow = swap_escrow_address(&payload.swap_id);
                let txid = if tx.txid.is_empty() {
                    tx.compute_txid()
                } else {
                    tx.txid.clone()
                };
                let record = SwapRecord {
                    swap_id: payload.swap_id.clone(),
                    escrow: escrow.clone(),
                    maker: tx.from.clone(),
                    recipient: payload.recipient.clone(),
                    amount: tx.amount,
                    hashlock: payload.hashlock.clone(),
                    timelock: payload.timelock,
                    foreign: payload.foreign.clone(),
                    status: SwapStatus::Open,
                    lock_txid: txid,
                    lock_height: height,
                    lock_time: tx.timestamp,
                    secret: String::new(),
                    settle_txid: String::new(),
                    settle_height: None,
                    payout: 0,
                };
                self.by_escrow.insert(escrow, payload.swap_id.clone());
                self.by_id.insert(payload.swap_id.clone(), record);
            }
            TxKind::SwapClaim | TxKind::SwapRefund => {
                let Some(record) = self.by_id.get_mut(&payload.swap_id) else {
                    return;
                };
                if !record.is_open() {
                    return;
                }
                record.status = if tx.kind == TxKind::SwapClaim {
                    record.secret = payload.secret.clone();
                    SwapStatus::Claimed
                } else {
                    SwapStatus::Refunded
                };
                record.settle_txid = if tx.txid.is_empty() {
                    tx.compute_txid()
                } else {
                    tx.txid.clone()
                };
                record.settle_height = Some(height);
                record.payout = tx.amount;
            }
            _ => {}
        }
    }

    pub fn get(&self, swap_id: &str) -> Option<&SwapRecord> {
        self.by_id.get(swap_id)
    }

    pub fn by_escrow(&self, escrow: &str) -> Option<&SwapRecord> {
        self.by_escrow.get(escrow).and_then(|id| self.by_id.get(id))
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Every swap, newest lock first.
    pub fn all(&self) -> Vec<&SwapRecord> {
        let mut out: Vec<&SwapRecord> = self.by_id.values().collect();
        out.sort_by(|a, b| {
            b.lock_height
                .cmp(&a.lock_height)
                .then_with(|| a.swap_id.cmp(&b.swap_id))
        });
        out
    }

    pub fn open(&self) -> Vec<&SwapRecord> {
        self.all().into_iter().filter(|r| r.is_open()).collect()
    }

    /// Swaps where `address` is the maker, the recipient or the escrow itself.
    pub fn for_address(&self, address: &str) -> Vec<&SwapRecord> {
        self.all()
            .into_iter()
            .filter(|r| r.maker == address || r.recipient == address || r.escrow == address)
            .collect()
    }
}

fn payload_of(tx: &Transaction) -> Result<&SwapPayload, NodeError> {
    tx.swap
        .as_ref()
        .ok_or_else(|| invalid("Swap transaction is missing its swap payload"))
}

/// Checks shared by all three swap kinds.
// The activation comparison is a no-op while the constant is 0, but it is what
// makes a future fork height a one-line change, so keep it.
#[allow(clippy::absurd_extreme_comparisons)]
pub fn validate_swap_common(tx: &Transaction, height: u64) -> Result<(), NodeError> {
    if height < SWAP_ACTIVATION_HEIGHT {
        return Err(invalid(format!(
            "Swap transactions activate at height {}",
            SWAP_ACTIVATION_HEIGHT
        )));
    }
    if tx.version < SWAP_TX_VERSION {
        return Err(invalid(format!(
            "Swap transactions require version {}",
            SWAP_TX_VERSION
        )));
    }
    let payload = payload_of(tx)?;
    if !is_hex_of_len(&payload.hashlock, SWAP_HASHLOCK_HEX_LEN) {
        return Err(invalid("Hashlock must be a lowercase sha256 hex digest"));
    }
    if payload.swap_id.is_empty() {
        return Err(invalid("Swap id is missing"));
    }
    if payload.timelock <= 0 {
        return Err(invalid("Timelock must be a positive unix timestamp"));
    }
    Ok(())
}

/// Validates a `SwapLock` and returns the escrow address it must fund.
///
/// `maker` is the address recovered from the transaction signature.
pub fn validate_swap_lock(tx: &Transaction, maker: &str, mtp: i64) -> Result<String, NodeError> {
    let payload = payload_of(tx)?;
    if !payload.secret.is_empty() {
        return Err(invalid("A lock must not reveal the secret"));
    }
    if payload.recipient.is_empty() {
        return Err(invalid("Swap lock is missing the recipient"));
    }
    if !crate::chain::is_valid_lfs_address(&payload.recipient) {
        return Err(invalid("Swap recipient must be an LFS address"));
    }
    if payload.recipient == maker {
        return Err(invalid("Swap recipient must differ from the maker"));
    }
    if tx.from != maker {
        return Err(invalid(
            "Swap lock must be sent from the maker's LFS address",
        ));
    }
    if let Some(foreign) = payload.foreign.as_ref() {
        foreign.validate().map_err(invalid)?;
    }
    // Settlements pay their fee out of the escrow, so a lock that cannot cover
    // one could never be claimed *or* refunded: the coins would be frozen for
    // good. Refuse those locks instead of creating them.
    if tx.amount <= MIN_TX_FEE {
        return Err(invalid(format!(
            "Swap amount must exceed the settlement fee ({})",
            MIN_TX_FEE
        )));
    }

    // Lifetime is measured from the transaction's own timestamp, which keeps
    // the check deterministic for every node replaying the block.
    let lifetime = payload.timelock.saturating_sub(tx.timestamp);
    if lifetime < SWAP_MIN_LOCK_SECS {
        return Err(invalid(format!(
            "Timelock too short (min {}s after the transaction timestamp)",
            SWAP_MIN_LOCK_SECS
        )));
    }
    if lifetime > SWAP_MAX_LOCK_SECS {
        return Err(invalid(format!(
            "Timelock too long (max {}s after the transaction timestamp)",
            SWAP_MAX_LOCK_SECS
        )));
    }
    // An already-expired lock would be refundable in the same breath, which is
    // never what the maker wants and only wastes chain space.
    if payload.timelock <= mtp {
        return Err(invalid("Timelock already expired at this height"));
    }

    let expected_id = swap_id(
        &tx.chain_id,
        maker,
        &payload.recipient,
        tx.amount,
        &payload.hashlock,
        payload.timelock,
        tx.nonce,
        payload.foreign.as_ref(),
    );
    if payload.swap_id != expected_id {
        return Err(invalid("Swap id does not commit to the swap terms"));
    }

    let escrow = swap_escrow_address(&expected_id);
    if tx.to != escrow {
        return Err(invalid("Swap lock must pay the escrow of its swap id"));
    }
    Ok(escrow)
}

/// Validates a `SwapClaim` or `SwapRefund` against the current swap state.
///
/// `signer` is the address recovered from the transaction signature; `mtp` is
/// the median time past of the blocks preceding this transaction.
pub fn validate_swap_settlement<'a>(
    tx: &Transaction,
    index: &'a SwapIndex,
    signer: &str,
    mtp: i64,
) -> Result<&'a SwapRecord, NodeError> {
    let payload = payload_of(tx)?;
    let record = index
        .get(&payload.swap_id)
        .ok_or_else(|| invalid("Unknown swap id"))?;
    if !record.is_open() {
        return Err(invalid(format!("Swap already {}", record.status.as_str())));
    }

    // The signed payload has to repeat the locked terms, so a settlement can
    // never be replayed against a different swap.
    if payload.hashlock != record.hashlock || payload.timelock != record.timelock {
        return Err(invalid("Settlement terms do not match the locked swap"));
    }
    if tx.from != record.escrow {
        return Err(invalid("Settlement must spend the swap escrow"));
    }
    // The escrow pays out its full balance: `amount` to the beneficiary and
    // `fee` to the miner. That keeps settlements from being free to relay
    // while leaving no dust behind in the escrow.
    if tx.amount.saturating_add(tx.fee) != record.amount {
        return Err(invalid(format!(
            "Settlement must spend the whole escrow ({} locked, got {} + {} fee)",
            record.amount, tx.amount, tx.fee
        )));
    }

    match tx.kind {
        TxKind::SwapClaim => {
            if payload.recipient != record.recipient {
                return Err(invalid("Settlement terms do not match the locked swap"));
            }
            if tx.to != record.recipient {
                return Err(invalid("Claim must pay the swap recipient"));
            }
            if signer != record.recipient {
                return Err(invalid("Only the recipient can claim a swap"));
            }
            if mtp >= record.timelock {
                return Err(invalid("Swap expired: claim window is closed"));
            }
            let secret = decode_secret_hex(&payload.secret)
                .ok_or_else(|| invalid("Secret must be 32 bytes of lowercase hex"))?;
            if sha256_hex(&secret) != record.hashlock {
                return Err(invalid("Secret does not match the hashlock"));
            }
        }
        TxKind::SwapRefund => {
            if !payload.secret.is_empty() {
                return Err(invalid("A refund must not reveal the secret"));
            }
            if tx.to != record.maker {
                return Err(invalid("Refund must pay the swap maker"));
            }
            if signer != record.maker {
                return Err(invalid("Only the maker can refund a swap"));
            }
            if mtp < record.timelock {
                return Err(invalid("Swap has not expired yet"));
            }
        }
        _ => return Err(invalid("Not a swap settlement transaction")),
    }

    Ok(record)
}
