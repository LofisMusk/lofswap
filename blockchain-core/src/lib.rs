use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// spec_v0.9 constants
pub const SPEC_VERSION: &str = "0.9";
pub const DEFAULT_DIFFICULTY_ZEROS: u32 = 4;
pub const CHAIN_ID: &str = "lofswap-testnet";
pub const GENESIS_TIMESTAMP: i64 = 1_735_689_600; // 2025-01-01 00:00:00 UTC

pub fn default_chain_id() -> String {
    CHAIN_ID.to_string()
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TxKind {
    Coinbase,
    Transfer,
}

fn default_tx_kind() -> TxKind {
    TxKind::Transfer
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    // spec fields (frozen v0.9)
    pub version: u8,
    #[serde(default = "default_chain_id")]
    pub chain_id: String,
    #[serde(default = "default_tx_kind")]
    pub kind: TxKind,
    pub timestamp: i64,
    pub from: String, // now address (LFS...), legacy: raw pubkey
    pub to: String,
    pub amount: u64,
    #[serde(default)]
    pub fee: u64,
    pub signature: String,
    #[serde(default)]
    pub pubkey: String, // sender pubkey for signature verification
    #[serde(default)]
    pub nonce: u64, // sender sequence for anti-replay/double-spend ordering
    // Computed identifier. Optional when deserializing from older nodes.
    #[serde(default)]
    pub txid: String,
}

impl Transaction {
    pub fn compute_txid(&self) -> String {
        // txid is sha256 over canonical v3 fields, including kind/fee/nonce for replay safety.
        let signer = if !self.pubkey.is_empty() {
            self.pubkey.as_str()
        } else {
            self.from.as_str()
        };
        let chain_id = if self.chain_id.is_empty() {
            CHAIN_ID
        } else {
            self.chain_id.as_str()
        };
        // Include nonce so txids remain unique and sender-ordered.
        let preimage = if self.version >= 3 {
            format!(
                "{}|{}|{:?}|{}|{}|{}|{}|{}",
                self.version,
                chain_id,
                self.kind,
                signer,
                self.to,
                self.amount,
                self.fee,
                self.timestamp
            )
        } else {
            format!(
                "{}|{:?}|{}|{}|{}|{}|{}",
                self.version, self.kind, signer, self.to, self.amount, self.fee, self.timestamp
            )
        };
        let preimage = format!("{}|{}", preimage, self.nonce);
        let mut hasher = Sha256::new();
        hasher.update(preimage.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

// Helper to convert pubkey string to address used by wallets (LFS + bs58 of sha256(pubkey)[0..20])
pub fn pubkey_to_address(pubkey: &str) -> String {
    let mut hasher = Sha256::new();
    // hash the canonical pubkey string (compressed hex) so wallet/node agree
    hasher.update(pubkey.as_bytes());
    let digest = hasher.finalize();
    let addr = bs58::encode(&digest[..20]).into_string();
    format!("LFS{}", addr)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub version: u8,
    pub index: u64,
    pub timestamp: i64,
    pub transactions: Vec<Transaction>,
    pub previous_hash: String,
    pub nonce: u64,
    pub hash: String,
    pub miner: String,
    pub difficulty: u32,
}

impl Block {
    pub fn genesis() -> Self {
        // Canonical deterministic genesis shared by all nodes.
        let mut block = Block {
            version: 1,
            index: 0,
            timestamp: GENESIS_TIMESTAMP,
            transactions: Vec::new(),
            previous_hash: "0".to_string(),
            nonce: 0,
            hash: String::new(),
            miner: "genesis".to_string(),
            difficulty: DEFAULT_DIFFICULTY_ZEROS,
        };
        block.mine(DEFAULT_DIFFICULTY_ZEROS as usize);
        block
    }

    pub fn new(
        index: u64,
        mut transactions: Vec<Transaction>,
        previous_hash: String,
        miner: String,
    ) -> Self {
        let timestamp = Utc::now().timestamp();
        // Ensure txids are populated for v0.9
        for tx in transactions.iter_mut() {
            if tx.txid.is_empty() {
                tx.txid = tx.compute_txid();
            }
        }
        let mut block = Block {
            version: 1,
            index,
            timestamp,
            transactions,
            previous_hash,
            nonce: 0,
            hash: String::new(),
            miner,
            difficulty: DEFAULT_DIFFICULTY_ZEROS,
        };
        block.mine(DEFAULT_DIFFICULTY_ZEROS as usize);
        block
    }

    pub fn calculate_hash(&self) -> String {
        // Canonical preimage for spec_v0.9: version|index|timestamp|prev|miner|difficulty|nonce|txs_json
        let txs_json = serde_json::to_string(&self.transactions).unwrap_or_default();
        let input = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            self.version,
            self.index,
            self.timestamp,
            self.previous_hash,
            self.miner,
            self.difficulty,
            self.nonce,
            txs_json
        );
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn mine(&mut self, difficulty: usize) {
        let target = "0".repeat(difficulty);
        // Ensure we start from a clean known state
        self.hash.clear();
        self.nonce = 0;
        let start = std::time::Instant::now();
        let mut iters: u64 = 0;
        let mut last_report = start;
        loop {
            self.hash = self.calculate_hash();
            iters += 1;
            if self.hash.starts_with(&target) {
                break;
            }
            self.nonce = self.nonce.wrapping_add(1);
            // Telemetry: print hashrate once per second
            let now = std::time::Instant::now();
            if now.duration_since(last_report).as_secs_f64() >= 1.0 {
                let elapsed = now.duration_since(start).as_secs_f64();
                let hps = (iters as f64) / elapsed;
                println!(
                    "[mining] height={} target_zeros={} hashrate={:.2} H/s nonce={}",
                    self.index, difficulty, hps, self.nonce
                );
                last_report = now;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Block;

    #[test]
    fn genesis_is_deterministic() {
        let a = Block::genesis();
        let b = Block::genesis();
        assert_eq!(a.hash, b.hash);
        assert_eq!(a.nonce, b.nonce);
        assert_eq!(a.timestamp, b.timestamp);
    }
}
