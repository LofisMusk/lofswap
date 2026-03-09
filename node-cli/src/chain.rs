use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use blockchain_core::{
    Block, CHAIN_ID, DEFAULT_DIFFICULTY_ZEROS, Transaction, TxKind, pubkey_to_address,
};
use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};

use crate::{
    errors::NodeError,
    mempool::{read_mempool, replace_mempool},
    storage::{data_path, read_data_file, remove_data_file, write_data_file},
};

const MAX_FUTURE_DRIFT_SECS: i64 = 2 * 60 * 60;
pub const TARGET_BLOCK_TIME_SECS: i64 = 60;
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 10;
pub const DIFFICULTY_MIN_ZEROS: u32 = 1;
pub const DIFFICULTY_MAX_ZEROS: u32 = 32;
const MIN_TX_FEE: u64 = 1;
const CHAIN_SNAPSHOT_FILE: &str = "blockchain.json";
const CHAIN_DB_DIR: &str = "chain_db";
const CHAIN_DB_BLOCKS_TREE: &str = "blocks";
const CHAIN_DB_HEIGHT_TO_HASH_TREE: &str = "height_to_hash";
const CHAIN_DB_TXID_TO_LOC_TREE: &str = "txid_to_loc";
const CHAIN_DB_STATE_SNAPSHOTS_TREE: &str = "state_snapshots";
const STATE_SNAPSHOT_FILE: &str = "state_snapshot.json";
const STATE_SNAPSHOT_INTERVAL: u64 = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TxLocation {
    height: u64,
    tx_index: u32,
    block_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateSnapshot {
    version: u8,
    height: u64,
    block_hash: String,
    balances: HashMap<String, i128>,
}

pub fn block_subsidy(_height: u64) -> u64 {
    10
}

pub fn expected_next_difficulty(chain: &[Block]) -> u32 {
    if chain.is_empty() {
        return DEFAULT_DIFFICULTY_ZEROS
            .max(DIFFICULTY_MIN_ZEROS)
            .min(DIFFICULTY_MAX_ZEROS);
    }

    let prev = match chain.last() {
        Some(b) => b,
        None => return DEFAULT_DIFFICULTY_ZEROS,
    };
    let next_index = prev.index.saturating_add(1);
    let mut next = prev
        .difficulty
        .max(DIFFICULTY_MIN_ZEROS)
        .min(DIFFICULTY_MAX_ZEROS);

    if DIFFICULTY_ADJUSTMENT_INTERVAL == 0 || next_index % DIFFICULTY_ADJUSTMENT_INTERVAL != 0 {
        return next;
    }

    let window = DIFFICULTY_ADJUSTMENT_INTERVAL as usize;
    if chain.len() < 3 {
        return next;
    }
    let end_idx = chain.len().saturating_sub(1);
    let mut start_idx = end_idx.saturating_sub(window);
    // Ignore ancient genesis timestamp when network starts long after genesis.
    if start_idx == 0 && end_idx > 1 {
        start_idx = 1;
    }
    if end_idx <= start_idx {
        return next;
    }
    let start = &chain[start_idx];
    let end = &chain[end_idx];
    let intervals = (end_idx - start_idx) as i64;
    let actual_span = end.timestamp.saturating_sub(start.timestamp).max(1);
    let target_span = TARGET_BLOCK_TIME_SECS.saturating_mul(intervals).max(1);

    if actual_span < target_span / 2 {
        next = next.saturating_add(1);
    } else if actual_span > target_span.saturating_mul(2) {
        next = next.saturating_sub(1);
    }

    next.max(DIFFICULTY_MIN_ZEROS).min(DIFFICULTY_MAX_ZEROS)
}

fn is_coinbase_tx(tx: &Transaction) -> bool {
    tx.kind == TxKind::Coinbase
        && tx.from.is_empty()
        && tx.pubkey.is_empty()
        && tx.nonce == 0
        && tx.signature.starts_with("coinbase:")
}

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn median_time_past(chain: &[Block], window: usize) -> i64 {
    if chain.is_empty() {
        return 0;
    }
    let mut times: Vec<i64> = chain
        .iter()
        .rev()
        .take(window)
        .map(|b| b.timestamp)
        .collect();
    times.sort_unstable();
    times[times.len() / 2]
}

pub fn calculate_balance(address: &str, chain: &[Block]) -> i128 {
    let address = normalize_addr(address);
    let mut balance = 0i128;
    for block in chain {
        for tx in &block.transactions {
            let to_addr = normalize_addr(&tx.to);
            if to_addr == address {
                balance += tx.amount as i128;
            }
            let from_addr = normalize_addr(&tx.from);
            if from_addr == address && !tx.from.is_empty() {
                balance -= (tx.amount as i128) + (tx.fee as i128);
            }
        }
    }
    balance
}

pub fn calculate_balances(chain: &[Block]) -> HashMap<String, i128> {
    let mut balances = HashMap::new();
    for block in chain {
        for tx in &block.transactions {
            let from_addr = normalize_addr(&tx.from);
            let to_addr = normalize_addr(&tx.to);
            if !from_addr.is_empty() {
                *balances.entry(from_addr).or_insert(0) -= (tx.amount as i128) + (tx.fee as i128);
            }
            *balances.entry(to_addr).or_insert(0) += tx.amount as i128;
        }
    }
    balances
}

pub fn is_tx_valid(tx: &Transaction, chain: &[Block]) -> Result<(), NodeError> {
    is_tx_valid_inner(tx, chain, true)
}

fn normalize_addr(addr: &str) -> String {
    if addr.is_empty() {
        String::new()
    } else if addr.starts_with("LFS") {
        addr.to_string()
    } else {
        pubkey_to_address(addr)
    }
}

fn same_tx(a: &Transaction, b: &Transaction) -> bool {
    a.signature == b.signature || (!a.txid.is_empty() && !b.txid.is_empty() && a.txid == b.txid)
}

pub fn is_valid_lfs_address(addr: &str) -> bool {
    if !addr.starts_with("LFS") {
        return false;
    }
    let payload = &addr[3..];
    if payload.is_empty() {
        return false;
    }
    bs58::decode(payload)
        .into_vec()
        .map(|v| v.len() == 20)
        .unwrap_or(false)
}

fn is_valid_recipient(recipient: &str) -> bool {
    if recipient.starts_with("LFS") {
        is_valid_lfs_address(recipient)
    } else {
        recipient.parse::<PublicKey>().is_ok()
    }
}

fn validate_tx_common(tx: &Transaction) -> Result<(), NodeError> {
    if tx.amount == 0 {
        return Err(NodeError::ValidationError("Invalid amount".to_string()));
    }
    if tx.to.is_empty() {
        return Err(NodeError::ValidationError("Missing recipient".to_string()));
    }
    // Recipient syntax is enforced for transfers; coinbase policy is validated at block level.
    if !tx.from.is_empty() && !is_valid_recipient(&tx.to) {
        return Err(NodeError::ValidationError(
            "Invalid recipient address".to_string(),
        ));
    }
    if tx.version >= 3 {
        let chain_id = if tx.chain_id.is_empty() {
            CHAIN_ID
        } else {
            tx.chain_id.as_str()
        };
        if chain_id != CHAIN_ID {
            return Err(NodeError::ValidationError("Wrong chain id".to_string()));
        }
    }
    match tx.kind {
        TxKind::Coinbase => {
            if tx.fee != 0 {
                return Err(NodeError::ValidationError(
                    "Coinbase fee must be zero".to_string(),
                ));
            }
        }
        TxKind::Transfer => {
            if tx.fee < MIN_TX_FEE {
                return Err(NodeError::ValidationError(format!(
                    "Fee too low (min {})",
                    MIN_TX_FEE
                )));
            }
        }
    }
    Ok(())
}

fn confirmed_next_nonce(sender_addr: &str, chain: &[Block]) -> u64 {
    chain
        .iter()
        .flat_map(|b| b.transactions.iter())
        .filter(|tx| !tx.from.is_empty() && normalize_addr(&tx.from) == sender_addr)
        .map(|tx| tx.nonce)
        .max()
        .map(|n| n.saturating_add(1))
        .unwrap_or(0)
}

fn expected_nonce(
    sender_addr: &str,
    chain: &[Block],
    mempool: &[Transaction],
    exclude: Option<&Transaction>,
) -> u64 {
    let mut next = confirmed_next_nonce(sender_addr, chain);
    let mut pending_nonces = HashSet::new();
    for tx in mempool {
        if exclude.is_some_and(|x| same_tx(tx, x)) {
            continue;
        }
        if !tx.from.is_empty() && normalize_addr(&tx.from) == sender_addr {
            pending_nonces.insert(tx.nonce);
        }
    }
    while pending_nonces.contains(&next) {
        next = next.saturating_add(1);
    }
    next
}

pub fn next_nonce_for_address(address: &str, chain: &[Block]) -> u64 {
    let addr = normalize_addr(address);
    if addr.is_empty() {
        return 0;
    }
    let mempool = read_mempool();
    expected_nonce(&addr, chain, &mempool, None)
}

fn derive_pubkey(tx: &Transaction) -> Result<String, NodeError> {
    if !tx.pubkey.is_empty() {
        Ok(tx.pubkey.clone())
    } else if !tx.from.is_empty() && !tx.from.starts_with("LFS") {
        Ok(tx.from.clone())
    } else {
        Err(NodeError::ValidationError(
            "Missing pubkey for address".to_string(),
        ))
    }
}

fn resolve_sender(tx: &Transaction) -> Result<(String, PublicKey, String), NodeError> {
    let pubkey_str = derive_pubkey(tx)?;
    let from_pubkey = pubkey_str
        .parse::<PublicKey>()
        .map_err(|_| NodeError::ValidationError("Invalid public key".to_string()))?;
    let derived_addr = pubkey_to_address(&pubkey_str);
    if !tx.from.is_empty() && normalize_addr(&tx.from) != derived_addr {
        return Err(NodeError::ValidationError(
            "From address does not match pubkey".to_string(),
        ));
    }
    Ok((pubkey_str, from_pubkey, derived_addr))
}

fn verify_tx_signature(
    tx: &Transaction,
    pubkey_str: &str,
    from_pubkey: &PublicKey,
) -> Result<(), NodeError> {
    let secp = Secp256k1::new();
    let chain_id = if tx.chain_id.is_empty() {
        CHAIN_ID
    } else {
        tx.chain_id.as_str()
    };
    let msg_data_v3 = format!(
        "{}|{}|{:?}|{}|{}|{}|{}|{}",
        tx.version, chain_id, tx.kind, pubkey_str, tx.to, tx.amount, tx.fee, tx.timestamp
    );
    let msg_data_v3 = format!("{}|{}", msg_data_v3, tx.nonce);
    let hash_v3 = Sha256::digest(msg_data_v3.as_bytes());
    let msg_v3 = Message::from_digest(hash_v3.into());

    let msg_data_v2 = format!(
        "{}|{}|{}|{}|{}|{}",
        tx.version, pubkey_str, tx.to, tx.amount, tx.timestamp, tx.nonce
    );
    let hash_v2 = Sha256::digest(msg_data_v2.as_bytes());
    let msg_v2 = Message::from_digest(hash_v2.into());

    let msg_data_v1 = format!(
        "{}|{}|{}|{}|{}",
        tx.version, pubkey_str, tx.to, tx.amount, tx.timestamp
    );
    let hash_v1 = Sha256::digest(msg_data_v1.as_bytes());
    let msg_v1 = Message::from_digest(hash_v1.into());

    let msg_data_legacy = format!("{}{}{}", pubkey_str, tx.to, tx.amount);
    let hash_legacy = Sha256::digest(msg_data_legacy.as_bytes());
    let msg_legacy = Message::from_digest(hash_legacy.into());

    let sig_bytes = hex::decode(&tx.signature)
        .map_err(|_| NodeError::ValidationError("Invalid signature format".to_string()))?;
    let signature = Signature::from_compact(&sig_bytes)
        .map_err(|_| NodeError::ValidationError("Invalid signature".to_string()))?;

    let verified = if tx.version >= 3 {
        secp.verify_ecdsa(msg_v3, &signature, from_pubkey)
    } else if tx.version >= 2 {
        secp.verify_ecdsa(msg_v2, &signature, from_pubkey)
    } else {
        secp.verify_ecdsa(msg_v1, &signature, from_pubkey)
            .or_else(|_| secp.verify_ecdsa(msg_legacy, &signature, from_pubkey))
    };
    verified
        .map_err(|_| NodeError::ValidationError("Signature verification failed".to_string()))?;
    Ok(())
}

fn is_tx_valid_inner(
    tx: &Transaction,
    chain: &[Block],
    check_mempool_duplicates: bool,
) -> Result<(), NodeError> {
    validate_tx_common(tx)?;
    if tx.kind == TxKind::Coinbase || tx.from.is_empty() {
        return Err(NodeError::ValidationError(
            "Coinbase transaction is block-only".to_string(),
        ));
    }

    let (pubkey_str, from_pubkey, derived_addr) = resolve_sender(tx)?;

    let mempool = read_mempool();
    let expected = expected_nonce(&derived_addr, chain, &mempool, Some(tx));
    if tx.nonce != expected {
        return Err(NodeError::ValidationError(format!(
            "Invalid nonce (expected {}, got {})",
            expected, tx.nonce
        )));
    }

    let balance = calculate_balance(&derived_addr, chain);
    let pending_out: u128 = mempool
        .iter()
        .filter(|m| !same_tx(m, tx))
        .filter(|m| {
            let m_from = normalize_addr(&m.from);
            if m_from != derived_addr || m_from.is_empty() {
                return false;
            }
            true
        })
        .map(|m| (m.amount as u128).saturating_add(m.fee as u128))
        .sum();
    if (tx.amount as u128)
        .saturating_add(tx.fee as u128)
        .saturating_add(pending_out)
        > (balance.max(0) as u128)
    {
        return Err(NodeError::ValidationError(
            "Insufficient balance (pending)".to_string(),
        ));
    }

    let already_exists_in_chain = chain
        .iter()
        .any(|block| block.transactions.iter().any(|btx| same_tx(btx, tx)));

    let already_exists_in_mempool = if check_mempool_duplicates {
        mempool.iter().any(|m| same_tx(m, tx))
    } else {
        false
    };

    if already_exists_in_chain || already_exists_in_mempool {
        return Err(NodeError::ValidationError(
            "Transaction already exists".to_string(),
        ));
    }

    verify_tx_signature(tx, &pubkey_str, &from_pubkey)?;

    Ok(())
}

pub fn validate_block(
    block: &Block,
    prev: Option<&Block>,
    chain: &[Block],
) -> Result<(), NodeError> {
    if let Some(prev) = prev {
        if block.index != prev.index + 1 {
            return Err(NodeError::ValidationError(
                "Invalid block index".to_string(),
            ));
        }
        if block.previous_hash != prev.hash {
            return Err(NodeError::ValidationError(
                "Invalid previous hash".to_string(),
            ));
        }
        if block.timestamp < prev.timestamp {
            return Err(NodeError::ValidationError(
                "Block timestamp regressed".to_string(),
            ));
        }
        let mtp = median_time_past(chain, 11);
        if block.timestamp < mtp {
            return Err(NodeError::ValidationError(
                "Block timestamp below median time past".to_string(),
            ));
        }
    } else if block.index != 0 {
        return Err(NodeError::ValidationError(
            "Invalid genesis index".to_string(),
        ));
    }
    if block.timestamp > now_unix_secs().saturating_add(MAX_FUTURE_DRIFT_SECS) {
        return Err(NodeError::ValidationError(
            "Block timestamp too far in future".to_string(),
        ));
    }

    let calculated = block.calculate_hash();
    if calculated != block.hash {
        return Err(NodeError::ValidationError("Invalid block hash".to_string()));
    }

    let difficulty = block.difficulty as usize;
    if difficulty == 0 {
        return Err(NodeError::ValidationError("Invalid difficulty".to_string()));
    }
    let expected_difficulty = if block.index == 0 {
        DEFAULT_DIFFICULTY_ZEROS
            .max(DIFFICULTY_MIN_ZEROS)
            .min(DIFFICULTY_MAX_ZEROS)
    } else {
        expected_next_difficulty(chain)
    };
    if block.difficulty != expected_difficulty {
        return Err(NodeError::ValidationError(format!(
            "Invalid difficulty (expected {}, got {})",
            expected_difficulty, block.difficulty
        )));
    }
    if !block.hash.starts_with(&"0".repeat(difficulty)) {
        return Err(NodeError::ValidationError(
            "Proof-of-work invalid".to_string(),
        ));
    }

    if block.transactions.is_empty() {
        return Err(NodeError::ValidationError(
            "Block must contain coinbase at index 0".to_string(),
        ));
    }

    let coinbase = &block.transactions[0];
    if !is_coinbase_tx(coinbase) {
        return Err(NodeError::ValidationError(
            "Invalid coinbase transaction".to_string(),
        ));
    }

    let mut balances = calculate_balances(chain);
    let mut seen = HashSet::new();
    let mut chain_seen = HashSet::new();
    let mut next_nonces = HashMap::new();
    for b in chain {
        for tx in &b.transactions {
            if !tx.txid.is_empty() {
                chain_seen.insert(tx.txid.clone());
            }
            chain_seen.insert(tx.signature.clone());
        }
    }
    let mut fees_sum: u64 = 0;
    for (idx, tx) in block.transactions.iter().enumerate() {
        validate_tx_common(tx)?;
        let txid = if !tx.txid.is_empty() {
            tx.txid.clone()
        } else {
            tx.compute_txid()
        };

        if !tx.txid.is_empty() && tx.txid != txid {
            return Err(NodeError::ValidationError("Invalid txid".to_string()));
        }

        if chain_seen.contains(&txid) || chain_seen.contains(&tx.signature) {
            return Err(NodeError::ValidationError(
                "Duplicate transaction".to_string(),
            ));
        }

        if !seen.insert(txid.clone()) || !seen.insert(tx.signature.clone()) {
            return Err(NodeError::ValidationError(
                "Duplicate transaction".to_string(),
            ));
        }

        if idx == 0 {
            continue;
        } else if tx.kind != TxKind::Transfer || tx.from.is_empty() {
            return Err(NodeError::ValidationError(
                "Only transfer transactions are allowed after coinbase".to_string(),
            ));
        } else {
            let (pubkey_str, from_pubkey, from_addr) = resolve_sender(tx)?;
            verify_tx_signature(tx, &pubkey_str, &from_pubkey)?;
            let expected = *next_nonces
                .entry(from_addr.clone())
                .or_insert_with(|| confirmed_next_nonce(&from_addr, chain));
            if tx.nonce != expected {
                return Err(NodeError::ValidationError(format!(
                    "Invalid nonce (expected {}, got {})",
                    expected, tx.nonce
                )));
            }
            next_nonces.insert(from_addr.clone(), expected.saturating_add(1));
            let bal = balances.entry(from_addr.clone()).or_insert(0);
            let spend = (tx.amount as i128) + (tx.fee as i128);
            if *bal < spend {
                return Err(NodeError::ValidationError(
                    "Insufficient balance".to_string(),
                ));
            }
            *bal -= spend;
            fees_sum = fees_sum.saturating_add(tx.fee);
        }
        let to_addr = normalize_addr(&tx.to);
        *balances.entry(to_addr).or_insert(0) += tx.amount as i128;
    }

    let expected_reward = block_subsidy(block.index).saturating_add(fees_sum);
    if coinbase.amount != expected_reward {
        return Err(NodeError::ValidationError(format!(
            "Invalid coinbase amount (expected {}, got {})",
            expected_reward, coinbase.amount
        )));
    }

    Ok(())
}

pub fn validate_chain(chain: &[Block]) -> Result<(), NodeError> {
    if chain.is_empty() {
        return Ok(());
    }
    for i in 0..chain.len() {
        let prev = if i == 0 { None } else { Some(&chain[i - 1]) };
        validate_block(&chain[i], prev, &chain[..i])?;
    }
    Ok(())
}

fn height_key(height: u64) -> [u8; 8] {
    height.to_be_bytes()
}

fn open_chain_db() -> Result<sled::Db, NodeError> {
    let path = data_path(CHAIN_DB_DIR);
    sled::open(path).map_err(|e| NodeError::NetworkError(format!("chain db open: {}", e)))
}

fn remove_dir_if_exists(path: &Path) -> Result<(), NodeError> {
    match fs::remove_dir_all(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(NodeError::NetworkError(e.to_string())),
    }
}

fn normalize_loaded_chain(mut chain: Vec<Block>) -> Vec<Block> {
    if chain.is_empty() {
        return vec![Block::genesis()];
    }
    // One-time normalization for old local stores that had time-based genesis.
    if chain.len() == 1 {
        let candidate = &chain[0];
        if candidate.index == 0
            && candidate.previous_hash == "0"
            && candidate.transactions.is_empty()
        {
            chain[0] = Block::genesis();
        }
    }
    chain
}

fn persist_chain_to_sled(chain: &[Block]) -> Result<(), NodeError> {
    let db = open_chain_db()?;
    let blocks = db
        .open_tree(CHAIN_DB_BLOCKS_TREE)
        .map_err(|e| NodeError::NetworkError(format!("chain db blocks tree: {}", e)))?;
    let height_to_hash = db
        .open_tree(CHAIN_DB_HEIGHT_TO_HASH_TREE)
        .map_err(|e| NodeError::NetworkError(format!("chain db height tree: {}", e)))?;
    let txid_to_loc = db
        .open_tree(CHAIN_DB_TXID_TO_LOC_TREE)
        .map_err(|e| NodeError::NetworkError(format!("chain db tx index tree: {}", e)))?;
    let state_snapshots = db
        .open_tree(CHAIN_DB_STATE_SNAPSHOTS_TREE)
        .map_err(|e| NodeError::NetworkError(format!("chain db state tree: {}", e)))?;

    blocks
        .clear()
        .map_err(|e| NodeError::NetworkError(format!("clear blocks tree: {}", e)))?;
    height_to_hash
        .clear()
        .map_err(|e| NodeError::NetworkError(format!("clear height tree: {}", e)))?;
    txid_to_loc
        .clear()
        .map_err(|e| NodeError::NetworkError(format!("clear tx index tree: {}", e)))?;
    state_snapshots
        .clear()
        .map_err(|e| NodeError::NetworkError(format!("clear state snapshot tree: {}", e)))?;

    let mut balances: HashMap<String, i128> = HashMap::new();
    let mut latest_snapshot: Option<StateSnapshot> = None;

    for block in chain {
        let block_bytes = serde_json::to_vec(block)
            .map_err(|e| NodeError::SerializationError(format!("serialize block: {}", e)))?;
        blocks
            .insert(block.hash.as_bytes(), block_bytes)
            .map_err(|e| NodeError::NetworkError(format!("insert block: {}", e)))?;
        height_to_hash
            .insert(height_key(block.index), block.hash.as_bytes())
            .map_err(|e| NodeError::NetworkError(format!("insert height index: {}", e)))?;

        for (tx_index, tx) in block.transactions.iter().enumerate() {
            let txid = if tx.txid.is_empty() {
                tx.compute_txid()
            } else {
                tx.txid.clone()
            };
            let loc = TxLocation {
                height: block.index,
                tx_index: tx_index as u32,
                block_hash: block.hash.clone(),
            };
            let loc_bytes = serde_json::to_vec(&loc)
                .map_err(|e| NodeError::SerializationError(format!("serialize tx index: {}", e)))?;
            txid_to_loc
                .insert(txid.as_bytes(), loc_bytes)
                .map_err(|e| NodeError::NetworkError(format!("insert tx index: {}", e)))?;

            let from_addr = normalize_addr(&tx.from);
            if !from_addr.is_empty() {
                *balances.entry(from_addr).or_insert(0) -= (tx.amount as i128) + (tx.fee as i128);
            }
            let to_addr = normalize_addr(&tx.to);
            *balances.entry(to_addr).or_insert(0) += tx.amount as i128;
        }

        let is_tip = block.index.saturating_add(1) == chain.len() as u64;
        if block.index % STATE_SNAPSHOT_INTERVAL == 0 || is_tip {
            let snapshot = StateSnapshot {
                version: 1,
                height: block.index,
                block_hash: block.hash.clone(),
                balances: balances.clone(),
            };
            let snapshot_bytes = serde_json::to_vec(&snapshot).map_err(|e| {
                NodeError::SerializationError(format!("serialize state snapshot: {}", e))
            })?;
            state_snapshots
                .insert(height_key(block.index), snapshot_bytes)
                .map_err(|e| NodeError::NetworkError(format!("insert state snapshot: {}", e)))?;
            latest_snapshot = Some(snapshot);
        }
    }

    db.flush()
        .map_err(|e| NodeError::NetworkError(format!("flush chain db: {}", e)))?;

    if let Some(snapshot) = latest_snapshot {
        let json = serde_json::to_string_pretty(&snapshot)
            .map_err(|e| NodeError::SerializationError(e.to_string()))?;
        write_data_file(STATE_SNAPSHOT_FILE, &json)
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    }

    Ok(())
}

fn load_chain_from_sled() -> Result<Option<Vec<Block>>, NodeError> {
    let db = open_chain_db()?;
    let blocks = db
        .open_tree(CHAIN_DB_BLOCKS_TREE)
        .map_err(|e| NodeError::NetworkError(format!("chain db blocks tree: {}", e)))?;
    let height_to_hash = db
        .open_tree(CHAIN_DB_HEIGHT_TO_HASH_TREE)
        .map_err(|e| NodeError::NetworkError(format!("chain db height tree: {}", e)))?;

    if height_to_hash.is_empty() {
        return Ok(None);
    }

    let mut chain = Vec::new();
    for item in height_to_hash.iter() {
        let (_, hash_bytes) =
            item.map_err(|e| NodeError::NetworkError(format!("iterate height index: {}", e)))?;
        let hash = String::from_utf8(hash_bytes.to_vec())
            .map_err(|e| NodeError::SerializationError(format!("invalid hash key: {}", e)))?;
        let Some(block_bytes) = blocks
            .get(hash.as_bytes())
            .map_err(|e| NodeError::NetworkError(format!("read block by hash: {}", e)))?
        else {
            return Err(NodeError::ValidationError(format!(
                "missing block payload for hash {}",
                hash
            )));
        };
        let block = serde_json::from_slice::<Block>(&block_bytes)
            .map_err(|e| NodeError::SerializationError(format!("decode block: {}", e)))?;
        chain.push(block);
    }

    Ok(Some(chain))
}

pub fn clear_chain_storage() -> Result<(), NodeError> {
    remove_data_file(CHAIN_SNAPSHOT_FILE).map_err(|e| NodeError::NetworkError(e.to_string()))?;
    remove_data_file(STATE_SNAPSHOT_FILE).map_err(|e| NodeError::NetworkError(e.to_string()))?;

    let data_db_path = data_path(CHAIN_DB_DIR);
    remove_dir_if_exists(&data_db_path)?;
    remove_dir_if_exists(Path::new(CHAIN_DB_DIR))?;
    Ok(())
}

pub fn save_chain(chain: &[Block]) -> Result<(), NodeError> {
    persist_chain_to_sled(chain)?;
    let json = serde_json::to_string_pretty(chain)
        .map_err(|e| NodeError::SerializationError(e.to_string()))?;
    write_data_file(CHAIN_SNAPSHOT_FILE, &json).map_err(|e| NodeError::NetworkError(e.to_string()))
}

pub fn load_chain() -> Result<Vec<Block>, NodeError> {
    match load_chain_from_sled() {
        Ok(Some(chain)) => return Ok(normalize_loaded_chain(chain)),
        Ok(None) => {}
        Err(e) => {
            eprintln!("[CHAIN] Failed to load chain from sled, falling back to JSON snapshot: {e}")
        }
    }

    let loaded = match read_data_file(CHAIN_SNAPSHOT_FILE)
        .map_err(|e| NodeError::NetworkError(e.to_string()))?
    {
        Some(json) => {
            let chain: Vec<Block> = serde_json::from_str(&json)
                .map_err(|e| NodeError::SerializationError(e.to_string()))?;
            normalize_loaded_chain(chain)
        }
        None => vec![Block::genesis()],
    };

    persist_chain_to_sled(&loaded)?;
    Ok(loaded)
}

pub fn load_peers() -> Result<Vec<String>, NodeError> {
    match read_data_file("peers.json").map_err(|e| NodeError::NetworkError(e.to_string()))? {
        Some(json) => serde_json::from_str(&json)
            .map_err(|e| NodeError::SerializationError(e.to_string()))
            .or(Ok(vec![])),
        None => Ok(vec![]),
    }
}

pub fn save_peers(peers: &[String]) -> Result<(), NodeError> {
    let json = serde_json::to_string_pretty(peers)
        .map_err(|e| NodeError::SerializationError(e.to_string()))?;
    write_data_file("peers.json", &json).map_err(|e| NodeError::NetworkError(e.to_string()))
}

fn parse_mempool_transactions() -> Vec<Transaction> {
    read_mempool()
}

fn filter_valid_transactions(parsed: Vec<Transaction>, chain: &[Block]) -> Vec<Transaction> {
    let mut balances = calculate_balances(chain);
    let mut next_nonces: HashMap<String, u64> = HashMap::new();
    let mut seen_sigs = HashSet::new();
    let mut seen_txids = HashSet::new();
    let mut valid_txs = Vec::new();

    for tx in parsed {
        if tx.kind == TxKind::Coinbase || tx.from.is_empty() {
            // Never mine coinbase/reward from mempool.
            continue;
        }
        if validate_tx_common(&tx).is_err() {
            continue;
        }
        if !seen_sigs.insert(tx.signature.clone()) {
            continue;
        }
        if !tx.txid.is_empty() && !seen_txids.insert(tx.txid.clone()) {
            continue;
        }
        if is_tx_valid_inner(&tx, chain, false).is_ok() {
            let from_addr = normalize_addr(&tx.from);
            let to_addr = normalize_addr(&tx.to);
            let expected = *next_nonces
                .entry(from_addr.clone())
                .or_insert_with(|| confirmed_next_nonce(&from_addr, chain));
            if tx.nonce != expected {
                continue;
            }
            let balance = balances.entry(from_addr.clone()).or_insert(0);
            let spend = (tx.amount as i128) + (tx.fee as i128);
            if *balance >= spend {
                next_nonces.insert(from_addr, expected.saturating_add(1));
                *balance -= spend;
                *balances.entry(to_addr).or_insert(0) += tx.amount as i128;
                valid_txs.push(tx);
            }
        }
    }

    valid_txs
}

pub fn load_valid_transactions(chain: &[Block]) -> Vec<Transaction> {
    filter_valid_transactions(parse_mempool_transactions(), chain)
}

pub fn prune_mempool(chain: &[Block]) -> Result<(usize, usize), NodeError> {
    let parsed = parse_mempool_transactions();
    let before = parsed.len();
    let valid = filter_valid_transactions(parsed, chain);
    let after = valid.len();
    replace_mempool(valid).map_err(NodeError::NetworkError)?;
    Ok((before, after))
}
