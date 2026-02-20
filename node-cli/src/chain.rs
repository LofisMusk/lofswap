use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use blockchain_core::{
    Block, CHAIN_ID, DEFAULT_DIFFICULTY_ZEROS, Transaction, TxKind, pubkey_to_address,
};
use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};
use serde_json;
use sha2::{Digest, Sha256};

use crate::{
    errors::NodeError,
    storage::{read_data_file, write_data_file},
    wallet::read_mempool,
};

const INITIAL_SUBSIDY: u64 = 1000;
const HALVING_INTERVAL: u64 = 100_000;
const MAX_FUTURE_DRIFT_SECS: i64 = 2 * 60 * 60;
const MIN_TX_FEE: u64 = 1;

pub fn block_subsidy(height: u64) -> u64 {
    let halvings = height / HALVING_INTERVAL;
    if halvings >= 63 {
        0
    } else {
        INITIAL_SUBSIDY >> halvings
    }
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
                *balances.entry(from_addr).or_insert(0) -=
                    (tx.amount as i128) + (tx.fee as i128);
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

fn is_valid_lfs_address(addr: &str) -> bool {
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
    // Coinbase output can use miner identifier if reward address is not configured yet.
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
        tx.version,
        chain_id,
        tx.kind,
        pubkey_str,
        tx.to,
        tx.amount,
        tx.fee,
        tx.timestamp
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
    let min_diff = DEFAULT_DIFFICULTY_ZEROS as usize;
    if difficulty == 0 || difficulty < min_diff {
        return Err(NodeError::ValidationError("Invalid difficulty".to_string()));
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

pub fn save_chain(chain: &[Block]) -> Result<(), NodeError> {
    let json = serde_json::to_string_pretty(chain)
        .map_err(|e| NodeError::SerializationError(e.to_string()))?;
    write_data_file("blockchain.json", &json).map_err(|e| NodeError::NetworkError(e.to_string()))
}

pub fn load_chain() -> Result<Vec<Block>, NodeError> {
    match read_data_file("blockchain.json").map_err(|e| NodeError::NetworkError(e.to_string()))? {
        Some(json) => {
            let mut chain: Vec<Block> = serde_json::from_str(&json)
                .map_err(|e| NodeError::SerializationError(e.to_string()))?;
            if chain.is_empty() {
                return Ok(vec![Block::genesis()]);
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
            Ok(chain)
        }
        None => Ok(vec![Block::genesis()]),
    }
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
    read_data_file("mempool.json")
        .ok()
        .flatten()
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
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
    let json = valid
        .iter()
        .filter_map(|tx| serde_json::to_string(tx).ok())
        .collect::<Vec<_>>()
        .join("\n");
    write_data_file("mempool.json", &json).map_err(|e| NodeError::NetworkError(e.to_string()))?;
    Ok((before, after))
}
