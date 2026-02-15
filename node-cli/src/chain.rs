use std::collections::{HashMap, HashSet};

use blockchain_core::{Block, DEFAULT_DIFFICULTY_ZEROS, Transaction, pubkey_to_address};
use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};
use serde_json;
use sha2::{Digest, Sha256};

use crate::{
    errors::NodeError,
    storage::{read_data_file, write_data_file},
    wallet::read_mempool,
};

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
                balance -= tx.amount as i128;
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
                *balances.entry(from_addr).or_insert(0) -= tx.amount as i128;
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
    if !is_valid_recipient(&tx.to) {
        return Err(NodeError::ValidationError(
            "Invalid recipient address".to_string(),
        ));
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

    let verified = if tx.version >= 2 {
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
    if tx.from.is_empty() {
        if tx.signature.starts_with("reward") {
            return Ok(());
        }
        return Err(NodeError::ValidationError(
            "Missing sender for non-reward transaction".to_string(),
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
        .map(|m| m.amount as u128)
        .sum();
    if (tx.amount as u128) + pending_out > (balance.max(0) as u128) {
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
    } else if block.index != 0 {
        return Err(NodeError::ValidationError(
            "Invalid genesis index".to_string(),
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
    for tx in &block.transactions {
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

        if tx.from.is_empty() {
            if !tx.signature.starts_with("reward") {
                return Err(NodeError::ValidationError(
                    "Invalid reward transaction".to_string(),
                ));
            }
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
            if *bal < tx.amount as i128 {
                return Err(NodeError::ValidationError(
                    "Insufficient balance".to_string(),
                ));
            }
            *bal -= tx.amount as i128;
        }
        let to_addr = normalize_addr(&tx.to);
        *balances.entry(to_addr).or_insert(0) += tx.amount as i128;
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
            serde_json::from_str(&json).map_err(|e| NodeError::SerializationError(e.to_string()))
        }
        None => Ok(vec![Block::new(
            0,
            vec![],
            "0".to_string(),
            "genesis".to_string(),
        )]),
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
        if validate_tx_common(&tx).is_err() {
            continue;
        }
        if !seen_sigs.insert(tx.signature.clone()) {
            continue;
        }
        if !tx.txid.is_empty() && !seen_txids.insert(tx.txid.clone()) {
            continue;
        }
        if tx.from.is_empty() {
            if tx.signature.starts_with("reward") {
                valid_txs.push(tx);
            }
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
            if *balance >= tx.amount as i128 {
                next_nonces.insert(from_addr, expected.saturating_add(1));
                *balance -= tx.amount as i128;
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
