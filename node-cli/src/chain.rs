use std::collections::{HashMap, HashSet};

use blockchain_core::{pubkey_to_address, Block, Transaction, DEFAULT_DIFFICULTY_ZEROS};
use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};
use serde_json;
use sha2::{Digest, Sha256};

use crate::{
    errors::NodeError,
    storage::{read_data_file, write_data_file},
    wallet::read_mempool,
};

pub fn calculate_balance(address: &str, chain: &[Block]) -> i128 {
    let mut balance = 0i128;
    for block in chain {
        for tx in &block.transactions {
            let to_addr = normalize_addr(&tx.to, &tx.pubkey);
            if to_addr == address {
                balance += tx.amount as i128;
            }
            let from_addr = normalize_addr(&tx.from, &tx.pubkey);
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
            let from_addr = normalize_addr(&tx.from, &tx.pubkey);
            let to_addr = normalize_addr(&tx.to, &tx.pubkey);
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

fn normalize_addr(addr: &str, pubkey: &str) -> String {
    if addr.starts_with("LFS") {
        addr.to_string()
    } else if !pubkey.is_empty() {
        pubkey_to_address(pubkey)
    } else {
        pubkey_to_address(addr)
    }
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

fn is_tx_valid_inner(tx: &Transaction, chain: &[Block], check_mempool_duplicates: bool) -> Result<(), NodeError> {
    if tx.from.is_empty() && tx.signature.starts_with("reward") {
        return Ok(());
    }

    let secp = Secp256k1::new();
    let pubkey_str = derive_pubkey(tx)?;
    let from_pubkey = pubkey_str
        .parse::<PublicKey>()
        .map_err(|_| NodeError::ValidationError("Invalid public key".to_string()))?;

    let from_addr = normalize_addr(&tx.from, &tx.pubkey);
    let derived_addr = pubkey_to_address(&pubkey_str);
    if !from_addr.is_empty() && from_addr != derived_addr {
        return Err(NodeError::ValidationError(
            "From address does not match pubkey".to_string(),
        ));
    }

    let balance = calculate_balance(&derived_addr, chain);
    let pending_out: u128 = read_mempool()
        .into_iter()
        .filter(|m| {
            let m_from = normalize_addr(&m.from, &m.pubkey);
            m_from == derived_addr && !m_from.is_empty()
        })
        .map(|m| m.amount as u128)
        .sum();
    if (tx.amount as u128) + pending_out > (balance.max(0) as u128) {
        return Err(NodeError::ValidationError(
            "Insufficient balance (pending)".to_string(),
        ));
    }

    let msg_data_new = format!("{}|{}|{}|{}|{}", tx.version, pubkey_str, tx.to, tx.amount, tx.timestamp);
    let hash_new = Sha256::digest(msg_data_new.as_bytes());
    let msg_new = Message::from_digest(hash_new.into());

    let msg_data_legacy = format!("{}{}{}", pubkey_str, tx.to, tx.amount);
    let hash_legacy = Sha256::digest(msg_data_legacy.as_bytes());
    let msg_legacy = Message::from_digest(hash_legacy.into());

    let sig_bytes = hex::decode(&tx.signature)
        .map_err(|_| NodeError::ValidationError("Invalid signature format".to_string()))?;
    let signature = Signature::from_compact(&sig_bytes)
        .map_err(|_| NodeError::ValidationError("Invalid signature".to_string()))?;

    let already_exists_in_chain = chain.iter().any(|block| {
        block.transactions.iter().any(|btx| {
            btx.signature == tx.signature || (!tx.txid.is_empty() && btx.txid == tx.txid)
        })
    });

    let already_exists_in_mempool = if check_mempool_duplicates {
        read_mempool()
            .iter()
            .any(|m| m.signature == tx.signature || (!tx.txid.is_empty() && m.txid == tx.txid))
    } else {
        false
    };

    if already_exists_in_chain || already_exists_in_mempool {
        return Err(NodeError::ValidationError(
            "Transaction already exists".to_string(),
        ));
    }


    secp.verify_ecdsa(msg_new, &signature, &from_pubkey)
        .or_else(|_| secp.verify_ecdsa(msg_legacy, &signature, &from_pubkey))
        .map_err(|_| NodeError::ValidationError("Signature verification failed".to_string()))?;

    Ok(())
}

fn verify_tx_signature(tx: &Transaction) -> Result<(), NodeError> {
    if tx.from.is_empty() && tx.signature.starts_with("reward") {
        return Ok(());
    }

    let secp = Secp256k1::new();
    let from_pubkey = tx
        .from
        .parse::<PublicKey>()
        .map_err(|_| NodeError::ValidationError("Invalid public key".to_string()))?;

    let msg_data_new = format!(
        "{}|{}|{}|{}|{}",
        tx.version, tx.from, tx.to, tx.amount, tx.timestamp
    );
    let hash_new = Sha256::digest(msg_data_new.as_bytes());
    let msg_new = Message::from_digest(hash_new.into());

    let msg_data_legacy = format!("{}{}{}", tx.from, tx.to, tx.amount);
    let hash_legacy = Sha256::digest(msg_data_legacy.as_bytes());
    let msg_legacy = Message::from_digest(hash_legacy.into());

    let sig_bytes = hex::decode(&tx.signature)
        .map_err(|_| NodeError::ValidationError("Invalid signature format".to_string()))?;
    let signature = Signature::from_compact(&sig_bytes)
        .map_err(|_| NodeError::ValidationError("Invalid signature".to_string()))?;

    secp.verify_ecdsa(msg_new, &signature, &from_pubkey)
        .or_else(|_| secp.verify_ecdsa(msg_legacy, &signature, &from_pubkey))
        .map_err(|_| NodeError::ValidationError("Signature verification failed".to_string()))?;
    Ok(())
}

pub fn validate_block(block: &Block, prev: Option<&Block>, chain: &[Block]) -> Result<(), NodeError> {
    if let Some(prev) = prev {
        if block.index != prev.index + 1 {
            return Err(NodeError::ValidationError("Invalid block index".to_string()));
        }
        if block.previous_hash != prev.hash {
            return Err(NodeError::ValidationError("Invalid previous hash".to_string()));
        }
        if block.timestamp < prev.timestamp {
            return Err(NodeError::ValidationError("Block timestamp regressed".to_string()));
        }
    } else if block.index != 0 {
        return Err(NodeError::ValidationError("Invalid genesis index".to_string()));
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
        return Err(NodeError::ValidationError("Proof-of-work invalid".to_string()));
    }

    let mut balances = calculate_balances(chain);
    let mut seen = HashSet::new();
    let mut chain_seen = HashSet::new();
    for b in chain {
        for tx in &b.transactions {
            if !tx.txid.is_empty() {
                chain_seen.insert(tx.txid.clone());
            }
            chain_seen.insert(tx.signature.clone());
        }
    }
    for tx in &block.transactions {
        let txid = if !tx.txid.is_empty() {
            tx.txid.clone()
        } else {
            tx.compute_txid()
        };

        if !tx.txid.is_empty() && tx.txid != txid {
            return Err(NodeError::ValidationError("Invalid txid".to_string()));
        }

        if chain_seen.contains(&txid) || chain_seen.contains(&tx.signature) {
            return Err(NodeError::ValidationError("Duplicate transaction".to_string()));
        }

        if !seen.insert(txid.clone()) || !seen.insert(tx.signature.clone()) {
            return Err(NodeError::ValidationError("Duplicate transaction".to_string()));
        }

        verify_tx_signature(tx)?;

        if !tx.from.is_empty() {
            let from_addr = normalize_addr(&tx.from, &tx.pubkey);
            let bal = balances.entry(from_addr.clone()).or_insert(0);
            if *bal < tx.amount as i128 {
                return Err(NodeError::ValidationError("Insufficient balance".to_string()));
            }
            *bal -= tx.amount as i128;
        }
        let to_addr = normalize_addr(&tx.to, &tx.pubkey);
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

pub fn load_valid_transactions(chain: &[Block]) -> Vec<Transaction> {
    let parsed: Vec<Transaction> = read_data_file("mempool.json")
        .ok()
        .flatten()
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    let mut balances = calculate_balances(chain);
    let mut valid_txs = Vec::new();

    for tx in parsed {
        if tx.from.is_empty() {
            valid_txs.push(tx);
            continue;
        }

        if is_tx_valid_inner(&tx, chain, false).is_ok() {
            let balance = balances.entry(tx.from.clone()).or_insert(0);
            if *balance >= tx.amount as i128 {
                *balance -= tx.amount as i128;
                *balances.entry(tx.to.clone()).or_insert(0) += tx.amount as i128;
                valid_txs.push(tx);
            }
        }
    }

    valid_txs
}
