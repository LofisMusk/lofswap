use std::collections::HashMap;

use blockchain_core::{Block, Transaction};
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
            if tx.to == address {
                balance += tx.amount as i128;
            }
            if tx.from == address {
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
            if !tx.from.is_empty() {
                *balances.entry(tx.from.clone()).or_insert(0) -= tx.amount as i128;
            }
            *balances.entry(tx.to.clone()).or_insert(0) += tx.amount as i128;
        }
    }
    balances
}

pub fn is_tx_valid(tx: &Transaction, chain: &[Block]) -> Result<(), NodeError> {
    if tx.from.is_empty() && tx.signature == "reward" {
        return Ok(());
    }

    let secp = Secp256k1::new();
    let from_pubkey = tx
        .from
        .parse::<PublicKey>()
        .map_err(|_| NodeError::ValidationError("Invalid public key".to_string()))?;

    let balance = calculate_balance(&tx.from, chain);
    let pending_out: u128 = read_mempool()
        .into_iter()
        .filter(|m| m.from == tx.from && !m.from.is_empty())
        .map(|m| m.amount as u128)
        .sum();
    if (tx.amount as u128) + pending_out > (balance.max(0) as u128) {
        return Err(NodeError::ValidationError(
            "Insufficient balance (pending)".to_string(),
        ));
    }

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

    let already_exists = chain.iter().any(|block| {
        block.transactions.iter().any(|btx| {
            btx.signature == tx.signature || (!tx.txid.is_empty() && btx.txid == tx.txid)
        })
    }) || read_mempool()
        .iter()
        .any(|m| m.signature == tx.signature || (!tx.txid.is_empty() && m.txid == tx.txid));

    if already_exists {
        return Err(NodeError::ValidationError(
            "Transaction already exists".to_string(),
        ));
    }

    secp.verify_ecdsa(msg_new, &signature, &from_pubkey)
        .or_else(|_| secp.verify_ecdsa(msg_legacy, &signature, &from_pubkey))
        .map_err(|_| NodeError::ValidationError("Signature verification failed".to_string()))?;

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

        if is_tx_valid(&tx, chain).is_ok() {
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
