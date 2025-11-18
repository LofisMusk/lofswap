use std::{
    collections::HashMap,
    fs,
    path::Path,
};

use blockchain_core::{Block, Transaction};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use sha2::{Digest, Sha256};
use serde_json;

use crate::{
    errors::NodeError,
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
    let from_pubkey = tx.from.parse::<PublicKey>()
        .map_err(|_| NodeError::ValidationError("Invalid public key".to_string()))?;

    let balance = calculate_balance(&tx.from, chain);
    let pending_out: u128 = read_mempool()
        .into_iter()
        .filter(|m| m.from == tx.from && !m.from.is_empty())
        .map(|m| m.amount as u128)
        .sum();
    if (tx.amount as u128) + pending_out > (balance.max(0) as u128) {
        return Err(NodeError::ValidationError("Insufficient balance (pending)".to_string()));
    }

    let msg_data = format!("{}{}{}", tx.from, tx.to, tx.amount);
    let hash = Sha256::digest(msg_data.as_bytes());
    let msg = Message::from_digest(hash.into());

    let sig_bytes = hex::decode(&tx.signature)
        .map_err(|_| NodeError::ValidationError("Invalid signature format".to_string()))?;
    let signature = Signature::from_compact(&sig_bytes)
        .map_err(|_| NodeError::ValidationError("Invalid signature".to_string()))?;

    let already_exists = chain.iter().any(|block| {
        block.transactions.iter().any(|btx| {
            btx.signature == tx.signature || (!tx.txid.is_empty() && btx.txid == tx.txid)
        })
    }) || read_mempool().iter().any(|m| {
        m.signature == tx.signature || (!tx.txid.is_empty() && m.txid == tx.txid)
    });

    if already_exists {
        return Err(NodeError::ValidationError("Transaction already exists".to_string()));
    }

    secp.verify_ecdsa(msg, &signature, &from_pubkey)
        .map_err(|_| NodeError::ValidationError("Signature verification failed".to_string()))?;

    Ok(())
}

pub fn save_chain(chain: &[Block]) -> Result<(), NodeError> {
    let json = serde_json::to_string_pretty(chain)
        .map_err(|e| NodeError::SerializationError(e.to_string()))?;
    fs::write("blockchain.json", json)
        .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    Ok(())
}

pub fn load_chain() -> Result<Vec<Block>, NodeError> {
    if Path::new("blockchain.json").exists() {
        let json = fs::read_to_string("blockchain.json")
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
        serde_json::from_str(&json)
            .map_err(|e| NodeError::SerializationError(e.to_string()))
    } else {
        Ok(vec![Block::new(0, vec![], "0".to_string(), "genesis".to_string())])
    }
}

pub fn load_peers() -> Result<Vec<String>, NodeError> {
    if Path::new("peers.json").exists() {
        let json = fs::read_to_string("peers.json")
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
        serde_json::from_str(&json)
            .map_err(|e| NodeError::SerializationError(e.to_string()))
            .or(Ok(vec![]))
    } else {
        Ok(vec![])
    }
}

pub fn save_peers(peers: &[String]) -> Result<(), NodeError> {
    let json = serde_json::to_string_pretty(peers)
        .map_err(|e| NodeError::SerializationError(e.to_string()))?;
    fs::write("peers.json", json)
        .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    Ok(())
}

pub fn load_valid_transactions(chain: &[Block]) -> Vec<Transaction> {
    let parsed: Vec<Transaction> = fs::read_to_string("mempool.json")
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
