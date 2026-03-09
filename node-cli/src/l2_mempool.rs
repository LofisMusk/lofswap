// l2_mempool.rs — pula L2 transakcji oczekujących na włączenie przez sequencera.
// Oddzielna od L1 mempool — różne zasady walidacji, brak PoW.

use blockchain_core::l2::L2Transaction;
use serde_json;

use crate::storage::{read_data_file, write_data_file};

const L2_MEMPOOL_FILE: &str = "l2_mempool.json";

pub fn read_l2_mempool() -> Vec<L2Transaction> {
    read_data_file(L2_MEMPOOL_FILE)
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn insert_l2_tx(tx: L2Transaction) -> Result<(), String> {
    let mut pool = read_l2_mempool();
    // Duplikat?
    if pool.iter().any(|t| t.txid == tx.txid) {
        return Err(format!("L2 TX {} już w mempool", tx.txid));
    }
    pool.push(tx);
    let json = serde_json::to_string_pretty(&pool)
        .map_err(|e| e.to_string())?;
    write_data_file(L2_MEMPOOL_FILE, &json)
        .map_err(|e| e.to_string())
}

pub fn drain_l2_mempool(limit: usize) -> Vec<L2Transaction> {
    let mut pool = read_l2_mempool();
    let drained: Vec<L2Transaction> = pool.drain(..limit.min(pool.len())).collect();
    let json = serde_json::to_string_pretty(&pool).unwrap_or_default();
    let _ = write_data_file(L2_MEMPOOL_FILE, &json);
    drained
}

#[allow(dead_code)]
pub fn clear_l2_mempool() -> Result<(), String> {
    write_data_file(L2_MEMPOOL_FILE, "[]").map_err(|e| e.to_string())
}

pub fn l2_mempool_len() -> usize {
    read_l2_mempool().len()
}
