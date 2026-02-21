use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use blockchain_core::{Transaction, pubkey_to_address};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json;

use crate::storage::{read_data_file, write_data_file};

const MEMPOOL_SNAPSHOT_FILE: &str = "mempool_snapshot.json";
const MEMPOOL_COMPAT_FILE: &str = "mempool.json";
const MEMPOOL_MAX_BYTES: usize = 8 * 1024 * 1024;
const MEMPOOL_MAX_TX_PER_SENDER: usize = 128;
const MEMPOOL_MAX_AGE_SECS: i64 = 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedEntry {
    tx: Transaction,
    added_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedSnapshot {
    version: u8,
    entries: Vec<PersistedEntry>,
}

#[derive(Debug, Clone)]
struct MempoolEntry {
    tx: Transaction,
    added_at: i64,
    serialized: String,
}

#[derive(Debug, Default)]
struct MempoolState {
    entries: Vec<MempoolEntry>,
    total_bytes: usize,
}

static MEMPOOL_STATE: Lazy<RwLock<MempoolState>> = Lazy::new(|| RwLock::new(load_initial_state()));

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn tx_sender_key(tx: &Transaction) -> String {
    if tx.from.is_empty() {
        String::new()
    } else if tx.from.starts_with("LFS") {
        tx.from.clone()
    } else {
        pubkey_to_address(&tx.from)
    }
}

fn same_tx(a: &Transaction, b: &Transaction) -> bool {
    a.signature == b.signature || (!a.txid.is_empty() && !b.txid.is_empty() && a.txid == b.txid)
}

fn parse_legacy_mempool(raw: &str) -> Vec<Transaction> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if trimmed.starts_with('[') {
        return serde_json::from_str::<Vec<Transaction>>(trimmed).unwrap_or_default();
    }
    trimmed
        .lines()
        .filter_map(|line| serde_json::from_str::<Transaction>(line).ok())
        .collect()
}

fn entry_from_tx(mut tx: Transaction, added_at: i64) -> Option<MempoolEntry> {
    if tx.txid.is_empty() {
        tx.txid = tx.compute_txid();
    }
    let serialized = serde_json::to_string(&tx).ok()?;
    Some(MempoolEntry {
        tx,
        added_at,
        serialized,
    })
}

fn load_initial_state() -> MempoolState {
    let mut entries: Vec<MempoolEntry> = Vec::new();

    if let Ok(Some(raw)) = read_data_file(MEMPOOL_SNAPSHOT_FILE) {
        if let Ok(snapshot) = serde_json::from_str::<PersistedSnapshot>(&raw) {
            for item in snapshot.entries {
                if let Some(entry) = entry_from_tx(item.tx, item.added_at) {
                    entries.push(entry);
                }
            }
        }
    } else if let Ok(Some(raw)) = read_data_file(MEMPOOL_COMPAT_FILE) {
        let now = now_unix_secs();
        for tx in parse_legacy_mempool(&raw) {
            if let Some(entry) = entry_from_tx(tx, now) {
                entries.push(entry);
            }
        }
    }

    let mut state = MempoolState {
        entries,
        total_bytes: 0,
    };
    rebalance_locked(&mut state);
    let _ = persist_locked(&state);
    state
}

fn recompute_total_bytes(state: &mut MempoolState) {
    state.total_bytes = state
        .entries
        .iter()
        .map(|entry| entry.serialized.len().saturating_add(1))
        .sum();
}

fn evict_index(state: &mut MempoolState, index: usize) {
    if index < state.entries.len() {
        state.entries.swap_remove(index);
        recompute_total_bytes(state);
    }
}

fn prune_expired_locked(state: &mut MempoolState) {
    let now = now_unix_secs();
    state
        .entries
        .retain(|entry| now.saturating_sub(entry.added_at) <= MEMPOOL_MAX_AGE_SECS);
    recompute_total_bytes(state);
}

fn worst_entry_index(state: &MempoolState, sender_filter: Option<&str>) -> Option<usize> {
    let mut worst: Option<usize> = None;
    for (idx, entry) in state.entries.iter().enumerate() {
        if let Some(sender) = sender_filter {
            if tx_sender_key(&entry.tx) != sender {
                continue;
            }
        }
        let key = (entry.tx.fee, entry.added_at);
        if let Some(current_idx) = worst {
            let curr = &state.entries[current_idx];
            let curr_key = (curr.tx.fee, curr.added_at);
            if key < curr_key {
                worst = Some(idx);
            }
        } else {
            worst = Some(idx);
        }
    }
    worst
}

fn enforce_sender_cap_locked(state: &mut MempoolState) {
    loop {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for entry in &state.entries {
            let sender = tx_sender_key(&entry.tx);
            *counts.entry(sender).or_insert(0) += 1;
        }

        let mut violating_sender: Option<String> = None;
        for (sender, count) in counts {
            if !sender.is_empty() && count > MEMPOOL_MAX_TX_PER_SENDER {
                violating_sender = Some(sender);
                break;
            }
        }

        let Some(sender) = violating_sender else {
            break;
        };
        if let Some(idx) = worst_entry_index(state, Some(&sender)) {
            evict_index(state, idx);
        } else {
            break;
        }
    }
}

fn enforce_size_cap_locked(state: &mut MempoolState) {
    while state.total_bytes > MEMPOOL_MAX_BYTES {
        let Some(idx) = worst_entry_index(state, None) else {
            break;
        };
        evict_index(state, idx);
    }
}

fn dedupe_locked(state: &mut MempoolState) {
    let mut unique: Vec<MempoolEntry> = Vec::with_capacity(state.entries.len());
    for entry in state.entries.drain(..) {
        if unique.iter().any(|u| same_tx(&u.tx, &entry.tx)) {
            continue;
        }
        unique.push(entry);
    }
    state.entries = unique;
    recompute_total_bytes(state);
}

fn rebalance_locked(state: &mut MempoolState) {
    dedupe_locked(state);
    prune_expired_locked(state);
    enforce_sender_cap_locked(state);
    enforce_size_cap_locked(state);
}

fn persist_locked(state: &MempoolState) -> Result<(), String> {
    let snapshot = PersistedSnapshot {
        version: 1,
        entries: state
            .entries
            .iter()
            .map(|entry| PersistedEntry {
                tx: entry.tx.clone(),
                added_at: entry.added_at,
            })
            .collect(),
    };
    let snapshot_json =
        serde_json::to_string_pretty(&snapshot).map_err(|e| format!("serialize mempool: {}", e))?;
    write_data_file(MEMPOOL_SNAPSHOT_FILE, &snapshot_json)
        .map_err(|e| format!("persist mempool snapshot: {}", e))?;

    let compat_body = state
        .entries
        .iter()
        .map(|entry| entry.serialized.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    write_data_file(MEMPOOL_COMPAT_FILE, &compat_body)
        .map_err(|e| format!("persist mempool compat file: {}", e))?;
    Ok(())
}

pub fn read_mempool() -> Vec<Transaction> {
    let mut state = MEMPOOL_STATE
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let before = state.entries.len();
    rebalance_locked(&mut state);
    if state.entries.len() != before {
        let _ = persist_locked(&state);
    }
    state.entries.iter().map(|entry| entry.tx.clone()).collect()
}

pub fn mempool_len() -> usize {
    let state = MEMPOOL_STATE
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    state.entries.len()
}

#[cfg(test)]
pub fn clear_mempool() -> Result<(), String> {
    let mut state = MEMPOOL_STATE
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    state.entries.clear();
    state.total_bytes = 0;
    persist_locked(&state)
}

pub fn insert_transaction(mut tx: Transaction) -> Result<(), String> {
    if tx.txid.is_empty() {
        tx.txid = tx.compute_txid();
    }
    let now = now_unix_secs();
    let Some(candidate) = entry_from_tx(tx, now) else {
        return Err("failed to serialize transaction".to_string());
    };

    let mut state = MEMPOOL_STATE
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if state
        .entries
        .iter()
        .any(|existing| same_tx(&existing.tx, &candidate.tx))
    {
        return Ok(());
    }

    state.entries.push(candidate);
    recompute_total_bytes(&mut state);
    rebalance_locked(&mut state);
    persist_locked(&state)
}

pub fn replace_mempool(transactions: Vec<Transaction>) -> Result<(), String> {
    let mut state = MEMPOOL_STATE
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let mut age_by_sig: HashMap<String, i64> = HashMap::new();
    let mut age_by_txid: HashMap<String, i64> = HashMap::new();
    for entry in &state.entries {
        age_by_sig.insert(entry.tx.signature.clone(), entry.added_at);
        if !entry.tx.txid.is_empty() {
            age_by_txid.insert(entry.tx.txid.clone(), entry.added_at);
        }
    }

    let now = now_unix_secs();
    let mut next_entries = Vec::with_capacity(transactions.len());
    for tx in transactions {
        let added_at = if !tx.txid.is_empty() {
            age_by_txid
                .get(&tx.txid)
                .copied()
                .or_else(|| age_by_sig.get(&tx.signature).copied())
                .unwrap_or(now)
        } else {
            age_by_sig.get(&tx.signature).copied().unwrap_or(now)
        };
        if let Some(entry) = entry_from_tx(tx, added_at) {
            next_entries.push(entry);
        }
    }

    state.entries = next_entries;
    recompute_total_bytes(&mut state);
    rebalance_locked(&mut state);
    persist_locked(&state)
}
