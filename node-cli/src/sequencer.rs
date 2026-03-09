// sequencer.rs — L2 Sequencer jako tokio task.
//
// Odpowiedzialności:
//  • Co BLOCK_INTERVAL_SECS: pakuje L2 TX z l2_mempool → L2Block, aktualizuje L2 state
//  • Co COMMITMENT_INTERVAL bloków L2: oblicza state_root, składa StateCommitment na L1
//  • L2 state = L1 balances (z blockchain) + narastające L2 transfers
//
// Uruchamianie: node-cli --sequencer <LFS_ADDRESS>

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use blockchain_core::l2::{
    ConfirmationState, L2Block, L2Transaction,
    compute_state_root,
};
use blockchain_core::Block;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::{Duration, sleep};

use crate::{
    chain::calculate_balances,
    errors::NodeError,
    l2_anchor::{
        load_l2_store, save_l2_store, submit_commitment, try_unlock_bridge_outputs,
    },
    l2_mempool::drain_l2_mempool,
    storage::{read_data_file, write_data_file},
};
use std::sync::Arc;

// ─── Stałe sequencera ───────────────────────
/// Co ile sekund sequencer produkuje nowy blok L2
pub const BLOCK_INTERVAL_SECS: u64 = 10;
/// Co ile bloków L2 sequencer składa StateCommitment na L1
pub const COMMITMENT_INTERVAL: u64 = 6; // ~60s przy 10s blokach
/// Max TX w jednym bloku L2
pub const MAX_TXS_PER_L2_BLOCK: usize = 256;

const L2_CHAIN_FILE: &str = "l2_chain.json";
const L2_STATE_FILE: &str = "l2_state.json";

// ─── L2 Stan ────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct L2State {
    /// Numer ostatniego wyprodukowanego bloku L2 (0 = genesis)
    pub height: u64,
    /// Hash ostatniego bloku L2
    pub tip_hash: String,
    /// Salda kont L2 (uwzględniają L1 + L2 transfery)
    pub balances: HashMap<String, u64>,
    /// State root Merkle z balances
    pub state_root: String,
}

pub fn load_l2_state(blockchain: &[Block]) -> L2State {
    // 1. Start od L1 balances
    let l1_bals = calculate_balances(blockchain);
    let mut balances: HashMap<String, u64> = l1_bals
        .into_iter()
        .filter_map(|(k, v)| if v > 0 { Some((k, v as u64)) } else { None })
        .collect();

    // 2. Aplikuj zapisane bloki L2
    if let Ok(Some(s)) = read_data_file(L2_CHAIN_FILE) {
        if let Ok(blocks) = serde_json::from_str::<Vec<L2Block>>(&s) {
            for block in &blocks {
                apply_l2_block_to_state(&mut balances, block);
            }
            if let Some(last) = blocks.last() {
                let root = compute_state_root(&balances);
                return L2State {
                    height: last.height,
                    tip_hash: last.compute_hash(),
                    balances,
                    state_root: root,
                };
            }
        }
    }

    // 3. Genesis L2 state
    let root = compute_state_root(&balances);
    L2State { height: 0, tip_hash: "0".repeat(64), balances, state_root: root }
}

fn apply_l2_block_to_state(bals: &mut HashMap<String, u64>, block: &L2Block) {
    for tx in &block.transactions {
        let total = tx.amount.saturating_add(tx.fee);
        let from_bal = bals.entry(tx.from.clone()).or_insert(0);
        if *from_bal >= total {
            *from_bal -= total;
        }
        *bals.entry(tx.to.clone()).or_insert(0) += tx.amount;
    }
}

fn save_l2_block(block: &L2Block) -> Result<(), NodeError> {
    let mut blocks: Vec<L2Block> = read_data_file(L2_CHAIN_FILE)
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    blocks.push(block.clone());
    let json = serde_json::to_string_pretty(&blocks)
        .map_err(|e| NodeError::SerializationError(e.to_string()))?;
    write_data_file(L2_CHAIN_FILE, &json)
        .map_err(|e| NodeError::NetworkError(e.to_string()))
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ─── Główna pętla sequencera ─────────────────

pub async fn sequencer_loop(
    blockchain: Arc<Mutex<Vec<Block>>>,
    sequencer_addr: String,
) {
    println!("[SEQ] Sequencer uruchomiony: addr={}", sequencer_addr);
    println!("[SEQ] Interval bloku L2={}s, commitment co {} bloków",
        BLOCK_INTERVAL_SECS, COMMITMENT_INTERVAL);

    loop {
        sleep(Duration::from_secs(BLOCK_INTERVAL_SECS)).await;

        let l1_chain: Vec<Block> = {
            let chain = blockchain.lock().await;
            chain.clone()
        };
        let l1_height = l1_chain.last().map(|b| b.index).unwrap_or(0);

        // Załaduj aktualny stan L2
        let mut state = load_l2_state(&l1_chain);

        // Pobierz TX z l2 mempool
        let txs = drain_l2_mempool(MAX_TXS_PER_L2_BLOCK);

        // Waliduj i aplikuj TX
        let mut valid_txs: Vec<L2Transaction> = Vec::new();
        for mut tx in txs {
            if tx.txid.is_empty() {
                tx.txid = tx.compute_txid();
            }
            let total = tx.amount.saturating_add(tx.fee);
            let bal = state.balances.get(&tx.from).copied().unwrap_or(0);
            if bal < total || tx.amount == 0 || tx.to.is_empty() {
                continue; // pomiń nieprawidłowe
            }
            // Aplikuj do stanu
            *state.balances.entry(tx.from.clone()).or_insert(0) -= total;
            *state.balances.entry(tx.to.clone()).or_insert(0) += tx.amount;
            valid_txs.push(tx);
        }

        // Oblicz nowy state_root
        let new_root = compute_state_root(&state.balances);
        let new_height = state.height + 1;

        // Produkuj blok L2
        let block = L2Block {
            height: new_height,
            timestamp: now_secs(),
            transactions: valid_txs.clone(),
            parent_hash: state.tip_hash.clone(),
            state_root: new_root.clone(),
            sequencer: sequencer_addr.clone(),
            sequencer_sig: String::new(), // TODO: ECDSA podpis nad compute_hash()
            l1_anchor: Some(l1_height),
            confirm_state: ConfirmationState::Soft,
        };

        let block_hash = block.compute_hash();

        match save_l2_block(&block) {
            Ok(_) => {
                println!(
                    "[SEQ] L2 blok #{} | txs={} | root={}... | l1_anchor={}",
                    new_height, valid_txs.len(),
                    &new_root[..8], l1_height
                );
            }
            Err(e) => {
                eprintln!("[SEQ] Błąd zapisu bloku L2: {}", e);
                continue;
            }
        }

        // Co COMMITMENT_INTERVAL bloków → złóż StateCommitment na L1
        if new_height % COMMITMENT_INTERVAL == 0 {
            let mut l2_store = load_l2_store();
            match submit_commitment(
                &mut l2_store,
                sequencer_addr.clone(),
                new_height,
                l1_height,
                new_root.clone(),
                String::new(), // TODO: podpis
            ) {
                Ok(_) => {
                    // Sprawdź finalizację przy każdym commitment
                    let finalized = crate::l2_anchor::try_finalize_all(&mut l2_store);
                    let unlocked = try_unlock_bridge_outputs(&mut l2_store, l1_height);

                    match save_l2_store(&l2_store) {
                        Ok(_) => {
                            println!(
                                "[SEQ] StateCommitment złożony: l2_height={} l1_anchor={} root={}...",
                                new_height, l1_height, &new_root[..8]
                            );
                            if finalized > 0 {
                                println!("[SEQ] {} commitmentów → Hard", finalized);
                            }
                            if !unlocked.is_empty() {
                                println!("[SEQ] Bridge outputy odblokowane: {:?}", unlocked);
                            }
                        }
                        Err(e) => eprintln!("[SEQ] Błąd zapisu L2 store: {}", e),
                    }
                }
                Err(e) => {
                    eprintln!("[SEQ] Błąd commitment: {} — upewnij się że sequencer ma aktywny bond", e);
                }
            }
        }

        // Zapisz aktualny L2 state (dla diagnostyki)
        let updated_state = L2State {
            height: new_height,
            tip_hash: block_hash,
            balances: state.balances,
            state_root: new_root,
        };
        if let Ok(json) = serde_json::to_string_pretty(&updated_state) {
            let _ = write_data_file(L2_STATE_FILE, &json);
        }
    }
}
