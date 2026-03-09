// sequencer.rs — L2 Sequencer jako tokio task.
//
// Fixy bezpieczeństwa (wszystkie aktywne):
//  [1] Weryfikacja ECDSA secp256k1 podpisu każdej L2 TX przed włączeniem do bloku
//  [2] Nonce deduplication per-sender — TX z powtórzonym nonce odrzucana
//  [3] Sequencer podpisuje StateCommitment kluczem ed25519 node identity
//  [4] Snapshot stanu L2 zapisywany przed każdym blokiem — pre_state dla FraudProof
//
// Uruchamianie: node-cli --sequencer <LFS_ADDRESS>

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use blockchain_core::l2::{
    ConfirmationState, L2Block, L2Transaction, compute_state_root,
};
use blockchain_core::Block;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::{Duration, sleep};

use crate::{
    chain::calculate_balances,
    errors::NodeError,
    identity::{sign_message, NODE_IDENTITY},
    l2_anchor::{
        load_l2_store, save_l2_snapshot, save_l2_store, submit_commitment,
        try_finalize_all, try_unlock_bridge_outputs,
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
/// Czy odrzucać TX bez podpisu (false = dev mode, true = produkcja)
pub const REQUIRE_TX_SIG: bool = true;

const L2_CHAIN_FILE: &str = "l2_chain.json";
const L2_STATE_FILE: &str = "l2_state.json";
/// Nonce store: l2_nonces.json — per-sender max użyty nonce
const L2_NONCES_FILE: &str = "l2_nonces.json";

// ─── Nonce store ─────────────────────────────

fn load_nonces() -> HashMap<String, u64> {
    read_data_file(L2_NONCES_FILE)
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_nonces(nonces: &HashMap<String, u64>) {
    if let Ok(json) = serde_json::to_string_pretty(nonces) {
        let _ = write_data_file(L2_NONCES_FILE, &json);
    }
}

// ─── L2 Stan ────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct L2State {
    pub height: u64,
    pub tip_hash: String,
    pub balances: HashMap<String, u64>,
    pub state_root: String,
}

pub fn load_l2_state(blockchain: &[Block]) -> L2State {
    let l1_bals = calculate_balances(blockchain);
    let mut balances: HashMap<String, u64> = l1_bals
        .into_iter()
        .filter_map(|(k, v)| if v > 0 { Some((k, v as u64)) } else { None })
        .collect();

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

// ─── Walidacja TX ────────────────────────────

#[derive(Debug)]
enum TxRejectReason {
    InsufficientFunds { have: u64, need: u64 },
    ZeroAmount,
    EmptyRecipient,
    DuplicateNonce { nonce: u64 },
    InvalidSignature(String),
}

impl std::fmt::Display for TxRejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxRejectReason::InsufficientFunds { have, need } =>
                write!(f, "za mało środków: masz={} potrzebujesz={}", have, need),
            TxRejectReason::ZeroAmount => write!(f, "amount=0"),
            TxRejectReason::EmptyRecipient => write!(f, "pusty adres odbiorcy"),
            TxRejectReason::DuplicateNonce { nonce } =>
                write!(f, "duplikat nonce={}", nonce),
            TxRejectReason::InvalidSignature(r) => write!(f, "nieprawidłowy podpis: {}", r),
        }
    }
}

/// Waliduje TX względem aktualnego stanu.
/// seen_nonces: nonce użyte w tym bloku (dedup wewnątrz bloku)
/// stored_nonces: ostatni zaakceptowany nonce per sender (dedup historyczny)
fn validate_tx(
    tx: &L2Transaction,
    balances: &HashMap<String, u64>,
    seen_nonces: &HashSet<(String, u64)>,
    stored_nonces: &HashMap<String, u64>,
) -> Result<(), TxRejectReason> {
    // [1] Kwota
    if tx.amount == 0 {
        return Err(TxRejectReason::ZeroAmount);
    }
    if tx.to.is_empty() {
        return Err(TxRejectReason::EmptyRecipient);
    }

    // [2] Nonce dedup — wewnątrz bloku
    if seen_nonces.contains(&(tx.from.clone(), tx.nonce)) {
        return Err(TxRejectReason::DuplicateNonce { nonce: tx.nonce });
    }
    // Nonce historyczny — musi być wyższy niż ostatni zaakceptowany
    if let Some(&last_nonce) = stored_nonces.get(&tx.from) {
        if tx.nonce <= last_nonce {
            return Err(TxRejectReason::DuplicateNonce { nonce: tx.nonce });
        }
    }

    // [3] Saldo
    let total = tx.amount.saturating_add(tx.fee);
    let bal = balances.get(&tx.from).copied().unwrap_or(0);
    if bal < total {
        return Err(TxRejectReason::InsufficientFunds { have: bal, need: total });
    }

    // [4] ECDSA podpis secp256k1
    if REQUIRE_TX_SIG {
        tx.verify_sig().map_err(|e| TxRejectReason::InvalidSignature(e))?;
    } else if !tx.signature.is_empty() {
        // Dev mode: jeśli sig dostarczony, sprawdź go
        tx.verify_sig().map_err(|e| TxRejectReason::InvalidSignature(e))?;
    }

    Ok(())
}

// ─── Główna pętla sequencera ─────────────────

pub async fn sequencer_loop(
    blockchain: Arc<Mutex<Vec<Block>>>,
    sequencer_addr: String,
) {
    let seq_pubkey = NODE_IDENTITY.public_key_hex.clone();
    println!("[SEQ] Sequencer uruchomiony: addr={}", sequencer_addr);
    println!("[SEQ] pubkey={}", &seq_pubkey[..16]);
    println!("[SEQ] interval={}s  commitment co {} bloków  sig_required={}",
        BLOCK_INTERVAL_SECS, COMMITMENT_INTERVAL, REQUIRE_TX_SIG);

    loop {
        sleep(Duration::from_secs(BLOCK_INTERVAL_SECS)).await;

        let l1_chain: Vec<Block> = {
            let chain = blockchain.lock().await;
            chain.clone()
        };
        let l1_height = l1_chain.last().map(|b| b.index).unwrap_or(0);
        let mut state = load_l2_state(&l1_chain);
        let new_height = state.height + 1;

        // [FIX-4] Snapshot stanu PRZED blokiem — pre_state dla FraudProof
        if let Err(e) = save_l2_snapshot(state.height, &state.balances) {
            eprintln!("[SEQ] Błąd zapisu snapshot #{}: {}", state.height, e);
        }

        // Pobierz TX z mempool + załaduj nonce store
        let txs = drain_l2_mempool(MAX_TXS_PER_L2_BLOCK);
        let mut stored_nonces = load_nonces();
        let mut seen_nonces: HashSet<(String, u64)> = HashSet::new();
        let mut valid_txs: Vec<L2Transaction> = Vec::new();
        let mut rejected = 0usize;

        for mut tx in txs {
            if tx.txid.is_empty() {
                tx.txid = tx.compute_txid();
            }
            // [FIX-1][FIX-2] Pełna walidacja: ECDSA + nonce + saldo
            match validate_tx(&tx, &state.balances, &seen_nonces, &stored_nonces) {
                Ok(()) => {
                    let total = tx.amount.saturating_add(tx.fee);
                    *state.balances.entry(tx.from.clone()).or_insert(0) -= total;
                    *state.balances.entry(tx.to.clone()).or_insert(0) += tx.amount;
                    seen_nonces.insert((tx.from.clone(), tx.nonce));
                    // Aktualizuj max nonce per sender
                    let entry = stored_nonces.entry(tx.from.clone()).or_insert(0);
                    if tx.nonce > *entry { *entry = tx.nonce; }
                    valid_txs.push(tx);
                }
                Err(reason) => {
                    eprintln!("[SEQ] TX {} odrzucona: {}", &tx.txid[..8.min(tx.txid.len())], reason);
                    rejected += 1;
                }
            }
        }

        save_nonces(&stored_nonces);

        let new_root = compute_state_root(&state.balances);

        // [FIX-3] Podpisz blok L2 kluczem ed25519 sequencera
        let block_preimage = format!("L2B_SIG|{}|{}|{}", new_height, new_root, l1_height);
        let block_sig = sign_message(block_preimage.as_bytes());

        let block = L2Block {
            height: new_height,
            timestamp: now_secs(),
            transactions: valid_txs.clone(),
            parent_hash: state.tip_hash.clone(),
            state_root: new_root.clone(),
            sequencer: sequencer_addr.clone(),
            sequencer_sig: block_sig,
            l1_anchor: Some(l1_height),
            confirm_state: ConfirmationState::Soft,
        };

        let block_hash = block.compute_hash();
        match save_l2_block(&block) {
            Ok(_) => println!(
                "[SEQ] L2#{} ok={} rej={} root={}... l1={}",
                new_height, valid_txs.len(), rejected, &new_root[..8], l1_height
            ),
            Err(e) => { eprintln!("[SEQ] Błąd zapisu L2 bloku: {}", e); continue; }
        }

        // Co COMMITMENT_INTERVAL → złóż StateCommitment z podpisem ed25519
        if new_height % COMMITMENT_INTERVAL == 0 {
            let commit_preimage = format!(
                "SC|{}|{}|{}|{}", new_height, l1_height, new_root, sequencer_addr
            );
            let commit_sig = sign_message(commit_preimage.as_bytes());

            let mut l2_store = load_l2_store();
            match submit_commitment(
                &mut l2_store,
                sequencer_addr.clone(),
                new_height,
                l1_height,
                new_root.clone(),
                commit_sig,
                seq_pubkey.clone(),
            ) {
                Ok(_) => {
                    let finalized = try_finalize_all(&mut l2_store);
                    let unlocked = try_unlock_bridge_outputs(&mut l2_store, l1_height);
                    match save_l2_store(&l2_store) {
                        Ok(_) => {
                            println!("[SEQ] Commitment l2={} l1={} root={}...", new_height, l1_height, &new_root[..8]);
                            if finalized > 0 { println!("[SEQ] {} → Hard", finalized); }
                            if !unlocked.is_empty() { println!("[SEQ] Odblokowane: {:?}", unlocked); }
                        }
                        Err(e) => eprintln!("[SEQ] Błąd zapisu store: {}", e),
                    }
                }
                Err(e) => eprintln!("[SEQ] Błąd commitment: {}", e),
            }
        }

        let updated = L2State {
            height: new_height,
            tip_hash: block_hash,
            balances: state.balances,
            state_root: new_root,
        };
        if let Ok(json) = serde_json::to_string_pretty(&updated) {
            let _ = write_data_file(L2_STATE_FILE, &json);
        }
    }
}
