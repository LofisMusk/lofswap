// l2_anchor.rs — node-cli integration for L2 StateCommitments + BridgeOutputs
// Zarządza lokalnym storage commitmentów i bridge outputów.
// Finalizacja: przy każdym nowym bloku L1 → try_finalize() na Soft commitmentach.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use blockchain_core::l2::{
    BridgeOutput, BridgeOutputState, ConfirmationState, FraudProof,
    SequencerBond, StateCommitment,
};
use hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    errors::NodeError,
    storage::{read_data_file, write_data_file},
};

const COMMITMENTS_FILE: &str = "l2_commitments.json";
const BRIDGE_OUTPUTS_FILE: &str = "l2_bridge_outputs.json";
const SEQUENCER_BONDS_FILE: &str = "l2_sequencer_bonds.json";

// ─────────────────────────────────────────────
// Storage
// ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct L2Store {
    pub commitments: Vec<StateCommitment>,
    pub bridge_outputs: Vec<BridgeOutput>,
    pub sequencer_bonds: Vec<SequencerBond>,
}

pub fn load_l2_store() -> L2Store {
    let commitments = read_data_file(COMMITMENTS_FILE)
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let bridge_outputs = read_data_file(BRIDGE_OUTPUTS_FILE)
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let sequencer_bonds = read_data_file(SEQUENCER_BONDS_FILE)
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    L2Store { commitments, bridge_outputs, sequencer_bonds }
}

pub fn save_l2_store(store: &L2Store) -> Result<(), NodeError> {
    let c = serde_json::to_string_pretty(&store.commitments)
        .map_err(|e| NodeError::SerializationError(e.to_string()))?;
    write_data_file(COMMITMENTS_FILE, &c).map_err(|e| NodeError::NetworkError(e.to_string()))?;

    let b = serde_json::to_string_pretty(&store.bridge_outputs)
        .map_err(|e| NodeError::SerializationError(e.to_string()))?;
    write_data_file(BRIDGE_OUTPUTS_FILE, &b).map_err(|e| NodeError::NetworkError(e.to_string()))?;

    let s = serde_json::to_string_pretty(&store.sequencer_bonds)
        .map_err(|e| NodeError::SerializationError(e.to_string()))?;
    write_data_file(SEQUENCER_BONDS_FILE, &s).map_err(|e| NodeError::NetworkError(e.to_string()))?;

    Ok(())
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ─────────────────────────────────────────────
// Commitment operations
// ─────────────────────────────────────────────

/// Sequencer składa StateCommitment na L1 (anchor do aktualnego bloku L1).
/// Weryfikuje że sequencer ma aktywny bond o wymaganej wartości.
pub fn submit_commitment(
    store: &mut L2Store,
    sequencer: String,
    l2_height: u64,
    l1_anchor_index: u64,
    state_root: String,
    sequencer_sig: String,
) -> Result<(), NodeError> {
    // Sprawdź bond
    let has_bond = store.sequencer_bonds.iter().any(|b| {
        b.sequencer == sequencer
            && b.status == blockchain_core::l2::BondStatus::Active
            && b.amount >= StateCommitment::MIN_SEQUENCER_BOND
    });
    if !has_bond {
        return Err(NodeError::ValidationError(format!(
            "Sequencer {} nie ma wymaganego bondu (min {})",
            sequencer,
            StateCommitment::MIN_SEQUENCER_BOND
        )));
    }

    // Duplikat?
    if store.commitments.iter().any(|c| c.l2_height == l2_height) {
        return Err(NodeError::ValidationError(format!(
            "Commitment dla l2_height={} już istnieje",
            l2_height
        )));
    }

    let bond = store
        .sequencer_bonds
        .iter()
        .find(|b| b.sequencer == sequencer)
        .map(|b| b.amount)
        .unwrap_or(StateCommitment::MIN_SEQUENCER_BOND);

    let commitment = StateCommitment {
        l2_height,
        l1_anchor_index,
        state_root,
        sequencer,
        sequencer_sig,
        sequencer_bond: bond,
        submitted_at: now_secs(),
        challenge_period_secs: StateCommitment::DEFAULT_CHALLENGE_PERIOD,
        state: ConfirmationState::Soft,
    };

    store.commitments.push(commitment);
    // Sortuj po l2_height rosnąco
    store.commitments.sort_by_key(|c| c.l2_height);
    Ok(())
}

/// Próbuje sfinalizować wszystkie Soft commitmenty których challenge period minął.
/// Wywołuje się po każdym nowym bloku L1.
/// Zwraca liczbę commitmentów które przeszły do Hard.
pub fn try_finalize_all(store: &mut L2Store) -> usize {
    let now = now_secs();
    let mut finalized = 0;
    for c in store.commitments.iter_mut() {
        if c.state == ConfirmationState::Soft && c.is_challenge_expired(now) {
            c.state = ConfirmationState::Hard;
            finalized += 1;
        }
    }
    finalized
}

/// Próbuje odblokować bridge outputs które mają Hard commitment.
/// Zwraca listę odblokowanych output IDs.
pub fn try_unlock_bridge_outputs(store: &mut L2Store, current_l1_index: u64) -> Vec<String> {
    let hard_heights: HashMap<u64, &StateCommitment> = store
        .commitments
        .iter()
        .filter(|c| c.state == ConfirmationState::Hard)
        .map(|c| (c.l2_height, c))
        .collect();

    let mut unlocked = Vec::new();
    for output in store.bridge_outputs.iter_mut() {
        if output.state == BridgeOutputState::Locked {
            if let Some(commitment) = hard_heights.get(&output.commitment_l2_height) {
                if output.try_unlock(commitment, current_l1_index) {
                    unlocked.push(output.id.clone());
                }
            }
        }
    }
    unlocked
}

// ─────────────────────────────────────────────
// Fraud proof
// ─────────────────────────────────────────────

/// Challenger składa fraud proof przeciwko commitment.
#[allow(dead_code)]
pub fn submit_fraud_proof(
    store: &mut L2Store,
    proof: FraudProof,
    pre_state: &HashMap<String, u64>,
) -> Result<bool, NodeError> {
    let now = now_secs();

    let commitment = store
        .commitments
        .iter()
        .find(|c| c.l2_height == proof.commitment_l2_height)
        .ok_or_else(|| {
            NodeError::ValidationError(format!(
                "Brak commitment dla l2_height={}",
                proof.commitment_l2_height
            ))
        })?
        .clone();

    let is_fraud = proof
        .verify(&commitment, pre_state, now)
        .map_err(|e| NodeError::ValidationError(e.to_string()))?;

    if is_fraud {
        // Slash commitment
        let height = commitment.l2_height;
        let seq = commitment.sequencer.clone();

        if let Some(c) = store.commitments.iter_mut().find(|c| c.l2_height == height) {
            c.slash();
        }

        // Slash bond
        let slashed_amount = store
            .sequencer_bonds
            .iter_mut()
            .find(|b| b.sequencer == seq)
            .map(|b| b.slash())
            .unwrap_or(0);

        // Burn bridge outputs pokryte tym commitment
        for output in store.bridge_outputs.iter_mut() {
            if output.commitment_l2_height == height
                && output.state == BridgeOutputState::Locked
            {
                output.burn();
            }
        }

        println!(
            "[L2] FRAUD CONFIRMED @ height={} sequencer={} slashed={}",
            height, seq, slashed_amount
        );
    } else {
        println!("[L2] Challenge failed — commitment valid @ height={}", proof.commitment_l2_height);
    }

    Ok(is_fraud)
}

// ─────────────────────────────────────────────
// Bridge
// ─────────────────────────────────────────────

/// Rejestruje bridge output L2→L1.
/// Output zostaje LOCKED do momentu Hard finality commitment.
pub fn register_bridge_output(
    store: &mut L2Store,
    from_l2: String,
    to_l1: String,
    amount: u64,
    commitment_l2_height: u64,
) -> Result<String, NodeError> {
    // Commitment musi istnieć
    if !store.commitments.iter().any(|c| c.l2_height == commitment_l2_height) {
        return Err(NodeError::ValidationError(format!(
            "Commitment l2_height={} nie istnieje — zarejestruj najpierw",
            commitment_l2_height
        )));
    }

    // Generuj deterministyczny ID
    let id_hash = Sha256::digest(
        format!("BRIDGE|{}|{}|{}|{}|{}", from_l2, to_l1, amount, commitment_l2_height, now_secs())
            .as_bytes(),
    );
    let id = format!("bridge_{}", hex::encode(&id_hash[..8]));

    let output = BridgeOutput {
        id: id.clone(),
        from_l2,
        to_l1,
        amount,
        commitment_l2_height,
        unlock_l1_index: None,
        state: BridgeOutputState::Locked,
    };
    store.bridge_outputs.push(output);
    Ok(id)
}

/// Zarejestruj bond sequencera.
pub fn register_sequencer_bond(
    store: &mut L2Store,
    sequencer: String,
    amount: u64,
    l1_index: u64,
) -> Result<(), NodeError> {
    // Już ma aktywny bond?
    if store.sequencer_bonds.iter().any(|b| {
        b.sequencer == sequencer
            && b.status == blockchain_core::l2::BondStatus::Active
    }) {
        return Err(NodeError::ValidationError(format!(
            "Sequencer {} już ma aktywny bond",
            sequencer
        )));
    }

    let bond = SequencerBond::new(sequencer, amount, l1_index)
        .map_err(|e| NodeError::ValidationError(e.to_string()))?;

    store.sequencer_bonds.push(bond);
    Ok(())
}

// ─────────────────────────────────────────────
// Display helpers
// ─────────────────────────────────────────────

pub fn print_l2_status(store: &L2Store) {
    let now = now_secs();

    println!("=== L2 STATE COMMITMENTS ({}) ===", store.commitments.len());
    if store.commitments.is_empty() {
        println!("  (brak)");
    }
    for c in &store.commitments {
        let remaining = if c.state == ConfirmationState::Soft {
            let expires = c.submitted_at + c.challenge_period_secs as i64;
            let r = expires - now;
            if r > 0 {
                format!("challenge expires in {}s", r)
            } else {
                "expired (pending finalize)".to_string()
            }
        } else {
            String::new()
        };
        println!(
            "  L2#{}  L1_anchor={}  root={}...  seq={}  state={:?}  {}",
            c.l2_height,
            c.l1_anchor_index,
            &c.state_root[..8.min(c.state_root.len())],
            &c.sequencer[..12.min(c.sequencer.len())],
            c.state,
            remaining
        );
    }

    println!("\n=== BRIDGE OUTPUTS ({}) ===", store.bridge_outputs.len());
    if store.bridge_outputs.is_empty() {
        println!("  (brak)");
    }
    for o in &store.bridge_outputs {
        println!(
            "  {}  {}→{}  amount={}  commitment_height={}  state={:?}  unlock_l1={:?}",
            &o.id[..16.min(o.id.len())],
            &o.from_l2[..12.min(o.from_l2.len())],
            &o.to_l1[..12.min(o.to_l1.len())],
            o.amount,
            o.commitment_l2_height,
            o.state,
            o.unlock_l1_index
        );
    }

    println!("\n=== SEQUENCER BONDS ({}) ===", store.sequencer_bonds.len());
    if store.sequencer_bonds.is_empty() {
        println!("  (brak)");
    }
    for b in &store.sequencer_bonds {
        println!(
            "  seq={}  bond={}  locked_at_l1={}  status={:?}",
            b.sequencer, b.amount, b.locked_at_l1_index, b.status
        );
    }
}

// ─────────────────────────────────────────────
// Block event hook
// ─────────────────────────────────────────────

/// Wywoływany przy każdym nowym bloku L1 (miner + p2p).
/// Finalizuje Soft commitmenty i odblokowuje bridge outputy.
/// Non-blocking — loguje błędy bez panikowania.
pub fn on_new_block(l1_index: u64) {
    let mut store = load_l2_store();

    let finalized = try_finalize_all(&mut store);
    let unlocked = try_unlock_bridge_outputs(&mut store, l1_index);

    if finalized > 0 || !unlocked.is_empty() {
        match save_l2_store(&store) {
            Ok(_) => {
                if finalized > 0 {
                    println!("[L2] {} commitment(ów) → Hard (l1={})", finalized, l1_index);
                }
                if !unlocked.is_empty() {
                    println!("[L2] Bridge outputy odblokowane @ l1={}: {:?}", l1_index, unlocked);
                }
            }
            Err(e) => eprintln!("[L2] on_new_block: błąd zapisu store: {}", e),
        }
    }
}
