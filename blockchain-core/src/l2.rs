// l2.rs — Lofswap L2 layer: Optimistic Rollup + Fraud Proof
// Architektura: StateCommitment na L1, challenge period, deterministyczna re-egzekucja.
// Zasada twarda: BridgeOutput L2→L1 odblokowany WYŁĄCZNIE po Hard finality.

use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature as EcdsaSignature};
use std::collections::HashMap;

// ─────────────────────────────────────────────
// Confirmation state
// ─────────────────────────────────────────────

/// Stan potwierdzenia bloku L2.
/// Soft = challenge period aktywny, outputs LOCKED.
/// Hard = okres minął bez fraud proof — outputs UNLOCKED.
/// Fraud = fraud proof zaakceptowany, blok UNIEWAŻNIONY, bond skasowany.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConfirmationState {
    Soft,
    Hard,
    Fraud,
}

// ─────────────────────────────────────────────
// L2 Transaction
// ─────────────────────────────────────────────

/// Fast L2 transfer — sequencer ordered, ~5-10s finality (soft).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2Transaction {
    pub txid: String,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    pub nonce: u64,
    pub timestamp: i64,
    /// ECDSA sig (hex). API nigdy nie zwraca raw sig — tylko txid/from/to/amount.
    pub signature: String,
    /// Compressed pubkey hex. Używany tylko przy weryfikacji, nie w API response.
    pub pubkey: String,
}

impl L2Transaction {
    pub fn compute_txid(&self) -> String {
        let preimage = format!(
            "L2TX|{}|{}|{}|{}|{}|{}",
            self.from, self.to, self.amount, self.fee, self.nonce, self.timestamp
        );
        let mut h = Sha256::new();
        h.update(preimage.as_bytes());
        format!("{:x}", h.finalize())
    }

    /// Preimage nad którym wallet podpisuje TX.
    /// Identyczny z compute_txid preimage — SHA256 tego jest message dla ECDSA.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let preimage = format!(
            "L2TX|{}|{}|{}|{}|{}|{}",
            self.from, self.to, self.amount, self.fee, self.nonce, self.timestamp
        );
        Sha256::digest(preimage.as_bytes()).to_vec()
    }

    /// Weryfikuje secp256k1 podpis TX.
    /// Zwraca Ok(()) jeśli prawidłowy, Err(reason) jeśli nieprawidłowy.
    /// UWAGA: jeśli signature jest pusty — zwraca Err (użyj tylko w trybie dev).
    pub fn verify_sig(&self) -> Result<(), String> {
        if self.signature.is_empty() {
            return Err("brak podpisu (unsigned tx)".into());
        }
        if self.pubkey.is_empty() {
            return Err("brak pubkey".into());
        }
        let secp = Secp256k1::new();
        let sig_bytes = hex::decode(&self.signature)
            .map_err(|_| "nieprawidłowy hex podpisu")?;
        let pub_bytes = hex::decode(&self.pubkey)
            .map_err(|_| "nieprawidłowy hex pubkey")?;
        let sig = EcdsaSignature::from_compact(&sig_bytes)
            .map_err(|_| "nieprawidłowa kompaktowa sygnatura")?;
        let pubkey = PublicKey::from_slice(&pub_bytes)
            .map_err(|_| "nieprawidłowy pubkey")?;
        let hash_bytes = self.signing_preimage();
        let hash_arr: [u8; 32] = hash_bytes.try_into()
            .map_err(|_| "hash nieprawidłowy")?;
        let msg = Message::from_digest(hash_arr);
        secp.verify_ecdsa(msg, &sig, &pubkey)
            .map_err(|_| "weryfikacja ECDSA nieudana".into())
    }
}

// ─────────────────────────────────────────────
// Merkle State Root
// ─────────────────────────────────────────────

/// Oblicza Merkle root ze stanu salda kont L2.
/// Deterministyczne: sortowane po adresie przed budową drzewa.
pub fn compute_state_root(balances: &HashMap<String, u64>) -> String {
    let mut entries: Vec<(&String, &u64)> = balances.iter().collect();
    entries.sort_by_key(|(k, _)| k.as_str());

    if entries.is_empty() {
        return "0".repeat(64);
    }

    // Liście: sha256(addr_bytes ++ balance_be)
    let mut leaves: Vec<Vec<u8>> = entries
        .iter()
        .map(|(addr, bal)| {
            let mut h = Sha256::new();
            h.update(addr.as_bytes());
            h.update(&bal.to_be_bytes());
            h.finalize().to_vec()
        })
        .collect();

    // Budowa drzewa bottom-up
    while leaves.len() > 1 {
        let mut next = Vec::new();
        for chunk in leaves.chunks(2) {
            let mut h = Sha256::new();
            h.update(&chunk[0]);
            // Duplikuj odd node zamiast paddingu zerami
            h.update(chunk.get(1).unwrap_or(&chunk[0]));
            next.push(h.finalize().to_vec());
        }
        leaves = next;
    }

    hex::encode(&leaves[0])
}

// ─────────────────────────────────────────────
// StateCommitment
// ─────────────────────────────────────────────

/// StateCommitment publikowany przez sequencera na L1.
/// Zawiera Merkle root salda L2 w danej wysokości.
/// Po submission — challenge period aktywny (domyślnie 7 dni).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StateCommitment {
    /// Wysokość L2 którą ten commitment pokrywa
    pub l2_height: u64,
    /// Indeks bloku L1 gdzie commitment jest zakotwiczony (anchor tx)
    pub l1_anchor_index: u64,
    /// Merkle root stanu salda na l2_height
    pub state_root: String,
    /// Adres L1 sequencera
    pub sequencer: String,
    /// Podpis sequencera (ed25519) nad preimage()
    pub sequencer_sig: String,
    /// ed25519 pubkey sequencera (hex) — do weryfikacji sequencer_sig
    #[serde(default)]
    pub sequencer_pubkey: String,
    /// Bond sequencera w lofs (slashowany przy fraud). Min: MIN_SEQUENCER_BOND
    pub sequencer_bond: u64,
    /// Unix timestamp złożenia commitment
    pub submitted_at: i64,
    /// Długość challenge period w sekundach (default: 7 dni)
    pub challenge_period_secs: u64,
    /// Stan potwierdzenia
    pub state: ConfirmationState,
}

impl StateCommitment {
    pub const DEFAULT_CHALLENGE_PERIOD: u64 = 7 * 24 * 3600;
    /// 1 MLofs = minimalny bond sequencera
    pub const MIN_SEQUENCER_BOND: u64 = 1_000_000;

    /// Kanoniczny preimage do podpisania przez sequencera
    pub fn preimage(&self) -> String {
        format!(
            "SC|{}|{}|{}|{}",
            self.l2_height, self.l1_anchor_index, self.state_root, self.sequencer
        )
    }

    /// Czy challenge period minął (ready for Hard finality)?
    pub fn is_challenge_expired(&self, now: i64) -> bool {
        (now - self.submitted_at) as u64 >= self.challenge_period_secs
    }

    /// Przejdź do Hard jeśli okres minął i brak fraud.
    /// Wywołaj po każdym nowym L1 bloku.
    pub fn try_finalize(&mut self, now: i64) {
        if self.state == ConfirmationState::Soft && self.is_challenge_expired(now) {
            self.state = ConfirmationState::Hard;
        }
    }

    /// Sequencer stracił bond — oznacz jako Fraud
    pub fn slash(&mut self) {
        self.state = ConfirmationState::Fraud;
    }
}

// ─────────────────────────────────────────────
// FraudProof
// ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FraudProofError {
    /// Podany pre_state nie pasuje do zadeklarowanego pre_state_root
    PreStateMismatch,
    /// Przepełnienie arytmetyczne przy sumowaniu amount + fee
    ArithmeticOverflow,
    /// Challenge period minął — za późno na fraud proof
    ChallengeWindowExpired,
    /// Blok jest już w stanie Hard lub Fraud — niedopuszczalny challenge
    InvalidCommitmentState,
}

impl std::fmt::Display for FraudProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FraudProofError::PreStateMismatch => write!(f, "pre-state root mismatch"),
            FraudProofError::ArithmeticOverflow => write!(f, "arithmetic overflow in tx amounts"),
            FraudProofError::ChallengeWindowExpired => write!(f, "challenge period expired"),
            FraudProofError::InvalidCommitmentState => write!(f, "commitment not in Soft state"),
        }
    }
}

impl std::error::Error for FraudProofError {}

/// FraudProof składany przez challengera w trakcie challenge period.
/// L1 re-wykonuje sporną TX deterministycznie na pre_state.
/// Jeśli wynik != claimed_post_state_root → fraud potwierdzony → slash sequencera.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FraudProof {
    /// Commitment który jest challengowany
    pub commitment_l2_height: u64,
    /// Sporna L2 transakcja
    pub disputed_tx: L2Transaction,
    /// Root stanu PRZED sporną TX
    pub pre_state_root: String,
    /// Root stanu jaki sequencer TWIERDZIŁ po TX
    pub claimed_post_state_root: String,
    /// Root stanu jaki challenger WYLICZYŁ po TX
    pub correct_post_state_root: String,
    /// Adres L1 challengera
    pub challenger: String,
    /// Podpis challengera
    pub challenger_sig: String,
    /// Timestamp złożenia
    pub submitted_at: i64,
}

impl FraudProof {
    /// L1 deterministycznie weryfikuje fraud.
    /// Zwraca Ok(true) jeśli fraud potwierdzony, Ok(false) jeśli sequencer miał rację.
    ///
    /// Wywołujący musi:
    ///   1. Sprawdzić że commitment.state == Soft
    ///   2. Sprawdzić że now < submitted_at + challenge_period
    ///   3. Dostarczyć pre_state pasujący do pre_state_root
    pub fn verify(
        &self,
        commitment: &StateCommitment,
        pre_state: &HashMap<String, u64>,
        now: i64,
    ) -> Result<bool, FraudProofError> {
        // Guard: commitment musi być Soft (aktywny challenge period)
        if commitment.state != ConfirmationState::Soft {
            return Err(FraudProofError::InvalidCommitmentState);
        }

        // Guard: window nie minęło
        if commitment.is_challenge_expired(now) {
            return Err(FraudProofError::ChallengeWindowExpired);
        }

        // 1. Weryfikuj pre_state_root
        let computed_pre = compute_state_root(pre_state);
        if computed_pre != self.pre_state_root {
            return Err(FraudProofError::PreStateMismatch);
        }

        let tx = &self.disputed_tx;
        let from_balance = pre_state.get(&tx.from).copied().unwrap_or(0);

        // 2. Oblicz total_debit
        let total_debit = tx
            .amount
            .checked_add(tx.fee)
            .ok_or(FraudProofError::ArithmeticOverflow)?;

        // 3. Re-egzekucja TX
        let mut post_state = pre_state.clone();
        if from_balance >= total_debit {
            // Prawidłowa TX: zastosuj transfer
            *post_state.entry(tx.from.clone()).or_insert(0) -= total_debit;
            *post_state.entry(tx.to.clone()).or_insert(0) += tx.amount;
            // fee → sequencer bond pool (uproszczenie: fee burns)
        }
        // Jeśli from_balance < total_debit: TX invalid → post_state == pre_state
        // Sequencer nie powinien był includować tej TX → każde claimed_post != pre → fraud

        // 4. Porównaj claimed vs correct
        let correct_root = compute_state_root(&post_state);
        Ok(self.claimed_post_state_root != correct_root)
    }
}

// ─────────────────────────────────────────────
// L2 Block
// ─────────────────────────────────────────────

/// Blok L2 produkowany przez sequencera.
/// Czas bloku: ~5-10s (soft confirm), Hard po challenge period.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2Block {
    pub height: u64,
    pub timestamp: i64,
    pub transactions: Vec<L2Transaction>,
    pub parent_hash: String,
    /// Merkle root stanu salda po zastosowaniu wszystkich TX w tym bloku
    pub state_root: String,
    pub sequencer: String,
    pub sequencer_sig: String,
    /// Indeks bloku L1 gdzie jest zakotwiczony StateCommitment (None jeśli nie anchored)
    pub l1_anchor: Option<u64>,
    pub confirm_state: ConfirmationState,
}

impl L2Block {
    pub fn compute_hash(&self) -> String {
        let txids: Vec<&str> = self.transactions.iter().map(|t| t.txid.as_str()).collect();
        let preimage = format!(
            "L2B|{}|{}|{}|{}|{}",
            self.height,
            self.timestamp,
            self.parent_hash,
            self.state_root,
            txids.join(",")
        );
        let mut h = Sha256::new();
        h.update(preimage.as_bytes());
        format!("{:x}", h.finalize())
    }

    /// Soft-confirmed block: outputs LOCKED, bridge withdrawals BLOCKED
    pub fn is_soft(&self) -> bool {
        self.confirm_state == ConfirmationState::Soft
    }

    /// Hard-confirmed: challenge period minął, bridge withdrawals ALLOWED
    pub fn is_hard(&self) -> bool {
        self.confirm_state == ConfirmationState::Hard
    }
}

// ─────────────────────────────────────────────
// Bridge Output (L2 → L1)
// ─────────────────────────────────────────────

/// Output mostu L2→L1.
/// ZASADA TWARDA: nigdy nie odblokowywany bez Hard finality commitment.
/// Zero wyjątków — nawet dla fast withdrawals z sequencer bond.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BridgeOutput {
    pub id: String,
    /// Adres L2 inicjujący wypłatę
    pub from_l2: String,
    /// Adres L1 odbiorcy
    pub to_l1: String,
    pub amount: u64,
    /// Commitment który pokrywa tę wypłatę
    pub commitment_l2_height: u64,
    /// L1 block index od którego output jest spendable (ustawiane przy unlock)
    pub unlock_l1_index: Option<u64>,
    pub state: BridgeOutputState,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BridgeOutputState {
    /// Challenge period aktywny — output LOCKED
    Locked,
    /// Hard finality potwierdzona — output SPENDABLE na L1
    Unlocked,
    /// Fraud wykryty — output ANULOWANY, środki w bond sequencera
    Burned,
}

impl BridgeOutput {
    /// Próbuje odblokować output.
    /// INVARIANT: wymaga commitment.state == Hard.
    /// Zwraca true jeśli odblokowanie nastąpiło.
    pub fn try_unlock(
        &mut self,
        commitment: &StateCommitment,
        current_l1_index: u64,
    ) -> bool {
        if commitment.state == ConfirmationState::Hard
            && commitment.l2_height == self.commitment_l2_height
            && self.state == BridgeOutputState::Locked
        {
            self.state = BridgeOutputState::Unlocked;
            self.unlock_l1_index = Some(current_l1_index);
            true
        } else {
            false
        }
    }

    /// Burn output przy fraud (sequencer bond pokrywa straty)
    pub fn burn(&mut self) {
        self.state = BridgeOutputState::Burned;
    }
}

// ─────────────────────────────────────────────
// Sequencer Bond
// ─────────────────────────────────────────────

/// Rejestr bondu sequencera na L1.
/// Bond blokowany przy rejestracji, slashowany przy fraud.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SequencerBond {
    pub sequencer: String,
    pub amount: u64,
    pub locked_at_l1_index: u64,
    pub status: BondStatus,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BondStatus {
    Active,
    Slashed,
    /// Sequencer wypłacił bond (po min lock period bez fraud)
    Withdrawn,
}

impl SequencerBond {
    pub fn new(sequencer: String, amount: u64, l1_index: u64) -> Result<Self, &'static str> {
        if amount < StateCommitment::MIN_SEQUENCER_BOND {
            return Err("bond below minimum required");
        }
        Ok(Self {
            sequencer,
            amount,
            locked_at_l1_index: l1_index,
            status: BondStatus::Active,
        })
    }

    /// Slash bond — zwraca kwotę do wypłaty challengerowi
    pub fn slash(&mut self) -> u64 {
        let slashed = self.amount;
        self.amount = 0;
        self.status = BondStatus::Slashed;
        slashed
    }
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_balances() -> HashMap<String, u64> {
        let mut m = HashMap::new();
        m.insert("LFSalice111".to_string(), 1_000_000);
        m.insert("LFSbob22222".to_string(), 500_000);
        m
    }

    #[test]
    fn state_root_is_deterministic() {
        let a = compute_state_root(&test_balances());
        let b = compute_state_root(&test_balances());
        assert_eq!(a, b, "state root musi być deterministyczny");
    }

    #[test]
    fn state_root_changes_on_balance_change() {
        let mut m = test_balances();
        let root_before = compute_state_root(&m);
        *m.get_mut("LFSalice111").unwrap() -= 100;
        let root_after = compute_state_root(&m);
        assert_ne!(root_before, root_after, "root musi odzwierciedlać zmianę salda");
    }

    #[test]
    fn state_root_empty_is_64_zeros() {
        let empty: HashMap<String, u64> = HashMap::new();
        assert_eq!(compute_state_root(&empty), "0".repeat(64));
    }

    #[test]
    fn fraud_proof_detects_invalid_post_state() {
        let pre_state = test_balances();
        let pre_root = compute_state_root(&pre_state);

        // Sequencer twierdzi że po TX state root to same co pre (ale powinien być inny)
        let tx = L2Transaction {
            txid: "abc".to_string(),
            from: "LFSalice111".to_string(),
            to: "LFSbob22222".to_string(),
            amount: 100_000,
            fee: 1_000,
            nonce: 1,
            timestamp: 0,
            signature: String::new(),
            pubkey: String::new(),
        };

        // Oblicz poprawny post root
        let mut post = pre_state.clone();
        *post.get_mut("LFSalice111").unwrap() -= 101_000;
        *post.get_mut("LFSbob22222").unwrap() += 100_000;
        let correct_root = compute_state_root(&post);

        let commitment = StateCommitment {
            l2_height: 1,
            l1_anchor_index: 10,
            state_root: pre_root.clone(),
            sequencer: "LFSseq0001".to_string(),
            sequencer_sig: String::new(),
            sequencer_pubkey: String::new(),
            sequencer_bond: StateCommitment::MIN_SEQUENCER_BOND,
            submitted_at: 0,
            challenge_period_secs: StateCommitment::DEFAULT_CHALLENGE_PERIOD,
            state: ConfirmationState::Soft,
        };

        let proof = FraudProof {
            commitment_l2_height: 1,
            disputed_tx: tx,
            pre_state_root: pre_root.clone(),
            // Sequencer claimed wrong root (używa pre jako claimed — ewidentny fraud)
            claimed_post_state_root: pre_root.clone(),
            correct_post_state_root: correct_root,
            challenger: "LFSchallenger".to_string(),
            challenger_sig: String::new(),
            submitted_at: 1000,
        };

        let now = 1000; // w ramach challenge period
        let result = proof.verify(&commitment, &pre_state, now).unwrap();
        assert!(result, "fraud powinien być wykryty");
    }

    #[test]
    fn fraud_proof_no_fraud_when_correct() {
        let pre_state = test_balances();
        let pre_root = compute_state_root(&pre_state);

        let tx = L2Transaction {
            txid: "def".to_string(),
            from: "LFSalice111".to_string(),
            to: "LFSbob22222".to_string(),
            amount: 50_000,
            fee: 500,
            nonce: 1,
            timestamp: 0,
            signature: String::new(),
            pubkey: String::new(),
        };

        let mut post = pre_state.clone();
        *post.get_mut("LFSalice111").unwrap() -= 50_500;
        *post.get_mut("LFSbob22222").unwrap() += 50_000;
        let correct_root = compute_state_root(&post);

        let commitment = StateCommitment {
            l2_height: 1,
            l1_anchor_index: 10,
            state_root: correct_root.clone(),
            sequencer: "LFSseq0001".to_string(),
            sequencer_sig: String::new(),
            sequencer_pubkey: String::new(),
            sequencer_bond: StateCommitment::MIN_SEQUENCER_BOND,
            submitted_at: 0,
            challenge_period_secs: StateCommitment::DEFAULT_CHALLENGE_PERIOD,
            state: ConfirmationState::Soft,
        };

        let proof = FraudProof {
            commitment_l2_height: 1,
            disputed_tx: tx,
            pre_state_root: pre_root.clone(),
            // Sequencer claimed poprawny root
            claimed_post_state_root: correct_root.clone(),
            correct_post_state_root: correct_root,
            challenger: "LFSchallenger".to_string(),
            challenger_sig: String::new(),
            submitted_at: 1000,
        };

        let now = 1000;
        let result = proof.verify(&commitment, &pre_state, now).unwrap();
        assert!(!result, "brak fraud gdy sequencer miał rację");
    }

    #[test]
    fn state_commitment_finalizes_after_period() {
        let mut commitment = StateCommitment {
            l2_height: 5,
            l1_anchor_index: 100,
            state_root: "aaa".to_string(),
            sequencer: "LFSseq0001".to_string(),
            sequencer_sig: String::new(),
            sequencer_pubkey: String::new(),
            sequencer_bond: StateCommitment::MIN_SEQUENCER_BOND,
            submitted_at: 0,
            challenge_period_secs: 100,
            state: ConfirmationState::Soft,
        };
        commitment.try_finalize(50);
        assert_eq!(commitment.state, ConfirmationState::Soft, "za wcześnie na Hard");
        commitment.try_finalize(101);
        assert_eq!(commitment.state, ConfirmationState::Hard, "powinno być Hard po okresie");
    }

    #[test]
    fn bridge_output_unlocks_only_on_hard() {
        let commitment_soft = StateCommitment {
            l2_height: 3,
            l1_anchor_index: 50,
            state_root: "bbb".to_string(),
            sequencer: "LFSseq0001".to_string(),
            sequencer_sig: String::new(),
            sequencer_pubkey: String::new(),
            sequencer_bond: StateCommitment::MIN_SEQUENCER_BOND,
            submitted_at: 0,
            challenge_period_secs: 1000,
            state: ConfirmationState::Soft,
        };

        let mut output = BridgeOutput {
            id: "bridge_001".to_string(),
            from_l2: "LFSalice111".to_string(),
            to_l1: "LFSalice_l1".to_string(),
            amount: 200_000,
            commitment_l2_height: 3,
            unlock_l1_index: None,
            state: BridgeOutputState::Locked,
        };

        // Soft commitment → NIE odblokowuje
        assert!(!output.try_unlock(&commitment_soft, 55));
        assert_eq!(output.state, BridgeOutputState::Locked);

        // Hard commitment → odblokowuje
        let mut commitment_hard = commitment_soft.clone();
        commitment_hard.state = ConfirmationState::Hard;
        assert!(output.try_unlock(&commitment_hard, 55));
        assert_eq!(output.state, BridgeOutputState::Unlocked);
        assert_eq!(output.unlock_l1_index, Some(55));
    }

    #[test]
    fn fraud_proof_rejects_expired_window() {
        let pre_state = test_balances();
        let pre_root = compute_state_root(&pre_state);
        let commitment = StateCommitment {
            l2_height: 1,
            l1_anchor_index: 10,
            state_root: pre_root.clone(),
            sequencer: "LFSseq0001".to_string(),
            sequencer_sig: String::new(),
            sequencer_pubkey: String::new(),
            sequencer_bond: StateCommitment::MIN_SEQUENCER_BOND,
            submitted_at: 0,
            challenge_period_secs: 100,
            state: ConfirmationState::Soft,
        };
        let proof = FraudProof {
            commitment_l2_height: 1,
            disputed_tx: L2Transaction {
                txid: "ghi".to_string(),
                from: "LFSalice111".to_string(),
                to: "LFSbob22222".to_string(),
                amount: 1,
                fee: 0,
                nonce: 1,
                timestamp: 0,
                signature: String::new(),
                pubkey: String::new(),
            },
            pre_state_root: pre_root.clone(),
            claimed_post_state_root: pre_root.clone(),
            correct_post_state_root: pre_root.clone(),
            challenger: "LFSchallenger".to_string(),
            challenger_sig: String::new(),
            submitted_at: 0,
        };
        // now = 200 > challenge_period 100 → błąd
        let err = proof.verify(&commitment, &pre_state, 200).unwrap_err();
        assert_eq!(err, FraudProofError::ChallengeWindowExpired);
    }
}
