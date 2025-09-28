use tokio::time::{sleep, Duration};
use sha2::{Digest, Sha256};
use k256::ecdsa::{signature::DigestSigner, SigningKey, Signature};
use blockchain_core::{KeyBlockHeader, MicroBlock, Transaction};

use crate::app::AppState;
use chrono::Utc;

/// Pętla kopania KEY‑bloków (PoW).
pub async fn mine_key_loop(st: AppState, miner_id: String) {
    loop {
        {
            let mut n = st.node.lock().await;
            let index = n.height() + 1;
            let prev = n.previous_key_hash();

            let mut kb = KeyBlockHeader {
                index,
                timestamp: Utc::now().timestamp(),
                previous_key_hash: prev,
                difficulty: n.difficulty.max(1),
                nonce: 0,
                miner: miner_id.clone(),
                micro_root: String::new(), // uzupełnimy przy append (z mikrobloków poprzedniej epoki)
                hash: String::new(),
            };
            kb.mine();
            n.append_key_block(kb);
        }
        sleep(Duration::from_millis(200)).await;
    }
}

/// Pętla LIDERA – produkcja mikrobloków (bez PoW).
/// Aktywna tylko jeśli ostatni key‑blok ma `miner == st.observed_ip`.
pub async fn micro_leader_loop(st: AppState, leader_sk_hex: String) {
    let sk_bytes = match hex::decode(&leader_sk_hex) {
        Ok(b) => b,
        Err(_) => return,
    };
    let signing_key = match SigningKey::from_slice(&sk_bytes) {
        Ok(s) => s,
        Err(_) => return,
    };
    let vk = signing_key.verifying_key();
    let leader_pk_hex = hex::encode(vk.to_encoded_point(true).as_bytes());

    let interval = Duration::from_millis(200);
    let mut seq: u32 = 1;

    loop {
        {
            let mut n = st.node.lock().await;

            // czy jesteśmy liderem epoki?
            let am_leader = n
                .key_chain
                .last()
                .map(|kb| kb.miner == st.observed_ip)
                .unwrap_or(false);

            if !am_leader {
                // nie jesteśmy liderem – krótszy sen i dalej
            } else if !n.mempool.is_empty() {
                // zbierz paczkę TX (tu: wszystkie)
                let txs: Vec<Transaction> = n.mempool.drain(..).collect();

                let mut mb = MicroBlock {
                    parent_key_hash: n.best_key_hash(),
                    seq,
                    timestamp: Utc::now().timestamp(),
                    txs,
                    leader_pubkey_sec1: leader_pk_hex.clone(),
                    leader_sig_der: String::new(),
                };

                let mut clone = mb.clone();
                clone.leader_sig_der.clear();
                let body = serde_json::to_vec(&clone).unwrap();
                let mut hasher = Sha256::new();
                hasher.update(&body);let sig: Signature = signing_key.sign_digest(hasher);mb.leader_sig_der = hex::encode(sig.to_der().as_bytes());

                // stosujemy mikroblok (tylko na tip)
                let _ok = n.apply_micro_on_tip(mb);
                seq = seq.wrapping_add(1);
            }
        }
        sleep(interval).await;
    }
}
