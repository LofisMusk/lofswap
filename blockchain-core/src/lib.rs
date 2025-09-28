use k256::ecdsa::{signature::DigestVerifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize, Debug, Clone)]

pub struct Transaction {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    pub timestamp: i64,
    pub signature: String,
    pub hash: String,
}
pub struct KeyBlockHeader {
    pub index: u64,
    pub timestamp: i64,
    pub previous_key_hash: String,
    pub difficulty: usize,
    pub nonce: u64,
    pub miner: String,         // np. Twój OBSERVED_IP
    pub micro_root: String,    // Merkle root z ID mikrobloków tej epoki
    pub hash: String,
}

impl KeyBlockHeader {
    pub fn pow_input(&self) -> String {
        format!("{}{}{}{}{}{}",
            self.index, self.timestamp, self.previous_key_hash,
            self.difficulty, self.nonce, self.miner
        )
    }
    pub fn calculate_hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.pow_input().as_bytes());
        format!("{:x}", h.finalize())
    }
    pub fn mine(&mut self) {
        let target = "0".repeat(self.difficulty);
        loop {
            self.hash = self.calculate_hash();
            if self.hash.starts_with(&target) { break; }
            self.nonce = self.nonce.wrapping_add(1);
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MicroBlock {
    pub parent_key_hash: String,
    pub seq: u32,
    pub timestamp: i64,
    pub txs: Vec<Transaction>,
    pub leader_pubkey_sec1: String, // hex (compressed 33B)
    pub leader_sig_der: String,     // hex (DER)
}

impl MicroBlock {
    pub fn id(&self) -> String {
        // ID mikrobloku = hash (parent,seq,timestamp,txs,leader_pubkey)
        let body = serde_json::to_string(self).unwrap();
        let mut h = Sha256::new();
        h.update(body.as_bytes());
        format!("{:x}", h.finalize())
    }
    pub fn verify_sig(&self) -> bool {
        let Ok(pk_bytes) = hex::decode(&self.leader_pubkey_sec1) else { return false; };
        let Ok(vk) = VerifyingKey::from_sec1_bytes(&pk_bytes) else { return false; };
        let Ok(sig_bytes) = hex::decode(&self.leader_sig_der) else { return false; };
        let Ok(sig) = Signature::from_der(&sig_bytes) else { return false; };

        // Kanoniczny hash treści do podpisu (bez samego podpisu)
        let to_sign = {
            let mut clone = self.clone();
            clone.leader_sig_der.clear();
            serde_json::to_vec(&clone).unwrap()
        };
        let mut hasher = Sha256::new();
        hasher.update(&to_sign);
        vk.verify_digest(hasher, &sig).is_ok()
    }
}

pub fn merkle_root(ids: &[String]) -> String {
    if ids.is_empty() { return String::from("0"); }
    let mut layer = ids.iter().map(|s| {
        let mut h = Sha256::new();
        h.update(s.as_bytes());
        format!("{:x}", h.finalize())
    }).collect::<Vec<_>>();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity((layer.len()+1)/2);
        for pair in layer.chunks(2) {
            let a = &pair[0];
            let b = if pair.len() == 2 { &pair[1] } else { &pair[0] };
            let mut h = Sha256::new();
            h.update(a.as_bytes());
            h.update(b.as_bytes());
            next.push(format!("{:x}", h.finalize()));
        }
        layer = next;
    }
    layer[0].clone()
}
