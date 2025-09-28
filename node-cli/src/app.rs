use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::sync::Mutex;

use blockchain_core::{KeyBlockHeader, MicroBlock, Transaction, merkle_root};

#[derive(Clone)]
pub struct AppState {
    pub node: Arc<Mutex<NodeState>>,
    pub peers: Arc<Mutex<crate::peers::PeersDb>>,
    pub observed_ip: String,
    pub rpc_port: u16,
    pub p2p_port: u16,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            node: Arc::new(Mutex::new(NodeState::default())),
            peers: Arc::new(Mutex::new(crate::peers::PeersDb::default())),
            observed_ip: "0.0.0.0".to_string(),
            rpc_port: 6060,
            p2p_port: 6000,
        }
    }
}

#[derive(Default)]
pub struct NodeState {
    pub key_chain: Vec<KeyBlockHeader>,                                   // PoW nagłówki
    pub micro_by_parent: HashMap<String, BTreeMap<u32, MicroBlock>>,      // parent_key_hash -> seq -> micro
    pub mempool: Vec<Transaction>,
    pub difficulty: usize,
}

impl NodeState {
    pub fn height(&self) -> u64 {
        self.key_chain.last().map(|kb| kb.index).unwrap_or(0)
    }

    pub fn best_key_hash(&self) -> String {
        self.key_chain
            .last()
            .map(|kb| kb.hash.clone())
            .unwrap_or_default()
    }

    pub fn previous_key_hash(&self) -> String {
        self.best_key_hash()
    }

    pub fn append_key_block(&mut self, mut kb: KeyBlockHeader) {
        // Uzupełnij micro_root dla poprzedniej epoki (jeśli pusta) – na devnecie tolerujemy brak.
        if kb.micro_root.is_empty() {
            let prev = kb.previous_key_hash.clone();
            let ids: Vec<String> = self
                .micro_by_parent
                .get(&prev)
                .map(|m| m.values().map(|mb| mb.id()).collect())
                .unwrap_or_default();
            kb.micro_root = merkle_root(&ids);
        }
        self.key_chain.push(kb);
    }

    pub fn apply_micro_on_tip(&mut self, mb: MicroBlock) -> bool {
        if mb.parent_key_hash != self.best_key_hash() { return false; }
        if !mb.verify_sig() { return false; }
        let entry = self.micro_by_parent.entry(mb.parent_key_hash.clone()).or_default();
        if entry.contains_key(&mb.seq) { return false; }
        entry.insert(mb.seq, mb);
        true
    }

    pub fn get_balance(&self, address: &str) -> u64 {
        // Liczymy saldo po wszystkich mikroblokach przypiętych do KAŻDEGO key-bloka w łańcuchu (prosto na devnet).
        // W przyszłości możesz ograniczyć do sfinalizowanych epok.
        let mut bal: i128 = 0;
        for kb in &self.key_chain {
            if let Some(mset) = self.micro_by_parent.get(&kb.hash) {
                for (_seq, mb) in mset {
                    for tx in &mb.txs {
                        if tx.to == address { bal += tx.amount as i128; }
                        if tx.from == address { bal -= (tx.amount + tx.fee) as i128; }
                    }
                }
            }
        }
        if bal < 0 { 0 } else { bal as u64 }
    }
}
