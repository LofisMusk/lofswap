use serde::{Serialize, Deserialize};
use tokio::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const PEERS_PATH: &str = "peers.json";
pub const MAX_PEERS_RETURNED: usize = 16;

#[derive(Serialize)]
pub struct PeersResp {
    pub peers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PeerInfo {
    addr: String,
    last_ok: u64,
    score: i32,
    ttl: u64,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct PeersDb {
    peers: Vec<PeerInfo>,
}

impl PeersDb {
    pub async fn load() -> Self {
        if Path::new(PEERS_PATH).exists() {
            if let Ok(bytes) = fs::read(PEERS_PATH).await {
                if let Ok(db) = serde_json::from_slice::<PeersDb>(&bytes) {
                    return db;
                }
            }
        }
        Self::default()
    }

    pub async fn save(&self) {
        if let Ok(json) = serde_json::to_vec_pretty(self) {
            let _ = fs::write(PEERS_PATH, json).await;
        }
    }

    pub fn upsert(&mut self, addr: String, ok: bool) {
        let now = now_ts();
        let ttl = now + 7 * 24 * 3600; // 7 dni
        if let Some(p) = self.peers.iter_mut().find(|p| p.addr == addr) {
            if ok {
                p.last_ok = now;
                p.score = (p.score + 1).min(100);
            } else {
                p.score = (p.score - 1).max(-100);
            }
            p.ttl = ttl;
            return;
        }
        self.peers.push(PeerInfo {
            addr,
            last_ok: if ok { now } else { 0 },
            score: if ok { 1 } else { -1 },
            ttl,
        });
    }

    pub fn best(&self, n: usize) -> Vec<String> {
        let now = now_ts();
        let mut v: Vec<_> = self.peers.iter().filter(|p| p.ttl > now).collect();
        v.sort_by_key(|p| -(p.score)); // malejąco po score
        v.into_iter().take(n).map(|p| p.addr.clone()).collect()
    }
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
