//! Talking to LofSwap nodes.
//!
//! Nodes speak a line-oriented request protocol over TCP: write a request such
//! as `/balance/LFS…`, read the reply, connection closed. Everything here
//! blocks and runs on the worker thread.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use blockchain_core::{
    Block, CHAIN_ID, Transaction, TxKind, pubkey_to_address,
    wallet_keystore::DEFAULT_DERIVATION_PATH,
};
use chrono::Utc;
use rand::seq::SliceRandom;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::storage::{self, Settings};

/// Seed nodes compiled into the binary. `LOFSWAP_BOOTSTRAP` and the wallet's
/// own settings both override this, so a wallet can join a network whose seeds
/// changed without waiting for a new release.
pub const BOOTSTRAP_NODES: &[&str] = &["89.168.107.239:6000", "79.76.116.108:6000"];
pub const BOOTSTRAP_ENV: &str = "LOFSWAP_BOOTSTRAP";

pub const DEFAULT_TX_FEE: u64 = 1;
const TX_VERSION: u8 = 3;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(1200);
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE: u64 = 4 * 1024 * 1024;

/// Node-side page limits (`BLOCKS_PAGE_LIMIT_MAX` / `HEADERS_PAGE_LIMIT_MAX`).
const BLOCK_PAGE: usize = 64;
const HEADER_PAGE: usize = 1024;
const SCAN_PAGES_PER_TICK: usize = 3;

/// Nodes allow five header/block requests per second per IP and hand out
/// infraction points above that — enough of them and the wallet's own address
/// is temporarily banned. Space the requests out with a wide margin.
const BLOCK_REQUEST_INTERVAL: Duration = Duration::from_millis(350);
static LAST_BLOCK_REQUEST: Mutex<Option<Instant>> = Mutex::new(None);

fn pace_block_request() {
    let mut last = LAST_BLOCK_REQUEST
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(previous) = *last {
        let elapsed = previous.elapsed();
        if elapsed < BLOCK_REQUEST_INTERVAL {
            std::thread::sleep(BLOCK_REQUEST_INTERVAL - elapsed);
        }
    }
    *last = Some(Instant::now());
}

// ------------------------------------------------------------------ wire ----

fn resolve(peer: &str) -> Option<SocketAddr> {
    // Plain `host:port` is resolved through DNS so seed nodes can be named.
    peer.to_socket_addrs().ok()?.next()
}

fn request(peer: &str, payload: &[u8], read_timeout: Duration) -> std::io::Result<Vec<u8>> {
    let addr = resolve(peer)
        .ok_or_else(|| std::io::Error::other(format!("cannot resolve peer {peer}")))?;
    let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(read_timeout))?;
    stream.set_write_timeout(Some(CONNECT_TIMEOUT))?;
    stream.write_all(payload)?;
    let mut buf = Vec::new();
    stream.take(MAX_RESPONSE).read_to_end(&mut buf)?;
    Ok(buf)
}

fn request_text(peer: &str, query: &str) -> Option<String> {
    let bytes = request(peer, query.as_bytes(), READ_TIMEOUT).ok()?;
    Some(String::from_utf8_lossy(&bytes).trim().to_owned())
}

fn request_json<T: for<'de> Deserialize<'de>>(peer: &str, query: &str) -> Option<T> {
    let bytes = request(peer, query.as_bytes(), READ_TIMEOUT).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn ping(peer: &str) -> bool {
    matches!(request_text(peer, "/ping"), Some(reply) if reply == "pong")
}

pub fn balance(peer: &str, address: &str) -> Option<u64> {
    request_text(peer, &format!("/balance/{address}"))?
        .parse()
        .ok()
}

pub fn next_nonce(peer: &str, address: &str) -> Option<u64> {
    request_text(peer, &format!("/nonce/{address}"))?
        .parse()
        .ok()
}

/// Only the height is used; the node sends more, serde ignores the rest.
#[derive(Debug, Clone, Deserialize)]
pub struct BlockHeader {
    pub index: u64,
}

pub fn headers(peer: &str, from: u64, limit: usize) -> Option<Vec<BlockHeader>> {
    pace_block_request();
    request_json(peer, &format!("/headers?from={from}&limit={limit}"))
}

pub fn blocks(peer: &str, from: u64, limit: usize) -> Option<Vec<Block>> {
    pace_block_request();
    request_json(peer, &format!("/blocks?from={from}&limit={limit}"))
}

// ------------------------------------------------------------- peer store ---

/// Candidate nodes, in the order the wallet prefers them: the local node
/// first, then the configured or compiled seeds, then whatever answered
/// before.
pub struct PeerStore {
    candidates: Vec<String>,
    /// Peers the user or the build configured; never dropped when unreachable.
    configured: Vec<String>,
    online: Vec<String>,
    offline_since: HashMap<String, Instant>,
}

const OFFLINE_GRACE: Duration = Duration::from_secs(180);

impl PeerStore {
    pub fn new(settings: &Settings) -> Self {
        let mut store = Self {
            candidates: Vec::new(),
            configured: Vec::new(),
            online: Vec::new(),
            offline_since: HashMap::new(),
        };
        store.reconfigure(settings);
        store
    }

    /// Rebuild the candidate list after the user edits the network settings.
    pub fn reconfigure(&mut self, settings: &Settings) {
        let mut candidates: Vec<String> = Vec::new();
        let push = |peer: &str, into: &mut Vec<String>| {
            let peer = peer.trim();
            if !peer.is_empty() && !into.iter().any(|p| p == peer) {
                into.push(peer.to_owned());
            }
        };

        push(&settings.local_node, &mut candidates);
        for peer in &settings.bootstrap_peers {
            push(peer, &mut candidates);
        }
        if settings.bootstrap_peers.is_empty() {
            if let Ok(from_env) = std::env::var(BOOTSTRAP_ENV) {
                for peer in from_env.split(',') {
                    push(peer, &mut candidates);
                }
            }
            for peer in BOOTSTRAP_NODES {
                push(peer, &mut candidates);
            }
        }
        self.configured = candidates.clone();
        for peer in load_peer_cache() {
            push(&peer, &mut candidates);
        }

        self.candidates = candidates;
        self.online.retain(|peer| self.candidates.contains(peer));
    }

    pub fn known(&self) -> usize {
        self.candidates.len()
    }

    pub fn online(&self) -> &[String] {
        &self.online
    }

    /// Re-probe every candidate. Peers that have been unreachable for a while
    /// and were only learned from the cache are dropped.
    pub fn refresh(&mut self) {
        let mut online = Vec::new();
        let mut dead = Vec::new();
        for peer in self.candidates.clone() {
            if ping(&peer) {
                self.offline_since.remove(&peer);
                online.push(peer);
            } else {
                let since = self
                    .offline_since
                    .entry(peer.clone())
                    .or_insert_with(Instant::now);
                if since.elapsed() >= OFFLINE_GRACE && !self.configured.contains(&peer) {
                    dead.push(peer);
                }
            }
        }
        if !dead.is_empty() {
            self.candidates.retain(|peer| !dead.contains(peer));
            for peer in dead {
                self.offline_since.remove(&peer);
            }
        }
        self.online = online;
        save_peer_cache(&self.online);
    }
}

fn load_peer_cache() -> Vec<String> {
    fs::read_to_string(storage::peer_cache_path())
        .ok()
        .and_then(|body| serde_json::from_str::<Vec<String>>(&body).ok())
        .unwrap_or_default()
}

fn save_peer_cache(peers: &[String]) {
    storage::ensure_dirs();
    if let Ok(body) = serde_json::to_string_pretty(peers) {
        let _ = fs::write(storage::peer_cache_path(), body);
    }
}

// ---------------------------------------------------------- chain scanning --

/// One transfer touching the wallet, as shown in the activity list.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletTx {
    pub txid: String,
    pub counterparty: String,
    pub amount: u64,
    pub fee: u64,
    pub timestamp: i64,
    pub block_index: u64,
    pub incoming: bool,
    pub coinbase: bool,
}

/// Scan progress, persisted so a restart does not re-read the whole chain.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TxIndex {
    pub address: String,
    /// Index of the next block to read.
    pub scanned_to: u64,
    pub txs: Vec<WalletTx>,
}

impl TxIndex {
    pub fn load(address: &str) -> Self {
        let path = index_path(address);
        let loaded: Option<Self> = fs::read_to_string(path)
            .ok()
            .and_then(|body| serde_json::from_str(&body).ok());
        match loaded {
            Some(index) if index.address == address => index,
            _ => Self {
                address: address.to_owned(),
                ..Self::default()
            },
        }
    }

    pub fn save(&self) {
        storage::ensure_dirs();
        if let Ok(body) = serde_json::to_string(self) {
            let _ = fs::write(index_path(&self.address), body);
        }
    }

    /// A chain reorg can orphan blocks the wallet already indexed. Dropping
    /// everything from the fork point is cheap because the scan resumes from
    /// there.
    pub fn rewind_to(&mut self, height: u64) {
        self.scanned_to = self.scanned_to.min(height);
        self.txs.retain(|tx| tx.block_index < height);
    }

    fn ingest(&mut self, block: &Block, address: &str) {
        for tx in &block.transactions {
            let from = normalize(&tx.from);
            let to = normalize(&tx.to);
            let outgoing = from == address;
            let incoming = to == address;
            if !outgoing && !incoming {
                continue;
            }
            if self.txs.iter().any(|existing| existing.txid == tx.txid) {
                continue;
            }
            self.txs.push(WalletTx {
                txid: if tx.txid.is_empty() {
                    tx.compute_txid()
                } else {
                    tx.txid.clone()
                },
                counterparty: if outgoing { to.clone() } else { from.clone() },
                amount: tx.amount,
                fee: tx.fee,
                timestamp: tx.timestamp,
                block_index: block.index,
                incoming: incoming && !outgoing,
                coinbase: matches!(tx.kind, TxKind::Coinbase),
            });
        }
    }
}

fn index_path(address: &str) -> std::path::PathBuf {
    let digest = Sha256::digest(address.as_bytes());
    storage::cache_dir().join(format!("tx-index-{}.json", hex::encode(&digest[..8])))
}

/// Addresses reach the wallet either already encoded or as a raw pubkey.
fn normalize(value: &str) -> String {
    if value.is_empty() || value.starts_with("LFS") {
        value.to_owned()
    } else {
        pubkey_to_address(value)
    }
}

/// Walk the header pages upwards to learn the current tip.
pub fn tip_height(peer: &str, known_tip: u64) -> Option<u64> {
    let mut from = known_tip;
    let mut tip = known_tip;
    loop {
        let page = headers(peer, from, HEADER_PAGE)?;
        if page.is_empty() {
            break;
        }
        tip = page.last().map(|h| h.index).unwrap_or(tip);
        if page.len() < HEADER_PAGE {
            break;
        }
        from = tip + 1;
    }
    Some(tip)
}

pub struct ScanStep {
    /// True once the scan has read every block the peer has.
    pub caught_up: bool,
    pub blocks_read: usize,
}

/// Read the next slice of the chain into `index`. Bounded so a refresh tick
/// stays inside the node's block-range rate limit.
pub fn scan_step(peer: &str, index: &mut TxIndex) -> Option<ScanStep> {
    let address = index.address.clone();
    let mut blocks_read = 0;
    for _ in 0..SCAN_PAGES_PER_TICK {
        let page = blocks(peer, index.scanned_to, BLOCK_PAGE)?;
        if page.is_empty() {
            return Some(ScanStep {
                caught_up: true,
                blocks_read,
            });
        }
        for block in &page {
            index.ingest(block, &address);
            index.scanned_to = index.scanned_to.max(block.index + 1);
        }
        blocks_read += page.len();
        if page.len() < BLOCK_PAGE {
            return Some(ScanStep {
                caught_up: true,
                blocks_read,
            });
        }
    }
    Some(ScanStep {
        caught_up: false,
        blocks_read,
    })
}

// ------------------------------------------------------------- broadcasting --

pub fn build_transfer(
    secret_key: &SecretKey,
    to: &str,
    amount: u64,
    nonce: u64,
) -> Result<Transaction, String> {
    let secp = Secp256k1::new();
    let pubkey = PublicKey::from_secret_key(&secp, secret_key);
    let from = pubkey_to_address(&pubkey.to_string());

    let mut tx = Transaction {
        version: TX_VERSION,
        chain_id: CHAIN_ID.to_owned(),
        kind: TxKind::Transfer,
        timestamp: Utc::now().timestamp(),
        from,
        to: to.to_owned(),
        amount,
        fee: DEFAULT_TX_FEE,
        signature: String::new(),
        pubkey: pubkey.to_string(),
        nonce,
        txid: String::new(),
        swap: None,
    };

    let digest = Sha256::digest(tx.signing_preimage(&pubkey.to_string()).as_bytes());
    let signature = secp.sign_ecdsa(Message::from_digest(digest.into()), secret_key);
    tx.signature = hex::encode(signature.serialize_compact());
    tx.txid = tx.compute_txid();
    Ok(tx)
}

pub struct Broadcast {
    pub accepted_by: Vec<String>,
}

fn already_known(reason: &str) -> bool {
    let reason = reason.to_ascii_lowercase();
    reason.contains("transaction already exists") || reason.contains("duplicate transaction")
}

/// Push a signed transaction to `min_peers` reachable nodes.
pub fn broadcast(
    peers: &[String],
    tx: &Transaction,
    min_peers: usize,
) -> Result<Broadcast, String> {
    let required = min_peers.max(1);
    if peers.len() < required {
        return Err(format!(
            "only {} of the {required} required peers are reachable",
            peers.len()
        ));
    }

    let payload =
        serde_json::to_vec(tx).map_err(|e| format!("failed to encode the transaction: {e}"))?;
    let mut shuffled = peers.to_vec();
    shuffled.shuffle(&mut rand::rng());

    let mut accepted = Vec::new();
    let mut last_rejection = None;
    for peer in shuffled {
        if accepted.len() >= required {
            break;
        }
        match request(&peer, &payload, READ_TIMEOUT) {
            Ok(reply) => {
                let reply = String::from_utf8_lossy(&reply).trim().to_owned();
                match reply.strip_prefix("reject: ") {
                    Some(reason) if !already_known(reason) => {
                        last_rejection = Some(format!("{peer} rejected it: {reason}"));
                    }
                    _ => accepted.push(peer),
                }
            }
            Err(_) => continue,
        }
    }

    if accepted.len() < required {
        return Err(last_rejection.unwrap_or_else(|| {
            format!(
                "the transaction reached {} of the {required} required peers",
                accepted.len()
            )
        }));
    }

    Ok(Broadcast {
        accepted_by: accepted,
    })
}

/// The nonce a new transaction should carry: the highest any peer knows about.
pub fn best_next_nonce(peers: &[String], address: &str) -> u64 {
    peers
        .iter()
        .filter_map(|peer| next_nonce(peer, address))
        .max()
        .unwrap_or(0)
}

/// Shown on the receive screen so users can tell which derivation produced the
/// address they are looking at.
pub const DERIVATION_PATH: &str = DEFAULT_DERIVATION_PATH;
