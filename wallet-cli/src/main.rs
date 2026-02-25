mod gpu;
mod opencl;
mod vanity;

use blockchain_core::{
    Block, CHAIN_ID, Transaction, TxKind, pubkey_to_address,
    wallet_keystore::{
        DEFAULT_DERIVATION_PATH, decrypt_secret_key, derive_secret_key_from_mnemonic,
        encrypt_secret_key, generate_mnemonic_12, load_keystore_file, payload_secret_key_bytes,
        save_keystore_file,
    },
};
use chrono::Utc;
use rand::seq::IndexedRandom;
use rustyline::{DefaultEditor, error::ReadlineError};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature};
use serde_json;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::gpu::{
    GpuPipelineProbeConfig, GpuVanityJobPipelineConfig, GpuVanityProbeConfig,
    gpu_hash_pubkey_batch, gpu_pipeline_test, gpu_smoke_test, gpu_vanity_job_pipeline_test,
    gpu_vanity_probe, print_gpu_info,
};
use crate::opencl::print_opencl_info;
use crate::vanity::{
    VanityComputeMode, VanitySearchBackend, VanitySearchRequest, address_matches_vanity,
    default_cpu_workers, parse_vanity_args, run_vanity_search,
};

static BOOTSTRAP_NODES: &[&str] = &["89.168.107.239:6000", "79.76.116.108:6000"];

const MEMPOOL_FILE: &str = "wallet_mempool.json";
const RAW_SIGNED_FILE: &str = "wallet_raw_signed.json";
const WALLET_CACHE_DIR: &str = "wallet-cache";
const PEER_CACHE_FILE: &str = "wallet-cache/peers_cache.json";
const CONNECT_TIMEOUT: Duration = Duration::from_millis(800);
const OFFLINE_GRACE: Duration = Duration::from_secs(10);
const MIN_BROADCAST_PEERS: usize = 2;
const WHOAMI_TIMEOUT: Duration = Duration::from_millis(800);
const DEFAULT_TX_FEE: u64 = 1;
const DEFAULT_VANITY_MAX_ATTEMPTS: u64 = 500_000_000;

// ---------- Default wallet ----------
const LEGACY_WALLET: &str = ".default_wallet";
const ENCRYPTED_WALLET: &str = ".default_wallet.keystore.json";
const WALLET_PASSPHRASE_ENV: &str = "LOFSWAP_WALLET_PASSPHRASE";
const WALLET_MNEMONIC_ENV: &str = "LOFSWAP_WALLET_MNEMONIC_PASSPHRASE";
const PRIVATE_EXPORT_CONFIRM_ENV: &str = "LOFSWAP_ALLOW_PRIVATE_KEY_EXPORT";
const PRIVATE_EXPORT_CONFIRM_VALUE: &str = "YES_I_UNDERSTAND";

static CACHED_WALLET_PASSPHRASE: OnceLock<String> = OnceLock::new();

fn read_line_prompt(prompt: &str) -> Option<String> {
    print!("{prompt}");
    let _ = io::stdout().flush();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok()?;
    let trimmed = input.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn wallet_passphrase() -> Option<String> {
    if let Ok(value) = env::var(WALLET_PASSPHRASE_ENV) {
        let value = value.trim().to_string();
        if !value.is_empty() {
            return Some(value);
        }
    }
    if let Some(cached) = CACHED_WALLET_PASSPHRASE.get() {
        return Some(cached.clone());
    }
    let entered = rpassword::prompt_password("Wallet passphrase: ").ok()?;
    let entered = entered.trim().to_string();
    if entered.is_empty() {
        return None;
    }
    let _ = CACHED_WALLET_PASSPHRASE.set(entered.clone());
    Some(entered)
}

fn mnemonic_passphrase() -> String {
    env::var(WALLET_MNEMONIC_ENV)
        .ok()
        .map(|v| v.trim().to_string())
        .unwrap_or_default()
}

fn save_default_wallet_with_mnemonic(sk: &SecretKey, mnemonic: Option<&str>) -> Result<(), String> {
    let Some(passphrase) = wallet_passphrase() else {
        return Err("wallet passphrase is required".to_string());
    };
    let bytes = sk.secret_bytes();
    let keystore =
        encrypt_secret_key(&bytes, mnemonic, Some(DEFAULT_DERIVATION_PATH), &passphrase)?;
    save_keystore_file(Path::new(ENCRYPTED_WALLET), &keystore)?;
    let _ = fs::remove_file(LEGACY_WALLET);
    Ok(())
}

fn migrate_legacy_wallet(passphrase: &str) -> Option<SecretKey> {
    let legacy_key = fs::read_to_string(LEGACY_WALLET)
        .ok()
        .and_then(|h| hex::decode(h.trim()).ok())
        .and_then(|b| {
            if b.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                SecretKey::from_byte_array(arr).ok()
            } else {
                None
            }
        })?;
    let bytes = legacy_key.secret_bytes();
    let keystore =
        encrypt_secret_key(&bytes, None, Some(DEFAULT_DERIVATION_PATH), passphrase).ok()?;
    if save_keystore_file(Path::new(ENCRYPTED_WALLET), &keystore).is_ok() {
        let _ = fs::remove_file(LEGACY_WALLET);
    }
    Some(legacy_key)
}

fn load_default_wallet() -> Option<SecretKey> {
    if Path::new(ENCRYPTED_WALLET).exists() {
        let passphrase = wallet_passphrase()?;
        let keystore = load_keystore_file(Path::new(ENCRYPTED_WALLET)).ok()?;
        let payload = decrypt_secret_key(&keystore, &passphrase).ok()?;
        let bytes = payload_secret_key_bytes(&payload).ok()?;
        return SecretKey::from_byte_array(bytes).ok();
    }
    if Path::new(LEGACY_WALLET).exists() {
        let passphrase = wallet_passphrase()?;
        return migrate_legacy_wallet(&passphrase);
    }
    None
}

fn default_address() -> Option<String> {
    load_default_wallet().map(|sk| {
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        pubkey_to_address(&pk.to_string())
    })
}

fn vanity_max_attempts() -> u64 {
    env::var("LOFSWAP_VANITY_MAX_ATTEMPTS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_VANITY_MAX_ATTEMPTS)
}

// ---------- Peers ----------
fn ensure_cache_dir() {
    let _ = fs::create_dir_all(WALLET_CACHE_DIR);
}

fn peer_cache_path() -> PathBuf {
    PathBuf::from(PEER_CACHE_FILE)
}

fn is_valid_peer(p: &str) -> bool {
    p.parse::<SocketAddr>().is_ok()
}

struct PeerStore {
    peers: Vec<String>,
    offline_since: std::collections::HashMap<String, Instant>,
}

impl PeerStore {
    fn load() -> Self {
        ensure_cache_dir();
        let mut peers: Vec<String> = BOOTSTRAP_NODES.iter().map(|s| s.to_string()).collect();
        // Always include a local node endpoint so wallet can talk to a node on the same host/IP.
        // Nodes themselves may skip same-IP peers; wallet should not.
        let local_port = env::var("WALLET_LOCAL_PORT")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(6000);
        let local_env = env::var("WALLET_LOCAL_NODE").ok();
        let local_candidates = [
            local_env.unwrap_or_else(|| format!("127.0.0.1:{local_port}")),
            format!("localhost:{local_port}"),
        ];
        for p in local_candidates {
            if is_valid_peer(&p) && !peers.contains(&p) {
                peers.push(p);
            }
        }
        if let Ok(txt) = fs::read_to_string(peer_cache_path()) {
            if let Ok(v) = serde_json::from_str::<Vec<String>>(&txt) {
                for p in v {
                    if is_valid_peer(&p) && !peers.contains(&p) {
                        peers.push(p);
                    }
                }
            }
        }
        PeerStore {
            peers,
            offline_since: std::collections::HashMap::new(),
        }
    }

    fn save(&self) {
        ensure_cache_dir();
        let _ = fs::write(
            peer_cache_path(),
            serde_json::to_string_pretty(&self.peers).unwrap_or_default(),
        );
    }

    fn as_slice(&self) -> &[String] {
        &self.peers
    }

    fn add_many(&mut self, list: &[String]) {
        for p in list {
            if is_valid_peer(p) && !self.peers.contains(p) {
                self.peers.push(p.clone());
            }
        }
    }

    fn discover(&mut self) {
        let candidates: Vec<String> = self
            .peers
            .iter()
            .cloned()
            .chain(BOOTSTRAP_NODES.iter().map(|s| s.to_string()))
            .collect();

        for peer in candidates {
            let Ok(sock) = peer.parse::<SocketAddr>() else {
                continue;
            };
            if let Ok(mut stream) = TcpStream::connect_timeout(&sock, CONNECT_TIMEOUT) {
                let _ = stream.set_read_timeout(Some(CONNECT_TIMEOUT));
                let _ = stream.set_write_timeout(Some(CONNECT_TIMEOUT));
                let _ = stream.write_all(b"/peers");
                let mut buf = Vec::new();
                if stream.read_to_end(&mut buf).is_ok() {
                    if let Ok(v) = serde_json::from_slice::<Vec<String>>(&buf) {
                        let filtered: Vec<String> =
                            v.into_iter().filter(|p| is_valid_peer(p)).collect();
                        self.add_many(&filtered);
                    }
                }
            }
        }
    }

    fn refresh_online(&mut self) -> Vec<String> {
        let mut online = Vec::new();
        let mut to_remove = Vec::new();
        let peers = self.peers.clone();
        for peer in peers {
            if probe_peer(&peer) {
                online.push(peer.clone());
                self.offline_since.remove(&peer);
            } else {
                let since = self
                    .offline_since
                    .entry(peer.clone())
                    .or_insert_with(Instant::now);
                if since.elapsed() >= OFFLINE_GRACE {
                    to_remove.push(peer.clone());
                }
            }
        }
        if !to_remove.is_empty() {
            self.peers.retain(|p| !to_remove.contains(p));
            for p in to_remove {
                self.offline_since.remove(&p);
            }
        }
        online
    }

    fn online_peers(&mut self) -> Vec<String> {
        self.discover();
        dedupe_peers_by_node_identity(self.refresh_online())
    }
}

#[allow(dead_code)]
fn connect_and_send(addr: &str, data: &[u8]) -> io::Result<()> {
    let sock: SocketAddr = addr.parse().map_err(|_| io::Error::other("bad addr"))?;
    let mut s = TcpStream::connect_timeout(&sock, CONNECT_TIMEOUT)?;
    s.write_all(data)?;
    Ok(())
}

fn send_tx_and_get_reply(addr: &str, data: &[u8]) -> io::Result<Option<String>> {
    let sock: SocketAddr = addr.parse().map_err(|_| io::Error::other("bad addr"))?;
    let mut s = TcpStream::connect_timeout(&sock, CONNECT_TIMEOUT)?;
    let _ = s.set_read_timeout(Some(Duration::from_millis(1200)));
    let _ = s.set_write_timeout(Some(CONNECT_TIMEOUT));
    s.write_all(data)?;
    let mut buf = Vec::new();
    match s.read_to_end(&mut buf) {
        Ok(_) => {
            if buf.is_empty() {
                Ok(None)
            } else {
                Ok(Some(String::from_utf8_lossy(&buf).trim().to_string()))
            }
        }
        Err(e) => Err(e),
    }
}

fn probe_peer(addr: &str) -> bool {
    let Ok(sock) = addr.parse::<SocketAddr>() else {
        return false;
    };
    TcpStream::connect_timeout(&sock, CONNECT_TIMEOUT).is_ok()
}

fn peer_is_loopback(addr: &str) -> bool {
    addr.parse::<SocketAddr>()
        .map(|sock| sock.ip().is_loopback())
        .unwrap_or(false)
}

enum PeerIdentity {
    SameChain(String),
    DifferentChain,
    Unknown,
}

fn peer_identity(addr: &str) -> PeerIdentity {
    let Ok(sock) = addr.parse::<SocketAddr>() else {
        return PeerIdentity::Unknown;
    };
    let Ok(mut s) = TcpStream::connect_timeout(&sock, WHOAMI_TIMEOUT) else {
        return PeerIdentity::Unknown;
    };
    let _ = s.set_read_timeout(Some(WHOAMI_TIMEOUT));
    if s.write_all(b"/whoami").is_err() {
        return PeerIdentity::Unknown;
    }
    let mut buf = Vec::new();
    if s.read_to_end(&mut buf).is_err() {
        return PeerIdentity::Unknown;
    }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&buf) else {
        return PeerIdentity::Unknown;
    };
    let Some(chain_id) = v.get("chain_id").and_then(|id| id.as_str()) else {
        return PeerIdentity::Unknown;
    };
    if chain_id != CHAIN_ID {
        return PeerIdentity::DifferentChain;
    }
    let Some(node_id) = v.get("node_id").and_then(|id| id.as_str()) else {
        return PeerIdentity::Unknown;
    };
    PeerIdentity::SameChain(node_id.to_string())
}

fn dedupe_peers_by_node_identity(peers: Vec<String>) -> Vec<String> {
    let mut deduped: Vec<String> = Vec::new();
    let mut node_to_index: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    for peer in peers {
        match peer_identity(&peer) {
            PeerIdentity::SameChain(node_id) => {
                if let Some(&existing_idx) = node_to_index.get(&node_id) {
                    let existing = &deduped[existing_idx];
                    if peer_is_loopback(&peer) && !peer_is_loopback(existing) {
                        deduped[existing_idx] = peer;
                    }
                    continue;
                }
                node_to_index.insert(node_id, deduped.len());
                deduped.push(peer);
            }
            PeerIdentity::DifferentChain => {
                continue;
            }
            PeerIdentity::Unknown => {
                if !deduped.contains(&peer) {
                    deduped.push(peer);
                }
            }
        }
    }

    deduped
}

fn is_already_known_reject(reason: &str) -> bool {
    let normalized = reason.to_ascii_lowercase();
    normalized.contains("transaction already exists")
        || normalized.contains("duplicate transaction")
}

fn normalize_tx_addr(addr: &str) -> String {
    if addr.is_empty() {
        String::new()
    } else if addr.starts_with("LFS") {
        addr.to_string()
    } else {
        pubkey_to_address(addr)
    }
}

fn append_pending(json: &[u8]) {
    let line = String::from_utf8_lossy(json);
    let _ = OpenOptions::new()
        .append(true)
        .create(true)
        .open(MEMPOOL_FILE)
        .and_then(|mut f| writeln!(f, "{}", line));
}

fn load_pending_transactions() -> Vec<Transaction> {
    let Ok(content) = fs::read_to_string(MEMPOOL_FILE) else {
        return Vec::new();
    };
    serde_json::Deserializer::from_str(&content)
        .into_iter::<Transaction>()
        .filter_map(Result::ok)
        .collect()
}

fn save_pending_transactions(list: &[Transaction]) {
    let body: Vec<String> = list
        .iter()
        .filter_map(|tx| serde_json::to_string(tx).ok())
        .collect();
    let _ = fs::write(MEMPOOL_FILE, body.join("\n"));
}

// ---------- Raw signed (not yet broadcast) ----------
fn append_raw_signed(tx: &Transaction) {
    let _ = OpenOptions::new()
        .append(true)
        .create(true)
        .open(RAW_SIGNED_FILE)
        .and_then(|mut f| writeln!(f, "{}", serde_json::to_string(tx).unwrap_or_default()));
}

fn load_raw_signed() -> Vec<Transaction> {
    let Ok(content) = fs::read_to_string(RAW_SIGNED_FILE) else {
        return Vec::new();
    };
    serde_json::Deserializer::from_str(&content)
        .into_iter::<Transaction>()
        .filter_map(Result::ok)
        .collect()
}

fn save_raw_signed(list: &[Transaction]) {
    let body: Vec<String> = list
        .iter()
        .filter_map(|tx| serde_json::to_string(tx).ok())
        .collect();
    let _ = fs::write(RAW_SIGNED_FILE, body.join("\n"));
}

fn broadcast(store: &mut PeerStore, json: &[u8], min_peers: usize) {
    let required = min_peers.max(MIN_BROADCAST_PEERS);
    let peers = store.online_peers();
    if peers.is_empty() {
        println!("No reachable peers; transaction saved to local mempool");
        append_pending(json);
        wait_and_retry_pending(store, required);
        return;
    }
    if peers.len() < required {
        println!("Fewer than {required} peers online; transaction saved to local mempool");
        append_pending(json);
        wait_and_retry_pending(store, required);
        return;
    }
    let mut rng = rand::rng();
    let selected: Vec<String> = peers.sample(&mut rng, required).cloned().collect();
    let mut ok = 0;
    let mut rejected_reason: Option<String> = None;
    for p in &selected {
        match send_tx_and_get_reply(p, json) {
            Ok(Some(reply)) => {
                if let Some(reason) = reply.strip_prefix("reject: ") {
                    if is_already_known_reject(reason) {
                        println!("Sent to {}", p);
                        ok += 1;
                    } else {
                        println!("TX rejected by {}: {}", p, reason);
                        rejected_reason = Some(reason.to_string());
                    }
                } else {
                    println!("Sent to {}", p);
                    ok += 1;
                }
            }
            Ok(None) => {
                println!("Sent to {}", p);
                ok += 1;
            }
            Err(_) => println!("Failed to connect to {}", p),
        }
    }
    if let Some(reason) = rejected_reason {
        println!("TX rejected: {}", reason);
        return;
    }
    if ok < required {
        println!("Sent to {ok}/{required} peers; transaction saved to local mempool");
        append_pending(json);
        wait_and_retry_pending(store, required);
    } else {
        // If sent successfully, try to broadcast any pending transactions
        try_broadcast_pending(store, required);
    }
}

// ---------- Transakcje ----------
fn fetch_next_nonce_from_peers(store: &mut PeerStore, from_addr: &str) -> Option<u64> {
    if cfg!(test) {
        return None;
    }
    store.discover();
    let query = format!("/nonce/{}", from_addr);
    let mut best: Option<u64> = None;
    for p in store.as_slice() {
        let Ok(sock) = p.parse::<SocketAddr>() else {
            continue;
        };
        if let Ok(mut s) = TcpStream::connect_timeout(&sock, CONNECT_TIMEOUT) {
            let _ = s.set_read_timeout(Some(CONNECT_TIMEOUT));
            let _ = s.set_write_timeout(Some(CONNECT_TIMEOUT));
            if s.write_all(query.as_bytes()).is_ok() {
                let mut buf = String::new();
                if s.read_to_string(&mut buf).is_ok() {
                    if let Ok(nonce) = buf.trim().parse::<u64>() {
                        best = Some(best.map_or(nonce, |b| b.max(nonce)));
                    }
                }
            }
        }
    }
    best
}

fn next_nonce_fallback_from_local(from_addr: &str) -> u64 {
    let mut next = 0u64;
    let mut nonces = std::collections::HashSet::new();
    for tx in load_pending_transactions() {
        if normalize_tx_addr(&tx.from) == from_addr {
            nonces.insert(tx.nonce);
        }
    }
    while nonces.contains(&next) {
        next = next.saturating_add(1);
    }
    next
}

fn build_tx(store: &mut PeerStore, sk: &SecretKey, to: &str, amount: u64) -> Transaction {
    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, sk);
    // Use UTC seconds (consistent with blocks and faucet)
    let ts = Utc::now().timestamp();
    let from_addr = pubkey_to_address(&pk.to_string());
    let nonce = fetch_next_nonce_from_peers(store, &from_addr)
        .unwrap_or_else(|| next_nonce_fallback_from_local(&from_addr));
    let preimage = format!(
        "{}|{}|{:?}|{}|{}|{}|{}|{}|{}",
        3,
        CHAIN_ID,
        TxKind::Transfer,
        pk,
        to,
        amount,
        DEFAULT_TX_FEE,
        ts,
        nonce
    );
    let hash = Sha256::digest(preimage.as_bytes());
    let sig = secp.sign_ecdsa(Message::from_digest(hash.into()), sk);
    let mut tx = Transaction {
        version: 3,
        chain_id: CHAIN_ID.to_string(),
        kind: TxKind::Transfer,
        timestamp: ts,
        from: from_addr,
        to: to.into(),
        amount,
        fee: DEFAULT_TX_FEE,
        signature: hex::encode(sig.serialize_compact()),
        pubkey: pk.to_string(),
        nonce,
        txid: String::new(),
    };
    tx.txid = tx.compute_txid();
    tx
}

fn send_default(store: &mut PeerStore, to: &str, amount: u64, min_peers: usize) {
    if let Some(sk) = load_default_wallet() {
        let tx = build_tx(store, &sk, to, amount);
        let payload = serde_json::to_vec(&tx).unwrap();
        broadcast(store, &payload, min_peers.max(MIN_BROADCAST_PEERS));
    } else {
        println!("No default wallet");
    }
}
fn send_priv(store: &mut PeerStore, priv_hex: &str, to: &str, amount: u64, min_peers: usize) {
    if let Ok(sk) = SecretKey::from_byte_array(hex_to_32(priv_hex)) {
        let tx = build_tx(store, &sk, to, amount);
        let payload = serde_json::to_vec(&tx).unwrap();
        broadcast(store, &payload, min_peers.max(MIN_BROADCAST_PEERS));
    } else {
        println!("Invalid private key");
    }
}

fn sign_raw_default(store: &mut PeerStore, to: &str, amount: u64) {
    if let Some(sk) = load_default_wallet() {
        let tx = build_tx(store, &sk, to, amount);
        println!("Signed (not sent):");
        println!("  From : {}", tx.from);
        println!("  To   : {}", tx.to);
        println!("  Amt  : {}", tx.amount);
        println!("  Time : {} (UTC)", tx.timestamp);
        println!("  Nonce: {}", tx.nonce);
        println!("  TxID : {}", tx.txid);
        println!("  Sig  : {}", tx.signature);
        append_raw_signed(&tx);
        println!(
            "Saved to raw-signed list. Use `send-raw {}` to broadcast.",
            tx.signature
        );
    } else {
        println!("No default wallet");
    }
}

fn sign_raw_priv(store: &mut PeerStore, priv_hex: &str, to: &str, amount: u64) {
    if let Ok(sk) = SecretKey::from_byte_array(hex_to_32(priv_hex)) {
        let tx = build_tx(store, &sk, to, amount);
        println!("Signed (not sent):");
        println!("  From : {}", tx.from);
        println!("  To   : {}", tx.to);
        println!("  Amt  : {}", tx.amount);
        println!("  Time : {} (UTC)", tx.timestamp);
        println!("  Nonce: {}", tx.nonce);
        println!("  TxID : {}", tx.txid);
        println!("  Sig  : {}", tx.signature);
        append_raw_signed(&tx);
        println!(
            "Saved to raw-signed list. Use `send-raw {}` to broadcast.",
            tx.signature
        );
    } else {
        println!("Invalid private key");
    }
}

// ---------- Saldo ----------
fn balance(store: &mut PeerStore, addr: &str) {
    store.discover();
    let query = format!("/balance/{}", addr);
    for p in store.as_slice() {
        let Ok(sock) = p.parse::<SocketAddr>() else {
            continue;
        };
        if let Ok(mut s) = TcpStream::connect_timeout(&sock, CONNECT_TIMEOUT) {
            let _ = s.set_read_timeout(Some(CONNECT_TIMEOUT));
            let _ = s.set_write_timeout(Some(CONNECT_TIMEOUT));
            if s.write_all(query.as_bytes()).is_ok() {
                let mut buf = String::new();
                if s.read_to_string(&mut buf).is_ok() {
                    println!("Balance {}: {}", addr, buf.trim());
                    return;
                }
            }
        }
    }
    println!("No response from peers");
}

fn fetch_chain(store: &mut PeerStore) -> Option<Vec<Block>> {
    store.discover();
    for p in store.as_slice() {
        let Ok(sock) = p.parse::<SocketAddr>() else {
            continue;
        };
        if let Ok(mut s) = TcpStream::connect_timeout(&sock, CONNECT_TIMEOUT) {
            if s.write_all(b"/chain").is_ok() {
                let mut buf = Vec::new();
                if s.read_to_end(&mut buf).is_ok() {
                    if let Ok(chain) = serde_json::from_slice::<Vec<Block>>(&buf) {
                        return Some(chain);
                    }
                }
            }
        }
    }
    None
}

fn print_history(store: &mut PeerStore, addr: &str) {
    let Some(chain) = fetch_chain(store) else {
        println!("Could not load chain from peers");
        return;
    };
    let target = normalize_tx_addr(addr);
    let mut txs = Vec::new();
    for block in &chain {
        for tx in &block.transactions {
            let from_addr = normalize_tx_addr(&tx.from);
            let to_addr = normalize_tx_addr(&tx.to);
            if from_addr == target || to_addr == target {
                txs.push((block.index, tx.clone()));
            }
        }
    }
    if txs.is_empty() {
        println!("No transactions found for {}", addr);
        return;
    }
    for (index, tx) in txs {
        let direction = if normalize_tx_addr(&tx.from) == target {
            "OUT"
        } else {
            "IN "
        };
        println!(
            "[{}] #{index} {} -> {} amount: {} txid: {}",
            direction, tx.from, tx.to, tx.amount, tx.txid
        );
    }
}

fn print_tx_details(tx: &Transaction, location: Option<String>) {
    println!("Transaction details:");
    if let Some(loc) = location {
        println!("  Location : {}", loc);
    }
    println!("  From     : {}", tx.from);
    println!("  To       : {}", tx.to);
    println!("  Amount   : {}", tx.amount);
    println!("  Nonce    : {}", tx.nonce);
    println!("  Timestamp: {}", tx.timestamp);
    println!("  TXID     : {}", tx.txid);
    println!("  Signature: {}", tx.signature);
}

fn tx_info(store: &mut PeerStore, id: &str) {
    if let Some(chain) = fetch_chain(store) {
        for block in &chain {
            for tx in &block.transactions {
                if tx.txid == id || tx.signature.eq_ignore_ascii_case(id) {
                    let loc = format!("block height {}", block.index);
                    print_tx_details(tx, Some(loc));
                    return;
                }
            }
        }
    }
    let pending = load_pending_transactions();
    if let Some(tx) = pending
        .iter()
        .find(|tx| tx.txid == id || tx.signature.eq_ignore_ascii_case(id))
    {
        print_tx_details(tx, Some("pending (local mempool)".into()));
        return;
    }
    println!("Transaction not found on chain or in local mempool");
}

// ---------- Faucet ----------
fn faucet(store: &mut PeerStore, addr: &str) {
    let _ = store;
    let _ = addr;
    println!("Faucet is disabled in hard-fork v2.");
    println!("Emission exists only via coinbase in mined blocks.");
}

// ---------- Import / export ----------
fn import_dat(path: &str) {
    let mut buf = [0u8; 32];
    if File::open(path)
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok()
    {
        if let Ok(sk) = SecretKey::from_byte_array(buf) {
            let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
            if let Err(e) = save_default_wallet_with_mnemonic(&sk, None) {
                println!("Failed to save imported wallet: {}", e);
                return;
            }
            println!("Imported file. Public Key: {}", pk);
            return;
        }
    }
    println!("Import failed");
}
fn export_dat(path: &str) {
    if let Some(sk) = load_default_wallet() {
        if fs::write(path, sk.secret_bytes()).is_ok() {
            println!("Saved to {}", path);
        } else {
            println!("Write error");
        }
    } else {
        println!("No default wallet");
    }
}

// ---------- CLI ----------
fn help() {
    println!(
        "Commands:\n  help\n  create-wallet [startswith <prefix>] [endswith <suffix>] [cpu [workers]|gpu [workers]|opencl [workers]]\n                              (prefix/suffix applies after LFS; omitted workers auto-selects a system default)\n  gpu-info                    (list detected GPU adapters/backends via wgpu)\n  opencl-info                 (list detected OpenCL devices; OpenCL backend is feature-gated)\n  gpu-test [adapter_index]    (run a small compute shader smoke test)\n  gpu-pubkey-hash-test [adapter_index] [count]\n                              (GPU SHA-256 over compressed pubkey hex strings with CPU verification)\n  gpu-pipeline-test [adapter_index] [chunks] [workgroups]\n                              (chunked compute dispatch test for future GPU vanity pipeline)\n  gpu-vanity-probe [adapter_index] [chunks] [workgroups] [prefix|-] [suffix|-]\n                              (vanity-like GPU probe: params+pattern buffers+hit counters; no real crypto yet)\n  gpu-vanity-job-test [adapter_index] [chunks] [workgroups] [prefix|-] [suffix|-] [max_hits] [stop_after_hits]\n                              (work-item + hit-buffer + stop-flag GPU pipeline test, closer to final vanity backend)\n  recover-mnemonic <seed words...>\n  import-priv <hex>\n  import-dat <file>\n  export-dat <file>\n  export-priv               (requires strong confirmation)\n  default-wallet\n  send <to?> <amount> [n=2]   (defaults to your address)\n  send-priv <priv> <to> <amount> [n=2]\n  sign-raw <to> <amount>      (sign only; save locally)\n  sign-raw-priv <priv> <to> <amount>\n  send-raw <sig|txid> [n=2]   (broadcast a stored raw tx)\n  raw_tx                      (list stored raw-signed txs)\n  force-send <signature>     (resend a pending tx even if only one peer is reachable)\n  balance [address]          (defaults to your address)\n  faucet [address]           (disabled in v2; coinbase-only emission)\n  tx-history [address]       (defaults to your address)\n  tx-info <txid|signature>\n  list-peers\n  print-mempool\n  exit"
    );
}

fn deterministic_pubkey_batch_for_gpu_hash_test(count: usize) -> Vec<String> {
    let target = count.clamp(1, 4096);
    let secp = Secp256k1::new();
    let mut out = Vec::with_capacity(target);
    let mut counter = 1u64;
    while out.len() < target {
        let mut hasher = Sha256::new();
        hasher.update(b"lofswap-gpu-pubkey-hash-test");
        hasher.update(counter.to_le_bytes());
        let digest = hasher.finalize();
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&digest);
        counter = counter.wrapping_add(1);

        let Ok(sk) = SecretKey::from_byte_array(sk_bytes) else {
            continue;
        };
        let pk = PublicKey::from_secret_key(&secp, &sk).to_string();
        if pk.is_ascii() {
            out.push(pk);
        }
    }
    out
}

// Create a new wallet and set it as default
fn create_wallet(
    starts_with: Option<&str>,
    ends_with: Option<&str>,
    mode: VanityComputeMode,
    workers: Option<usize>,
) {
    let tries_limit = vanity_max_attempts();
    let mnemonic_pwd = mnemonic_passphrase();
    let vanity_enabled = starts_with.is_some() || ends_with.is_some();
    if vanity_enabled {
        let requested_workers = workers.unwrap_or_else(default_cpu_workers).max(1);
        let backend = VanitySearchBackend::prepare(mode, requested_workers);
        let request = VanitySearchRequest {
            starts_with: starts_with.map(str::to_string),
            ends_with: ends_with.map(str::to_string),
            tries_limit,
            mnemonic_pwd,
            cpu_workers: requested_workers,
        };
        println!(
            "Generating vanity wallet (startswith={:?}, endswith={:?}, mode={}, workers={}, max_attempts={})",
            request.starts_with.as_deref(),
            request.ends_with.as_deref(),
            backend.mode_label(),
            request.cpu_workers,
            tries_limit
        );
        backend.print_preflight();

        match run_vanity_search(&request, &backend) {
            Ok(Some(found)) => {
                if let Err(e) = save_default_wallet_with_mnemonic(&found.sk, Some(&found.mnemonic))
                {
                    println!("Failed to save wallet: {}", e);
                    return;
                }
                println!("Created new encrypted wallet.");
                println!("Vanity matched after {} attempts.", found.attempts);
                println!("Public : {}", found.public_key);
                println!("Address: {}", found.address);
                println!("Recovery phrase (store offline, never share):");
                println!("  {}", found.mnemonic);
                println!("Derivation path: {}", DEFAULT_DERIVATION_PATH);
                return;
            }
            Ok(None) => {
                println!(
                    "Vanity pattern not found in {} attempts. Try shorter prefix/suffix or increase LOFSWAP_VANITY_MAX_ATTEMPTS.",
                    tries_limit
                );
                return;
            }
            Err(e) => {
                println!("Vanity search failed: {}", e);
                return;
            }
        }
    }

    if workers.is_some() || mode != VanityComputeMode::Cpu {
        println!(
            "Note: compute mode/worker count options are used only for vanity search (startswith/endswith)."
        );
    }

    for attempt in 1..=tries_limit {
        let mnemonic = match generate_mnemonic_12() {
            Ok(m) => m,
            Err(e) => {
                println!("Failed to generate mnemonic: {}", e);
                return;
            }
        };
        let derived = match derive_secret_key_from_mnemonic(
            &mnemonic,
            &mnemonic_pwd,
            DEFAULT_DERIVATION_PATH,
        ) {
            Ok(v) => v,
            Err(e) => {
                println!("Failed to derive key from mnemonic: {}", e);
                return;
            }
        };
        let Ok(sk) = SecretKey::from_byte_array(derived) else {
            continue;
        };
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let address = pubkey_to_address(&pk.to_string());

        if !address_matches_vanity(&address, starts_with, ends_with) {
            continue;
        }

        if let Err(e) = save_default_wallet_with_mnemonic(&sk, Some(&mnemonic)) {
            println!("Failed to save wallet: {}", e);
            return;
        }
        println!("Created new encrypted wallet.");
        if vanity_enabled {
            println!("Vanity matched after {} attempts.", attempt);
        }
        println!("Public : {}", pk);
        println!("Address: {}", address);
        println!("Recovery phrase (store offline, never share):");
        println!("  {}", mnemonic);
        println!("Derivation path: {}", DEFAULT_DERIVATION_PATH);
        return;
    }

    if !vanity_enabled {
        println!("Failed to create wallet");
    }
}

fn recover_wallet_from_mnemonic(words: &str) {
    let phrase = words.trim();
    if phrase.is_empty() {
        println!("Recovery phrase is required");
        return;
    }
    let derived = match derive_secret_key_from_mnemonic(
        phrase,
        &mnemonic_passphrase(),
        DEFAULT_DERIVATION_PATH,
    ) {
        Ok(v) => v,
        Err(e) => {
            println!("Invalid recovery phrase: {}", e);
            return;
        }
    };
    let Ok(sk) = SecretKey::from_byte_array(derived) else {
        println!("Derived key is invalid for secp256k1");
        return;
    };
    if let Err(e) = save_default_wallet_with_mnemonic(&sk, Some(phrase)) {
        println!("Failed to save recovered wallet: {}", e);
        return;
    }
    let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
    println!("Recovered wallet.");
    println!("Public : {}", pk);
    println!("Address: {}", pubkey_to_address(&pk.to_string()));
}

// Import a private key and set it as default
fn import_priv(priv_hex: &str) {
    match hex::decode(priv_hex) {
        Ok(bytes) => match SecretKey::from_byte_array(hex_to_32_bytes(bytes)) {
            Ok(sk) => {
                let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
                if let Err(e) = save_default_wallet_with_mnemonic(&sk, None) {
                    println!("Failed to save wallet: {}", e);
                    return;
                }
                println!("Imported private key. Public Key: {}", pk);
                println!("Address: {}", pubkey_to_address(&pk.to_string()));
            }
            Err(_) => println!("Invalid private key"),
        },
        Err(_) => println!("Invalid hex format"),
    }
}

fn export_private_key() {
    let env_ok = env::var(PRIVATE_EXPORT_CONFIRM_ENV)
        .ok()
        .map(|v| v.trim() == PRIVATE_EXPORT_CONFIRM_VALUE)
        .unwrap_or(false);
    if !env_ok {
        println!(
            "Private key export blocked. Set {}={} to unlock.",
            PRIVATE_EXPORT_CONFIRM_ENV, PRIVATE_EXPORT_CONFIRM_VALUE
        );
        return;
    }
    let Some(typed) = read_line_prompt("Type EXACTLY 'EXPORT PRIVATE KEY' to continue: ") else {
        println!("Cancelled.");
        return;
    };
    if typed != "EXPORT PRIVATE KEY" {
        println!("Cancelled.");
        return;
    }
    if !confirm("Final confirmation? (y/N)") {
        println!("Cancelled.");
        return;
    }
    let Some(sk) = load_default_wallet() else {
        println!("No default wallet");
        return;
    };
    println!("Private: {}", hex::encode(sk.secret_bytes()));
}

fn hex_to_32(priv_hex: &str) -> [u8; 32] {
    match hex::decode(priv_hex) {
        Ok(bytes) => hex_to_32_bytes(bytes),
        Err(_) => [0u8; 32],
    }
}

fn hex_to_32_bytes(bytes: Vec<u8>) -> [u8; 32] {
    let mut out = [0u8; 32];
    if bytes.len() == 32 {
        out.copy_from_slice(&bytes);
    }
    out
}

fn list_peers(store: &mut PeerStore) {
    let online = store.online_peers();
    let peers = store.as_slice();
    println!("Available peers ({}):", peers.len());
    for p in peers {
        let status = if online.contains(p) {
            "online"
        } else {
            "offline"
        };
        println!("- {} ({})", p, status);
    }
    if peers.is_empty() {
        return;
    }
    if online.is_empty() {
        println!("All peers are currently offline");
    }
}

fn wait_and_retry_pending(store: &mut PeerStore, min_peers: usize) {
    if min_peers < 2 {
        return;
    }
    println!(
        "Retrying pending transactions in {}s",
        OFFLINE_GRACE.as_secs()
    );
    std::thread::sleep(OFFLINE_GRACE);
    try_broadcast_pending(store, min_peers);
}

fn pending_should_wait(min_peers: usize, online_count: usize) -> bool {
    online_count < min_peers
}

fn show_mempool() {
    let pending = load_pending_transactions();
    if pending.is_empty() {
        println!("Mempool is empty");
        return;
    }
    for tx in pending {
        println!(
            "TX: {} -> {} amount: {} sig: {}",
            tx.from, tx.to, tx.amount, tx.signature
        );
    }
}

fn show_raw_signed() {
    let list = load_raw_signed();
    if list.is_empty() {
        println!("No raw-signed transactions");
        return;
    }
    for tx in list {
        println!(
            "RAW: {} -> {} amount: {} sig: {} txid: {} ts: {}",
            tx.from, tx.to, tx.amount, tx.signature, tx.txid, tx.timestamp
        );
    }
}

fn try_broadcast_pending(store: &mut PeerStore, min_peers: usize) {
    let mut pending = load_pending_transactions();
    if pending.is_empty() {
        return;
    }
    let required = min_peers.max(MIN_BROADCAST_PEERS);
    let peers = store.online_peers();
    if pending_should_wait(required, peers.len()) {
        return;
    }
    let mut sent = 0;
    pending.retain(|tx| {
        let payload = serde_json::to_vec(tx).unwrap();
        let mut ok = 0;
        let mut rejected = false;
        for p in &peers {
            match send_tx_and_get_reply(p, &payload) {
                Ok(Some(reply)) => {
                    if let Some(reason) = reply.strip_prefix("reject: ") {
                        if is_already_known_reject(reason) {
                            ok += 1;
                        } else {
                            println!("TX rejected by {}: {}", p, reason);
                            rejected = true;
                            break;
                        }
                    } else {
                        ok += 1;
                    }
                }
                Ok(None) => ok += 1,
                Err(_) => {}
            }
            if ok >= required {
                break;
            }
        }
        if rejected {
            false
        } else if ok >= required {
            sent += 1;
            false
        } else {
            true
        }
    });
    if sent > 0 {
        println!("Sent {} pending transactions from mempool", sent);
        save_pending_transactions(&pending);
    }
}

fn confirm(prompt: &str) -> bool {
    print!("{prompt} ");
    let _ = io::stdout().flush();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_ok() {
        matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
    } else {
        false
    }
}

fn tx_signed_by_wallet(tx: &Transaction, sk: &SecretKey) -> bool {
    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, sk);
    let pk_str = pk.to_string();
    let expected_addr = pubkey_to_address(&pk_str);
    if tx.from != expected_addr && tx.from != pk_str {
        return false;
    }
    if !tx.pubkey.is_empty() && tx.pubkey != pk_str {
        return false;
    }
    if tx.pubkey.is_empty() && tx.from.starts_with("LFS") {
        return false;
    }
    let signer = if !tx.pubkey.is_empty() {
        tx.pubkey.as_str()
    } else {
        tx.from.as_str()
    };
    let Ok(sig_bytes) = hex::decode(&tx.signature) else {
        return false;
    };
    let Ok(sig) = Signature::from_compact(&sig_bytes) else {
        return false;
    };
    let chain_id = if tx.chain_id.is_empty() {
        CHAIN_ID
    } else {
        tx.chain_id.as_str()
    };
    if tx.version >= 3 {
        if chain_id != CHAIN_ID {
            return false;
        }
        let v3_preimage = format!(
            "{}|{}|{:?}|{}|{}|{}|{}|{}|{}",
            tx.version, chain_id, tx.kind, signer, tx.to, tx.amount, tx.fee, tx.timestamp, tx.nonce
        );
        let v3_hash = Sha256::digest(v3_preimage.as_bytes());
        return secp
            .verify_ecdsa(Message::from_digest(v3_hash.into()), &sig, &pk)
            .is_ok();
    }
    if tx.version >= 2 {
        let v2_preimage = format!(
            "{}|{}|{}|{}|{}|{}",
            tx.version, signer, tx.to, tx.amount, tx.timestamp, tx.nonce
        );
        let v2_hash = Sha256::digest(v2_preimage.as_bytes());
        return secp
            .verify_ecdsa(Message::from_digest(v2_hash.into()), &sig, &pk)
            .is_ok();
    }
    let v1_preimage = format!(
        "{}|{}|{}|{}|{}",
        tx.version, signer, tx.to, tx.amount, tx.timestamp
    );
    let v1_hash = Sha256::digest(v1_preimage.as_bytes());
    if secp
        .verify_ecdsa(Message::from_digest(v1_hash.into()), &sig, &pk)
        .is_ok()
    {
        return true;
    }
    // Legacy compatibility: older txs signed only (from|to|amount)
    let legacy_preimage = format!("{}{}{}", signer, tx.to, tx.amount);
    let legacy_hash = Sha256::digest(legacy_preimage.as_bytes());
    secp.verify_ecdsa(Message::from_digest(legacy_hash.into()), &sig, &pk)
        .is_ok()
}

fn broadcast_force(store: &mut PeerStore, json: &[u8]) -> (usize, Option<String>) {
    let peers = store.online_peers();
    if peers.is_empty() {
        println!("No known peers");
        return (0, None);
    }
    let mut ok = 0;
    let mut rejected_reason: Option<String> = None;
    for p in &peers {
        match send_tx_and_get_reply(p, json) {
            Ok(Some(reply)) => {
                if let Some(reason) = reply.strip_prefix("reject: ") {
                    if is_already_known_reject(reason) {
                        println!("Sent to {}", p);
                        ok += 1;
                    } else {
                        println!("TX rejected by {}: {}", p, reason);
                        rejected_reason = Some(reason.to_string());
                    }
                } else {
                    ok += 1;
                    println!("Sent to {}", p);
                }
            }
            Ok(None) => {
                ok += 1;
                println!("Sent to {}", p);
            }
            Err(_) => println!("Failed to connect to {}", p),
        }
    }
    (ok, rejected_reason)
}

fn send_raw(store: &mut PeerStore, sig_or_txid: &str, min_peers: usize) {
    let mut list = load_raw_signed();
    if list.is_empty() {
        println!("No raw-signed transactions stored");
        return;
    }
    let Some(idx) = list.iter().position(|tx| {
        tx.signature.eq_ignore_ascii_case(sig_or_txid) || tx.txid.eq_ignore_ascii_case(sig_or_txid)
    }) else {
        println!("No raw transaction with that signature/txid");
        return;
    };
    let tx = list[idx].clone();
    let payload = serde_json::to_vec(&tx).unwrap();
    let peers_online = store.online_peers();
    if peers_online.is_empty() {
        println!("No reachable peers; raw tx kept");
        return;
    }
    let mut rng = rand::rng();
    let selected: Vec<String> = peers_online
        .sample(&mut rng, min_peers.max(1).min(peers_online.len()))
        .cloned()
        .collect();
    let mut ok = 0;
    let mut rejected_reason: Option<String> = None;
    for p in &selected {
        match send_tx_and_get_reply(p, &payload) {
            Ok(Some(reply)) => {
                if let Some(reason) = reply.strip_prefix("reject: ") {
                    if is_already_known_reject(reason) {
                        println!("Sent to {}", p);
                        ok += 1;
                    } else {
                        println!("TX rejected by {}: {}", p, reason);
                        rejected_reason = Some(reason.to_string());
                        break;
                    }
                } else {
                    println!("Sent to {}", p);
                    ok += 1;
                }
            }
            Ok(None) => {
                println!("Sent to {}", p);
                ok += 1;
            }
            Err(_) => println!("Failed to connect to {}", p),
        }
    }
    if let Some(reason) = rejected_reason {
        println!("TX rejected: {}", reason);
        return;
    }
    if ok > 0 {
        println!("Broadcast raw tx to {ok} peer(s)");
        list.remove(idx);
        save_raw_signed(&list);
    } else {
        println!("Broadcast failed; raw tx kept");
    }
}

fn force_send(store: &mut PeerStore, signature: &str) {
    let Some(sk) = load_default_wallet() else {
        println!("No default wallet");
        return;
    };
    let mut pending = load_pending_transactions();
    if pending.is_empty() {
        println!("No pending transactions in local mempool");
        return;
    }
    let Some(idx) = pending
        .iter()
        .position(|tx| tx.signature.eq_ignore_ascii_case(signature))
    else {
        println!("No pending transaction with that signature");
        return;
    };
    let tx = pending[idx].clone();
    if !tx_signed_by_wallet(&tx, &sk) {
        println!("Signature does not match your default wallet; aborting force send");
        return;
    }
    println!(
        "Warning: forcing send may not reach the network.\n  From: {}\n  To  : {}\n  Amount: {}\n  Signature: {}",
        tx.from, tx.to, tx.amount, tx.signature
    );
    if !confirm("Proceed? (y/N)") {
        println!("Cancelled.");
        return;
    }
    let payload = serde_json::to_vec(&tx).unwrap();
    let (sent, rejected_reason) = broadcast_force(store, &payload);
    if let Some(reason) = rejected_reason {
        println!("TX rejected: {}", reason);
        return;
    }
    if sent > 0 {
        println!("Force-sent transaction to {sent} peer(s)");
        pending.remove(idx);
        save_pending_transactions(&pending);
    } else {
        println!("Force send failed; transaction kept locally");
    }
}

fn main() {
    println!("Wallet CLI (bootstrap discovery, cached peers)");
    let mut peers = PeerStore::load();
    peers.discover();

    if io::stdin().is_terminal() && io::stdout().is_terminal() {
        if let Ok(mut editor) = DefaultEditor::new() {
            loop {
                match editor.readline("> ") {
                    Ok(line) => {
                        if line.trim().is_empty() {
                            continue;
                        }
                        let _ = editor.add_history_entry(line.as_str());
                        if !handle_command_line(&mut peers, &line) {
                            break;
                        }
                    }
                    Err(ReadlineError::Interrupted) => {
                        println!("^C");
                        continue;
                    }
                    Err(ReadlineError::Eof) => break,
                    Err(err) => {
                        eprintln!("Interactive input error ({err}); falling back to basic stdin.");
                        break;
                    }
                }
            }
            peers.save();
            return;
        }
    }

    loop {
        print!("> ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        if io::stdin().read_line(&mut line).is_err() {
            continue;
        }
        if !handle_command_line(&mut peers, &line) {
            break;
        }
    }
    peers.save();
}

fn handle_command_line(peers: &mut PeerStore, line: &str) -> bool {
    let a: Vec<&str> = line.trim().split_whitespace().collect();
    if a.is_empty() {
        return true;
    }
    match a[0] {
        "help" => help(),
        "gpu-info" => print_gpu_info(),
        "opencl-info" => print_opencl_info(),
        "gpu-test" => {
            let adapter_index = match a.get(1) {
                None => None,
                Some(raw) => match raw.parse::<usize>() {
                    Ok(idx) => Some(idx),
                    Err(_) => {
                        println!("Usage: gpu-test [adapter_index]");
                        return true;
                    }
                },
            };
            if let Err(e) = gpu_smoke_test(adapter_index) {
                println!("GPU smoke test failed: {}", e);
            }
        }
        "gpu-pubkey-hash-test" => {
            let usage = "Usage: gpu-pubkey-hash-test [adapter_index] [count]";
            let adapter_index = match a.get(1) {
                None => None,
                Some(raw) => match raw.parse::<usize>() {
                    Ok(idx) => Some(idx),
                    Err(_) => {
                        println!("{usage}");
                        return true;
                    }
                },
            };
            let count = match a.get(2) {
                None => 512usize,
                Some(raw) => match raw.parse::<usize>() {
                    Ok(v) if v > 0 => v,
                    _ => {
                        println!("{usage}");
                        return true;
                    }
                },
            };
            let pubkeys = deterministic_pubkey_batch_for_gpu_hash_test(count);
            if pubkeys.is_empty() {
                println!("No deterministic pubkeys generated for test");
                return true;
            }
            match gpu_hash_pubkey_batch(adapter_index, &pubkeys, true) {
                Ok(result) => {
                    let first_prefix = result
                        .digests
                        .first()
                        .map(|d| hex::encode(&d[..8]))
                        .unwrap_or_default();
                    println!(
                        "GPU pubkey SHA-256 summary: count={} verified={} mismatches={} verify={} elapsed={:.3}s rate={:.2} Khash/s first_digest_prefix={}",
                        result.candidate_count,
                        result.verified_digests,
                        result.verification_mismatches,
                        result.verification_performed,
                        result.elapsed.as_secs_f64(),
                        (result.candidate_count as f64 / result.elapsed.as_secs_f64().max(1e-9))
                            / 1_000.0,
                        first_prefix
                    );
                }
                Err(e) => println!("GPU pubkey SHA-256 test failed: {}", e),
            }
        }
        "gpu-pipeline-test" => {
            let adapter_index = match a.get(1) {
                None => None,
                Some(raw) => match raw.parse::<usize>() {
                    Ok(idx) => Some(idx),
                    Err(_) => {
                        println!("Usage: gpu-pipeline-test [adapter_index] [chunks] [workgroups]");
                        return true;
                    }
                },
            };
            let chunks = match a.get(2) {
                None => 8,
                Some(raw) => match raw.parse::<u32>() {
                    Ok(v) => v,
                    Err(_) => {
                        println!("Usage: gpu-pipeline-test [adapter_index] [chunks] [workgroups]");
                        return true;
                    }
                },
            };
            let workgroups_per_chunk = match a.get(3) {
                None => 1024,
                Some(raw) => match raw.parse::<u32>() {
                    Ok(v) => v,
                    Err(_) => {
                        println!("Usage: gpu-pipeline-test [adapter_index] [chunks] [workgroups]");
                        return true;
                    }
                },
            };
            let config = GpuPipelineProbeConfig {
                chunks,
                workgroups_per_chunk,
            };
            match gpu_pipeline_test(adapter_index, config) {
                Ok(result) => {
                    println!(
                        "Pipeline summary: chunks={}, workgroups/chunk={}, wg_size={}, total_invocations={}, elapsed={:.3}s",
                        result.chunks_executed,
                        result.workgroups_per_chunk,
                        result.workgroup_size,
                        result.total_invocations,
                        result.elapsed.as_secs_f64()
                    );
                }
                Err(e) => println!("GPU pipeline test failed: {}", e),
            }
        }
        "gpu-vanity-probe" => {
            let usage = "Usage: gpu-vanity-probe [adapter_index] [chunks] [workgroups] [prefix|-] [suffix|-]";
            let adapter_index = match a.get(1) {
                None => None,
                Some(raw) => match raw.parse::<usize>() {
                    Ok(idx) => Some(idx),
                    Err(_) => {
                        println!("{usage}");
                        return true;
                    }
                },
            };
            let chunks = match a.get(2) {
                None => 2,
                Some(raw) => match raw.parse::<u32>() {
                    Ok(v) => v,
                    Err(_) => {
                        println!("{usage}");
                        return true;
                    }
                },
            };
            let workgroups_per_chunk = match a.get(3) {
                None => 512,
                Some(raw) => match raw.parse::<u32>() {
                    Ok(v) => v,
                    Err(_) => {
                        println!("{usage}");
                        return true;
                    }
                },
            };
            let prefix = match a.get(4).copied() {
                Some("-") | None => None,
                Some(v) => Some(v.to_string()),
            };
            let suffix = match a.get(5).copied() {
                Some("-") | None => None,
                Some(v) => Some(v.to_string()),
            };
            let config = GpuVanityProbeConfig {
                chunks,
                workgroups_per_chunk,
                prefix,
                suffix,
            };
            match gpu_vanity_probe(adapter_index, &config) {
                Ok(result) => println!(
                    "Vanity probe summary: candidates={} prefix_hits={} suffix_hits={} combined_hits={} first_hit={:?} elapsed={:.3}s",
                    result.total_candidates,
                    result.prefix_hits,
                    result.suffix_hits,
                    result.combined_hits,
                    result.first_hit_index,
                    result.elapsed.as_secs_f64()
                ),
                Err(e) => println!("GPU vanity probe failed: {}", e),
            }
        }
        "gpu-vanity-job-test" => {
            let usage = "Usage: gpu-vanity-job-test [adapter_index] [chunks] [workgroups] [prefix|-] [suffix|-] [max_hits] [stop_after_hits]";
            let adapter_index = match a.get(1) {
                None => None,
                Some(raw) => match raw.parse::<usize>() {
                    Ok(idx) => Some(idx),
                    Err(_) => {
                        println!("{usage}");
                        return true;
                    }
                },
            };
            let chunks = match a.get(2) {
                None => 4,
                Some(raw) => match raw.parse::<u32>() {
                    Ok(v) => v,
                    Err(_) => {
                        println!("{usage}");
                        return true;
                    }
                },
            };
            let workgroups_per_chunk = match a.get(3) {
                None => 512,
                Some(raw) => match raw.parse::<u32>() {
                    Ok(v) => v,
                    Err(_) => {
                        println!("{usage}");
                        return true;
                    }
                },
            };
            let prefix = match a.get(4).copied() {
                Some("-") | None => None,
                Some(v) => Some(v.to_string()),
            };
            let suffix = match a.get(5).copied() {
                Some("-") | None => None,
                Some(v) => Some(v.to_string()),
            };
            let max_hits = match a.get(6) {
                None => 16,
                Some(raw) => match raw.parse::<u32>() {
                    Ok(v) => v,
                    Err(_) => {
                        println!("{usage}");
                        return true;
                    }
                },
            };
            let stop_after_hits = match a.get(7) {
                None => 4,
                Some(raw) => match raw.parse::<u32>() {
                    Ok(v) => v,
                    Err(_) => {
                        println!("{usage}");
                        return true;
                    }
                },
            };
            let config = GpuVanityJobPipelineConfig {
                chunks,
                workgroups_per_chunk,
                prefix,
                suffix,
                max_hits,
                stop_after_hits,
            };
            match gpu_vanity_job_pipeline_test(adapter_index, &config) {
                Ok(result) => println!(
                    "Vanity job test summary: attempts={}/{} prefix_hits={} suffix_hits={} combined_hits={} hit_count={} stop_flag={} stored_hits={} verified_hits={} mismatches={} elapsed={:.3}s",
                    result.attempts,
                    result.total_candidates,
                    result.prefix_hits,
                    result.suffix_hits,
                    result.combined_hits,
                    result.hit_count,
                    result.stop_flag_triggered,
                    result.stored_hit_indices.len(),
                    result.verified_stored_hits,
                    result.verification_mismatches,
                    result.elapsed.as_secs_f64()
                ),
                Err(e) => println!("GPU vanity job test failed: {}", e),
            }
        }
        "create-wallet" => match parse_vanity_args(&a[1..]) {
            Ok(opts) => create_wallet(
                opts.starts_with.as_deref(),
                opts.ends_with.as_deref(),
                opts.compute_mode,
                opts.worker_count,
            ),
            Err(e) => println!(
                "{}\nUsage: create-wallet [startswith <prefix>] [endswith <suffix>] [cpu [workers]|gpu [workers]|opencl [workers]]",
                e
            ),
        },
        "recover-mnemonic" if a.len() >= 2 => recover_wallet_from_mnemonic(&a[1..].join(" ")),
        "import-priv" if a.len() == 2 => import_priv(a[1]),
        "import-dat" if a.len() == 2 => import_dat(a[1]),
        "export-dat" if a.len() == 2 => export_dat(a[1]),
        "export-priv" => export_private_key(),
        "default-wallet" => {
            if let Some(sk) = load_default_wallet() {
                let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
                println!("Public : {}", pk);
                println!("Address: {}", pubkey_to_address(&pk.to_string()));
                println!("Private key is hidden by default.");
            } else {
                println!("No default wallet");
            }
        }
        "send" => {
            // send <to> <amount> [n], or if <to> missing, use default address
            match (a.get(1), a.get(2)) {
                (Some(to), Some(amt)) => {
                    if let Ok(amount) = amt.parse() {
                        let n = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(2);
                        send_default(peers, to, amount, n);
                    } else {
                        println!("Invalid amount");
                    }
                }
                (None, Some(amt)) => {
                    if let Some(def_to) = default_address() {
                        if let Ok(amount) = amt.parse() {
                            let n = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(2);
                            send_default(peers, &def_to, amount, n);
                        } else {
                            println!("Invalid amount");
                        }
                    } else {
                        println!("No default wallet and no destination address");
                    }
                }
                _ => println!("Usage: send <to?> <amount> [n_peers]"),
            }
        }
        "send-priv" if a.len() >= 4 => {
            if let Ok(amount) = a[3].parse() {
                let n = a.get(4).and_then(|s| s.parse().ok()).unwrap_or(2);
                send_priv(peers, a[1], a[2], amount, n);
            } else {
                println!("Invalid amount");
            }
        }
        "sign-raw" => match (a.get(1), a.get(2)) {
            (Some(to), Some(amt)) => {
                if let Ok(amount) = amt.parse() {
                    sign_raw_default(peers, to, amount);
                } else {
                    println!("Invalid amount");
                }
            }
            _ => println!("Usage: sign-raw <to> <amount>"),
        },
        "sign-raw-priv" if a.len() >= 4 => {
            if let Ok(amount) = a[3].parse() {
                sign_raw_priv(peers, a[1], a[2], amount);
            } else {
                println!("Invalid amount");
            }
        }
        "send-raw" => match a.get(1) {
            Some(sig) => {
                let n = a
                    .get(2)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(MIN_BROADCAST_PEERS);
                send_raw(peers, sig, n);
            }
            None => println!("Usage: send-raw <sig|txid> [n_peers]"),
        },
        "raw_tx" => show_raw_signed(),
        "force-send" if a.len() == 2 => {
            force_send(peers, a[1]);
        }
        "balance" => {
            if a.len() == 2 {
                balance(peers, a[1]);
            } else if let Some(addr) = default_address() {
                balance(peers, &addr);
            } else {
                println!("No default wallet");
            }
        }
        "faucet" => {
            if a.len() == 2 {
                faucet(peers, a[1]);
            } else if let Some(addr) = default_address() {
                faucet(peers, &addr);
            } else {
                println!("No default wallet or address");
            }
        }
        "tx-history" => {
            if a.len() == 2 {
                print_history(peers, a[1]);
            } else if let Some(addr) = default_address() {
                print_history(peers, &addr);
            } else {
                println!("No default wallet");
            }
        }
        "tx-info" if a.len() == 2 => {
            tx_info(peers, a[1]);
        }
        "list-peers" => list_peers(peers),
        "print-mempool" => show_mempool(),
        "exit" => {
            peers.save();
            return false;
        }
        _ => println!("Unknown command - type 'help'"),
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_signed_by_wallet_accepts_address_based_sender() {
        let sk = SecretKey::from_byte_array([9u8; 32]).unwrap();
        let mut store = PeerStore {
            peers: Vec::new(),
            offline_since: std::collections::HashMap::new(),
        };
        let tx = build_tx(&mut store, &sk, "LFS11111111111111111111", 5);
        assert!(tx_signed_by_wallet(&tx, &sk));
    }

    #[test]
    fn parse_vanity_args_supports_combined_filters() {
        let parsed = parse_vanity_args(&["startswith", "abc", "endswith", "9"]).unwrap();
        assert_eq!(parsed.starts_with.as_deref(), Some("abc"));
        assert_eq!(parsed.ends_with.as_deref(), Some("9"));
        assert_eq!(parsed.compute_mode, VanityComputeMode::Cpu);
        assert_eq!(parsed.worker_count, None);
    }

    #[test]
    fn parse_vanity_args_supports_gpu_and_worker_count() {
        let parsed = parse_vanity_args(&["startswith", "abc", "gpu", "8"]).unwrap();
        assert_eq!(parsed.starts_with.as_deref(), Some("abc"));
        assert_eq!(parsed.compute_mode, VanityComputeMode::Gpu);
        assert_eq!(parsed.worker_count, Some(8));
    }

    #[test]
    fn parse_vanity_args_supports_gpu_without_worker_count() {
        let parsed = parse_vanity_args(&["startswith", "abc", "gpu"]).unwrap();
        assert_eq!(parsed.starts_with.as_deref(), Some("abc"));
        assert_eq!(parsed.compute_mode, VanityComputeMode::Gpu);
        assert_eq!(parsed.worker_count, None);
    }

    #[test]
    fn parse_vanity_args_supports_gpu_without_worker_before_other_keys() {
        let parsed = parse_vanity_args(&["gpu", "endswith", "9"]).unwrap();
        assert_eq!(parsed.compute_mode, VanityComputeMode::Gpu);
        assert_eq!(parsed.worker_count, None);
        assert_eq!(parsed.ends_with.as_deref(), Some("9"));
    }

    #[test]
    fn parse_vanity_args_supports_opencl_without_worker_count() {
        let parsed = parse_vanity_args(&["startswith", "abc", "opencl"]).unwrap();
        assert_eq!(parsed.starts_with.as_deref(), Some("abc"));
        assert_eq!(parsed.compute_mode, VanityComputeMode::OpenCl);
        assert_eq!(parsed.worker_count, None);
    }

    #[test]
    fn parse_vanity_args_supports_opencl_and_worker_count() {
        let parsed = parse_vanity_args(&["opencl", "12", "endswith", "9"]).unwrap();
        assert_eq!(parsed.compute_mode, VanityComputeMode::OpenCl);
        assert_eq!(parsed.worker_count, Some(12));
        assert_eq!(parsed.ends_with.as_deref(), Some("9"));
    }

    #[test]
    fn vanity_match_uses_payload_after_lfs() {
        let addr = "LFSabc1239";
        assert!(address_matches_vanity(addr, Some("abc"), Some("9")));
        assert!(!address_matches_vanity(addr, Some("LFS"), None));
    }
}
