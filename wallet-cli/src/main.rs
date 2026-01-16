// === /wallet-cli/src/main.rs ===
//! Wallet CLI - relies only on `peers.json` + `BOOTSTRAP_NODES`.
//! All legacy `nodes.txt` paths have been removed.

use blockchain_core::{Block, Transaction};
use rand::seq::IndexedRandom;
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use serde_json;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

static BOOTSTRAP_NODES: &[&str] = &["89.168.107.239:6000", "79.76.116.108:6000"];

const MEMPOOL_FILE: &str = "wallet_mempool.json";
const WALLET_CACHE_DIR: &str = "wallet-cache";
const PEER_CACHE_FILE: &str = "wallet-cache/peers_cache.json";

// ---------- Default wallet ----------
const DEFAULT_WALLET: &str = ".default_wallet";
fn save_default_wallet(sk: &SecretKey) {
    let _ = fs::write(DEFAULT_WALLET, hex::encode(sk.secret_bytes()));
}
fn load_default_wallet() -> Option<SecretKey> {
    fs::read_to_string(DEFAULT_WALLET)
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
        })
}

fn default_address() -> Option<String> {
    load_default_wallet().map(|sk| {
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        format!(
            "LFS{}",
            bs58::encode(&Sha256::digest(&pk.serialize())[..20]).into_string()
        )
    })
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
}

impl PeerStore {
    fn load() -> Self {
        ensure_cache_dir();
        let mut peers: Vec<String> = BOOTSTRAP_NODES.iter().map(|s| s.to_string()).collect();
        if let Ok(txt) = fs::read_to_string(peer_cache_path()) {
            if let Ok(v) = serde_json::from_str::<Vec<String>>(&txt) {
                for p in v {
                    if is_valid_peer(&p) && !peers.contains(&p) {
                        peers.push(p);
                    }
                }
            }
        }
        PeerStore { peers }
    }

    fn save(&self) {
        ensure_cache_dir();
        let _ = fs::write(peer_cache_path(), serde_json::to_string_pretty(&self.peers).unwrap_or_default());
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
            if let Ok(mut stream) = TcpStream::connect_timeout(&peer.parse().unwrap(), Duration::from_millis(800)) {
                let _ = stream.write_all(b"/peers");
                let mut buf = Vec::new();
                if stream.read_to_end(&mut buf).is_ok() {
                    if let Ok(v) = serde_json::from_slice::<Vec<String>>(&buf) {
                        let filtered: Vec<String> = v.into_iter().filter(|p| is_valid_peer(p)).collect();
                        self.add_many(&filtered);
                    }
                }
            }
        }
    }
}

fn connect_and_send(addr: &str, data: &[u8]) -> io::Result<()> {
    let sock: SocketAddr = addr
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "bad addr"))?;
    let mut s = TcpStream::connect_timeout(&sock, Duration::from_millis(800))?;
    s.write_all(data)?;
    Ok(())
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

fn broadcast(store: &mut PeerStore, json: &[u8], min_peers: usize) {
    store.discover();
    let peers = store.as_slice();
    if peers.is_empty() {
        println!("No known peers");
        return;
    }
    let mut rng = rand::rng();
    let selected: Vec<String> = peers
        .choose_multiple(&mut rng, min_peers.max(1))
        .cloned()
        .collect();
    let mut ok = 0;
    for p in &selected {
        match connect_and_send(p, json) {
            Ok(_) => {
                println!("Sent to {}", p);
                ok += 1;
            }
            Err(_) => println!("Failed to connect to {}", p),
        }
    }
    if ok < min_peers {
        println!(
            "Sent to {ok}/{min_peers} peers; transaction saved to local mempool"
        );
        append_pending(json);
    } else {
        // If sent successfully, try to broadcast any pending transactions
        try_broadcast_pending(store, min_peers);
    }
}

// ---------- Transakcje ----------
fn build_tx(sk: &SecretKey, to: &str, amount: u64) -> Transaction {
    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, sk);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let preimage = format!("{}|{}|{}|{}|{}", 1, pk, to, amount, ts);
    let hash = Sha256::digest(preimage.as_bytes());
    let sig = secp.sign_ecdsa(Message::from_digest(hash.into()), sk);
    let mut tx = Transaction {
        version: 1,
        timestamp: ts,
        from: pk.to_string(),
        to: to.into(),
        amount,
        signature: hex::encode(sig.serialize_compact()),
        txid: String::new(),
    };
    tx.txid = tx.compute_txid();
    tx
}

fn send_default(store: &mut PeerStore, to: &str, amount: u64, min_peers: usize) {
    if let Some(sk) = load_default_wallet() {
        let tx = build_tx(&sk, to, amount);
        let payload = serde_json::to_vec(&tx).unwrap();
        broadcast(store, &payload, min_peers);
    } else {
        println!("No default wallet");
    }
}
fn send_priv(store: &mut PeerStore, priv_hex: &str, to: &str, amount: u64, min_peers: usize) {
    if let Ok(sk) = SecretKey::from_slice(&hex::decode(priv_hex).unwrap_or_default()) {
        let tx = build_tx(&sk, to, amount);
        let payload = serde_json::to_vec(&tx).unwrap();
        broadcast(store, &payload, min_peers);
    } else {
        println!("Invalid private key");
    }
}

// ---------- Saldo ----------
fn balance(store: &mut PeerStore, addr: &str) {
    store.discover();
    let query = format!("/balance/{}", addr);
    for p in store.as_slice() {
        if let Ok(mut s) =
            TcpStream::connect_timeout(&p.parse().unwrap(), Duration::from_millis(800))
        {
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
        if let Ok(mut s) = TcpStream::connect_timeout(&sock, Duration::from_millis(800)) {
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
    let mut txs = Vec::new();
    for block in &chain {
        for tx in &block.transactions {
            if tx.from == addr || tx.to == addr {
                txs.push((block.index, tx.clone()));
            }
        }
    }
    if txs.is_empty() {
        println!("No transactions found for {}", addr);
        return;
    }
    for (index, tx) in txs {
        let direction = if tx.from == addr { "OUT" } else { "IN " };
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
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let mut tx = Transaction {
        version: 1,
        timestamp: ts,
        from: String::new(),
        to: addr.into(),
        amount: 1000,
        signature: "reward".into(),
        txid: String::new(),
    };
    tx.txid = tx.compute_txid();
    let data = serde_json::to_vec(&tx).unwrap();
    store.discover();
    for p in store.as_slice() {
        if connect_and_send(&p, &data).is_ok() {
            println!("Faucet to {} via {}", addr, p);
            return;
        }
    }
    println!("Faucet failed; no reachable peers");
}

// ---------- Import / export ----------
fn import_dat(path: &str) {
    let mut buf = [0u8; 32];
    if File::open(path)
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok()
    {
        if let Ok(sk) = SecretKey::from_slice(&buf) {
            let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
            save_default_wallet(&sk);
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
        "Commands:\n  help\n  create-wallet\n  import-priv <hex>\n  import-dat <file>\n  export-dat <file>\n  default-wallet\n  send <to?> <amount> [n=2]   (defaults to your address)\n  send-priv <priv> <to> <amount> [n=2]\n  force-send <signature>     (resend a pending tx even if only one peer is reachable)\n  balance [address]          (defaults to your address)\n  faucet [address]           (defaults to your address)\n  tx-history [address]       (defaults to your address)\n  tx-info <txid|signature>\n  list-peers\n  print-mempool\n  exit"
    );
}

// Create a new wallet and set it as default
fn create_wallet() {
    let secp = Secp256k1::new();
    let mut rng = rand::rng();
    let mut bytes = [0u8; 32];
    use rand::RngCore;
    rng.fill_bytes(&mut bytes);
    let sk = SecretKey::from_byte_array(bytes).expect("rng produced invalid bytes");
    let pk = PublicKey::from_secret_key(&secp, &sk);
    save_default_wallet(&sk);
    println!("Created new wallet.");
    println!("Private: {}", hex::encode(sk.secret_bytes()));
    println!("Public : {}", pk);
    println!(
        "Address: LFS{}",
        bs58::encode(&Sha256::digest(&pk.serialize())[..20]).into_string()
    );
}

// Import a private key and set it as default
fn import_priv(priv_hex: &str) {
    match hex::decode(priv_hex) {
        Ok(bytes) => match SecretKey::from_slice(&bytes) {
            Ok(sk) => {
                let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
                save_default_wallet(&sk);
                println!("Imported private key. Public Key: {}", pk);
                println!(
                    "Address: LFS{}",
                    bs58::encode(&Sha256::digest(&pk.serialize())[..20]).into_string()
                );
            }
            Err(_) => println!("Invalid private key"),
        },
        Err(_) => println!("Invalid hex format"),
    }
}

fn list_peers(store: &mut PeerStore) {
    store.discover();
    let peers = store.as_slice();
    println!("Available peers ({}):", peers.len());
    for p in peers {
        println!("- {}", p);
    }
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

fn try_broadcast_pending(store: &mut PeerStore, min_peers: usize) {
    let mut pending = load_pending_transactions();
    if pending.is_empty() {
        return;
    }
    store.discover();
    let peers = store.as_slice();
    if peers.is_empty() {
        return;
    }
    let mut sent = 0;
    pending.retain(|tx| {
        let payload = serde_json::to_vec(tx).unwrap();
        let mut ok = 0;
        for p in peers {
            if connect_and_send(p, &payload).is_ok() {
                ok += 1;
                if ok >= min_peers {
                    break;
                }
            }
        }
        if ok >= min_peers {
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
    if tx.from != pk.to_string() {
        return false;
    }
    let Ok(sig_bytes) = hex::decode(&tx.signature) else {
        return false;
    };
    let Ok(sig) = Signature::from_compact(&sig_bytes) else {
        return false;
    };
    let new_preimage = format!(
        "{}|{}|{}|{}|{}",
        tx.version, tx.from, tx.to, tx.amount, tx.timestamp
    );
    let new_hash = Sha256::digest(new_preimage.as_bytes());
    if secp
        .verify_ecdsa(Message::from_digest(new_hash.into()), &sig, &pk)
        .is_ok()
    {
        return true;
    }
    // Legacy compatibility: older txs signed only (from|to|amount)
    let legacy_preimage = format!("{}{}{}", tx.from, tx.to, tx.amount);
    let legacy_hash = Sha256::digest(legacy_preimage.as_bytes());
    secp.verify_ecdsa(Message::from_digest(legacy_hash.into()), &sig, &pk)
        .is_ok()
}

fn broadcast_force(store: &mut PeerStore, json: &[u8]) -> usize {
    store.discover();
    let peers = store.as_slice();
    if peers.is_empty() {
        println!("No known peers");
        return 0;
    }
    let mut ok = 0;
    for p in peers {
        match connect_and_send(p, json) {
            Ok(_) => {
                ok += 1;
                println!("Sent to {}", p);
            }
            Err(_) => println!("Failed to connect to {}", p),
        }
    }
    ok
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
    let sent = broadcast_force(store, &payload);
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
    loop {
        print!("> ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        if io::stdin().read_line(&mut line).is_err() {
            continue;
        }
        let a: Vec<&str> = line.trim().split_whitespace().collect();
        if a.is_empty() {
            continue;
        }
        match a[0] {
            "help" => help(),
            "create-wallet" => create_wallet(),
            "import-priv" if a.len() == 2 => import_priv(a[1]),
            "import-dat" if a.len() == 2 => import_dat(a[1]),
            "export-dat" if a.len() == 2 => export_dat(a[1]),
            "default-wallet" => {
                if let Some(sk) = load_default_wallet() {
                    let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
                    println!("Private: {}", hex::encode(sk.secret_bytes()));
                    println!("Public : {}", pk);
                    println!(
                        "Address: LFS{}",
                        bs58::encode(&Sha256::digest(&pk.serialize())[..20]).into_string()
                    );
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
                            send_default(&mut peers, to, amount, n);
                        } else {
                            println!("Invalid amount");
                        }
                    }
                    (None, Some(amt)) => {
                        if let Some(def_to) = default_address() {
                            if let Ok(amount) = amt.parse() {
                                let n = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(2);
                                send_default(&mut peers, &def_to, amount, n);
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
                    send_priv(&mut peers, a[1], a[2], amount, n);
                } else {
                    println!("Invalid amount");
                }
            }
            "force-send" if a.len() == 2 => {
                force_send(&mut peers, a[1]);
            }
            "balance" => {
                if a.len() == 2 {
                    balance(&mut peers, a[1]);
                } else if let Some(addr) = default_address() {
                    balance(&mut peers, &addr);
                } else {
                    println!("No default wallet");
                }
            }
            "faucet" => {
                if a.len() == 2 {
                    faucet(&mut peers, a[1]);
                } else if let Some(addr) = default_address() {
                    faucet(&mut peers, &addr);
                } else {
                    println!("No default wallet or address");
                }
            }
            "tx-history" => {
                if a.len() == 2 {
                    print_history(&mut peers, a[1]);
                } else if let Some(addr) = default_address() {
                    print_history(&mut peers, &addr);
                } else {
                    println!("No default wallet");
                }
            }
            "tx-info" if a.len() == 2 => {
                tx_info(&mut peers, a[1]);
            }
            "list-peers" => list_peers(&mut peers),
            "print-mempool" => show_mempool(),
            "exit" => {
                peers.save();
                break;
            }
            _ => println!("Unknown command - type 'help'"),
        }
    }
    peers.save();
}
