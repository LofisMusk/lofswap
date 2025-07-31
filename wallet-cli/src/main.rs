// === /wallet-cli/src/main.rs ===
//! Wallet CLI – oparty wyłącznie o mechanizm `peers.json` + `BOOTSTRAP_NODES`.
//! Usunięto wszystkie ścieżki korzystające z `nodes.txt`.

use blockchain_core::Transaction;
use rand::seq::IndexedRandom;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde_json;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

static BOOTSTRAP_NODES: &[&str] = &["31.135.167.5:6000", "31.135.167.5:6001"];

const MEMPOOL_FILE: &str = "wallet_mempool.json";

// ---------- domyślny portfel ----------
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

// ---------- Peers ----------
fn load_peers() -> Vec<String> {
    if Path::new("peers.json").exists() {
        if let Ok(txt) = fs::read_to_string("peers.json") {
            if let Ok(v) = serde_json::from_str::<Vec<String>>(&txt) {
                if !v.is_empty() {
                    return v;
                }
            }
        }
    }
    BOOTSTRAP_NODES.iter().map(|s| s.to_string()).collect()
}

fn connect_and_send(addr: &str, data: &[u8]) -> io::Result<()> {
    let sock: SocketAddr = addr
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "bad addr"))?;
    let mut s = TcpStream::connect_timeout(&sock, Duration::from_millis(800))?;
    s.write_all(data)?;
    Ok(())
}

fn broadcast(json: &[u8], min_peers: usize) {
    let peers = load_peers();
    if peers.is_empty() {
        println!("✗ Brak znanych nodów");
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
                println!("✓ Wysłano do {}", p);
                ok += 1;
            }
            Err(_) => println!("✗ Nie udało się połączyć z {}", p),
        }
    }
    if ok < min_peers {
        println!(
            "⚠️ Wysłano tylko do {ok}/{min_peers} nodów – transakcja zostanie zapisana do lokalnego mempoola"
        );
        let _ = OpenOptions::new()
            .append(true)
            .create(true)
            .open(MEMPOOL_FILE)
            .and_then(|mut f| f.write_all(json));
    } else {
        // If sent successfully, try to broadcast any pending transactions
        try_broadcast_pending(min_peers);
    }
}

// ---------- Transakcje ----------
fn build_tx(sk: &SecretKey, to: &str, amount: u64) -> Transaction {
    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, sk);
    let preimage = format!("{}{}{}", pk, to, amount);
    let hash = Sha256::digest(preimage.as_bytes());
    let sig = secp.sign_ecdsa(Message::from_slice(&hash).unwrap(), sk);
    Transaction {
        from: pk.to_string(),
        to: to.into(),
        amount,
        signature: hex::encode(sig.serialize_compact()),
    }
}

fn send_default(to: &str, amount: u64, min_peers: usize) {
    if let Some(sk) = load_default_wallet() {
        let tx = build_tx(&sk, to, amount);
        let payload = serde_json::to_vec(&tx).unwrap();
        broadcast(&payload, min_peers);
    } else {
        println!("✗ Brak domyślnego portfela");
    }
}
fn send_priv(priv_hex: &str, to: &str, amount: u64, min_peers: usize) {
    if let Ok(sk) = SecretKey::from_slice(&hex::decode(priv_hex).unwrap_or_default()) {
        let tx = build_tx(&sk, to, amount);
        let payload = serde_json::to_vec(&tx).unwrap();
        broadcast(&payload, min_peers);
    } else {
        println!("✗ Niepoprawny klucz prywatny");
    }
}

// ---------- Saldo ----------
fn balance(addr: &str) {
    let query = format!("/balance/{}", addr);
    for p in load_peers() {
        if let Ok(mut s) =
            TcpStream::connect_timeout(&p.parse().unwrap(), Duration::from_millis(800))
        {
            if s.write_all(query.as_bytes()).is_ok() {
                let mut buf = String::new();
                if s.read_to_string(&mut buf).is_ok() {
                    println!("Saldo {}: {}", addr, buf.trim());
                    return;
                }
            }
        }
    }
    println!("✗ Brak odpowiedzi z nodów");
}

// ---------- Faucet ----------
fn faucet(addr: &str) {
    let tx = Transaction {
        from: String::new(),
        to: addr.into(),
        amount: 1000,
        signature: "reward".into(),
    };
    let data = serde_json::to_vec(&tx).unwrap();
    for p in load_peers() {
        if connect_and_send(&p, &data).is_ok() {
            println!("✓ Faucet do {} via {}", addr, p);
            return;
        }
    }
    println!("✗ Faucet nie powiódł się – brak działających nodów");
}

// ---------- Import / eksport ----------
fn import_dat(path: &str) {
    let mut buf = [0u8; 32];
    if File::open(path)
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok()
    {
        if let Ok(sk) = SecretKey::from_slice(&buf) {
            let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
            save_default_wallet(&sk);
            println!("✓ Zaimportowano plik. Public Key: {}", pk);
            return;
        }
    }
    println!("✗ Nie udało się zaimportować");
}
fn export_dat(path: &str) {
    if let Some(sk) = load_default_wallet() {
        if fs::write(path, sk.secret_bytes()).is_ok() {
            println!("✓ Zapisano do {}", path);
        } else {
            println!("✗ Błąd zapisu");
        }
    } else {
        println!("✗ Brak domyślnego portfela");
    }
}

// ---------- CLI ----------
fn help() {
    println!(
        "Komendy:\n  help\n  create-wallet\n  import-priv <hex>\n  import-dat <plik>\n  export-dat <plik>\n  default-wallet\n  send <to> <amount> [n=2]\n  send-priv <priv> <to> <amount> [n=2]\n  balance [address]\n  faucet <address>\n  list-peers\n  print-mempool\n  exit"
    );
}

// Dodano funkcję create_wallet
fn create_wallet() {
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let (sk, pk) = secp.generate_keypair(&mut rng);
    save_default_wallet(&sk);
    println!("✓ Utworzono nowy portfel.");
    println!("Private: {}", hex::encode(sk.secret_bytes()));
    println!("Public : {}", pk);
    println!(
        "Address: LFS{}",
        bs58::encode(&Sha256::digest(&pk.serialize())[..20]).into_string()
    );
}

// Dodano funkcję import_priv
fn import_priv(priv_hex: &str) {
    match hex::decode(priv_hex) {
        Ok(bytes) => match SecretKey::from_slice(&bytes) {
            Ok(sk) => {
                let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
                save_default_wallet(&sk);
                println!("✓ Zaimportowano klucz prywatny. Public Key: {}", pk);
                println!(
                    "Address: LFS{}",
                    bs58::encode(&Sha256::digest(&pk.serialize())[..20]).into_string()
                );
            }
            Err(_) => println!("✗ Niepoprawny klucz prywatny"),
        },
        Err(_) => println!("✗ Niepoprawny format hex"),
    }
}

fn list_peers() {
    let peers = load_peers();
    println!("Dostępne peery ({}):", peers.len());
    for p in peers {
        println!("- {}", p);
    }
}

fn show_mempool() {
    if let Ok(txt) = fs::read_to_string(MEMPOOL_FILE) {
        for line in txt.lines() {
            if let Ok(tx) = serde_json::from_str::<Transaction>(line) {
                println!("TX: {} -> {} amount: {}", tx.from, tx.to, tx.amount);
            }
        }
    } else {
        println!("✗ Mempool jest pusty");
    }
}

fn try_broadcast_pending(min_peers: usize) {
    if let Ok(txt) = fs::read_to_string(MEMPOOL_FILE) {
        let lines: Vec<_> = txt.lines().collect();
        if lines.is_empty() {
            return;
        }
        let peers = load_peers();
        if peers.is_empty() {
            return;
        }
        let mut sent = 0;
        let mut failed = Vec::new();
        for line in lines {
            if let Ok(tx) = serde_json::from_str::<serde_json::Value>(line) {
                let payload = serde_json::to_vec(&tx).unwrap();
                let mut ok = 0;
                for p in &peers {
                    if connect_and_send(p, &payload).is_ok() {
                        ok += 1;
                        if ok >= min_peers {
                            break;
                        }
                    }
                }
                if ok >= min_peers {
                    sent += 1;
                } else {
                    failed.push(line.to_string());
                }
            }
        }
        if sent > 0 {
            println!("✓ Wysłano {} zaległych transakcji z mempoola", sent);
        }
        // Rewrite mempool with failed txs
        let _ = fs::write(MEMPOOL_FILE, failed.join("\n"));
    }
}

fn main() {
    println!("Wallet CLI (peers.json + bootstrap)");
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
                    println!("Brak domyślnego portfela");
                }
            }
            "send" if a.len() >= 3 => {
                if let Ok(amount) = a[2].parse() {
                    let n = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(2);
                    send_default(a[1], amount, n);
                } else {
                    println!("Nieprawidłowa kwota");
                }
            }
            "send-priv" if a.len() >= 4 => {
                if let Ok(amount) = a[3].parse() {
                    let n = a.get(4).and_then(|s| s.parse().ok()).unwrap_or(2);
                    send_priv(a[1], a[2], amount, n);
                } else {
                    println!("Nieprawidłowa kwota");
                }
            }
            "balance" => {
                if a.len() == 2 {
                    balance(a[1]);
                } else if let Some(sk) = load_default_wallet() {
                    let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
                    balance(&pk.to_string());
                } else {
                    println!("Brak domyślnego portfela");
                }
            }
            "faucet" if a.len() == 2 => faucet(a[1]),
            "list-peers" => list_peers(),
            "print-mempool" => show_mempool(),
            "exit" => break,
            _ => println!("Nieznana komenda – wpisz 'help'"),
        }
    }
}
