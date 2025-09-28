use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use dirs::home_dir;
use k256::{
    ecdsa::{signature::{DigestSigner, Signer}, Signature, SigningKey}, 
    elliptic_curve::{rand_core::OsRng, sec1::ToEncodedPoint}, 
    PublicKey
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs, io::{self, Read}, path::{Path, PathBuf}, time::{Duration, Instant}};
use reqwest::Client;
use bs58;

/// Adres = "LFS" + Base58(pubkey_uncompressed[1..]) – 64 bajty (X||Y)
fn pubkey_to_address(pk: &PublicKey) -> String {
    let uncompressed = pk.to_encoded_point(false);
    let without_prefix = &uncompressed.as_bytes()[1..]; // usuń 0x04
    format!("LFS{}", bs58::encode(without_prefix).into_string())
}

/// Zamień LFS-base58 → czysty pubkey bytes
fn address_to_pubkey_bytes(addr: &str) -> Result<Vec<u8>> {
    let base58_part = addr.strip_prefix("LFS").unwrap_or(addr);
    let bytes = bs58::decode(base58_part).into_vec()?;
    if bytes.len() != 64 {
        return Err(anyhow!("decoded pubkey length != 64B"));
    }
    // dodaj prefix uncompressed 0x04
    let mut full = vec![0x04];
    full.extend_from_slice(&bytes);
    Ok(full)
}

fn canonical_tx_bytes(from: &str, to: &str, amount: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "from": from,
        "to": to,
        "amount": amount
    })).expect("json")
}

fn sign_offline(sk_hex: &str, from_addr: &str, to_addr: &str, amount: u64) -> Result<String> {
    let sk_bytes = hex::decode(sk_hex)?;
    let sk = SigningKey::from_slice(&sk_bytes)?;
    let msg = canonical_tx_bytes(from_addr, to_addr, amount);
    let digest = Sha256::new().chain_update(&msg).finalize();
    let sig: Signature = sk.sign_digest(Sha256::new().chain_update(&digest));
    Ok(hex::encode(sig.to_der().as_bytes()))
}

// ========= Dysk: katalog i pliki =========
#[derive(Clone)]
struct Store {
    dir: PathBuf,
    book_path: PathBuf,
    pending_path: PathBuf,
    keys_path: PathBuf,
}

impl Store {
    fn open() -> Result<Self> {
        let base = home_dir().ok_or_else(|| anyhow!("no home dir"))?.join(".lofswap");
        if !base.exists() { fs::create_dir_all(&base)?; }
        Ok(Self {
            dir: base.clone(),
            book_path: base.join("address_book.json"),
            pending_path: base.join("pending.json"),
            keys_path: base.join("keys.json"),
        })
    }
}

// ========= Typy danych =========
#[derive(Serialize, Deserialize, Clone, Debug)]
struct AddressBook {
    entries: HashMap<String, String>, // name -> address
}
impl Default for AddressBook {
    fn default() -> Self { Self { entries: HashMap::new() } }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct PendingTx {
    from: String,
    to: String,
    amount: u64,
    signature: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct PendingQueue {
    txs: Vec<PendingTx>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct KeyStore {
    keys: HashMap<String, (String, String)>, // label -> (sk_hex, address)
}

// ========= IO helpers =========
fn read_json_or_default<T: for<'de> Deserialize<'de> + Default>(p: &Path) -> Result<T> {
    if !p.exists() { return Ok(T::default()); }
    let s = fs::read_to_string(p)?;
    Ok(serde_json::from_str(&s)?)
}

fn write_json<T: Serialize>(p: &Path, v: &T) -> Result<()> {
    fs::write(p, serde_json::to_string_pretty(v)?)?;
    Ok(())
}

// ========= CLI =========
#[derive(Parser)]
#[command(name = "wallet-cli")]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:6060")]
    rpc: String,
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Vanity {
        #[arg(long)] startswith: Option<String>,
        #[arg(long)] endswith: Option<String>,
        #[arg(long, default_value_t = 1)] count: u32,
        #[arg(long, default_value_t = 0)] timeout: u64,
        #[arg(long)] label: Option<String>,
    },
    Generate { #[arg(long)] label: String },
    Keys,
    AddrAdd { name: String, address: String },
    AddrRm { name: String },
    AddrList,
    SignRaw {
        #[arg(long)] sk_hex: Option<String>,
        #[arg(long)] label: Option<String>,
        #[arg(long)] from: Option<String>,
        #[arg(long)] to: String,
        #[arg(long)] amount: u64,
        #[arg(long, default_value_t = false)] save: bool,
    },
    Pending,
    PendingClear,
    BroadcastPending,
    Broadcast { #[arg(long)] file: Option<String> },
}

// ========= MAIN =========
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let store = Store::open()?;

    match cli.cmd {
        Commands::Vanity { startswith, endswith, count, timeout, label } => {
            let (sk_hex, address) = vanity_find(startswith.as_deref(), endswith.as_deref(), count, timeout)?;
            println!("FOUND: {}\nsk: {}", address, sk_hex);
            if let Some(label) = label {
                let mut ks: KeyStore = read_json_or_default(&store.keys_path)?;
                ks.keys.insert(label.clone(), (sk_hex.clone(), address.clone()));
                write_json(&store.keys_path, &ks)?;
                println!("Saved under label: {}", label);
            }
        }
        Commands::Generate { label } => {
            let (sk_hex, address) = generate_keypair()?;
            let mut ks: KeyStore = read_json_or_default(&store.keys_path)?;
            ks.keys.insert(label.clone(), (sk_hex.clone(), address.clone()));
            write_json(&store.keys_path, &ks)?;
            println!("label: {}\naddress: {}\nsk: {}", label, address, sk_hex);
        }
        Commands::Keys => {
            let ks: KeyStore = read_json_or_default(&store.keys_path)?;
            for (label, (sk, addr)) in ks.keys {
                println!("{:<16} addr={} sk={}", label, addr, sk);
            }
        }
        Commands::AddrAdd { name, address } => {
            let mut book: AddressBook = read_json_or_default(&store.book_path)?;
            book.entries.insert(name.clone(), address.clone());
            write_json(&store.book_path, &book)?;
            println!("added: {} -> {}", name, address);
        }
        Commands::AddrRm { name } => {
            let mut book: AddressBook = read_json_or_default(&store.book_path)?;
            book.entries.remove(&name);
            write_json(&store.book_path, &book)?;
            println!("removed: {}", name);
        }
        Commands::AddrList => {
            let book: AddressBook = read_json_or_default(&store.book_path)?;
            for (n, a) in book.entries {
                println!("{:<16} {}", n, a);
            }
        }
        Commands::SignRaw { sk_hex, label, from, to, amount, save } => {
            let (sk_hex, from_addr) = resolve_key_source(&store, sk_hex, label, from)?;
            let sig = sign_offline(&sk_hex, &from_addr, &to, amount)?;
            let tx = PendingTx { from: from_addr, to, amount, signature: sig };
            if save {
                let mut q: PendingQueue = read_json_or_default(&store.pending_path)?;
                q.txs.push(tx.clone());
                write_json(&store.pending_path, &q)?;
                println!("saved to pending ({} tx total)", q.txs.len());
            } else {
                println!("{}", serde_json::to_string_pretty(&tx)?);
            }
        }
        Commands::Pending => {
            let q: PendingQueue = read_json_or_default(&store.pending_path)?;
            println!("pending: {}", q.txs.len());
            for (i, t) in q.txs.iter().enumerate() {
                println!("#{} from={} to={} amount={}", i, t.from, t.to, t.amount);
            }
        }
        Commands::PendingClear => {
            write_json(&store.pending_path, &PendingQueue::default())?;
            println!("pending cleared");
        }
        Commands::BroadcastPending => {
            let mut q: PendingQueue = read_json_or_default(&store.pending_path)?;
            let before = q.txs.len();
            q.txs = broadcast_many(&cli.rpc, q.txs).await?;
            let after = q.txs.len();
            write_json(&store.pending_path, &q)?;
            println!("broadcast done: {} sent, {} left", before - after, after);
        }
        Commands::Broadcast { file } => {
            let json = if let Some(path) = file {
                fs::read_to_string(path)?
            } else {
                let mut buf = String::new();
                io::stdin().read_to_string(&mut buf)?;
                buf
            };
            let tx: PendingTx = serde_json::from_str(&json)?;
            let ok = broadcast_one(&cli.rpc, &tx).await;
            println!("{}", if ok { "OK" } else { "FAIL" });
        }
    }
    Ok(())
}

// ========= Helpers =========
fn generate_keypair() -> Result<(String, String)> {
    let sk = SigningKey::random(&mut OsRng);
    let pk: PublicKey = sk.verifying_key().into();
    let sk_hex = hex::encode(sk.to_bytes());
    let address = pubkey_to_address(&pk);
    Ok((sk_hex, address))
}

fn vanity_find(starts: Option<&str>, ends: Option<&str>, count: u32, timeout: u64) -> Result<(String, String)> {
    if starts.is_none() && ends.is_none() {
        return generate_keypair();
    }
    let starts_lc = starts.map(|s| s.to_ascii_lowercase());
    let ends_lc   = ends.map(|s| s.to_ascii_lowercase());
    let t0 = Instant::now();
    let limit = if timeout == 0 { Duration::MAX } else { Duration::from_secs(timeout) };
    let mut found = Vec::new();
    while found.len() < count as usize && t0.elapsed() < limit {
        let (sk_hex, addr) = generate_keypair()?;
        let addr_lc = addr.to_ascii_lowercase();
        let ok1 = starts_lc.as_ref().map_or(true, |p| addr_lc.starts_with(p));
        let ok2 = ends_lc.as_ref().map_or(true, |p| addr_lc.ends_with(p));
        if ok1 && ok2 {
            found.push((sk_hex.clone(), addr.clone()));
            println!("match #{}: {}", found.len(), addr);
        }
    }
    found.last().cloned().ok_or_else(|| anyhow!("nie znaleziono w czasie limitu"))
}

fn resolve_key_source(store: &Store, sk_hex: Option<String>, label: Option<String>, from: Option<String>) -> Result<(String, String)> {
    if let Some(sk_hex) = sk_hex {
        let from = from.ok_or_else(|| anyhow!("podaj --from"))?;
        return Ok((sk_hex, from));
    }
    if let Some(label) = label {
        let ks: KeyStore = read_json_or_default(&store.keys_path)?;
        let (sk, addr) = ks.keys.get(&label).ok_or_else(|| anyhow!("brak label w keystore"))?.clone();
        return Ok((sk, addr));
    }
    Err(anyhow!("użyj --sk-hex + --from LUB --label"))
}

async fn broadcast_one(rpc: &str, tx: &PendingTx) -> bool {
    #[derive(Serialize)]
    struct SendTxReq<'a> { from: &'a str, to: &'a str, amount: u64, signature: &'a str }
    let url = format!("{}/rpc/send_tx", rpc);
    let from_pk_hex = hex::encode(address_to_pubkey_bytes(&tx.from).unwrap());
    let to_pk_hex   = hex::encode(address_to_pubkey_bytes(&tx.to).unwrap());
    let body = SendTxReq { from: &from_pk_hex, to: &to_pk_hex, amount: tx.amount, signature: &tx.signature };
    let resp = Client::new().post(url).json(&body).send().await;
    matches!(resp, Ok(r) if r.status().is_success())
}

async fn broadcast_many(rpc: &str, txs: Vec<PendingTx>) -> Result<Vec<PendingTx>> {
    let mut left = Vec::new();
    for tx in txs {
        if !broadcast_one(rpc, &tx).await { left.push(tx); }
    }
    Ok(left)
}
