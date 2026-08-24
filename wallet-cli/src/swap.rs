//! Wallet side of the cross-chain atomic swap protocol.
//!
//! The wallet never holds the escrow: it only builds the three HTLC
//! transactions the node understands and keeps the secrets that unlock them.
//!
//! Typical USDC(ETH) -> USDC(SOL) trade where LofSwap carries the LFS leg:
//!
//! ```text
//! maker: swap-secret                       # secret S, hashlock H = sha256(S)
//! maker: swap-lock --to <taker> --amount N --hours 24 --foreign ...
//! taker: locks the foreign asset under the SAME H, with a SHORTER timelock
//! maker: claims the foreign leg -> reveals S
//! taker: swap-claim <swap_id> <S>          # or maker's LFS leg is refunded
//! ```

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

use blockchain_core::{
    CHAIN_ID, ForeignLeg, SwapPayload, Transaction, TxKind, pubkey_to_address,
    swap::{
        SWAP_MAX_LOCK_SECS, SWAP_MIN_LOCK_SECS, SWAP_TX_VERSION, hashlock_for_secret_hex,
        is_hex_of_len, swap_escrow_address, swap_id,
    },
};
use chrono::Utc;
use rand::rand_core::Rng;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    CONNECT_TIMEOUT, DEFAULT_TX_FEE, MIN_BROADCAST_PEERS, PeerStore, broadcast, default_address,
    ensure_cache_dir, fetch_next_nonce_from_peers, load_default_wallet,
};

const SECRETS_FILE: &str = "wallet-cache/swap_secrets.json";
const DEFAULT_LOCK_HOURS: i64 = 24;

/// A swap as reported by a node (`/swap/{id}`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapView {
    pub swap_id: String,
    pub escrow: String,
    pub maker: String,
    pub recipient: String,
    pub amount: u64,
    pub hashlock: String,
    pub timelock: i64,
    #[serde(default)]
    pub foreign: Option<ForeignLeg>,
    pub status: String,
    #[serde(default)]
    pub lock_txid: String,
    #[serde(default)]
    pub lock_height: u64,
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub settle_txid: String,
    #[serde(default)]
    pub payout: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SecretEntry {
    secret: String,
    created_at: i64,
    #[serde(default)]
    note: String,
}

/// Locally stored preimages, keyed by their hashlock.
///
/// Losing this file before a claim means losing the swap: the counterparty can
/// still refund after the timelock, but the coins locked *for* you are gone.
fn load_secrets() -> BTreeMap<String, SecretEntry> {
    std::fs::read_to_string(SECRETS_FILE)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn save_secrets(map: &BTreeMap<String, SecretEntry>) {
    ensure_cache_dir();
    match serde_json::to_string_pretty(map) {
        Ok(json) => {
            if let Err(e) = std::fs::write(SECRETS_FILE, json) {
                println!("Warning: could not persist swap secrets: {}", e);
            }
        }
        Err(e) => println!("Warning: could not serialize swap secrets: {}", e),
    }
}

fn remember_secret(secret: &str, hashlock: &str, note: &str) {
    let mut map = load_secrets();
    map.insert(
        hashlock.to_string(),
        SecretEntry {
            secret: secret.to_string(),
            created_at: Utc::now().timestamp(),
            note: note.to_string(),
        },
    );
    save_secrets(&map);
}

fn secret_for_hashlock(hashlock: &str) -> Option<String> {
    load_secrets().get(hashlock).map(|e| e.secret.clone())
}

fn random_secret_hex() -> String {
    // Same CSPRNG the wallet uses for key material.
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Sends a request path to peers and returns the first answer.
fn query_peers(store: &mut PeerStore, path: &str) -> Option<String> {
    store.discover();
    let peers: Vec<String> = store.as_slice().to_vec();
    for p in peers {
        let Ok(sock) = p.parse::<SocketAddr>() else {
            continue;
        };
        if let Ok(mut s) = TcpStream::connect_timeout(&sock, CONNECT_TIMEOUT) {
            let _ = s.set_read_timeout(Some(CONNECT_TIMEOUT));
            let _ = s.set_write_timeout(Some(CONNECT_TIMEOUT));
            if s.write_all(path.as_bytes()).is_ok() {
                let mut buf = String::new();
                if s.read_to_string(&mut buf).is_ok() {
                    let trimmed = buf.trim().to_string();
                    if !trimmed.is_empty() && trimmed != "unknown swap" {
                        return Some(trimmed);
                    }
                }
            }
        }
    }
    None
}

fn fetch_swap(store: &mut PeerStore, id: &str) -> Option<SwapView> {
    let raw = query_peers(store, &format!("/swap/{}", id))?;
    match serde_json::from_str::<SwapView>(&raw) {
        Ok(view) => Some(view),
        Err(e) => {
            println!("Could not read the swap record from peers: {}", e);
            None
        }
    }
}

fn sign(sk: &SecretKey, mut tx: Transaction) -> Transaction {
    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, sk).to_string();
    tx.pubkey = pk.clone();
    let hash = Sha256::digest(tx.signing_preimage(&pk).as_bytes());
    let sig = secp.sign_ecdsa(Message::from_digest(hash.into()), sk);
    tx.signature = hex::encode(sig.serialize_compact());
    tx.txid = tx.compute_txid();
    tx
}

fn print_swap(view: &SwapView) {
    println!("Swap {}", view.swap_id);
    println!("  status     : {}", view.status);
    println!("  escrow     : {}", view.escrow);
    println!("  maker      : {}", view.maker);
    println!("  recipient  : {}", view.recipient);
    println!("  amount     : {} LFS", view.amount);
    println!("  hashlock   : {}", view.hashlock);
    println!(
        "  timelock   : {} ({})",
        view.timelock,
        remaining_label(view.timelock)
    );
    match view.foreign.as_ref() {
        Some(f) => println!(
            "  counter-leg: {} {} on {} -> {}{}",
            f.amount,
            f.asset,
            f.chain,
            f.beneficiary,
            if f.htlc_ref.is_empty() {
                String::new()
            } else {
                format!(" (htlc {})", f.htlc_ref)
            }
        ),
        None => println!("  counter-leg: -"),
    }
    if !view.secret.is_empty() {
        println!("  secret     : {} (revealed on chain)", view.secret);
    }
    if !view.settle_txid.is_empty() {
        println!("  settled by : {} ({} LFS)", view.settle_txid, view.payout);
    }
}

fn remaining_label(timelock: i64) -> String {
    let now = Utc::now().timestamp();
    if timelock <= now {
        return "expired, refundable".to_string();
    }
    let secs = timelock - now;
    format!("{}h {}m left", secs / 3600, (secs % 3600) / 60)
}

fn parse_foreign(spec: &str) -> Result<ForeignLeg, String> {
    let parts: Vec<&str> = spec.split(',').collect();
    if parts.len() < 4 || parts.len() > 5 {
        return Err(
            "expected --foreign <chain>,<asset>,<base-unit-amount>,<beneficiary>[,<htlc-ref>]"
                .to_string(),
        );
    }
    let leg = ForeignLeg {
        chain: parts[0].trim().to_string(),
        asset: parts[1].trim().to_string(),
        amount: parts[2].trim().to_string(),
        beneficiary: parts[3].trim().to_string(),
        htlc_ref: parts
            .get(4)
            .map(|s| s.trim().to_string())
            .unwrap_or_default(),
    };
    leg.validate()?;
    Ok(leg)
}

/// `swap-secret` — draw a fresh preimage and store it locally.
pub fn cmd_swap_secret() {
    let secret = random_secret_hex();
    let Some(hashlock) = hashlock_for_secret_hex(&secret) else {
        println!("Could not derive the hashlock");
        return;
    };
    remember_secret(&secret, &hashlock, "manual");
    println!("secret   : {}   (keep private until you claim)", secret);
    println!(
        "hashlock : {}   (share this with the counterparty)",
        hashlock
    );
    println!("Stored in {}", SECRETS_FILE);
}

/// `swap-lock --to <addr> --amount <n> [--hours <h>] [--hashlock <hex>] [--foreign ...]`
pub fn cmd_swap_lock(store: &mut PeerStore, args: &[&str]) {
    let mut to = String::new();
    let mut amount: Option<u64> = None;
    let mut hours = DEFAULT_LOCK_HOURS;
    let mut hashlock: Option<String> = None;
    let mut foreign: Option<ForeignLeg> = None;

    let mut i = 0;
    while i < args.len() {
        let Some(value) = args.get(i + 1) else {
            println!("Missing value for {}", args[i]);
            return;
        };
        match args[i] {
            "--to" => to = value.to_string(),
            "--amount" => match value.parse::<u64>() {
                Ok(v) if v > DEFAULT_TX_FEE => amount = Some(v),
                _ => {
                    println!(
                        "--amount must be an integer greater than the fee ({})",
                        DEFAULT_TX_FEE
                    );
                    return;
                }
            },
            "--hours" => match value.parse::<i64>() {
                Ok(v) => hours = v,
                Err(_) => {
                    println!("--hours must be an integer");
                    return;
                }
            },
            "--hashlock" => hashlock = Some(value.to_lowercase()),
            "--foreign" => match parse_foreign(value) {
                Ok(leg) => foreign = Some(leg),
                Err(e) => {
                    println!("Invalid --foreign: {}", e);
                    return;
                }
            },
            other => {
                println!("Unknown option {}", other);
                return;
            }
        }
        i += 2;
    }

    let Some(amount) = amount else {
        println!(
            "Usage: swap-lock --to <LFS_ADDRESS> --amount <n> [--hours <h>] [--hashlock <hex>] [--foreign <chain>,<asset>,<amount>,<beneficiary>[,<ref>]]"
        );
        return;
    };
    if to.is_empty() {
        println!("Usage: swap-lock --to <LFS_ADDRESS> --amount <n> ...");
        return;
    }

    let timelock_secs = hours.saturating_mul(3600);
    if !(SWAP_MIN_LOCK_SECS..=SWAP_MAX_LOCK_SECS).contains(&timelock_secs) {
        println!(
            "--hours must be between {} and {}",
            SWAP_MIN_LOCK_SECS / 3600 + 1,
            SWAP_MAX_LOCK_SECS / 3600
        );
        return;
    }

    // Either we start the swap (we draw the secret) or we answer somebody
    // else's hashlock — in that case we must NOT know the secret.
    let (hashlock, own_secret) = match hashlock {
        Some(h) => {
            if !is_hex_of_len(&h, 64) {
                println!("--hashlock must be a 64 character sha256 hex digest");
                return;
            }
            (h, false)
        }
        None => {
            let secret = random_secret_hex();
            let Some(h) = hashlock_for_secret_hex(&secret) else {
                println!("Could not derive the hashlock");
                return;
            };
            remember_secret(&secret, &h, &format!("lock to {}", to));
            (h, true)
        }
    };

    let Some(sk) = load_default_wallet() else {
        println!("No default wallet");
        return;
    };
    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, &sk).to_string();
    let maker = pubkey_to_address(&pk);
    if maker == to {
        println!("The recipient must be somebody else");
        return;
    }

    let ts = Utc::now().timestamp();
    let timelock = ts + timelock_secs;
    let nonce = fetch_next_nonce_from_peers(store, &maker).unwrap_or(0);
    let id = swap_id(
        CHAIN_ID,
        &maker,
        &to,
        amount,
        &hashlock,
        timelock,
        nonce,
        foreign.as_ref(),
    );
    let escrow = swap_escrow_address(&id);

    let tx = sign(
        &sk,
        Transaction {
            version: SWAP_TX_VERSION,
            chain_id: CHAIN_ID.to_string(),
            kind: TxKind::SwapLock,
            timestamp: ts,
            from: maker,
            to: escrow.clone(),
            amount,
            fee: DEFAULT_TX_FEE,
            signature: String::new(),
            pubkey: String::new(),
            nonce,
            txid: String::new(),
            swap: Some(SwapPayload {
                swap_id: id.clone(),
                hashlock: hashlock.clone(),
                timelock,
                recipient: to.clone(),
                secret: String::new(),
                foreign,
            }),
        },
    );

    println!("swap_id  : {}", id);
    println!("escrow   : {}", escrow);
    println!("hashlock : {}", hashlock);
    println!("timelock : {} ({})", timelock, remaining_label(timelock));
    if own_secret {
        println!(
            "You hold the secret. Give the counterparty only the hashlock, and make sure\n\
             their leg expires well BEFORE {} so you can never be left short.",
            timelock
        );
    } else {
        println!(
            "You are answering somebody else's hashlock: your timelock must be SHORTER than\n\
             theirs. Do not release anything until you see the secret on chain."
        );
    }

    match serde_json::to_vec(&tx) {
        Ok(payload) => broadcast(store, &payload, MIN_BROADCAST_PEERS),
        Err(e) => println!("Could not serialize the lock transaction: {}", e),
    }
}

fn settle(store: &mut PeerStore, id: &str, secret: Option<&str>, kind: TxKind) {
    let Some(view) = fetch_swap(store, id) else {
        println!("Swap {} not found on any reachable peer", id);
        return;
    };
    if view.status != "open" {
        println!("Swap is already {}", view.status);
        return;
    }
    let Some(sk) = load_default_wallet() else {
        println!("No default wallet");
        return;
    };
    let me = pubkey_to_address(&PublicKey::from_secret_key(&Secp256k1::new(), &sk).to_string());

    let (to, secret) = match kind {
        TxKind::SwapClaim => {
            if me != view.recipient {
                println!(
                    "Only {} can claim this swap (your address is {})",
                    view.recipient, me
                );
                return;
            }
            let secret = secret
                .map(|s| s.to_lowercase())
                .or_else(|| secret_for_hashlock(&view.hashlock));
            let Some(secret) = secret else {
                println!(
                    "No secret for hashlock {}. Pass it explicitly: swap-claim <swap_id> <secret>",
                    view.hashlock
                );
                return;
            };
            match hashlock_for_secret_hex(&secret) {
                Some(h) if h == view.hashlock => {}
                Some(_) => {
                    println!("That secret does not match the swap's hashlock");
                    return;
                }
                None => {
                    println!("The secret must be 32 bytes of hex (64 characters)");
                    return;
                }
            }
            if Utc::now().timestamp() >= view.timelock {
                println!("The claim window has closed; the maker can refund this swap now");
                return;
            }
            (view.recipient.clone(), secret)
        }
        TxKind::SwapRefund => {
            if me != view.maker {
                println!(
                    "Only {} can refund this swap (your address is {})",
                    view.maker, me
                );
                return;
            }
            if Utc::now().timestamp() < view.timelock {
                println!(
                    "Too early: this swap can only be refunded after {} ({})",
                    view.timelock,
                    remaining_label(view.timelock)
                );
                return;
            }
            (view.maker.clone(), String::new())
        }
        _ => return,
    };

    if view.amount <= DEFAULT_TX_FEE {
        println!("Escrow is too small to cover the settlement fee");
        return;
    }
    let nonce = fetch_next_nonce_from_peers(store, &view.escrow).unwrap_or(0);
    let tx = sign(
        &sk,
        Transaction {
            version: SWAP_TX_VERSION,
            chain_id: CHAIN_ID.to_string(),
            kind: kind.clone(),
            timestamp: Utc::now().timestamp(),
            from: view.escrow.clone(),
            to,
            // The escrow is drained in full: payout + fee == locked amount.
            amount: view.amount - DEFAULT_TX_FEE,
            fee: DEFAULT_TX_FEE,
            signature: String::new(),
            pubkey: String::new(),
            nonce,
            txid: String::new(),
            swap: Some(SwapPayload {
                swap_id: view.swap_id.clone(),
                hashlock: view.hashlock.clone(),
                timelock: view.timelock,
                recipient: view.recipient.clone(),
                secret,
                foreign: None,
            }),
        },
    );

    if kind == TxKind::SwapClaim {
        println!(
            "Claiming {} LFS from {}. This publishes the secret, which lets the counterparty\n\
             settle the other leg — expect them to do so immediately.",
            view.amount - DEFAULT_TX_FEE,
            view.escrow
        );
    }
    match serde_json::to_vec(&tx) {
        Ok(payload) => broadcast(store, &payload, MIN_BROADCAST_PEERS),
        Err(e) => println!("Could not serialize the settlement transaction: {}", e),
    }
}

/// `swap-claim <swap_id> [secret]`
pub fn cmd_swap_claim(store: &mut PeerStore, id: &str, secret: Option<&str>) {
    settle(store, id, secret, TxKind::SwapClaim);
}

/// `swap-refund <swap_id>`
pub fn cmd_swap_refund(store: &mut PeerStore, id: &str) {
    settle(store, id, None, TxKind::SwapRefund);
}

/// `swap-show <swap_id|escrow>`
pub fn cmd_swap_show(store: &mut PeerStore, id: &str) {
    match fetch_swap(store, id) {
        Some(view) => print_swap(&view),
        None => println!("Swap {} not found on any reachable peer", id),
    }
}

/// `swap-list [address|open]`
pub fn cmd_swap_list(store: &mut PeerStore, filter: Option<&str>) {
    let path = match filter {
        Some("open") => "/swaps/open".to_string(),
        Some(addr) => format!("/swaps/address/{}", addr),
        None => match default_address() {
            Some(addr) => format!("/swaps/address/{}", addr),
            None => "/swaps/open".to_string(),
        },
    };
    let Some(raw) = query_peers(store, &path) else {
        println!("No response from peers");
        return;
    };
    match serde_json::from_str::<Vec<SwapView>>(&raw) {
        Ok(list) if list.is_empty() => println!("No swaps"),
        Ok(list) => {
            for view in &list {
                print_swap(view);
                println!();
            }
        }
        Err(e) => println!("Could not read the swap list: {}", e),
    }
}
