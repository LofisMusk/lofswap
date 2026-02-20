use std::{
    convert::TryInto,
    fs::{self, OpenOptions},
    io::Write,
    net::TcpStream as StdTcpStream,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use blockchain_core::{Block, CHAIN_ID, Transaction, TxKind, pubkey_to_address};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde_json::{self, Value};
use sha2::{Digest, Sha256};

use crate::{
    chain,
    storage::{data_path, ensure_parent_dir, read_data_file},
};

#[allow(dead_code)]
pub fn secret_key_from_bytes(bytes: Vec<u8>) -> Option<SecretKey> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    SecretKey::from_byte_array(arr).ok()
}

pub fn read_mempool() -> Vec<Transaction> {
    read_data_file("mempool.json")
        .ok()
        .flatten()
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

#[allow(dead_code)]
pub fn latest_transaction(chain: &[Block]) -> Option<Transaction> {
    chain.last().and_then(|b| b.transactions.last().cloned())
}

#[allow(dead_code)]
pub fn wallet_save_default(sk: &SecretKey) {
    let _ = fs::write(".default_wallet", hex::encode(sk.secret_bytes()));
}

#[allow(dead_code)]
pub fn wallet_load_default() -> Option<SecretKey> {
    fs::read_to_string(".default_wallet")
        .ok()
        .and_then(|h| hex::decode(h.trim()).ok())
        .and_then(secret_key_from_bytes)
}

#[allow(dead_code)]
pub fn wallet_remove_default() {
    let _ = fs::remove_file(".default_wallet");
}

#[allow(dead_code)]
pub fn wallet_info_json() -> String {
    if let Some(sk) = wallet_load_default() {
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        serde_json::json!({"public_key": pk.to_string()}).to_string()
    } else {
        "{\"public_key\":null}".into()
    }
}

#[allow(dead_code)]
pub fn wallet_keys_json(confirmed: bool) -> String {
    if let Some(sk) = wallet_load_default() {
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        if confirmed {
            serde_json::json!({
                "public_key": pk.to_string(),
                "private_key": hex::encode(sk.secret_bytes())
            })
            .to_string()
        } else {
            serde_json::json!({"public_key": pk.to_string(), "private_key": null}).to_string()
        }
    } else {
        "{\"public_key\":null}".into()
    }
}

#[allow(dead_code)]
pub fn export_wallet_dat_bytes() -> Option<Vec<u8>> {
    wallet_load_default().map(|sk| sk.secret_bytes().to_vec())
}

#[allow(dead_code)]
pub fn wallet_pending_count() -> usize {
    fs::read_to_string(data_path("wallet_mempool.json"))
        .or_else(|_| fs::read_to_string("wallet_mempool.json"))
        .ok()
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

#[allow(dead_code)]
pub fn build_tx(sk: &SecretKey, to: &str, amount: u64) -> Transaction {
    const DEFAULT_TX_FEE: u64 = 1;
    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, sk);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let from_addr = pubkey_to_address(&pk.to_string());
    let nonce = if cfg!(test) {
        0
    } else {
        let chain = chain::load_chain().unwrap_or_default();
        chain::next_nonce_for_address(&from_addr, &chain)
    };
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
    let msg = Message::from_digest(hash.into());
    let sig = secp.sign_ecdsa(msg, sk);
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

#[allow(dead_code)]
pub fn broadcast_tx_payload(json: &[u8], min_peers: usize) -> (usize, usize) {
    let peers: Vec<String> = chain::load_peers().unwrap_or_default();
    let mut ok = 0usize;
    for p in &peers {
        if let Ok(addr) = p.parse::<std::net::SocketAddr>() {
            if let Ok(mut s) = StdTcpStream::connect_timeout(&addr, Duration::from_millis(800)) {
                if s.write_all(json).is_ok() {
                    ok += 1;
                }
            }
        }
    }
    if ok < min_peers {
        let path = data_path("wallet_mempool.json");
        let _ = ensure_parent_dir(&path)
            .and_then(|_| OpenOptions::new().append(true).create(true).open(&path))
            .or_else(|_| {
                // legacy fallback to cwd
                OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open("wallet_mempool.json")
            })
            .and_then(|mut f| f.write_all(json).and_then(|_| f.write_all(b"\n")));
    }
    (ok, peers.len())
}

#[allow(dead_code)]
pub fn try_broadcast_pending(min_peers: usize) -> usize {
    let txt = fs::read_to_string(data_path("wallet_mempool.json"))
        .or_else(|_| fs::read_to_string("wallet_mempool.json"))
        .unwrap_or_default();
    let lines: Vec<_> = txt.lines().collect();
    if lines.is_empty() {
        return 0;
    }
    let peers: Vec<String> = chain::load_peers().unwrap_or_default();
    if peers.is_empty() {
        return 0;
    }
    let mut sent = 0usize;
    let mut failed = Vec::new();
    for line in lines {
        if let Ok(val) = serde_json::from_str::<Value>(line) {
            let payload = serde_json::to_vec(&val).unwrap();
            let mut ok = 0usize;
            for p in &peers {
                if let Ok(addr) = p.parse::<std::net::SocketAddr>() {
                    if let Ok(mut s) =
                        StdTcpStream::connect_timeout(&addr, Duration::from_millis(800))
                    {
                        if s.write_all(&payload).is_ok() {
                            ok += 1;
                            if ok >= min_peers {
                                break;
                            }
                        }
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
    let path = data_path("wallet_mempool.json");
    let _ = ensure_parent_dir(&path)
        .and_then(|_| fs::write(&path, failed.join("\n")))
        .or_else(|_| fs::write("wallet_mempool.json", failed.join("\n")));
    sent
}
