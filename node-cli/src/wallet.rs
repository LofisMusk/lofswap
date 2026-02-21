use std::{
    convert::TryInto,
    fs::{self, OpenOptions},
    io::Write,
    net::TcpStream as StdTcpStream,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use blockchain_core::{
    Block, CHAIN_ID, Transaction, TxKind, pubkey_to_address,
    wallet_keystore::{
        DEFAULT_DERIVATION_PATH, decrypt_secret_key, encrypt_secret_key, load_keystore_file,
        payload_secret_key_bytes, save_keystore_file,
    },
};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde_json::{self, Value};
use sha2::{Digest, Sha256};

use crate::{
    chain,
    storage::{data_path, ensure_parent_dir},
};

const LEGACY_WALLET_FILE: &str = ".default_wallet";
const ENCRYPTED_WALLET_FILE: &str = ".default_wallet.keystore.json";
const WALLET_PASSPHRASE_ENV: &str = "LOFSWAP_WALLET_PASSPHRASE";
const PRIVATE_EXPORT_CONFIRM_ENV: &str = "LOFSWAP_ALLOW_PRIVATE_KEY_EXPORT";
const PRIVATE_EXPORT_CONFIRM_VALUE: &str = "YES_I_UNDERSTAND";

#[allow(dead_code)]
pub fn secret_key_from_bytes(bytes: Vec<u8>) -> Option<SecretKey> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    SecretKey::from_byte_array(arr).ok()
}

fn export_confirmation_ok() -> bool {
    std::env::var(PRIVATE_EXPORT_CONFIRM_ENV)
        .ok()
        .map(|v| v.trim() == PRIVATE_EXPORT_CONFIRM_VALUE)
        .unwrap_or(false)
}

fn wallet_passphrase() -> Option<String> {
    std::env::var(WALLET_PASSPHRASE_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn save_encrypted_wallet(
    sk: &SecretKey,
    mnemonic: Option<&str>,
    passphrase: &str,
) -> Result<(), String> {
    let key_bytes = sk.secret_bytes();
    let keystore = encrypt_secret_key(
        &key_bytes,
        mnemonic,
        Some(DEFAULT_DERIVATION_PATH),
        passphrase,
    )?;
    save_keystore_file(Path::new(ENCRYPTED_WALLET_FILE), &keystore)
}

fn load_encrypted_wallet(passphrase: &str) -> Option<SecretKey> {
    let keystore = load_keystore_file(Path::new(ENCRYPTED_WALLET_FILE)).ok()?;
    let payload = decrypt_secret_key(&keystore, passphrase).ok()?;
    let bytes = payload_secret_key_bytes(&payload).ok()?;
    SecretKey::from_byte_array(bytes).ok()
}

fn migrate_legacy_wallet(passphrase: &str) -> Option<SecretKey> {
    let sk = fs::read_to_string(LEGACY_WALLET_FILE)
        .ok()
        .and_then(|h| hex::decode(h.trim()).ok())
        .and_then(secret_key_from_bytes)?;

    if save_encrypted_wallet(&sk, None, passphrase).is_ok() {
        let _ = fs::remove_file(LEGACY_WALLET_FILE);
    }
    Some(sk)
}

#[allow(dead_code)]
pub fn latest_transaction(chain: &[Block]) -> Option<Transaction> {
    chain.last().and_then(|b| b.transactions.last().cloned())
}

#[allow(dead_code)]
pub fn wallet_save_default(sk: &SecretKey) {
    let Some(passphrase) = wallet_passphrase() else {
        eprintln!(
            "Wallet passphrase missing. Set {} to save encrypted wallet.",
            WALLET_PASSPHRASE_ENV
        );
        return;
    };
    if let Err(e) = save_encrypted_wallet(sk, None, &passphrase) {
        eprintln!("Failed to save encrypted wallet: {}", e);
    }
}

#[allow(dead_code)]
pub fn wallet_load_default() -> Option<SecretKey> {
    if Path::new(ENCRYPTED_WALLET_FILE).exists() {
        let Some(passphrase) = wallet_passphrase() else {
            return None;
        };
        return load_encrypted_wallet(&passphrase);
    }

    if Path::new(LEGACY_WALLET_FILE).exists() {
        let Some(passphrase) = wallet_passphrase() else {
            eprintln!(
                "Legacy wallet detected. Set {} to migrate wallet securely.",
                WALLET_PASSPHRASE_ENV
            );
            return None;
        };
        return migrate_legacy_wallet(&passphrase);
    }

    None
}

#[allow(dead_code)]
pub fn wallet_remove_default() {
    let _ = fs::remove_file(ENCRYPTED_WALLET_FILE);
    let _ = fs::remove_file(LEGACY_WALLET_FILE);
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
        if confirmed && export_confirmation_ok() {
            serde_json::json!({
                "public_key": pk.to_string(),
                "private_key": hex::encode(sk.secret_bytes())
            })
            .to_string()
        } else {
            serde_json::json!({
                "public_key": pk.to_string(),
                "private_key": null,
                "note": format!(
                    "private key export disabled unless confirmed and {}={}",
                    PRIVATE_EXPORT_CONFIRM_ENV, PRIVATE_EXPORT_CONFIRM_VALUE
                )
            })
            .to_string()
        }
    } else {
        "{\"public_key\":null}".into()
    }
}

#[allow(dead_code)]
pub fn export_wallet_dat_bytes() -> Option<Vec<u8>> {
    if !export_confirmation_ok() {
        return None;
    }
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
