use std::sync::{Arc, atomic::AtomicUsize};

use once_cell::sync::Lazy;
use rand::RngCore;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Duration;

mod chain;
mod cli;
mod errors;
mod miner;
mod p2p;
mod storage;
mod upnp;
mod wallet;

use storage::{ensure_data_dir, read_data_file, write_data_file};

pub use errors::NodeError;

pub static OBSERVED_IP: Lazy<RwLock<Option<String>>> = Lazy::new(|| RwLock::new(None));
pub static NODE_ID: Lazy<String> = Lazy::new(|| load_or_create_node_id());
pub const NODE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

pub const LISTEN_PORT: u16 = 6000;
pub const BOOTSTRAP_NODES: &[&str] = &["89.168.107.239:6000", "79.76.116.108:6000"];
pub const MAX_CONNECTIONS: usize = 50;
pub const BUFFER_SIZE: usize = 8192;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut no_upnp = false;
    let mut no_peer_exchange = false;
    let mut _miner_mode = false;
    let mut _fullnode_mode = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--no-upnp" => no_upnp = true,
            "--no-peer-exchange" => no_peer_exchange = true,
            "--miner" => _miner_mode = true,
            "--fullnode" => _fullnode_mode = true,
            _ => {}
        }
        i += 1;
    }

    println!("[STARTUP] Starting blockchain node...");
    ensure_data_dir()?;

    // Build a Tokio runtime manually to avoid relying on the #[tokio::main] proc-macro.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        if !no_upnp {
            println!(
                "[STARTUP] Step 1: Attempting UPnP port mapping for port {}...",
                LISTEN_PORT
            );
            match upnp::setup_upnp(LISTEN_PORT).await {
                Ok(_) => println!("[STARTUP] UPnP port mapping successful"),
                Err(e) => {
                    eprintln!(
                        "[STARTUP] UPnP port mapping failed: {}. Continuing without it.",
                        e
                    );
                }
            }
        } else {
            println!("[STARTUP] Step 1: Skipping UPnP setup (--no-upnp flag set)");
        }

        let loaded_chain = chain::load_chain()?;
        if let Ok((before, after)) = chain::prune_mempool(&loaded_chain) {
            if before != after {
                println!(
                    "[STARTUP] Pruned mempool: {} invalid/stale txs removed ({} -> {})",
                    before.saturating_sub(after),
                    before,
                    after
                );
            }
        }
        let blockchain = Arc::new(Mutex::new(loaded_chain));
        let peers = Arc::new(Mutex::new(chain::load_peers()?));

        println!("[STARTUP] Starting TCP server on port {}...", LISTEN_PORT);
        p2p::start_tcp_server(blockchain.clone(), peers.clone()).await?;

        tokio::spawn(p2p::maintenance_loop(blockchain.clone(), peers.clone()));
        println!("[STARTUP] Auto-miner enabled (10s cadence when mempool has txs)...");
        let bc = blockchain.clone();
        tokio::spawn(async move {
            miner::miner_loop(bc).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        if !no_peer_exchange {
            p2p::bootstrap_and_discover_ip(&peers).await;
        } else {
            println!(
                "[STARTUP] Skipping peer exchange and IP discovery (--no-peer-exchange flag set)"
            );
        }

        println!("[STARTUP] Node initialization complete!");
        println!("[STARTUP] Launching command line interface...");
        cli::run_cli(blockchain, peers).await;

        Ok::<(), Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{remove_data_file, write_data_file};
    use blockchain_core::{Block, CHAIN_ID, Transaction, pubkey_to_address};
    use once_cell::sync::Lazy;
    use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
    use serde_json;
    use sha2::{Digest, Sha256};
    use std::sync::{Mutex as StdMutex, MutexGuard};

    static TEST_IO_LOCK: Lazy<StdMutex<()>> = Lazy::new(|| StdMutex::new(()));

    fn test_guard() -> MutexGuard<'static, ()> {
        TEST_IO_LOCK.lock().expect("test io lock poisoned")
    }

    fn tmp_clean_files() {
        let _ = remove_data_file("mempool.json");
        let _ = remove_data_file("wallet_mempool.json");
    }

    fn signed_tx(sk: &SecretKey, to: &str, amount: u64, nonce: u64, ts: i64) -> Transaction {
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, sk);
        let from = pubkey_to_address(&pk.to_string());
        let preimage = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            3, CHAIN_ID, pk, to, amount, ts, nonce
        );
        let hash = Sha256::digest(preimage.as_bytes());
        let sig = secp.sign_ecdsa(Message::from_digest(hash.into()), sk);
        let mut tx = Transaction {
            version: 3,
            chain_id: CHAIN_ID.to_string(),
            timestamp: ts,
            from,
            to: to.into(),
            amount,
            signature: hex::encode(sig.serialize_compact()),
            pubkey: pk.to_string(),
            nonce,
            txid: String::new(),
        };
        tx.txid = tx.compute_txid();
        tx
    }

    #[test]
    fn tx_signature_validates() {
        let _guard = test_guard();
        tmp_clean_files();
        let sk = SecretKey::from_byte_array([1u8; 32]).unwrap();
        let from_pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk).to_string();
        let reward = Transaction {
            version: 1,
            chain_id: CHAIN_ID.to_string(),
            timestamp: 0,
            from: String::new(),
            to: pubkey_to_address(&from_pk),
            amount: 100,
            signature: "reward".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
        };
        let chain = vec![Block {
            version: 1,
            index: 0,
            timestamp: 0,
            transactions: vec![reward],
            previous_hash: "0".into(),
            nonce: 0,
            hash: "0000".into(),
            miner: "test".into(),
            difficulty: 4,
        }];
        let tx = signed_tx(&sk, "LFS11111111111111111111", 10, 0, 1);
        assert!(
            chain::is_tx_valid(&tx, &chain).is_ok(),
            "expected tx to be valid"
        );
    }

    #[test]
    fn mempool_double_spend_is_blocked() {
        let _guard = test_guard();
        tmp_clean_files();
        let from_sk = SecretKey::from_byte_array([2u8; 32]).unwrap();
        let from_pk = PublicKey::from_secret_key(&Secp256k1::new(), &from_sk).to_string();
        let reward = Transaction {
            version: 1,
            chain_id: CHAIN_ID.to_string(),
            timestamp: 0,
            from: String::new(),
            to: pubkey_to_address(&from_pk),
            amount: 100,
            signature: "reward".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
        };
        let fake_block = Block {
            version: 1,
            index: 0,
            timestamp: 0,
            transactions: vec![reward],
            previous_hash: "0".into(),
            nonce: 0,
            hash: "0000".into(),
            miner: "test".into(),
            difficulty: 4,
        };
        let chain = vec![fake_block];

        let tx1 = signed_tx(&from_sk, "LFS11111111111111111111", 60, 0, 1);
        assert!(chain::is_tx_valid(&tx1, &chain).is_ok());
        let _ = write_data_file(
            "mempool.json",
            &format!("{}\n", serde_json::to_string(&tx1).unwrap()),
        );

        let tx2 = signed_tx(&from_sk, "LFS11111111111111111111", 50, 1, 2);
        let err = chain::is_tx_valid(&tx2, &chain).unwrap_err();
        match err {
            NodeError::ValidationError(msg) => assert!(
                msg.contains("Insufficient balance") || msg.contains("Invalid nonce"),
                "unexpected validation error: {}",
                msg
            ),
            _ => panic!("unexpected error"),
        }
    }

    #[test]
    fn block_with_lfs_sender_and_pubkey_validates() {
        let _guard = test_guard();
        tmp_clean_files();
        let from_sk = SecretKey::from_byte_array([3u8; 32]).unwrap();
        let from_pk = PublicKey::from_secret_key(&Secp256k1::new(), &from_sk).to_string();
        let reward = Transaction {
            version: 1,
            chain_id: CHAIN_ID.to_string(),
            timestamp: 0,
            from: String::new(),
            to: pubkey_to_address(&from_pk),
            amount: 100,
            signature: "reward".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
        };
        let genesis = Block {
            version: 1,
            index: 0,
            timestamp: 0,
            transactions: vec![reward],
            previous_hash: "0".into(),
            nonce: 0,
            hash: "0000genesis".into(),
            miner: "test".into(),
            difficulty: 4,
        };
        let chain = vec![genesis.clone()];

        let tx = signed_tx(&from_sk, "LFS11111111111111111111", 10, 0, 1);
        let block = Block::new(1, vec![tx], genesis.hash.clone(), "miner".into());
        assert!(chain::validate_block(&block, Some(&genesis), &chain).is_ok());
    }

    #[test]
    fn raw_pubkey_recipient_is_credited_to_recipient_address() {
        let _guard = test_guard();
        tmp_clean_files();
        let from_sk = SecretKey::from_byte_array([4u8; 32]).unwrap();
        let to_sk = SecretKey::from_byte_array([5u8; 32]).unwrap();
        let from_pk = PublicKey::from_secret_key(&Secp256k1::new(), &from_sk).to_string();
        let to_pk = PublicKey::from_secret_key(&Secp256k1::new(), &to_sk).to_string();
        let to_addr = pubkey_to_address(&to_pk);
        let reward = Transaction {
            version: 1,
            chain_id: CHAIN_ID.to_string(),
            timestamp: 0,
            from: String::new(),
            to: pubkey_to_address(&from_pk),
            amount: 100,
            signature: "reward".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
        };
        let tx = signed_tx(&from_sk, &to_pk, 25, 0, 1);
        let chain = vec![Block {
            version: 1,
            index: 0,
            timestamp: 0,
            transactions: vec![reward, tx],
            previous_hash: "0".into(),
            nonce: 0,
            hash: "0000".into(),
            miner: "test".into(),
            difficulty: 4,
        }];

        assert_eq!(chain::calculate_balance(&to_addr, &chain), 25);
    }

    #[test]
    fn full_balance_tx_in_mempool_is_mineable() {
        let _guard = test_guard();
        tmp_clean_files();
        let from_sk = SecretKey::from_byte_array([6u8; 32]).unwrap();
        let from_pk = PublicKey::from_secret_key(&Secp256k1::new(), &from_sk).to_string();
        let reward = Transaction {
            version: 1,
            chain_id: CHAIN_ID.to_string(),
            timestamp: 0,
            from: String::new(),
            to: pubkey_to_address(&from_pk),
            amount: 500,
            signature: "reward".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
        };
        let chain = vec![Block {
            version: 1,
            index: 0,
            timestamp: 0,
            transactions: vec![reward],
            previous_hash: "0".into(),
            nonce: 0,
            hash: "0000".into(),
            miner: "test".into(),
            difficulty: 4,
        }];

        let tx = signed_tx(&from_sk, "LFS11111111111111111111", 500, 0, 1);
        let _ = write_data_file(
            "mempool.json",
            &format!("{}\n", serde_json::to_string(&tx).unwrap()),
        );

        let valid = chain::load_valid_transactions(&chain);
        assert_eq!(valid.len(), 1, "expected tx to be mineable from mempool");
    }

    #[test]
    fn invalid_recipient_is_rejected() {
        let _guard = test_guard();
        tmp_clean_files();
        let from_sk = SecretKey::from_byte_array([7u8; 32]).unwrap();
        let from_pk = PublicKey::from_secret_key(&Secp256k1::new(), &from_sk).to_string();
        let reward = Transaction {
            version: 1,
            chain_id: CHAIN_ID.to_string(),
            timestamp: 0,
            from: String::new(),
            to: pubkey_to_address(&from_pk),
            amount: 100,
            signature: "reward".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
        };
        let chain = vec![Block {
            version: 1,
            index: 0,
            timestamp: 0,
            transactions: vec![reward],
            previous_hash: "0".into(),
            nonce: 0,
            hash: "0000".into(),
            miner: "test".into(),
            difficulty: 4,
        }];
        let tx = signed_tx(&from_sk, "not-an-address", 10, 0, 1);
        let err = chain::is_tx_valid(&tx, &chain).unwrap_err();
        match err {
            NodeError::ValidationError(msg) => assert!(msg.contains("Invalid recipient address")),
            _ => panic!("unexpected error"),
        }
    }

    #[test]
    fn zero_amount_is_rejected() {
        let _guard = test_guard();
        tmp_clean_files();
        let from_sk = SecretKey::from_byte_array([8u8; 32]).unwrap();
        let from_pk = PublicKey::from_secret_key(&Secp256k1::new(), &from_sk).to_string();
        let reward = Transaction {
            version: 1,
            chain_id: CHAIN_ID.to_string(),
            timestamp: 0,
            from: String::new(),
            to: pubkey_to_address(&from_pk),
            amount: 100,
            signature: "reward".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
        };
        let chain = vec![Block {
            version: 1,
            index: 0,
            timestamp: 0,
            transactions: vec![reward],
            previous_hash: "0".into(),
            nonce: 0,
            hash: "0000".into(),
            miner: "test".into(),
            difficulty: 4,
        }];
        let mut tx = signed_tx(&from_sk, "LFS11111111111111111111", 1, 0, 1);
        tx.amount = 0;
        let err = chain::is_tx_valid(&tx, &chain).unwrap_err();
        match err {
            NodeError::ValidationError(msg) => assert!(msg.contains("Invalid amount")),
            _ => panic!("unexpected error"),
        }
    }

    #[test]
    fn nonce_sequence_is_enforced() {
        let _guard = test_guard();
        tmp_clean_files();
        let from_sk = SecretKey::from_byte_array([10u8; 32]).unwrap();
        let from_pk = PublicKey::from_secret_key(&Secp256k1::new(), &from_sk).to_string();
        let reward = Transaction {
            version: 1,
            chain_id: CHAIN_ID.to_string(),
            timestamp: 0,
            from: String::new(),
            to: pubkey_to_address(&from_pk),
            amount: 100,
            signature: "reward".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
        };
        let chain = vec![Block {
            version: 1,
            index: 0,
            timestamp: 0,
            transactions: vec![reward],
            previous_hash: "0".into(),
            nonce: 0,
            hash: "0000".into(),
            miner: "test".into(),
            difficulty: 4,
        }];
        let bad_nonce_tx = signed_tx(&from_sk, "LFS11111111111111111111", 10, 2, 1);
        let err = chain::is_tx_valid(&bad_nonce_tx, &chain).unwrap_err();
        match err {
            NodeError::ValidationError(msg) => assert!(msg.contains("Invalid nonce")),
            _ => panic!("unexpected error"),
        }
    }

    #[test]
    fn prune_mempool_removes_invalid_entries() {
        let _guard = test_guard();
        tmp_clean_files();
        let from_sk = SecretKey::from_byte_array([11u8; 32]).unwrap();
        let from_pk = PublicKey::from_secret_key(&Secp256k1::new(), &from_sk).to_string();
        let reward = Transaction {
            version: 1,
            chain_id: CHAIN_ID.to_string(),
            timestamp: 0,
            from: String::new(),
            to: pubkey_to_address(&from_pk),
            amount: 100,
            signature: "reward".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
        };
        let chain = vec![Block {
            version: 1,
            index: 0,
            timestamp: 0,
            transactions: vec![reward],
            previous_hash: "0".into(),
            nonce: 0,
            hash: "0000".into(),
            miner: "test".into(),
            difficulty: 4,
        }];
        let valid = signed_tx(&from_sk, "LFS11111111111111111111", 10, 0, 2);
        let invalid = Transaction {
            version: 3,
            chain_id: CHAIN_ID.to_string(),
            timestamp: 3,
            from: pubkey_to_address(&from_pk),
            to: "bad-address".into(),
            amount: 0,
            signature: "00".into(),
            pubkey: from_pk.clone(),
            nonce: 99,
            txid: String::new(),
        };
        let _ = write_data_file(
            "mempool.json",
            &format!(
                "{}\n{}\n",
                serde_json::to_string(&valid).unwrap(),
                serde_json::to_string(&invalid).unwrap()
            ),
        );
        let (before, after) = chain::prune_mempool(&chain).unwrap();
        assert_eq!(before, 2);
        assert_eq!(after, 1);
        assert_eq!(chain::load_valid_transactions(&chain).len(), 1);
    }

    #[test]
    fn two_node_roundtrip_block_validation() {
        let _guard = test_guard();
        tmp_clean_files();
        let from_sk = SecretKey::from_byte_array([12u8; 32]).unwrap();
        let from_pk = PublicKey::from_secret_key(&Secp256k1::new(), &from_sk).to_string();
        let reward = Transaction {
            version: 1,
            chain_id: CHAIN_ID.to_string(),
            timestamp: 0,
            from: String::new(),
            to: pubkey_to_address(&from_pk),
            amount: 100,
            signature: "reward".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
        };
        let genesis = Block {
            version: 1,
            index: 0,
            timestamp: 0,
            transactions: vec![reward],
            previous_hash: "0".into(),
            nonce: 0,
            hash: "0000genesis".into(),
            miner: "test".into(),
            difficulty: 4,
        };
        let mut node_a = vec![genesis.clone()];
        let mut node_b = vec![genesis.clone()];

        let tx = signed_tx(&from_sk, "LFS11111111111111111111", 30, 0, 4);
        assert!(chain::is_tx_valid(&tx, &node_a).is_ok());
        let block = Block::new(1, vec![tx], genesis.hash.clone(), "miner-a".into());
        assert!(chain::validate_block(&block, Some(&genesis), &node_b).is_ok());

        node_a.push(block.clone());
        node_b.push(block);
        assert_eq!(
            chain::calculate_balances(&node_a),
            chain::calculate_balances(&node_b)
        );
    }
}

fn load_or_create_node_id() -> String {
    if let Ok(Some(contents)) = read_data_file("node_id.txt") {
        let trimmed = contents.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let generated = hex::encode(bytes);
    if let Err(e) = write_data_file("node_id.txt", &generated) {
        eprintln!("[STARTUP] Failed to persist node id: {}", e);
    }
    generated
}
