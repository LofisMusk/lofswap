use std::net::ToSocketAddrs;
use std::sync::{Arc, OnceLock, atomic::AtomicUsize};

use once_cell::sync::Lazy;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Duration;

mod chain;
mod cli;
mod errors;
mod identity;
mod mempool;
mod miner;
mod p2p;
mod storage;
mod swap;
mod upnp;
mod wallet;

use storage::ensure_data_dir;

pub use errors::NodeError;

pub static OBSERVED_IP: Lazy<RwLock<Option<String>>> = Lazy::new(|| RwLock::new(None));
pub static NODE_ID: Lazy<String> = Lazy::new(identity::node_id);
pub static NODE_PUBKEY: Lazy<String> = Lazy::new(identity::public_key_hex);
pub const NODE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

pub const LISTEN_PORT: u16 = 6000;
pub const MAX_CONNECTIONS: usize = 50;
pub const BUFFER_SIZE: usize = 8192;

/// Seed nodes compiled into this build. `--peer` and `LOFSWAP_BOOTSTRAP`
/// override them, so a network whose seeds move does not need a new release.
pub const DEFAULT_BOOTSTRAP_NODES: &[&str] = &["89.168.107.239:6000", "79.76.116.108:6000"];
pub const BOOTSTRAP_ENV: &str = "LOFSWAP_BOOTSTRAP";

/// Seeds passed on the command line, filled in before the node starts.
static CLI_BOOTSTRAP: OnceLock<Vec<String>> = OnceLock::new();

pub static BOOTSTRAP_NODES: Lazy<Vec<String>> = Lazy::new(resolve_bootstrap_nodes);

/// Peers are tracked as `ip:port`, so host names are resolved once at startup.
fn resolve_bootstrap_nodes() -> Vec<String> {
    let configured: Vec<String> = CLI_BOOTSTRAP
        .get()
        .cloned()
        .filter(|peers| !peers.is_empty())
        .or_else(|| {
            std::env::var(BOOTSTRAP_ENV).ok().map(|value| {
                value
                    .split(',')
                    .map(|peer| peer.trim().to_string())
                    .filter(|peer| !peer.is_empty())
                    .collect()
            })
        })
        .filter(|peers: &Vec<String>| !peers.is_empty())
        .unwrap_or_else(|| {
            DEFAULT_BOOTSTRAP_NODES
                .iter()
                .map(|peer| (*peer).to_string())
                .collect()
        });

    let mut resolved = Vec::new();
    for peer in configured {
        match peer.to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    let addr = addr.to_string();
                    if !resolved.contains(&addr) {
                        resolved.push(addr);
                    }
                }
            }
            Err(e) => eprintln!("[STARTUP] Ignoring seed node {}: {}", peer, e),
        }
    }
    resolved
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut no_upnp = false;
    let mut no_peer_exchange = false;
    let mut miner_reward_arg: Option<String> = None;
    let mut _fullnode_mode = false;
    let mut cli_peers: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--no-upnp" => no_upnp = true,
            "--no-peer-exchange" => no_peer_exchange = true,
            "--miner" => {
                let Some(addr) = args.get(i + 1) else {
                    return Err("Usage: node-cli --miner <LFS_ADDRESS>".into());
                };
                if addr.starts_with("--") {
                    return Err("Usage: node-cli --miner <LFS_ADDRESS>".into());
                }
                miner_reward_arg = Some(addr.clone());
                i += 1;
            }
            flag if flag.starts_with("--miner=") => {
                let addr = flag.trim_start_matches("--miner=").trim().to_string();
                if addr.is_empty() {
                    return Err("Usage: node-cli --miner <LFS_ADDRESS>".into());
                }
                miner_reward_arg = Some(addr);
            }
            "--fullnode" => _fullnode_mode = true,
            "--peer" => {
                let Some(peer) = args.get(i + 1) else {
                    return Err("Usage: node-cli --peer <HOST:PORT>".into());
                };
                cli_peers.push(peer.clone());
                i += 1;
            }
            flag if flag.starts_with("--peer=") => {
                cli_peers.push(flag.trim_start_matches("--peer=").trim().to_string());
            }
            _ => {}
        }
        i += 1;
    }

    if let Some(addr) = miner_reward_arg.as_ref() {
        if !chain::is_valid_lfs_address(addr) {
            return Err(format!("Invalid miner reward address: {}", addr).into());
        }
    }

    let _ = CLI_BOOTSTRAP.set(cli_peers);

    println!("[STARTUP] Starting blockchain node...");
    if BOOTSTRAP_NODES.is_empty() {
        println!("[STARTUP] No seed nodes configured; waiting for inbound peers only");
    } else {
        println!("[STARTUP] Seed nodes: {}", BOOTSTRAP_NODES.join(", "));
    }
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
        if let Some(miner_reward_addr) = miner_reward_arg.clone() {
            println!(
                "[STARTUP] Auto-miner enabled (dynamic difficulty target=60s) reward={}",
                miner_reward_addr
            );
            let bc = blockchain.clone();
            tokio::spawn(async move {
                miner::miner_loop(bc, &miner_reward_addr).await;
            });
        } else {
            println!("[STARTUP] Auto-miner disabled (use `mine <LFS_ADDRESS>` or `--miner <LFS_ADDRESS>`)");
        }

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
    use crate::{
        chain::clear_chain_storage,
        mempool::{clear_mempool, replace_mempool},
        storage::remove_data_file,
    };
    use blockchain_core::{Block, CHAIN_ID, Transaction, TxKind, pubkey_to_address};
    use once_cell::sync::Lazy;
    use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};
    use std::sync::{Mutex as StdMutex, MutexGuard};

    static TEST_IO_LOCK: Lazy<StdMutex<()>> = Lazy::new(|| StdMutex::new(()));

    fn test_guard() -> MutexGuard<'static, ()> {
        TEST_IO_LOCK.lock().expect("test io lock poisoned")
    }

    fn tmp_clean_files() {
        let _ = clear_mempool();
        let _ = clear_chain_storage();
        let _ = remove_data_file("mempool.json");
        let _ = remove_data_file("mempool_snapshot.json");
        let _ = remove_data_file("wallet_mempool.json");
    }

    fn signed_tx(sk: &SecretKey, to: &str, amount: u64, nonce: u64, ts: i64) -> Transaction {
        const TEST_TX_FEE: u64 = 1;
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, sk);
        let from = pubkey_to_address(&pk.to_string());
        let preimage = format!(
            "{}|{}|{:?}|{}|{}|{}|{}|{}|{}",
            3,
            CHAIN_ID,
            TxKind::Transfer,
            pk,
            to,
            amount,
            TEST_TX_FEE,
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
            from,
            to: to.into(),
            amount,
            fee: TEST_TX_FEE,
            signature: hex::encode(sig.serialize_compact()),
            pubkey: pk.to_string(),
            nonce,
            txid: String::new(),
            swap: None,
        };
        tx.txid = tx.compute_txid();
        tx
    }

    #[test]
    fn block_subsidy_is_fixed_at_ten() {
        assert_eq!(chain::block_subsidy(0), 10);
        assert_eq!(chain::block_subsidy(100_000), 10);
        assert_eq!(chain::block_subsidy(u64::MAX), 10);
    }

    #[test]
    fn difficulty_retarget_increases_when_blocks_are_too_fast() {
        let genesis = Block::genesis();
        let mut chain = vec![genesis.clone()];

        for i in 1..10u64 {
            chain.push(Block {
                version: 1,
                index: i,
                timestamp: genesis.timestamp + i as i64,
                transactions: Vec::new(),
                previous_hash: chain
                    .last()
                    .map(|b| b.hash.clone())
                    .unwrap_or_else(|| "0".to_string()),
                nonce: 0,
                hash: format!("0000dummy{}", i),
                miner: "test".into(),
                difficulty: 4,
            });
        }

        assert_eq!(chain::expected_next_difficulty(&chain), 5);
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
            kind: TxKind::Coinbase,
            timestamp: 0,
            from: String::new(),
            to: pubkey_to_address(&from_pk),
            amount: 100,
            fee: 0,
            signature: "coinbase:0".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
            swap: None,
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
            kind: TxKind::Coinbase,
            timestamp: 0,
            from: String::new(),
            to: pubkey_to_address(&from_pk),
            amount: 100,
            fee: 0,
            signature: "coinbase:0".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
            swap: None,
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
        let _ = replace_mempool(vec![tx1.clone()]);

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
            kind: TxKind::Coinbase,
            timestamp: 0,
            from: String::new(),
            to: pubkey_to_address(&from_pk),
            amount: 100,
            fee: 0,
            signature: "coinbase:0".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
            swap: None,
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
        let mut coinbase = Transaction {
            version: 3,
            chain_id: CHAIN_ID.to_string(),
            kind: TxKind::Coinbase,
            timestamp: 1,
            from: String::new(),
            to: "miner".into(),
            amount: chain::block_subsidy(1).saturating_add(tx.fee),
            fee: 0,
            signature: "coinbase:1".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
            swap: None,
        };
        coinbase.txid = coinbase.compute_txid();
        let block = Block::new(1, vec![coinbase, tx], genesis.hash.clone(), "miner".into());
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
            kind: TxKind::Coinbase,
            timestamp: 0,
            from: String::new(),
            to: pubkey_to_address(&from_pk),
            amount: 100,
            fee: 0,
            signature: "coinbase:0".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
            swap: None,
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
            kind: TxKind::Coinbase,
            timestamp: 0,
            from: String::new(),
            to: pubkey_to_address(&from_pk),
            amount: 500,
            fee: 0,
            signature: "coinbase:0".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
            swap: None,
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

        let tx = signed_tx(&from_sk, "LFS11111111111111111111", 499, 0, 1);
        let _ = replace_mempool(vec![tx.clone()]);

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
            kind: TxKind::Coinbase,
            timestamp: 0,
            from: String::new(),
            to: pubkey_to_address(&from_pk),
            amount: 100,
            fee: 0,
            signature: "coinbase:0".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
            swap: None,
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
            kind: TxKind::Coinbase,
            timestamp: 0,
            from: String::new(),
            to: pubkey_to_address(&from_pk),
            amount: 100,
            fee: 0,
            signature: "coinbase:0".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
            swap: None,
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
            kind: TxKind::Coinbase,
            timestamp: 0,
            from: String::new(),
            to: pubkey_to_address(&from_pk),
            amount: 100,
            fee: 0,
            signature: "coinbase:0".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
            swap: None,
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
            kind: TxKind::Coinbase,
            timestamp: 0,
            from: String::new(),
            to: pubkey_to_address(&from_pk),
            amount: 100,
            fee: 0,
            signature: "coinbase:0".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
            swap: None,
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
            kind: TxKind::Transfer,
            timestamp: 3,
            from: pubkey_to_address(&from_pk),
            to: "bad-address".into(),
            amount: 0,
            fee: 1,
            signature: "00".into(),
            pubkey: from_pk.clone(),
            nonce: 99,
            txid: String::new(),
            swap: None,
        };
        let _ = replace_mempool(vec![valid.clone(), invalid.clone()]);
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
            kind: TxKind::Coinbase,
            timestamp: 0,
            from: String::new(),
            to: pubkey_to_address(&from_pk),
            amount: 100,
            fee: 0,
            signature: "coinbase:0".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
            swap: None,
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
        let mut coinbase = Transaction {
            version: 3,
            chain_id: CHAIN_ID.to_string(),
            kind: TxKind::Coinbase,
            timestamp: 4,
            from: String::new(),
            to: "miner-a".into(),
            amount: chain::block_subsidy(1).saturating_add(tx.fee),
            fee: 0,
            signature: "coinbase:1".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
            swap: None,
        };
        coinbase.txid = coinbase.compute_txid();
        let block = Block::new(
            1,
            vec![coinbase, tx],
            genesis.hash.clone(),
            "miner-a".into(),
        );
        assert!(chain::validate_block(&block, Some(&genesis), &node_b).is_ok());

        node_a.push(block.clone());
        node_b.push(block);
        assert_eq!(
            chain::calculate_balances(&node_a),
            chain::calculate_balances(&node_b)
        );
    }

    // == Cross-chain swap (HTLC) tests =====================================

    use crate::swap::{SwapIndex, SwapStatus, validate_swap_settlement};
    use blockchain_core::swap::{
        ForeignLeg, SwapPayload, hashlock_for_secret_hex, swap_escrow_address, swap_id,
    };

    const SWAP_FEE: u64 = 1;

    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    fn address_of(sk: &SecretKey) -> String {
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), sk);
        pubkey_to_address(&pk.to_string())
    }

    /// Signs a v4 transaction the same way the wallet does.
    fn sign_v4(sk: &SecretKey, mut tx: Transaction) -> Transaction {
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, sk);
        tx.pubkey = pk.to_string();
        let hash = Sha256::digest(tx.signing_preimage(&pk.to_string()).as_bytes());
        let sig = secp.sign_ecdsa(Message::from_digest(hash.into()), sk);
        tx.signature = hex::encode(sig.serialize_compact());
        tx.txid = tx.compute_txid();
        tx
    }

    fn coinbase(height: u64, fees: u64, ts: i64, tag: &str) -> Transaction {
        let mut tx = Transaction {
            version: 3,
            chain_id: CHAIN_ID.to_string(),
            kind: TxKind::Coinbase,
            timestamp: ts,
            from: String::new(),
            to: format!("miner-{}", tag),
            amount: chain::block_subsidy(height).saturating_add(fees),
            fee: 0,
            signature: format!("coinbase:{}", tag),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
            swap: None,
        };
        tx.txid = tx.compute_txid();
        tx
    }

    fn funded_genesis(addr: &str, amount: u64) -> Block {
        let mut reward = Transaction {
            version: 3,
            chain_id: CHAIN_ID.to_string(),
            kind: TxKind::Coinbase,
            timestamp: 0,
            from: String::new(),
            to: addr.to_string(),
            amount,
            fee: 0,
            signature: "coinbase:0".into(),
            pubkey: String::new(),
            nonce: 0,
            txid: String::new(),
            swap: None,
        };
        reward.txid = reward.compute_txid();
        Block {
            version: 1,
            index: 0,
            timestamp: 0,
            transactions: vec![reward],
            previous_hash: "0".into(),
            nonce: 0,
            hash: "0000genesis".into(),
            miner: "test".into(),
            difficulty: 4,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn swap_lock_tx(
        maker_sk: &SecretKey,
        recipient: &str,
        amount: u64,
        nonce: u64,
        ts: i64,
        timelock: i64,
        hashlock: &str,
        foreign: Option<ForeignLeg>,
    ) -> Transaction {
        let maker = address_of(maker_sk);
        let id = swap_id(
            CHAIN_ID,
            &maker,
            recipient,
            amount,
            hashlock,
            timelock,
            nonce,
            foreign.as_ref(),
        );
        sign_v4(
            maker_sk,
            Transaction {
                version: 4,
                chain_id: CHAIN_ID.to_string(),
                kind: TxKind::SwapLock,
                timestamp: ts,
                from: maker,
                to: swap_escrow_address(&id),
                amount,
                fee: SWAP_FEE,
                signature: String::new(),
                pubkey: String::new(),
                nonce,
                txid: String::new(),
                swap: Some(SwapPayload {
                    swap_id: id,
                    hashlock: hashlock.to_string(),
                    timelock,
                    recipient: recipient.to_string(),
                    secret: String::new(),
                    foreign,
                }),
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn swap_settle_tx(
        signer_sk: &SecretKey,
        kind: TxKind,
        lock: &Transaction,
        to: &str,
        ts: i64,
        secret: &str,
    ) -> Transaction {
        let payload = lock.swap.clone().expect("lock payload");
        sign_v4(
            signer_sk,
            Transaction {
                version: 4,
                chain_id: CHAIN_ID.to_string(),
                kind,
                timestamp: ts,
                from: lock.to.clone(),
                to: to.to_string(),
                amount: lock.amount - SWAP_FEE,
                fee: SWAP_FEE,
                signature: String::new(),
                pubkey: String::new(),
                nonce: 0,
                txid: String::new(),
                swap: Some(SwapPayload {
                    secret: secret.to_string(),
                    foreign: None,
                    ..payload
                }),
            },
        )
    }

    fn usdc_leg() -> ForeignLeg {
        ForeignLeg {
            chain: "eip155:1".into(),
            asset: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".into(),
            amount: "25000000".into(),
            beneficiary: "0x1111111111111111111111111111111111111111".into(),
            htlc_ref: String::new(),
        }
    }

    #[test]
    fn swap_lock_and_claim_pay_the_recipient() {
        let _guard = test_guard();
        tmp_clean_files();
        let maker_sk = SecretKey::from_byte_array([11u8; 32]).unwrap();
        let taker_sk = SecretKey::from_byte_array([12u8; 32]).unwrap();
        let maker = address_of(&maker_sk);
        let taker = address_of(&taker_sk);

        let genesis = funded_genesis(&maker, 100);
        let mut chain = vec![genesis.clone()];

        let secret = "11".repeat(32);
        let hashlock = hashlock_for_secret_hex(&secret).unwrap();
        let now = now_secs();
        let lock = swap_lock_tx(
            &maker_sk,
            &taker,
            50,
            0,
            now,
            now + 3600,
            &hashlock,
            Some(usdc_leg()),
        );
        assert!(
            chain::is_tx_valid(&lock, &chain).is_ok(),
            "lock should be accepted: {:?}",
            chain::is_tx_valid(&lock, &chain)
        );

        let block1 = Block::new(
            1,
            vec![coinbase(1, lock.fee, now, "1"), lock.clone()],
            genesis.hash.clone(),
            "miner-1".into(),
        );
        chain::validate_block(&block1, Some(&genesis), &chain).expect("lock block valid");
        chain.push(block1);

        // Escrow now holds the coins; nobody has been paid yet.
        let escrow = lock.to.clone();
        assert_eq!(chain::calculate_balance(&escrow, &chain), 50);
        assert_eq!(chain::calculate_balance(&taker, &chain), 0);
        assert_eq!(chain::calculate_balance(&maker, &chain), 49);

        let claim = swap_settle_tx(&taker_sk, TxKind::SwapClaim, &lock, &taker, now, &secret);
        assert!(
            chain::is_tx_valid(&claim, &chain).is_ok(),
            "claim should be accepted: {:?}",
            chain::is_tx_valid(&claim, &chain)
        );

        let prev = chain[1].clone();
        let block2 = Block::new(
            2,
            vec![coinbase(2, claim.fee, now, "2"), claim.clone()],
            prev.hash.clone(),
            "miner-2".into(),
        );
        chain::validate_block(&block2, Some(&prev), &chain).expect("claim block valid");
        chain.push(block2);

        assert_eq!(chain::calculate_balance(&escrow, &chain), 0);
        assert_eq!(chain::calculate_balance(&taker, &chain), 49);

        let index = SwapIndex::build(&chain);
        let record = index
            .get(&lock.swap.as_ref().unwrap().swap_id)
            .expect("swap indexed");
        assert_eq!(record.status, SwapStatus::Claimed);
        // The secret is public now, which is what unlocks the foreign leg.
        assert_eq!(record.secret, secret);
        assert_eq!(record.foreign.as_ref().unwrap().asset, usdc_leg().asset);
    }

    #[test]
    fn swap_claim_needs_the_right_secret_and_the_right_signer() {
        let _guard = test_guard();
        tmp_clean_files();
        let maker_sk = SecretKey::from_byte_array([13u8; 32]).unwrap();
        let taker_sk = SecretKey::from_byte_array([14u8; 32]).unwrap();
        let thief_sk = SecretKey::from_byte_array([15u8; 32]).unwrap();
        let maker = address_of(&maker_sk);
        let taker = address_of(&taker_sk);

        let genesis = funded_genesis(&maker, 100);
        let mut chain = vec![genesis.clone()];
        let secret = "22".repeat(32);
        let hashlock = hashlock_for_secret_hex(&secret).unwrap();
        let now = now_secs();
        let lock = swap_lock_tx(&maker_sk, &taker, 40, 0, now, now + 7200, &hashlock, None);
        let block1 = Block::new(
            1,
            vec![coinbase(1, lock.fee, now, "1"), lock.clone()],
            genesis.hash.clone(),
            "miner-1".into(),
        );
        chain::validate_block(&block1, Some(&genesis), &chain).expect("lock block valid");
        chain.push(block1);

        let wrong_secret = "33".repeat(32);
        let bad = swap_settle_tx(
            &taker_sk,
            TxKind::SwapClaim,
            &lock,
            &taker,
            now,
            &wrong_secret,
        );
        let err = chain::is_tx_valid(&bad, &chain).unwrap_err().to_string();
        assert!(err.contains("Secret does not match"), "{}", err);

        // Someone who learned the secret still cannot redirect the payout...
        let stolen = swap_settle_tx(
            &thief_sk,
            TxKind::SwapClaim,
            &lock,
            &address_of(&thief_sk),
            now,
            &secret,
        );
        let err = chain::is_tx_valid(&stolen, &chain).unwrap_err().to_string();
        assert!(err.contains("Claim must pay the swap recipient"), "{}", err);

        // ...nor claim on the recipient's behalf.
        let impersonated =
            swap_settle_tx(&thief_sk, TxKind::SwapClaim, &lock, &taker, now, &secret);
        let err = chain::is_tx_valid(&impersonated, &chain)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Only the recipient can claim"), "{}", err);
    }

    #[test]
    fn swap_refund_respects_the_timelock() {
        let _guard = test_guard();
        tmp_clean_files();
        let maker_sk = SecretKey::from_byte_array([16u8; 32]).unwrap();
        let taker_sk = SecretKey::from_byte_array([17u8; 32]).unwrap();
        let maker = address_of(&maker_sk);
        let taker = address_of(&taker_sk);
        let now = now_secs();

        let secret = "44".repeat(32);
        let hashlock = hashlock_for_secret_hex(&secret).unwrap();
        let timelock = now + 3600;
        let lock = swap_lock_tx(&maker_sk, &taker, 30, 0, now, timelock, &hashlock, None);
        let mut index = SwapIndex::build(&[]);
        index.apply(&lock, 1);

        let refund = swap_settle_tx(&maker_sk, TxKind::SwapRefund, &lock, &maker, now, "");
        // Before the deadline the maker cannot pull the funds back.
        let err = validate_swap_settlement(&refund, &index, &maker, timelock - 1)
            .unwrap_err()
            .to_string();
        assert!(err.contains("has not expired"), "{}", err);
        // After it, the refund is the only way the escrow can move.
        assert!(validate_swap_settlement(&refund, &index, &maker, timelock).is_ok());

        let claim = swap_settle_tx(&taker_sk, TxKind::SwapClaim, &lock, &taker, now, &secret);
        assert!(validate_swap_settlement(&claim, &index, &taker, timelock - 1).is_ok());
        let err = validate_swap_settlement(&claim, &index, &taker, timelock)
            .unwrap_err()
            .to_string();
        assert!(err.contains("claim window is closed"), "{}", err);

        // Only the maker gets the refund, and only to their own address.
        let err = validate_swap_settlement(&refund, &index, &taker, timelock)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Only the maker can refund"), "{}", err);
    }

    #[test]
    fn swap_cannot_be_settled_twice() {
        let _guard = test_guard();
        tmp_clean_files();
        let maker_sk = SecretKey::from_byte_array([18u8; 32]).unwrap();
        let taker_sk = SecretKey::from_byte_array([19u8; 32]).unwrap();
        let taker = address_of(&taker_sk);
        let now = now_secs();
        let secret = "55".repeat(32);
        let hashlock = hashlock_for_secret_hex(&secret).unwrap();
        let lock = swap_lock_tx(&maker_sk, &taker, 20, 0, now, now + 3600, &hashlock, None);

        let mut index = SwapIndex::build(&[]);
        index.apply(&lock, 1);
        let claim = swap_settle_tx(&taker_sk, TxKind::SwapClaim, &lock, &taker, now, &secret);
        assert!(validate_swap_settlement(&claim, &index, &taker, now).is_ok());
        index.apply(&claim, 2);

        let err = validate_swap_settlement(&claim, &index, &taker, now)
            .unwrap_err()
            .to_string();
        assert!(err.contains("already claimed"), "{}", err);
    }

    #[test]
    fn swap_lock_must_commit_to_its_terms() {
        let _guard = test_guard();
        tmp_clean_files();
        let maker_sk = SecretKey::from_byte_array([20u8; 32]).unwrap();
        let taker_sk = SecretKey::from_byte_array([21u8; 32]).unwrap();
        let maker = address_of(&maker_sk);
        let taker = address_of(&taker_sk);
        let genesis = funded_genesis(&maker, 100);
        let chain = vec![genesis];
        let now = now_secs();
        let hashlock = hashlock_for_secret_hex(&"66".repeat(32)).unwrap();

        // Escrow that does not belong to the committed terms.
        let mut tampered = swap_lock_tx(&maker_sk, &taker, 10, 0, now, now + 3600, &hashlock, None);
        tampered.to = swap_escrow_address("deadbeef");
        let tampered = sign_v4(&maker_sk, tampered);
        let err = chain::is_tx_valid(&tampered, &chain)
            .unwrap_err()
            .to_string();
        assert!(err.contains("must pay the escrow"), "{}", err);

        // Terms changed after the id was derived.
        let mut relabelled =
            swap_lock_tx(&maker_sk, &taker, 10, 0, now, now + 3600, &hashlock, None);
        if let Some(payload) = relabelled.swap.as_mut() {
            payload.timelock = now + 4000;
        }
        let relabelled = sign_v4(&maker_sk, relabelled);
        let err = chain::is_tx_valid(&relabelled, &chain)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not commit to the swap terms"), "{}", err);

        // A lock too small to pay for its own settlement would freeze the
        // coins for good.
        let dust = swap_lock_tx(&maker_sk, &taker, 1, 0, now, now + 3600, &hashlock, None);
        let err = chain::is_tx_valid(&dust, &chain).unwrap_err().to_string();
        assert!(err.contains("must exceed the settlement fee"), "{}", err);

        // Timelocks outside the allowed window are refused.
        let too_short = swap_lock_tx(&maker_sk, &taker, 10, 0, now, now + 60, &hashlock, None);
        let err = chain::is_tx_valid(&too_short, &chain)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Timelock too short"), "{}", err);
    }

    #[test]
    fn settlement_must_drain_the_whole_escrow() {
        let _guard = test_guard();
        tmp_clean_files();
        let maker_sk = SecretKey::from_byte_array([22u8; 32]).unwrap();
        let taker_sk = SecretKey::from_byte_array([23u8; 32]).unwrap();
        let taker = address_of(&taker_sk);
        let now = now_secs();
        let secret = "77".repeat(32);
        let hashlock = hashlock_for_secret_hex(&secret).unwrap();
        let lock = swap_lock_tx(&maker_sk, &taker, 25, 0, now, now + 3600, &hashlock, None);
        let mut index = SwapIndex::build(&[]);
        index.apply(&lock, 1);

        let mut greedy = swap_settle_tx(&taker_sk, TxKind::SwapClaim, &lock, &taker, now, &secret);
        greedy.fee = 5; // would leave dust behind in the escrow
        let greedy = sign_v4(&taker_sk, greedy);
        let err = validate_swap_settlement(&greedy, &index, &taker, now)
            .unwrap_err()
            .to_string();
        assert!(err.contains("whole escrow"), "{}", err);
    }
}
