use std::sync::{atomic::AtomicUsize, Arc};

use once_cell::sync::Lazy;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Duration;

mod chain;
mod cli;
mod errors;
mod explorer;
mod miner;
mod p2p;
mod ui;
mod upnp;
mod wallet;

pub use errors::NodeError;

pub static OBSERVED_IP: Lazy<RwLock<Option<String>>> = Lazy::new(|| RwLock::new(None));
pub static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

pub const LISTEN_PORT: u16 = 6000;
pub const EXPLORER_PORT: u16 = 7000;
pub const BOOTSTRAP_NODES: &[&str] = &["31.135.167.5:6000", "92.5.16.170:6000"];
pub const MAX_CONNECTIONS: usize = 50;
pub const BUFFER_SIZE: usize = 8192;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let no_upnp = args.iter().any(|a| a == "--no-upnp");
    let no_peer_exchange = args.iter().any(|a| a == "--no-peer-exchange");
    let miner_mode = args.iter().any(|a| a == "--miner");
    let fullnode_mode = args.iter().any(|a| a == "--fullnode");

    println!("[STARTUP] Starting blockchain node...");

    if !no_upnp {
        println!("[STARTUP] Step 1: Attempting UPnP port mapping for port {}...", LISTEN_PORT);
        match upnp::setup_upnp(LISTEN_PORT).await {
            Ok(_) => println!("[STARTUP] ✓ UPnP port mapping successful"),
            Err(e) => {
                eprintln!("[STARTUP] ⚠️ UPnP port mapping failed: {}. Continuing without it.", e);
            }
        }
    } else {
        println!("[STARTUP] Step 1: Skipping UPnP setup (--no-upnp flag set)");
    }

    let blockchain = Arc::new(Mutex::new(chain::load_chain()?));
    let peers = Arc::new(Mutex::new(chain::load_peers()?));

    println!("[STARTUP] Starting TCP server on port {}...", LISTEN_PORT);
    p2p::start_tcp_server(blockchain.clone(), peers.clone()).await?;

    if !miner_mode {
        tokio::spawn(explorer::start_http_explorer(blockchain.clone(), peers.clone()));
    }

    tokio::spawn(p2p::maintenance_loop(blockchain.clone(), peers.clone()));

    if miner_mode && !fullnode_mode {
        println!("[STARTUP] Miner mode enabled (no UI). Starting background miner...");
        let bc = blockchain.clone();
        tokio::spawn(async move {
            miner::miner_loop(bc).await;
        });
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    if !no_peer_exchange {
        p2p::bootstrap_and_discover_ip(&peers).await;
    } else {
        println!("[STARTUP] Skipping peer exchange and IP discovery (--no-peer-exchange flag set)");
    }

    println!("[STARTUP] ✓ Node initialization complete!");
    println!("[STARTUP] Launching command line interface...");
    cli::run_cli(blockchain, peers).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use blockchain_core::{Block, Transaction};
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use serde_json;

    fn tmp_clean_files() {
        let _ = std::fs::remove_file("mempool.json");
        let _ = std::fs::remove_file("wallet_mempool.json");
    }

    #[test]
    fn tx_signature_validates() {
        tmp_clean_files();
        let sk = SecretKey::from_byte_array([1u8; 32]).unwrap();
        let from_pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk).to_string();
        let reward = Transaction {
            version: 1,
            timestamp: 0,
            from: String::new(),
            to: from_pk.clone(),
            amount: 100,
            signature: "reward".into(),
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
        let tx = wallet::build_tx(&sk, "LFS11111111111111111111", 10);
        assert!(chain::is_tx_valid(&tx, &chain).is_ok(), "expected tx to be valid");
    }

    #[test]
    fn mempool_double_spend_is_blocked() {
        tmp_clean_files();
        let from_sk = SecretKey::from_byte_array([2u8; 32]).unwrap();
        let from_pk = PublicKey::from_secret_key(&Secp256k1::new(), &from_sk).to_string();
        let reward = Transaction {
            version: 1,
            timestamp: 0,
            from: String::new(),
            to: from_pk.clone(),
            amount: 100,
            signature: "reward".into(),
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

        let tx1 = wallet::build_tx(&from_sk, "LFS11111111111111111111", 60);
        assert!(chain::is_tx_valid(&tx1, &chain).is_ok());
        let _ = std::fs::write("mempool.json", format!("{}\n", serde_json::to_string(&tx1).unwrap()));

        let tx2 = wallet::build_tx(&from_sk, "LFS11111111111111111111", 50);
        let err = chain::is_tx_valid(&tx2, &chain).unwrap_err();
        match err {
            NodeError::ValidationError(msg) => assert!(msg.contains("Insufficient balance")),
            _ => panic!("unexpected error"),
        }
    }
}
