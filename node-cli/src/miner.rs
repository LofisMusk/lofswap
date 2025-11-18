use std::sync::Arc;

use blockchain_core::{Block, Transaction};
use serde_json;
use tokio::{
    sync::Mutex,
    time::{sleep, Duration},
};

use crate::{
    chain::{is_tx_valid, load_valid_transactions, save_chain},
    p2p::{broadcast_to_known_nodes, get_my_address},
    wallet::read_mempool,
};

pub async fn mine_block(blockchain: &Arc<Mutex<Vec<Block>>>) {
    let mut chain = blockchain.lock().await;
    let transactions = load_valid_transactions(&chain);

    if transactions.is_empty() {
        println!("No valid transactions to mine");
        return;
    }

    let pending_len = read_mempool().len();
    println!(
        "[mining] starting... txs_in_block={} mempool_pending={}",
        transactions.len(),
        pending_len
    );

    let _ = std::fs::remove_file("mempool.json");
    let prev_hash = chain.last().unwrap().hash.clone();
    let miner = get_my_address()
        .await
        .unwrap_or_else(|| "unknown".to_string());
    let block = Block::new(chain.len() as u64, transactions, prev_hash, miner);

    println!("[mining] solved block: {}", block.hash);
    chain.push(block.clone());

    if let Err(e) = save_chain(&chain) {
        eprintln!("Failed to save chain: {}", e);
        return;
    }

    drop(chain);
    broadcast_to_known_nodes(&block).await;
    sleep(Duration::from_secs(1)).await;
}

pub async fn miner_loop(blockchain: Arc<Mutex<Vec<Block>>>) {
    loop {
        {
            let chain = blockchain.lock().await;
            let parsed: Vec<Transaction> = std::fs::read_to_string("mempool.json")
                .unwrap_or_default()
                .lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            let has_any_valid = parsed.iter().any(|tx| is_tx_valid(tx, &chain).is_ok());
            drop(chain);
            if has_any_valid {
                mine_block(&blockchain).await;
            }
        }
        sleep(Duration::from_secs(5)).await;
    }
}
