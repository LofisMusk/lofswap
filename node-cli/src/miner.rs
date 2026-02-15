use std::sync::Arc;

use blockchain_core::Block;
use tokio::{
    sync::Mutex,
    time::{Duration, sleep},
};

use crate::{
    chain::{load_valid_transactions, save_chain},
    p2p::{broadcast_to_known_nodes, get_my_address},
    storage::remove_data_file,
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

    let _ = remove_data_file("mempool.json");
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
    // brief pause to avoid immediate tight loop after broadcasting
    sleep(Duration::from_secs(1)).await;
}

pub async fn miner_loop(blockchain: Arc<Mutex<Vec<Block>>>) {
    loop {
        {
            let chain = blockchain.lock().await;
            let has_any_valid = !load_valid_transactions(&chain).is_empty();
            drop(chain);
            if has_any_valid {
                mine_block(&blockchain).await;
            }
        }
        // target ~1 block every 10s when transactions are present
        sleep(Duration::from_secs(10)).await;
    }
}
