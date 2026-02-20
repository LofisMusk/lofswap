use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use blockchain_core::{Block, CHAIN_ID, Transaction, TxKind, pubkey_to_address};
use secp256k1::{PublicKey, Secp256k1};
use tokio::{
    sync::Mutex,
    time::{Duration, sleep},
};

use crate::{
    chain::{block_subsidy, load_valid_transactions, prune_mempool, save_chain},
    p2p::{broadcast_to_known_nodes, get_my_address},
    wallet::{read_mempool, wallet_load_default},
};

pub async fn mine_block(blockchain: &Arc<Mutex<Vec<Block>>>) {
    let (transactions, prev_hash, target_index) = {
        let chain = blockchain.lock().await;
        let txs = load_valid_transactions(&chain);
        let prev_hash = chain.last().map(|b| b.hash.clone()).unwrap_or_default();
        let target_index = chain.len() as u64;
        (txs, prev_hash, target_index)
    };

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

    let miner = get_my_address()
        .await
        .unwrap_or_else(|| "unknown".to_string());
    let miner_reward_addr = std::env::var("MINER_REWARD_ADDRESS")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            wallet_load_default().map(|sk| {
                let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
                pubkey_to_address(&pk.to_string())
            })
        })
        .unwrap_or_else(|| miner.clone());
    let mut block_txs = Vec::with_capacity(transactions.len() + 1);
    let fees_sum: u64 = transactions.iter().map(|tx| tx.fee).sum();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let mut coinbase = Transaction {
        version: 3,
        chain_id: CHAIN_ID.to_string(),
        kind: TxKind::Coinbase,
        timestamp: ts,
        from: String::new(),
        to: miner_reward_addr,
        amount: block_subsidy(target_index).saturating_add(fees_sum),
        fee: 0,
        signature: format!("coinbase:{}:{}", target_index, miner),
        pubkey: String::new(),
        nonce: 0,
        txid: String::new(),
    };
    coinbase.txid = coinbase.compute_txid();
    block_txs.push(coinbase);
    block_txs.extend(transactions);

    let block = Block::new(target_index, block_txs, prev_hash.clone(), miner);

    println!("[mining] solved block: {}", block.hash);
    {
        let mut chain = blockchain.lock().await;
        let current_index = chain.len() as u64;
        let current_prev_hash = chain.last().map(|b| b.hash.clone()).unwrap_or_default();

        if current_index != target_index || current_prev_hash != prev_hash {
            println!(
                "[mining] stale solved block discarded (target_idx={}, current_idx={})",
                target_index, current_index
            );
            return;
        }

        chain.push(block.clone());

        if let Err(e) = save_chain(&chain) {
            eprintln!("Failed to save chain: {}", e);
            return;
        }

        if let Err(e) = prune_mempool(&chain) {
            eprintln!("Failed to prune mempool after mining: {}", e);
        }
    }

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
