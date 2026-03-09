use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use blockchain_core::{Block, CHAIN_ID, Transaction, TxKind, pubkey_to_address};
use secp256k1::{PublicKey, Secp256k1};
use tokio::{
    sync::Mutex,
    time::{Duration, sleep},
};

use crate::{
    chain::{
        block_subsidy, expected_next_difficulty, is_valid_lfs_address, load_valid_transactions,
        prune_mempool, save_chain, validate_block,
    },
    l2_anchor::on_new_block,
    mempool::mempool_len,
    p2p::{broadcast_to_known_nodes, get_my_address},
    wallet::wallet_load_default,
};

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn resolve_reward_address(explicit: Option<&str>) -> Option<String> {
    if let Some(addr) = explicit.map(str::trim) {
        if is_valid_lfs_address(addr) {
            return Some(addr.to_string());
        }
        println!("[mining] invalid reward address: {}", addr);
        return None;
    }

    if let Some(addr) = std::env::var("MINER_REWARD_ADDRESS")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        if is_valid_lfs_address(&addr) {
            return Some(addr);
        }
        println!("[mining] MINER_REWARD_ADDRESS is invalid, ignoring");
    }

    wallet_load_default().map(|sk| {
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        pubkey_to_address(&pk.to_string())
    })
}

pub async fn mine_block(blockchain: &Arc<Mutex<Vec<Block>>>, explicit_reward_addr: Option<&str>) {
    let Some(miner_reward_addr) = resolve_reward_address(explicit_reward_addr) else {
        if explicit_reward_addr.is_some() {
            println!("Usage: mine <LFS_ADDRESS>");
        } else {
            println!(
                "[mining] reward address not configured (set MINER_REWARD_ADDRESS or create local wallet)"
            );
        }
        return;
    };

    let (transactions, prev_hash, target_index, target_difficulty) = {
        let chain = blockchain.lock().await;
        let txs = load_valid_transactions(&chain);
        let prev_hash = chain.last().map(|b| b.hash.clone()).unwrap_or_default();
        let target_index = chain.len() as u64;
        let target_difficulty = expected_next_difficulty(&chain);
        (txs, prev_hash, target_index, target_difficulty)
    };

    let pending_len = mempool_len();
    println!(
        "[mining] starting... txs_in_block={} mempool_pending={} target_difficulty={}",
        transactions.len(),
        pending_len,
        target_difficulty
    );
    if transactions.is_empty() {
        println!("[mining] mining coinbase-only block");
    }

    let miner = get_my_address()
        .await
        .unwrap_or_else(|| "unknown".to_string());

    let mut block_txs = Vec::with_capacity(transactions.len() + 1);
    let fees_sum: u64 = transactions.iter().map(|tx| tx.fee).sum();
    let ts = now_unix_secs();
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

    let mut block = Block {
        version: 1,
        index: target_index,
        timestamp: now_unix_secs(),
        transactions: block_txs,
        previous_hash: prev_hash.clone(),
        nonce: 0,
        hash: String::new(),
        miner,
        difficulty: target_difficulty,
    };
    block.mine(target_difficulty as usize);

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
        if let Err(e) = validate_block(&block, chain.last(), &chain) {
            println!("[mining] solved block failed local validation: {}", e);
            return;
        }

        chain.push(block.clone());

        if let Err(e) = save_chain(&chain) {
            eprintln!("Failed to save chain: {}", e);
            return;
        }

        // L2: sprawdź finalizację przy każdym nowym bloku L1
        let l1_index = block.index;
        on_new_block(l1_index);

        if let Err(e) = prune_mempool(&chain) {
            eprintln!("Failed to prune mempool after mining: {}", e);
        }
    }

    broadcast_to_known_nodes(&block).await;
    // brief pause to avoid immediate tight loop after broadcasting
    sleep(Duration::from_secs(1)).await;
}

pub async fn miner_loop(blockchain: Arc<Mutex<Vec<Block>>>, reward_address: &str) {
    loop {
        mine_block(&blockchain, Some(reward_address)).await;
        // No fixed block timer; difficulty targets ~60s average block time.
        sleep(Duration::from_secs(1)).await;
    }
}
