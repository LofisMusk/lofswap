use std::io::{self, Write};
use std::sync::Arc;

use blockchain_core::{Block, Transaction};
use serde_json;
use tokio::sync::Mutex;

use crate::{
    chain::save_peers,
    miner::mine_block,
    p2p::{determine_public_ip_from_peers, get_my_address, ping_peer, sync_chain},
    OBSERVED_IP,
};

pub async fn run_cli(blockchain: Arc<Mutex<Vec<Block>>>, peers: Arc<Mutex<Vec<String>>>) {
    println!("Commands: mine | sync | print-chain | list-peers | add-peer | remove-peer | remove-offline-peers | clear-chain | print-mempool | get-publicip | print-my-addr | debug-peers | exit");

    loop {
        print!("> ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        if io::stdin().read_line(&mut line).is_err() {
            continue;
        }

        match line.trim() {
            "print-my-addr" => {
                if let Some(addr) = get_my_address().await {
                    println!("My address: {}", addr);
                } else {
                    println!("Address not determined yet");
                }
            }
            "debug-peers" => debug_peers(&peers).await,
            "mine" => mine_block(&blockchain).await,
            "sync" => sync_chain(&blockchain, &peers, false).await,
            "print-chain" => print_chain(&blockchain).await,
            "list-peers" => list_peers(&peers).await,
            "remove-offline-peers" => remove_offline_peers(&peers).await,
            "clear-chain" => clear_chain(),
            "print-mempool" => print_mempool(),
            "get-publicip" => get_public_ip().await,
            "exit" => break,
            line if line.starts_with("add-peer ") => add_peer_command(line, &peers).await,
            line if line.starts_with("remove-peer ") => remove_peer_command(line, &peers).await,
            _ => println!("Unknown command"),
        }
    }
}

async fn print_chain(blockchain: &Arc<Mutex<Vec<Block>>>) {
    let chain = blockchain.lock().await;
    for block in chain.iter() {
        println!("#{} hash: {}", block.index, block.hash);
    }
}

async fn list_peers(peers: &Arc<Mutex<Vec<String>>>) {
    let peer_list = peers.lock().await;
    for peer in peer_list.iter() {
        let status = ping_peer(peer).await;
        println!("{} ({})", peer, if status { "online" } else { "offline" });
    }
}

async fn add_peer_command(line: &str, peers: &Arc<Mutex<Vec<String>>>) {
    let parts: Vec<&str> = line.trim().split_whitespace().collect();
    if parts.len() == 2 {
        let new_peer = parts[1].to_string();
        let mut p = peers.lock().await;
        if !p.contains(&new_peer) {
            p.push(new_peer.clone());
            if let Err(e) = save_peers(&p) {
                eprintln!("Failed to save peers: {}", e);
            } else {
                println!("✓ Peer added: {}", new_peer);
            }
        } else {
            println!("Peer already exists.");
        }
    } else {
        println!("Usage: add-peer <address:port>");
    }
}

async fn remove_peer_command(line: &str, peers: &Arc<Mutex<Vec<String>>>) {
    let parts: Vec<&str> = line.trim().split_whitespace().collect();
    if parts.len() == 2 {
        let target_peer = parts[1];
        let mut p = peers.lock().await;
        let before = p.len();
        p.retain(|peer| peer != target_peer);
        if p.len() < before {
            if let Err(e) = save_peers(&p) {
                eprintln!("Failed to save peers: {}", e);
            } else {
                println!("✓ Peer removed: {}", target_peer);
            }
        } else {
            println!("Peer not found.");
        }
    } else {
        println!("Usage: remove-peer <address:port>");
    }
}

async fn remove_offline_peers(peers: &Arc<Mutex<Vec<String>>>) {
    let mut p = peers.lock().await;
    let before = p.len();
    let mut online_peers = Vec::new();
    for peer in p.iter() {
        if ping_peer(peer).await {
            online_peers.push(peer.clone());
        }
    }
    *p = online_peers;
    let removed = before - p.len();

    if let Err(e) = save_peers(&p) {
        eprintln!("Failed to save peers: {}", e);
    } else {
        println!("✓ Removed {} offline peers", removed);
    }
}

fn clear_chain() {
    match std::fs::remove_file("blockchain.json") {
        Ok(_) => println!("✓ Chain cleared"),
        Err(e) => eprintln!("Failed to clear chain: {}", e),
    }
}

fn print_mempool() {
    match std::fs::read_to_string("mempool.json") {
        Ok(mempool) => {
            if mempool.trim().is_empty() {
                println!("Mempool is empty");
                return;
            }

            println!("Mempool transactions:");
            for (i, line) in mempool.lines().enumerate() {
                if let Ok(tx) = serde_json::from_str::<Transaction>(line) {
                    println!("{}. {} -> {} amount: {}", i + 1, tx.from, tx.to, tx.amount);
                }
            }
        }
        Err(_) => println!("Mempool is empty"),
    }
}

async fn debug_peers(peers: &Arc<Mutex<Vec<String>>>) {
    println!("=== PEER DEBUG INFO ===");

    let memory_peers = peers.lock().await;
    println!("In-memory peers ({}): {:?}", memory_peers.len(), *memory_peers);
    drop(memory_peers);

    match std::fs::read_to_string("peers.json") {
        Ok(content) => {
            println!("Peers file content: {}", content);
            match serde_json::from_str::<Vec<String>>(&content) {
                Ok(file_peers) => println!("Parsed peers from file ({}): {:?}", file_peers.len(), file_peers),
                Err(e) => println!("Failed to parse peers file: {}", e),
            }
        }
        Err(e) => println!("Failed to read peers file: {}", e),
    }

    if let Some(ip) = OBSERVED_IP.read().await.as_ref() {
        println!("Current observed IP: {}", ip);
        println!("My full address: {}:{}", ip, crate::LISTEN_PORT);
    } else {
        println!("No observed IP set");
    }
}

async fn get_public_ip() {
    match determine_public_ip_from_peers().await {
        Some(ip) => println!("Public IP: {}", ip),
        None => println!("Unable to determine public IP"),
    }
}
