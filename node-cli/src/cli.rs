use std::io::{self, IsTerminal};
use std::sync::Arc;
use std::time::Duration;

use blockchain_core::{Block, Transaction};
use rustyline::{DefaultEditor, error::ReadlineError};
use serde_json;
use tokio::sync::Mutex;

use crate::{
    OBSERVED_IP,
    chain::save_peers,
    miner::mine_block,
    p2p::{determine_public_ip_from_peers, get_my_address, ping_peer, sync_chain},
    storage::{read_data_file, remove_data_file},
};

const SELF_PEER_NOTE: &str = "Note: if peers.json contains this node's own address, it stays in the file but is hidden from the peer list while still being broadcast to other nodes.";

pub async fn run_cli(blockchain: Arc<Mutex<Vec<Block>>>, peers: Arc<Mutex<Vec<String>>>) {
    let interactive = io::stdin().is_terminal();
    println!(
        "Commands: mine | sync | print-chain | list-peers | add-peer | remove-peer | remove-offline-peers | clear-chain | print-mempool | get-publicip | print-my-addr | debug-peers | exit"
    );

    if interactive {
        let mut rl = DefaultEditor::new().unwrap_or_else(|_| DefaultEditor::new().unwrap());
        loop {
            match rl.readline("> ") {
                Ok(line) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let _ = rl.add_history_entry(trimmed);
                    if !handle_command(trimmed, &blockchain, &peers).await {
                        break;
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    println!("^C");
                    continue;
                }
                Err(ReadlineError::Eof) => break,
                Err(_) => break,
            }
        }
    } else {
        loop {
            let mut line = String::new();
            match io::stdin().read_line(&mut line) {
                Ok(0) => {
                    // Stdin closed (common if container started without -i). Wait and retry so
                    // attaching later still allows commands, but don't spam prompts in non-interactive mode.
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
                Ok(_) => {}
                Err(_) => continue,
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if !handle_command(trimmed, &blockchain, &peers).await {
                break;
            }
        }
    }
}

async fn handle_command(
    trimmed: &str,
    blockchain: &Arc<Mutex<Vec<Block>>>,
    peers: &Arc<Mutex<Vec<String>>>,
) -> bool {
    match trimmed {
        "print-my-addr" => {
            if let Some(addr) = get_my_address().await {
                println!("My address: {}", addr);
            } else {
                println!("Address not determined yet");
            }
        }
        "debug-peers" => debug_peers(peers).await,
        "mine" => mine_block(blockchain).await,
        "sync" => sync_chain(blockchain, peers, false, true).await,
        "print-chain" => print_chain(blockchain).await,
        "list-peers" => list_peers(peers).await,
        "remove-offline-peers" => remove_offline_peers(peers).await,
        "clear-chain" => clear_chain(),
        "print-mempool" => print_mempool(),
        "get-publicip" => get_public_ip().await,
        "exit" => return false,
        line if line.starts_with("add-peer ") => add_peer_command(line, peers).await,
        line if line.starts_with("remove-peer ") => remove_peer_command(line, peers).await,
        _ => println!("Unknown command"),
    }
    true
}

async fn print_chain(blockchain: &Arc<Mutex<Vec<Block>>>) {
    let chain = blockchain.lock().await;
    for block in chain.iter() {
        println!("#{} hash: {}", block.index, block.hash);
    }
}

async fn list_peers(peers: &Arc<Mutex<Vec<String>>>) {
    let peer_list = peers.lock().await;
    let my_addr = get_my_address().await;
    if let Some(addr) = my_addr.as_ref() {
        if peer_list.iter().any(|p| p == addr) {
            println!("{}", SELF_PEER_NOTE);
        }
    }
    for peer in peer_list.iter() {
        if Some(peer) == my_addr.as_ref() {
            continue;
        }
        let status = ping_peer(peer).await;
        println!("{} ({})", peer, if status { "online" } else { "offline" });
    }
}

async fn add_peer_command(line: &str, peers: &Arc<Mutex<Vec<String>>>) {
    let parts: Vec<&str> = line.trim().split_whitespace().collect();
    if parts.len() == 2 {
        let new_peer = parts[1].to_string();
        if let Some(my_addr) = get_my_address().await {
            if new_peer == my_addr {
                println!("Refusing to add self as peer: {}", new_peer);
                return;
            }
        }
        let mut p = peers.lock().await;
        if !p.contains(&new_peer) {
            p.push(new_peer.clone());
            if let Err(e) = save_peers(&p) {
                eprintln!("Failed to save peers: {}", e);
            } else {
                println!("Peer added: {}", new_peer);
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
                println!("Peer removed: {}", target_peer);
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
    let my_addr = get_my_address().await;
    for peer in p.iter() {
        if Some(peer) == my_addr.as_ref() {
            online_peers.push(peer.clone());
            continue;
        }
        if ping_peer(peer).await {
            online_peers.push(peer.clone());
        }
    }
    *p = online_peers;
    let removed = before - p.len();

    if let Err(e) = save_peers(&p) {
        eprintln!("Failed to save peers: {}", e);
    } else {
        println!("Removed {} offline peers", removed);
    }
}

fn clear_chain() {
    match remove_data_file("blockchain.json") {
        Ok(_) => println!("Chain cleared"),
        Err(e) => eprintln!("Failed to clear chain: {}", e),
    }
}

fn print_mempool() {
    match read_data_file("mempool.json").ok().flatten() {
        Some(mempool) if !mempool.trim().is_empty() => {
            println!("Mempool transactions:");
            for (i, line) in mempool.lines().enumerate() {
                if let Ok(tx) = serde_json::from_str::<Transaction>(line) {
                    println!("{}. {} -> {} amount: {}", i + 1, tx.from, tx.to, tx.amount);
                }
            }
        }
        _ => println!("Mempool is empty"),
    }
}

async fn debug_peers(peers: &Arc<Mutex<Vec<String>>>) {
    println!("=== PEER DEBUG INFO ===");

    let memory_peers = peers.lock().await;
    println!(
        "In-memory peers ({}): {:?}",
        memory_peers.len(),
        *memory_peers
    );
    drop(memory_peers);

    match read_data_file("peers.json") {
        Ok(Some(content)) => {
            println!("Peers file content: {}", content);
            match serde_json::from_str::<Vec<String>>(&content) {
                Ok(file_peers) => println!(
                    "Parsed peers from file ({}): {:?}",
                    file_peers.len(),
                    file_peers
                ),
                Err(e) => println!("Failed to parse peers file: {}", e),
            }
        }
        Ok(None) => println!("Peers file not found"),
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
