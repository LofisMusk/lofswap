use std::io::{self, IsTerminal};
use std::sync::Arc;
use std::time::Duration;

use blockchain_core::Block;
use rustyline::{DefaultEditor, error::ReadlineError};
use serde_json;
use tokio::sync::Mutex;

use crate::{
    OBSERVED_IP,
    chain::{clear_chain_storage, save_peers},
    identity::{sign_message, NODE_IDENTITY},
    l2_anchor::{
        load_l2_store, print_l2_status, register_bridge_output, register_sequencer_bond,
        save_l2_store, submit_commitment, try_finalize_all, try_unlock_bridge_outputs,
    },
    l2_mempool::{insert_l2_tx, l2_mempool_len, read_l2_mempool},
    mempool::read_mempool,
    miner::mine_block,
    p2p::{determine_public_ip_from_peers, get_my_address, ping_peer, sync_chain},
    sequencer::load_l2_state,
    storage::read_data_file,
};

const SELF_PEER_NOTE: &str = "Note: if peers.json contains this node's own address, it stays in the file but is hidden from the peer list while still being broadcast to other nodes.";

pub async fn run_cli(blockchain: Arc<Mutex<Vec<Block>>>, peers: Arc<Mutex<Vec<String>>>) {
    let interactive = io::stdin().is_terminal();
    println!(
        "Commands: mine <LFS_ADDRESS> | sync | print-chain | list-peers | add-peer | remove-peer | remove-offline-peers | clear-chain | print-mempool | get-publicip | print-my-addr | debug-peers\n\
         L2:       l2-status | l2-state | l2-mempool | l2-finalize | l2-send <from> <to> <amount>\n\
                   sequencer-bond <addr> <amount> | sequencer-commit <addr> <l2_height> <state_root>\n\
                   bridge-deposit <from_l2> <to_l1> <amount> <l2_height> | bridge-unlock | exit"
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
        "mine" => println!("Usage: mine <LFS_ADDRESS>"),
        "sync" => sync_chain(blockchain, peers, false, true).await,
        "print-chain" => print_chain(blockchain).await,
        "list-peers" => list_peers(peers).await,
        "remove-offline-peers" => remove_offline_peers(peers).await,
        "clear-chain" => clear_chain(),
        "print-mempool" => print_mempool(),
        "get-publicip" => get_public_ip().await,
        // ── L2 komendy ──
        "l2-status" => l2_status(),
        "l2-state" => l2_state_command(blockchain).await,
        "l2-mempool" => l2_mempool_command(),
        "l2-finalize" => l2_finalize(blockchain).await,
        "bridge-unlock" => bridge_unlock(blockchain).await,
        "exit" => return false,
        line if line.starts_with("mine ") => mine_command(line, blockchain).await,
        line if line.starts_with("add-peer ") => add_peer_command(line, peers).await,
        line if line.starts_with("remove-peer ") => remove_peer_command(line, peers).await,
        line if line.starts_with("sequencer-bond ") => sequencer_bond_command(line, blockchain).await,
        line if line.starts_with("sequencer-commit ") => sequencer_commit_command(line, blockchain).await,
        line if line.starts_with("bridge-deposit ") => bridge_deposit_command(line).await,
        line if line.starts_with("l2-send ") => l2_send_command(line),
        _ => println!("Unknown command"),
    }
    true
}

async fn mine_command(line: &str, blockchain: &Arc<Mutex<Vec<Block>>>) {
    let parts: Vec<&str> = line.trim().split_whitespace().collect();
    if parts.len() != 2 {
        println!("Usage: mine <LFS_ADDRESS>");
        return;
    }
    mine_block(blockchain, Some(parts[1])).await;
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
    match clear_chain_storage() {
        Ok(_) => println!("Chain cleared"),
        Err(e) => eprintln!("Failed to clear chain: {}", e),
    }
}

fn print_mempool() {
    let mempool = read_mempool();
    if mempool.is_empty() {
        println!("Mempool is empty");
        return;
    }

    println!("Mempool transactions:");
    for (i, tx) in mempool.iter().enumerate() {
        println!("{}. {} -> {} amount: {}", i + 1, tx.from, tx.to, tx.amount);
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

// ─────────────────────────────────────────────
// L2 CLI commands
// ─────────────────────────────────────────────

fn l2_status() {
    let store = load_l2_store();
    print_l2_status(&store);
}

async fn l2_finalize(blockchain: &Arc<Mutex<Vec<Block>>>) {
    let mut store = load_l2_store();
    let n = try_finalize_all(&mut store);

    // Odblokuj bridge outputs jeśli są Hard commitmenty
    let l1_height = {
        let chain = blockchain.lock().await;
        chain.last().map(|b| b.index).unwrap_or(0)
    };
    let unlocked = try_unlock_bridge_outputs(&mut store, l1_height);

    match save_l2_store(&store) {
        Ok(_) => {
            println!("[L2] Finalizacja: {} commitmentów → Hard", n);
            if !unlocked.is_empty() {
                println!("[L2] Odblokowane bridge outputs: {:?}", unlocked);
            }
        }
        Err(e) => eprintln!("[L2] Błąd zapisu: {}", e),
    }
}

async fn bridge_unlock(blockchain: &Arc<Mutex<Vec<Block>>>) {
    let l1_height = {
        let chain = blockchain.lock().await;
        chain.last().map(|b| b.index).unwrap_or(0)
    };
    let mut store = load_l2_store();
    let unlocked = try_unlock_bridge_outputs(&mut store, l1_height);
    match save_l2_store(&store) {
        Ok(_) => {
            if unlocked.is_empty() {
                println!("[L2] Brak outputów gotowych do odblokowania (oczekuj Hard finality)");
            } else {
                println!("[L2] Odblokowane: {:?}", unlocked);
            }
        }
        Err(e) => eprintln!("[L2] Błąd zapisu: {}", e),
    }
}

/// sequencer-bond <addr> <amount>
async fn sequencer_bond_command(line: &str, blockchain: &Arc<Mutex<Vec<Block>>>) {
    let parts: Vec<&str> = line.trim().splitn(3, ' ').collect();
    if parts.len() != 3 {
        println!("Usage: sequencer-bond <addr> <amount>");
        return;
    }
    let addr = parts[1].to_string();
    let amount: u64 = match parts[2].parse() {
        Ok(v) => v,
        Err(_) => {
            println!("Nieprawidłowy amount");
            return;
        }
    };
    let l1_index = {
        let chain = blockchain.lock().await;
        chain.last().map(|b| b.index).unwrap_or(0)
    };
    let mut store = load_l2_store();
    match register_sequencer_bond(&mut store, addr.clone(), amount, l1_index) {
        Ok(_) => match save_l2_store(&store) {
            Ok(_) => println!(
                "[L2] Bond zarejestrowany: seq={} amount={} locked_at_l1={}",
                addr, amount, l1_index
            ),
            Err(e) => eprintln!("[L2] Błąd zapisu: {}", e),
        },
        Err(e) => eprintln!("[L2] {}", e),
    }
}

/// sequencer-commit <addr> <l2_height> <state_root>
async fn sequencer_commit_command(line: &str, blockchain: &Arc<Mutex<Vec<Block>>>) {
    let parts: Vec<&str> = line.trim().splitn(4, ' ').collect();
    if parts.len() != 4 {
        println!("Usage: sequencer-commit <addr> <l2_height> <state_root>");
        return;
    }
    let addr = parts[1].to_string();
    let l2_height: u64 = match parts[2].parse() {
        Ok(v) => v,
        Err(_) => {
            println!("Nieprawidłowy l2_height");
            return;
        }
    };
    let state_root = parts[3].to_string();
    if state_root.len() != 64 {
        println!("state_root musi być 64-znakowym hex SHA256");
        return;
    }

    let l1_anchor = {
        let chain = blockchain.lock().await;
        chain.last().map(|b| b.index).unwrap_or(0)
    };

    let mut store = load_l2_store();
    // Podpisz commitment kluczem ed25519 node identity
    let preimage = format!("SC|{}|{}|{}|{}", l2_height, l1_anchor, state_root, addr);
    let sig = sign_message(preimage.as_bytes());
    let pubkey = NODE_IDENTITY.public_key_hex.clone();
    match submit_commitment(
        &mut store,
        addr.clone(),
        l2_height,
        l1_anchor,
        state_root.clone(),
        sig,
        pubkey,
    ) {
        Ok(_) => match save_l2_store(&store) {
            Ok(_) => println!(
                "[L2] Commitment złożony: l2_height={} l1_anchor={} root={}... state=Soft",
                l2_height,
                l1_anchor,
                &state_root[..8]
            ),
            Err(e) => eprintln!("[L2] Błąd zapisu: {}", e),
        },
        Err(e) => eprintln!("[L2] {}", e),
    }
}

/// bridge-deposit <from_l2> <to_l1> <amount> <l2_height>
async fn bridge_deposit_command(line: &str) {
    let parts: Vec<&str> = line.trim().splitn(5, ' ').collect();
    if parts.len() != 5 {
        println!("Usage: bridge-deposit <from_l2> <to_l1> <amount> <l2_height>");
        return;
    }
    let from_l2 = parts[1].to_string();
    let to_l1 = parts[2].to_string();
    let amount: u64 = match parts[3].parse() {
        Ok(v) => v,
        Err(_) => {
            println!("Nieprawidłowy amount");
            return;
        }
    };
    let l2_height: u64 = match parts[4].parse() {
        Ok(v) => v,
        Err(_) => {
            println!("Nieprawidłowy l2_height");
            return;
        }
    };

    let mut store = load_l2_store();
    match register_bridge_output(&mut store, from_l2, to_l1, amount, l2_height) {
        Ok(id) => match save_l2_store(&store) {
            Ok(_) => println!(
                "[L2] Bridge output zarejestrowany: id={}\n\
                 ⚠️  LOCKED — odblokowanie możliwe WYŁĄCZNIE po Hard finality commitment (l2_height={})",
                id, l2_height
            ),
            Err(e) => eprintln!("[L2] Błąd zapisu: {}", e),
        },
        Err(e) => eprintln!("[L2] {}", e),
    }
}

fn l2_mempool_command() {
    let pool = read_l2_mempool();
    if pool.is_empty() {
        println!("L2 mempool pusty");
        return;
    }
    println!("L2 mempool ({} TX):", pool.len());
    for tx in &pool {
        println!("  {} → {} amount={} nonce={}", tx.from, tx.to, tx.amount, tx.nonce);
    }
}

async fn l2_state_command(blockchain: &Arc<Mutex<Vec<Block>>>) {
    let chain = blockchain.lock().await;
    let state = load_l2_state(&chain);
    println!("=== L2 STATE ===");
    println!("  Height:     {}", state.height);
    println!("  Tip hash:   {}...", &state.tip_hash[..16.min(state.tip_hash.len())]);
    println!("  State root: {}...", &state.state_root[..16.min(state.state_root.len())]);
    println!("  Accounts:   {}", state.balances.len());
    let mut entries: Vec<(&String, &u64)> = state.balances.iter().collect();
    entries.sort_by(|a, b| b.1.cmp(a.1));
    for (addr, bal) in entries.iter().take(10) {
        println!("    {} → {}", addr, bal);
    }
    if state.balances.len() > 10 {
        println!("    ... ({} więcej)", state.balances.len() - 10);
    }
}

/// l2-send <from> <to> <amount>
/// Testowa komenda — bez podpisu (dev only). Produkcja wymaga wallet-cli.
fn l2_send_command(line: &str) {
    use blockchain_core::l2::L2Transaction;
    use std::time::{SystemTime, UNIX_EPOCH};

    let parts: Vec<&str> = line.trim().splitn(4, ' ').collect();
    if parts.len() != 4 {
        println!("Usage: l2-send <from> <to> <amount>");
        return;
    }
    let from = parts[1].to_string();
    let to = parts[2].to_string();
    let amount: u64 = match parts[3].parse() {
        Ok(v) => v,
        Err(_) => { println!("Nieprawidłowy amount"); return; }
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut tx = L2Transaction {
        txid: String::new(),
        from: from.clone(),
        to: to.clone(),
        amount,
        fee: 1,
        nonce: 0,
        timestamp,
        signature: String::new(),
        pubkey: String::new(),
    };
    tx.txid = tx.compute_txid();

    match insert_l2_tx(tx) {
        Ok(_) => println!(
            "[L2] TX dodany do mempool: {} → {} amount={} (mempool: {} TX)",
            from, to, amount, l2_mempool_len()
        ),
        Err(e) => eprintln!("[L2] {}", e),
    }
}
