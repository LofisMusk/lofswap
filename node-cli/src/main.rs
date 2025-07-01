// === /node-cli/src/main.rs ===
use blockchain_core::{Block, Transaction};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpStream as StdTcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;
use secp256k1::{Secp256k1, Message, PublicKey};
use secp256k1::ecdsa::Signature;
use sha2::{Digest, Sha256};
use serde_json;

#[tokio::main]
async fn main() {
    let blockchain = Arc::new(Mutex::new(load_chain()));
    let mempool = Arc::new(Mutex::new(Vec::<Transaction>::new()));

    // uruchom serwer TCP
    let blockchain_clone = blockchain.clone();
    tokio::spawn(async move {
        let listener = TcpListener::bind("0.0.0.0:6000").await.unwrap();
        println!("Node nasłuchuje na porcie 6000");
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buffer = vec![0; 2048];
                if let Ok(n) = stream.read(&mut buffer).await {
                    let input = &buffer[..n];
                    let input_str = String::from_utf8_lossy(input);

                    if input_str.starts_with("/balance/") {
                        let address = input_str.trim().replace("/balance/", "");
                        let chain = blockchain_clone.lock().await;
                        let mut balance: i64 = 0;
                        for block in chain.iter() {
                            for tx in &block.transactions {
                                if tx.to == address {
                                    balance += tx.amount as i64;
                                } else if tx.from == address {
                                    balance -= tx.amount as i64;
                                }
                            }
                        }
                        let _ = stream.write_all(balance.to_string().as_bytes()).await;
                    } else if let Ok(tx) = serde_json::from_slice::<Transaction>(input) {
                        let mut chain = blockchain_clone.lock().await;
                        if is_tx_valid(&tx, &chain) {
                            println!("✓ Transakcja zaakceptowana do mempoola");
                             if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("mempool.json") {
                            let _ = writeln!(file, "{}", serde_json::to_string(&tx).unwrap());
                        } else {
                            println!("✗ Błędna transakcja odrzucona");
                        }
                    }
                } else if input_str.starts_with("/register/") {
                    let new_addr = input_str.trim().replace("/register/", "");
                    if !add_node_to_file(&new_addr) {
                        println!("✓ Dodano nowy node: {}", new_addr);
                        broadcast_nodes_file().await;
                    }
                    let _ = stream.write_all(b"OK").await;
                    continue;
                } else if input_str.starts_with("/nodes_update/") {
                    let nodes_data = input_str.trim().replace("/nodes_update/", "");
                    std::fs::write("nodes.txt", nodes_data).unwrap();
                    println!("✓ Zaktualizowano nodes.txt z sieci");
                    continue;
                }
            }
        }
    }});

    // AUTOMATYCZNA SYNC PO URUCHOMIENIU
    let arc_chain = blockchain.clone();
    sync_chain(&arc_chain).await;

    // CLI pętla
    println!("Witaj w nodzie blockchain. Dostępne polecenia: mine, sync, exit, print-chain, list-peers, clear-chain");
    loop {
        print!("> ");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let mut input = String::new();
        let stdin = io::stdin();
        stdin.lock().read_line(&mut input).unwrap();
        let input = input.trim();

        match input {
            "mine" => {
                let mut chain = blockchain.lock().await;
                let mempool_data = std::fs::read_to_string("mempool.json").unwrap_or_default();
                let all_txs: Vec<Transaction> = mempool_data
                    .lines()
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .filter(|tx| is_tx_valid(tx, &chain))
                    .collect();

                if all_txs.is_empty() {
                    println!("Brak ważnych transakcji do wykopania.");
                    continue;
                }

                let prev_hash = chain.last().unwrap().hash.clone();
                let new_block = Block::new(chain.len() as u64, all_txs, prev_hash);
                println!("Wykopano nowy blok: {}", new_block.hash);
                chain.push(new_block.clone());
                save_chain(&chain);
                broadcast_to_known_nodes(&new_block).await;
                sleep(Duration::from_secs(1)).await;
            }
            "sync" => {
                let arc_chain = blockchain.clone();
                sync_chain(&arc_chain).await;
            }
            "print-chain" => {
                let chain = blockchain.lock().await;
                for block in chain.iter() {
                    println!("Blok #{} | hash: {}", block.index, block.hash);
                    for tx in &block.transactions {
                        println!("  {} -> {} : {}", tx.from, tx.to, tx.amount);
                    }
                }
            }
            "list-peers" => {
            if let Ok(file) = File::open("nodes.txt") {
                let reader = BufReader::new(file);
                println!("Znane nody:");
                for line in reader.lines().flatten() {
                    let addr = line.trim();
                    let mut status = "offline";
                    if let Ok(mut addrs) = addr.to_socket_addrs() {
                        if let Some(sock_addr) = addrs.find(|a| a.is_ipv4() || a.is_ipv6()) {
                            if StdTcpStream::connect_timeout(&sock_addr, std::time::Duration::from_millis(300)).is_ok() {
                                status = "online";
                            }
                        }
                    }
                    println!("- {} ({})", addr, status);
                }
            } else {
                println!("Brak pliku nodes.txt");
            }
}
            "clear-chain" => {
                std::fs::remove_file("blockchain.json").unwrap_or(());
                println!("Blockchain został usunięty.");
            }
            "exit" => {
                println!("Zamykam nod...");
                break;
            }
            _ => println!("Nieznane polecenie. Użyj: mine, sync, exit, print-chain, list-peers, clear-chain"),
        }
    }
}

fn is_tx_valid(tx: &Transaction, chain: &[Block]) -> bool {
        // coinbase (nagroda za blok)
    if tx.from.is_empty() && tx.signature == "reward" {
        return true;
    }

    let secp = Secp256k1::new();
    let from_pubkey = match tx.from.parse::<PublicKey>() {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let msg_data = format!("{}{}{}", tx.from, tx.to, tx.amount);
    let hash = Sha256::digest(msg_data.as_bytes());
    let msg = match Message::from_slice(&hash) {
        Ok(m) => m,
        Err(_) => return false,
    };

    let sig_bytes = match hex::decode(&tx.signature) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let signature = match Signature::from_compact(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let already_in_chain = chain.iter().any(|block| {
        block.transactions.iter().any(|btx| btx.signature == tx.signature)
    });

    if already_in_chain {
        return false;
    }

    secp.verify_ecdsa(msg, &signature, &from_pubkey).is_ok()
}

fn save_chain(chain: &Vec<Block>) {
    let json = serde_json::to_string_pretty(chain).unwrap();
    std::fs::write("blockchain.json", json).unwrap();
}

fn load_chain() -> Vec<Block> {
    if Path::new("blockchain.json").exists() {
        let json = std::fs::read_to_string("blockchain.json").unwrap();
        serde_json::from_str(&json).unwrap()
    } else {
        vec![Block::new(0, vec![], String::from("0"))]
    }
}

async fn broadcast_to_known_nodes(block: &Block) {
    if let Ok(list) = std::fs::read_to_string("nodes.txt") {
        for line in list.lines() {
            if let Ok(mut stream) = TcpStream::connect(line).await {
                let json = serde_json::to_string(block).unwrap();
                let _ = stream.write_all(json.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        }
    }
}

async fn sync_chain(blockchain: &Arc<Mutex<Vec<Block>>>) {
    if let Ok(list) = std::fs::read_to_string("nodes.txt") {
        for line in list.lines() {
            if let Ok(mut stream) = TcpStream::connect(line).await {
                let _ = stream.write_all(b"/chain").await;
                let mut buffer = vec![0; 8192];
                if let Ok(n) = stream.read(&mut buffer).await {
                    if let Ok(peer_chain) = serde_json::from_slice::<Vec<Block>>(&buffer[..n]) {
                        let mut local_chain = blockchain.lock().await;
                        if peer_chain.len() >= local_chain.len() || local_chain.is_empty() {
                            *local_chain = peer_chain;
                            save_chain(&local_chain);
                            println!("✓ Chain synchronized and saved from node {}", line);
                        } else {
                            println!("✗ Node {} miał krótszy chain – pomijam", line);
                        }
                    }
                }
            }
        }
    }
}

fn add_node_to_file(addr: &str) -> bool {
    let path = "nodes.txt";
    let mut nodes = std::fs::read_to_string(path).unwrap_or_default()
        .lines().map(|l| l.trim().to_string()).collect::<Vec<_>>();
    if nodes.iter().any(|a| a == addr) {
        return true; // już jest
    }
    nodes.push(addr.to_string());
    let content = nodes.join("\n");
    std::fs::write(path, content).unwrap();
    false // dodano nowy
}

async fn broadcast_nodes_file() {
    if let Ok(list) = std::fs::read_to_string("nodes.txt") {
        for line in list.lines() {
            if let Ok(mut stream) = TcpStream::connect(line).await {
                let nodes_content = std::fs::read_to_string("nodes.txt").unwrap();
                let msg = format!("/nodes_update/\n{}", nodes_content);
                let _ = stream.write_all(msg.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        }
    }
}

// Możesz dodać do CLI lub wywołać po sync:
async fn register_my_node(my_addr: &str, known_node: &str) {
    if let Ok(mut stream) = TcpStream::connect(known_node).await {
        let msg = format!("/register/{}", my_addr);
        let _ = stream.write_all(msg.as_bytes()).await;
        let mut buf = [0u8; 16];
        let _ = stream.read(&mut buf).await;
    }
}
