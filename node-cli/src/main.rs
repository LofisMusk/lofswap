// === node-cli/src/main.rs ===
use blockchain_core::{Block, Transaction};
use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};
use serde_json;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{self, Write},
    net::{IpAddr, TcpStream as StdTcpStream, ToSocketAddrs},
    path::Path,
    result,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    time::sleep,
};
use std::{error::Error, net::SocketAddrV4, sync::Arc};
use igd::aio::search_gateway;
use igd::PortMappingProtocol;
use local_ip_address::local_ip;

use easy_upnp::{add_ports, delete_ports, UpnpConfig as EasyConfig};

pub async fn setup_upnp(port: u16) -> Result<(), Box<dyn Error>> {
    // 1. Spróbuj przekierować port przez `igd`
    match try_igd_upnp(port).await {
        Ok(_) => return Ok(()),
        Err(e) => eprintln!("[DEBUG] IGD UPnP failed: {} – fallback to easy_upnp", e),
    }

    // 2. Spróbuj fallback do easy_upnp
    let cfg = Arc::new(EasyConfig {
        address: None,
        port,
        protocol: easy_upnp::PortMappingProtocol::TCP,
        duration: 3600,
        comment: "lofswap node".to_string(),
    });

    // Cleanup przy SIGINT
    {
        let cfg_for_cleanup = cfg.clone();
        ctrlc::set_handler(move || {
            let cleanup_cfg = easy_upnp::UpnpConfig {
                address: cfg_for_cleanup.address.clone(),
                port: cfg_for_cleanup.port,
                protocol: cfg_for_cleanup.protocol,
                duration: cfg_for_cleanup.duration,
                comment: cfg_for_cleanup.comment.clone(),
            };
            for result in delete_ports(std::iter::once(cleanup_cfg)) {
                match result {
                    Ok(_) => println!("🔌 Easy UPnP: port {} usunięty", port),
                    Err(e) => eprintln!("⚠️ Easy UPnP: błąd usuwania portu: {}", e),
                }
            }
            std::process::exit(0);
        }).expect("Nie udało się ustawić handlera SIGINT");
    }

    for result in add_ports(std::iter::once(EasyConfig { address: cfg.address.clone(), port: cfg.port, protocol: cfg.protocol, duration: cfg.duration, comment: cfg.comment.clone() })) {
        match result {
            Ok(_) => {
                println!("🔌 Easy UPnP: port {} przekierowany", port);
                return Ok(());
            }
            Err(e) => eprintln!("⚠️ Easy UPnP: błąd przekierowania portu: {}", e),
        }
    }
    Err("Nie udało się przekierować portu przez żaden mechanizm".into())
}

async fn try_igd_upnp(port: u16) -> Result<(), Box<dyn Error>> {
    let gateway = search_gateway(Default::default()).await?;
    let local_ip = local_ip()?; // z crate `local_ip_address`

    let ip = match local_ip {
        std::net::IpAddr::V4(ipv4) => ipv4,
        _ => return Err("Only IPv4 supported".into()),
    };

    let socket = SocketAddrV4::new(ip, port);
    gateway
        .add_port(PortMappingProtocol::TCP, port, socket, 3600, "lofswap node")
        .await?;

    println!("✓ Port {} przekierowany na {} (IGD)", port, socket);
    Ok(())
}
// ───── ustawienia ─────────────────────────────────────────────
const LISTEN_PORT: u16 = 6000;
const BOOTSTRAP_NODES: &[&str] = &["lofis.ddns.net:6000", "lofis.ddns.net:6001"];
// ──────────────────────────────────────────────────────────────

fn balances(chain: &[Block]) -> HashMap<String, i128> {
    let mut map = HashMap::new();
    for block in chain {
        for tx in &block.transactions {
            if !tx.from.is_empty() {
                *map.entry(tx.from.clone()).or_insert(0) -= tx.amount as i128;
            }
            *map.entry(tx.to.clone()).or_insert(0) += tx.amount as i128;
        }
    }
    map
}

#[tokio::main]
async fn main() {
    println!("[DEBUG] Attempting UPnP port mapping...");
    if let Err(e) = setup_upnp(LISTEN_PORT).await {
        eprintln!("[DEBUG] UPnP port mapping failed. Continuing without it, make sure to manually forward port 6000 in order to connect to the lofswap network");
    };
    // TODO: make this work
    let blockchain = Arc::new(Mutex::new(load_chain()));
    let peers = Arc::new(Mutex::new(load_peers()));

    // ─── 1. Serwer TCP (nasłuch na LISTEN_PORT) ───────────────
    {
        let blockchain = blockchain.clone();
        let peers = peers.clone();
        tokio::spawn(async move {
            let addr = format!("0.0.0.0:{LISTEN_PORT}");
            let listener = match TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!(
                        "[DEBUG] Failed to bind to port {LISTEN_PORT}: {e}. The port may be closed, in use, or blocked by a firewall."
                    );
                    return;
                }
            };
            println!("Node nasłuchuje na porcie {LISTEN_PORT}");

            loop {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let mut buf = vec![0; 4096];
                    if let Ok(n) = stream.read(&mut buf).await {
                        let slice = &buf[..n];
                        let txt = String::from_utf8_lossy(slice);

                        if txt.starts_with("/balance/") {
                            // ----- saldo -----
                            let addr = txt.trim().replace("/balance/", "");
                            let chain = blockchain.lock().await;
                            let mut bal: i128 = 0;
                            for b in chain.iter() {
                                for t in &b.transactions {
                                    if t.to == addr {
                                        bal += t.amount as i128
                                    }
                                    if t.from == addr {
                                        bal -= t.amount as i128
                                    }
                                }
                            }
                            let _ = stream.write_all(bal.to_string().as_bytes()).await;
                        } else if txt.trim() == "/peers" {
                            // ----- zwróć listę peerów -----
                            let p = peers.lock().await;
                            let _ = stream
                                .write_all(serde_json::to_string(&*p).unwrap().as_bytes())
                                .await;
                        } else if txt.trim() == "/chain" {
                            let chain = blockchain.lock().await;
                            let _ = stream
                                .write_all(serde_json::to_string(&*chain).unwrap().as_bytes())
                                .await;
                        } else if let Ok(tx) = serde_json::from_slice::<Transaction>(slice) {
                            // ----- transakcja -----
                            let chain = blockchain.lock().await;
                            if is_tx_valid(&tx, &chain) {
                                println!("✓ TX do mempoolu");
                                if let Ok(mut f) = OpenOptions::new()
                                    .create(true)
                                    .append(true)
                                    .open("mempool.json")
                                {
                                    let _ = writeln!(f, "{}", serde_json::to_string(&tx).unwrap());
                                }
                            } else {
                                println!("✗ TX odrzucony (podpis / saldo)");
                            }
                        }
                    }
                }
            }
        });
    }

    // ─── 2. Peer-discovery z BOOTSTRAP_NODES ──────────────────
    for &boot in BOOTSTRAP_NODES {
        if let Ok(mut s) = TcpStream::connect(boot).await {
            let _ = s.write_all(b"/peers").await;
            let mut buf = vec![0; 4096];
            if let Ok(n) = s.read(&mut buf).await {
                if let Ok(list) = serde_json::from_slice::<Vec<String>>(&buf[..n]) {
                    let mut p = peers.lock().await;
                    for peer in list {
                        if !p.contains(&peer) {
                            println!("Dodano peer z bootstrapu: {peer}");
                            p.push(peer);
                        }
                    }
                    save_peers(&p);
                }
            }
        }
    }

    // ─── 3. CLI ────────────────────────────────────────────────
    println!("Komendy: mine | sync | print-chain | list-peers | clear-chain | print-mempool | exit");
    loop {
        print!("> ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        io::stdin().read_line(&mut line).unwrap();
        match line.trim() {
            "mine" => {
                let mut chain = blockchain.lock().await;

                // Wczytaj i przefiltruj mempool (tylko poprawne TX)
                let parsed: Vec<Transaction> = std::fs::read_to_string("mempool.json")
                .unwrap_or_default()
                .lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .filter(|tx| is_tx_valid(tx, &chain))
                .collect();


                // selekcja
                let mut bal = balances(&chain);
                let mut chosen = Vec::new();
                for tx in parsed {
                    if tx.from.is_empty() {
                        chosen.push(tx);
                        continue;
                    }
                    let e = bal.entry(tx.from.clone()).or_insert(0);
                    if *e >= tx.amount as i128 {
                        *e -= tx.amount as i128;
                        *bal.entry(tx.to.clone()).or_insert(0) += tx.amount as i128;
                        chosen.push(tx);
                    } else {
                        println!("✗ TX {} pominięty – saldo {}", tx.signature, e);
                    }
                }
                if chosen.is_empty() {
                    println!("Brak TX");
                    continue;
                }
                let _ = std::fs::remove_file("mempool.json");

                let prev = chain.last().unwrap().hash.clone();
                let block = Block::new(chain.len() as u64, chosen, prev);
                println!("Nowy blok: {}", block.hash);
                chain.push(block.clone());
                save_chain(&chain);
                broadcast_to_known_nodes(&block).await;
                sleep(Duration::from_secs(1)).await;
            }
            "sync" => sync_chain(&blockchain).await,
            "print-chain" => {
                let c = blockchain.lock().await;
                for b in c.iter() {
                    println!("#{} hash: {}", b.index, b.hash);
                }
            }
            "list-peers" => {
                let p = peers.lock().await;
                for peer in p.iter() {
                    let status = peer
                        .to_socket_addrs()
                        .ok()
                        .and_then(|mut i| i.next())
                        .and_then(|a| {
                            StdTcpStream::connect_timeout(&a, Duration::from_millis(300)).ok()
                        })
                        .map(|_| "online")
                        .unwrap_or("offline");
                    println!("{peer} ({status})");
                }
            }
            "clear-chain" => {
                let _ = std::fs::remove_file("blockchain.json");
                println!("Chain usunięty");
            }
            "print-mempool" => {
                if let Ok(mempool) = std::fs::read_to_string("mempool.json") {
                    for line in mempool.lines() {
                        if let Ok(tx) = serde_json::from_str::<Transaction>(line) {
                            println!("TX: {} -> {} amount: {}", tx.from, tx.to, tx.amount);
                        }
                    }
                } else {
                    println!("Mempool jest pusty");
                }
            }

            "exit" => break,
            _ => println!("?"),
        }
    }
}
/* ---- reszta pliku: is_tx_valid, save_chain, load_chain, load_peers,
save_peers, broadcast_to_known_nodes, sync_chain – bez zmian ---- */

fn is_tx_valid(tx: &Transaction, chain: &[Block]) -> bool {
    if tx.from.is_empty() && tx.signature == "reward" {
        return true;
    }

    let secp = Secp256k1::new();
    let from_pubkey = match tx.from.parse::<PublicKey>() {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let mut balance: i64 = 0;
    for block in chain {
        for btx in &block.transactions {
            if btx.to == tx.from {
                balance += btx.amount as i64;
            } else if btx.from == tx.from {
                balance -= btx.amount as i64;
            }
        }
    }
    if balance < tx.amount as i64 {
        return false;
    }

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
        block
            .transactions
            .iter()
            .any(|btx| btx.signature == tx.signature)
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

fn load_peers() -> Vec<String> {
    if Path::new("peers.json").exists() {
        let json = std::fs::read_to_string("peers.json").unwrap();
        serde_json::from_str(&json).unwrap_or_else(|_| vec![])
    } else {
        vec![]
    }
}

fn save_peers(peers: &Vec<String>) {
    let json = serde_json::to_string_pretty(peers).unwrap();
    std::fs::write("peers.json", json).unwrap();
}

async fn broadcast_to_known_nodes(block: &Block) {
    if let Ok(list) = std::fs::read_to_string("peers.json") {
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
    if let Ok(list) = std::fs::read_to_string("peers.json") {
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
                        }
                    }
                }
            }
        }
    }
}
