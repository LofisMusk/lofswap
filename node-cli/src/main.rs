// === node-cli/src/main.rs ===
use blockchain_core::{Block, Transaction};
use easy_upnp::{UpnpConfig as EasyConfig, add_ports, delete_ports};
use igd::PortMappingProtocol;
use igd::aio::search_gateway;
use local_ip_address::local_ip;
use rand::seq::{IndexedRandom};
use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};
use serde_json;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{self, Write},
    net::{TcpStream as StdTcpStream, ToSocketAddrs},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    time::sleep,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;

static OBSERVED_IP: once_cell::sync::Lazy<RwLock<Option<String>>> = once_cell::sync::Lazy::new(|| RwLock::new(None));

const LISTEN_PORT: u16 = 6000;
const BOOTSTRAP_NODES: &[&str] = &["31.135.167.5:6000", "31.135.167.5:6001"];

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let no_upnp = args.iter().any(|a| a == "--no-upnp");
    let no_peer_exchange = args.iter().any(|a| a == "--no-peer-exchange");

    if !no_upnp {
        println!("[DEBUG] Attempting UPnP port mapping...");
        if let Err(_) = setup_upnp(LISTEN_PORT).await {
            eprintln!("[DEBUG] UPnP port mapping failed. Continuing without it.");
        };
    } else {
        println!("[DEBUG] Skipping UPnP setup (--no-upnp flag set)");
    }


    let blockchain = Arc::new(Mutex::new(load_chain()));
    let peers = Arc::new(Mutex::new(load_peers()));

    // Determine our own address for peer filtering
    let my_ip = OBSERVED_IP.read().unwrap().clone().unwrap_or_else(|| local_ip().unwrap().to_string());
    let my_addr = format!("{}:{}", my_ip, LISTEN_PORT);

    println!("[DEBUG] My address: {}", my_addr);
    println!("[DEBUG] My IP: {}", my_ip);

    // TCP server
    {
        let blockchain = blockchain.clone();
        let peers = peers.clone();
        let my_addr = my_addr.clone();
        tokio::spawn(async move {
            let addr = format!("0.0.0.0:{LISTEN_PORT}");
            let listener = TcpListener::bind(addr).await.unwrap();
            println!("Node nasłuchuje na porcie {LISTEN_PORT}");

            loop {
                if let Ok((mut stream, addr)) = listener.accept().await {
                    // zapisz IP jako peer
                    if addr.port() == LISTEN_PORT {
                        let ip = addr.ip().to_string();
                        {
                            let mut observed = OBSERVED_IP.write().unwrap();
                            *observed = Some(ip.clone());
                        }
                        let peer_addr = format!("{}:{}", ip, addr.port());
                        let mut p = peers.lock().await;
                        if !p.contains(&peer_addr) {
                            println!("Dodano nowego peera: {}", peer_addr);
                            p.push(peer_addr.clone());
                            save_peers(&p);
                        }
                        drop(p);
                    }

                    let blockchain = blockchain.clone();
                    let peers = peers.clone();
                    let my_addr = my_addr.clone();

                    tokio::spawn(async move {
                        let mut buf = vec![0; 65536];
                        if let Ok(n) = stream.read(&mut buf).await {
                            let slice = &buf[..n];
                            let txt = String::from_utf8_lossy(slice);

                            if txt.starts_with("/balance/") {
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
                                let _ = stream.shutdown().await;
                            } else if txt.trim() == "/peers" {
                                // Always send the current peers.json file, not just in-memory list
                                let peers_json = std::fs::read_to_string("peers.json").unwrap_or_else(|_| "[]".to_string());
                                let _ = stream.write_all(peers_json.as_bytes()).await;
                                let _ = stream.shutdown().await;
                            } else if txt.trim() == "/chain" {
                                let chain = blockchain.lock().await;
                                let _ = stream
                                    .write_all(serde_json::to_string(&*chain).unwrap().as_bytes())
                                    .await;
                                let _ = stream.shutdown().await;
                            } else if txt.trim() == "/chain-hash" {
                                let chain = blockchain.lock().await;
                                let json = serde_json::to_string(&*chain).unwrap();
                                let hash = Sha256::digest(json.as_bytes());
                                let _ = stream.write_all(hex::encode(hash).as_bytes()).await;
                                let _ = stream.shutdown().await;
                            } else if let Ok(tx) = serde_json::from_slice::<Transaction>(slice) {
                                let chain = blockchain.lock().await;
                                if is_tx_valid(&tx, &chain) {
                                    println!("✓ TX do mempoolu");
                                    if let Ok(mut f) = OpenOptions::new()
                                        .create(true)
                                        .append(true)
                                        .open("mempool.json")
                                    {
                                        let _ =
                                            writeln!(f, "{}", serde_json::to_string(&tx).unwrap());
                                    }
                                } else {
                                    println!("✗ TX odrzucony (podpis / saldo)");
                                }
                            } else if txt.starts_with("/iam/") {
                                let new_peer = txt.trim().replace("/iam/", "");
                                if new_peer.ends_with(":6000") && new_peer != my_addr {
                                    let mut p = peers.lock().await;
                                    if !p.contains(&new_peer) {
                                        println!("Dodano peera przez /iam/: {}", new_peer);
                                        p.push(new_peer.clone());
                                        save_peers(&p);
                                    }
                                }
                                let _ = stream.shutdown().await;
                                return;
                            } else if txt.trim().starts_with("/peers") {
                                let rest = txt.trim().strip_prefix("/peers").unwrap_or("");
                                if !rest.is_empty() {
                                    if let Ok(list) = serde_json::from_str::<Vec<String>>(rest) {
                                        let mut p = peers.lock().await;
                                        for peer in list {
                                            if peer.ends_with(":6000") && !p.contains(&peer) && peer != my_addr {
                                                println!("Dodano peera z /peers: {}", peer);
                                                p.push(peer);
                                            }
                                        }
                                        save_peers(&p);
                                    }
                                }
                                let _ = stream.shutdown().await;
                            } else if let Ok(block) = serde_json::from_slice::<Block>(slice) {
                                println!("[DEBUG] Otrzymano blok z sieci: {}. Rozpoczynam weryfikację...", block.hash);
                                let mut chain = blockchain.lock().await;
                                // Check if block is already present
                                if chain.iter().any(|b| b.hash == block.hash) {
                                    println!("[DEBUG] Blok {} już istnieje w łańcuchu. Pomijam.", block.hash);
                                    let _ = stream.shutdown().await;
                                    return;
                                }
                                // Check if block is valid and extends the chain
                                let zero = String::from("0");
                                let prev_hash = chain.last().map(|b| &b.hash).unwrap_or(&zero);
                                if &block.previous_hash == prev_hash && block.index == chain.len() as u64 {
                                    // Optionally: verify all transactions in the block here
                                    println!("[DEBUG] Blok {} jest poprawny. Dodaję do łańcucha.", block.hash);
                                    chain.push(block.clone());
                                    save_chain(&chain);
                                    println!("✓ Dodano nowy blok z sieci: {}", block.hash);
                                    // Propagate to other peers
                                    broadcast_to_known_nodes(&block).await;
                                } else {
                                    println!("[DEBUG] Blok {} odrzucony: nie pasuje do łańcucha.", block.hash);
                                    println!("✗ Odrzucono blok: nie pasuje do łańcucha");
                                }
                                let _ = stream.shutdown().await;
                                return;
                            }
                        }
                    });
                }
            }
        });
    }

    if !no_peer_exchange {
        // peer discovery z bootstrap
        for &boot in BOOTSTRAP_NODES {
            if let Ok(Ok(mut s)) =
                tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(boot)).await
            {
                let local = format!("{}:{}", local_ip().unwrap(), LISTEN_PORT);
                let _ = s.write_all(format!("/iam/{}\n", local).as_bytes()).await;
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
    } else {
        println!("[DEBUG] Skipping peer exchange (--no-peer-exchange flag set)");
    }

    // CLI
    println!(
        "Komendy: mine | sync | print-chain | list-peers | add-peer | remove-peer | remove-offline-peers | clear-chain | print-mempool | exit"
    );
    loop {
        print!("> ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        io::stdin().read_line(&mut line).unwrap();
        match line.trim() {
            "mine" => {
                let mut chain = blockchain.lock().await;
                let parsed: Vec<Transaction> = std::fs::read_to_string("mempool.json")
                    .unwrap_or_default()
                    .lines()
                    .filter_map(|l| serde_json::from_str(l).ok())
                    .filter(|tx| is_tx_valid(tx, &chain))
                    .collect();

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
                verify_and_broadcast_chain(&blockchain, &peers).await;
            }
            line if line.starts_with("add-peer ") => {
                let parts: Vec<&str> = line.trim().split_whitespace().collect();
                if parts.len() == 2 {
                    let new_peer = parts[1].to_string();
                    let mut p = peers.lock().await;
                    if !p.contains(&new_peer) {
                        p.push(new_peer.clone());
                        save_peers(&p);
                        println!("✓ Peer dodany: {}", new_peer);
                    } else {
                        println!("Peer już istnieje.");
                    }
                } else {
                    println!("Użycie: add-peer <adres:port>");
                }
            }
            line if line.starts_with("remove-peer ") => {
                let parts: Vec<&str> = line.trim().split_whitespace().collect();
                if parts.len() == 2 {
                    let target_peer = parts[1];
                    let mut p = peers.lock().await;
                    let before = p.len();
                    p.retain(|peer| peer != target_peer);
                    if p.len() < before {
                        save_peers(&p);
                        println!("✓ Peer usunięty: {}", target_peer);
                    } else {
                        println!("Nie znaleziono takiego peera.");
                    }
                } else {
                    println!("Użycie: remove-peer <adres:port>");
                }
            }
            "remove-offline-peers" => {
                let mut p = peers.lock().await;
                let before = p.len();
                p.retain(|peer| {
                    peer.to_socket_addrs()
                        .ok()
                        .and_then(|mut i| i.next())
                        .and_then(|a| {
                            StdTcpStream::connect_timeout(&a, Duration::from_millis(300)).ok()
                        })
                        .is_some()
                });
                let removed = before - p.len();
                save_peers(&p);
                println!("✓ Usunięto {} offline peerów", removed);
            }
            "sync" => sync_chain(&blockchain, &peers, false).await,
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
    let msg = match Message::from_slice(&hash).ok() {
        Some(m) => m,
        None => return false,
    };

    let sig_bytes = match hex::decode(&tx.signature).ok() {
        Some(bytes) => bytes,
        None => return false,
    };
    let signature = match Signature::from_compact(&sig_bytes).ok() {
        Some(sig) => sig,
        None => return false,
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
        serde_json::from_str(&json).unwrap_or_default()
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
            println!("[DEBUG] Próba wysłania bloku do peera: {}", line);
            if let Ok(mut stream) = TcpStream::connect(line).await {
                let json = serde_json::to_string(block).unwrap();
                let _ = stream.write_all(json.as_bytes()).await;
                let _ = stream.shutdown().await;
                println!("[DEBUG] Wysłano blok do peera: {}", line);
            } else {
                println!("[DEBUG] Nie udało się połączyć z peerem: {}", line);
            }
        }
    }
}

async fn sync_chain(blockchain: &Arc<Mutex<Vec<Block>>>, peers: &Arc<Mutex<Vec<String>>>, force: bool) {

    let peer_list = peers.lock().await.clone();
    let mut rng = rand::thread_rng();
    let sample: Vec<_> = peer_list.choose_multiple(&mut rng, 1).cloned().collect();

    let mut hash_map = HashMap::new();
    for peer in &sample {
        if let Ok(mut stream) = TcpStream::connect(peer).await {
            let _ = stream.write_all(b"/chain-hash").await;
            let mut buf = vec![0; 512];
            if let Ok(n) = stream.read(&mut buf).await {
                let hash = String::from_utf8_lossy(&buf[..n]).to_string();
                hash_map
                    .entry(hash)
                    .or_insert_with(Vec::new)
                    .push(peer.clone());
            }
        }
    }

    let sync_target = if force {
        // Take the first peer, regardless of hash agreement
        sample.get(0).cloned()
    } else {
        // Only sync if at least one matching hash
        hash_map.into_iter().find(|(_, v)| v.len() >= 1).map(|(_, nodes)| nodes[0].clone())
    };

    if let Some(chosen_peer) = sync_target {
        if let Ok(mut stream) = TcpStream::connect(&chosen_peer).await {
            let _ = stream.write_all(b"/chain").await;
            let mut buffer = vec![0; 8192];
            if let Ok(n) = stream.read(&mut buffer).await {
                if let Ok(peer_chain) = serde_json::from_slice::<Vec<Block>>(&buffer[..n]) {
                    let local_hash = {
                        let local = blockchain.lock().await;
                        let json = serde_json::to_string(&*local).unwrap();
                        hex::encode(Sha256::digest(json.as_bytes()))
                    };
                    if peer_chain.len() > blockchain.lock().await.len() || force {
                        let mut local = blockchain.lock().await;
                        *local = peer_chain;
                        save_chain(&local);
                        println!("✓ Synchronizacja zakończona z {} (force={})", chosen_peer, force);
                    } else {
                        println!(
                            "Chain z {} nie był dłuższy lub hash się nie zgadzał",
                            chosen_peer
                        );
                    }
                }
            }
        }
    } else {
        println!("✗ Nie udało się uzgodnić hashów łańcucha (brak zgodnych peerów)");
    }
}

async fn verify_and_broadcast_chain(blockchain: &Arc<Mutex<Vec<Block>>>, peers: &Arc<Mutex<Vec<String>>>) {
    use std::net::{TcpStream as StdTcpStream, ToSocketAddrs};

    let peer_list = peers.lock().await.clone();
    let online_peers: Vec<_> = peer_list
        .iter()
        .filter(|peer| {
            peer.to_socket_addrs()
                .ok()
                .and_then(|mut i| i.next())
                .and_then(|a| StdTcpStream::connect_timeout(&a, Duration::from_millis(300)).ok())
                .is_some()
        })
        .cloned()
        .collect();

    if online_peers.is_empty() {
        println!("✗ Brak online peerów do weryfikacji");
        return;
    }

    if let Some(random_peer) = online_peers.choose(&mut rand::thread_rng()) {
        println!("Wybrano peera do weryfikacji: {}", random_peer);
        if let Ok(mut stream) = TcpStream::connect(random_peer).await {
            let _ = stream.write_all(b"/chain-hash").await;
            let mut buf = vec![0; 512];
            if let Ok(n) = stream.read(&mut buf).await {
                let peer_hash = String::from_utf8_lossy(&buf[..n]).to_string();
                let local = blockchain.lock().await;
                let json = serde_json::to_string(&*local).unwrap();
                let local_hash = hex::encode(Sha256::digest(json.as_bytes()));
                if peer_hash == local_hash {
                    println!("✓ Hash zgodny z {} – rozsyłam chain", random_peer);
                    // Rozsyłaj cały chain, nie tylko ostatni blok
                    for peer in online_peers {
                        if let Ok(mut s) = TcpStream::connect(&peer).await {
                            let _ = s.write_all(b"/chain").await;
                            let _ = s.write_all(json.as_bytes()).await;
                            let _ = s.shutdown().await;
                        }
                    }
                } else {
                    println!("✗ Hash niezgodny z {} – chain nie został rozesłany", random_peer);
                }
            } else {
                println!("✗ Peer nie odpowiedział na zapytanie o hash");
            }
        } else {
            println!("✗ Nie udało się połączyć z peerem do weryfikacji");
        }
    }
}

async fn setup_upnp(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    match try_igd_upnp(port).await {
        Ok(_) => return Ok(()),
        Err(e) => eprintln!("[DEBUG] IGD UPnP failed: {e} – fallback to easy_upnp"),
    }

    let cfg = Arc::new(EasyConfig {
        address: None,
        port,
        protocol: easy_upnp::PortMappingProtocol::TCP,
        duration: 3600,
        comment: "lofswap node".to_string(),
    });

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
        })
        .expect("Nie udało się ustawić handlera SIGINT");
    }

    for result in add_ports(std::iter::once(EasyConfig {
        address: cfg.address.clone(),
        port: cfg.port,
        protocol: cfg.protocol,
        duration: cfg.duration,
        comment: cfg.comment.clone(),
    })) {
        match result {
            Ok(_) => {
                println!("✓ Port {} przekierowany (Easy UPnP fallback)", port);
                return Ok(());
            }
            Err(e) => eprintln!("⚠️ Easy UPnP: błąd przekierowania portu: {}", e),
        }
    }

    Err("Nie udało się przekierować portu przez żaden mechanizm".into())
}

async fn try_igd_upnp(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let gateway = search_gateway(Default::default()).await?;
    let local_ip = local_ip()?;
    let ip = match local_ip {
        std::net::IpAddr::V4(ipv4) => ipv4,
        _ => return Err("Only IPv4 supported".into()),
    };

    let socket = std::net::SocketAddrV4::new(ip, port);
    gateway
        .add_port(PortMappingProtocol::TCP, port, socket, 3600, "lofswap node")
        .await?;

    println!("✓ Port {} przekierowany na {} (IGD)", port, socket);
    Ok(())
}
