use blockchain_core::{Block, Transaction};
use easy_upnp::{UpnpConfig as EasyConfig, add_ports, delete_ports};
use igd::PortMappingProtocol;
use igd::aio::search_gateway;
use local_ip_address::local_ip;
// rand helpers
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
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, RwLock},
    time::sleep,
};

// Use Tokio's RwLock for async compatibility
static OBSERVED_IP: once_cell::sync::Lazy<RwLock<Option<String>>> = 
    once_cell::sync::Lazy::new(|| RwLock::new(None));

// Connection limiting
static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

const LISTEN_PORT: u16 = 6000;
const EXPLORER_PORT: u16 = 7000; // simple HTTP JSON explorer
const BOOTSTRAP_NODES: &[&str] = &["31.135.167.5:6000", "92.5.16.170:6000"];
const MAX_CONNECTIONS: usize = 50;
const BUFFER_SIZE: usize = 8192;

#[derive(Debug)]
enum NodeError {
    NetworkError(String),
    SerializationError(String),
    ValidationError(String),
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            NodeError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            NodeError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl std::error::Error for NodeError {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let no_upnp = args.iter().any(|a| a == "--no-upnp");
    let no_peer_exchange = args.iter().any(|a| a == "--no-peer-exchange");

    println!("[STARTUP] Starting blockchain node...");

    // Step 1: Setup UPnP port mapping
    if !no_upnp {
        println!("[STARTUP] Step 1: Attempting UPnP port mapping for port {}...", LISTEN_PORT);
        match setup_upnp(LISTEN_PORT).await {
            Ok(_) => println!("[STARTUP] ✓ UPnP port mapping successful"),
            Err(e) => {
                eprintln!("[STARTUP] ⚠️ UPnP port mapping failed: {}. Continuing without it.", e);
            }
        }
    } else {
        println!("[STARTUP] Step 1: Skipping UPnP setup (--no-upnp flag set)");
    }

    // Initialize blockchain and peers
    let blockchain = Arc::new(Mutex::new(load_chain()?));
    let peers = Arc::new(Mutex::new(load_peers()?));

    // Start TCP server first so we can receive connections
    println!("[STARTUP] Starting TCP server on port {}...", LISTEN_PORT);
    start_tcp_server(blockchain.clone(), peers.clone()).await?;

    // Start simple HTTP explorer server
    tokio::spawn(start_http_explorer(blockchain.clone(), peers.clone()));

    // Start periodic maintenance (peer finding + light sync)
    tokio::spawn(maintenance_loop(blockchain.clone(), peers.clone()));

    // Give the server a moment to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    if !no_peer_exchange {
        // Step 2-7: Complete bootstrap and peer discovery sequence
        bootstrap_and_discover_ip(&peers).await;
    } else {
        println!("[STARTUP] Skipping peer exchange and IP discovery (--no-peer-exchange flag set)");
    }

    println!("[STARTUP] ✓ Node initialization complete!");
    
    // Final step: Start CLI
    println!("[STARTUP] Launching command line interface...");
    run_cli(blockchain, peers).await;
    
    Ok(())
}

async fn start_tcp_server(
    blockchain: Arc<Mutex<Vec<Block>>>,
    peers: Arc<Mutex<Vec<String>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let bind_ip = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0".to_string());
    let addr = format!("{}:{}", bind_ip, LISTEN_PORT);
    let listener = TcpListener::bind(&addr).await?;
    println!("Node listening on port {}", LISTEN_PORT);

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    // Connection limiting
                    if ACTIVE_CONNECTIONS.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                        println!("[DEBUG] Max connections reached, dropping connection from {}", addr);
                        continue;
                    }

                    ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
                    
                    // Handle peer IP detection
                    if addr.port() == LISTEN_PORT {
                        let ip = addr.ip().to_string();
                        if is_public_ip(&ip) {
                            // Only set observed IP if we don't have one yet
                            if OBSERVED_IP.read().await.is_none() {
                                println!("[DEBUG] Setting public IP from incoming connection: {}", ip);
                                *OBSERVED_IP.write().await = Some(ip.clone());
                            }
                            
                            let peer_addr = format!("{}:{}", ip, addr.port());
                            let mut p = peers.lock().await;
                            if !p.contains(&peer_addr) {
                                println!("Added new peer: {}", peer_addr);
                                p.push(peer_addr);
                                if let Err(e) = save_peers(&p) {
                                    eprintln!("Failed to save peers: {}", e);
                                }
                            }
                        }
                    }

                    let blockchain = blockchain.clone();
                    let peers = peers.clone();
                    
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, blockchain, peers).await {
                            eprintln!("[DEBUG] Connection handling error: {}", e);
                        }
                        ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                Err(e) => eprintln!("[DEBUG] Failed to accept connection: {}", e),
            }
        }
    });

    Ok(())
}

async fn handle_connection(
    mut stream: TcpStream,
    blockchain: Arc<Mutex<Vec<Block>>>,
    peers: Arc<Mutex<Vec<String>>>,
) -> Result<(), NodeError> {
    let mut buf = vec![0; BUFFER_SIZE];
    let n = stream.read(&mut buf).await
        .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    
    let slice = &buf[..n];
    let request = String::from_utf8_lossy(slice);

    match handle_request(&request, &mut stream, blockchain, peers).await {
        Ok(_) => Ok(()),
        Err(e) => {
            let _ = stream.shutdown().await;
            Err(e)
        }
    }
}

async fn handle_request(
    request: &str,
    stream: &mut TcpStream,
    blockchain: Arc<Mutex<Vec<Block>>>,
    peers: Arc<Mutex<Vec<String>>>,
) -> Result<(), NodeError> {
    // Basic HTTP compatibility: if request starts with GET, trim to path only
    let request = if request.starts_with("GET ") {
        request
            .split_whitespace()
            .nth(1)
            .unwrap_or("")
            .to_string()
    } else {
        request.to_string()
    };
    if let Some(addr) = request.strip_prefix("/balance/") {
        let addr = addr.trim();
        let chain = blockchain.lock().await;
        let balance = calculate_balance(addr, &chain);
        stream.write_all(balance.to_string().as_bytes()).await
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    }
    else if request.trim() == "/peers" {
        let peers_json = std::fs::read_to_string("peers.json")
            .unwrap_or_else(|_| "[]".to_string());
        stream.write_all(peers_json.as_bytes()).await
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    }
    else if request.trim() == "/chain" {
        let chain = blockchain.lock().await;
        let json = serde_json::to_string(&*chain)
            .map_err(|e| NodeError::SerializationError(e.to_string()))?;
        stream.write_all(json.as_bytes()).await
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    }
    else if request.trim() == "/chain-hash" {
        let chain = blockchain.lock().await;
        let json = serde_json::to_string(&*chain)
            .map_err(|e| NodeError::SerializationError(e.to_string()))?;
        let hash = Sha256::digest(json.as_bytes());
        stream.write_all(hex::encode(hash).as_bytes()).await
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    }
    else if request.trim() == "/whoami" {
        if let Some(ip) = OBSERVED_IP.read().await.as_ref() {
            let response = format!("{}:{}", ip, LISTEN_PORT);
            println!("[DEBUG] Responding to /whoami with: {}", response);
            stream.write_all(response.as_bytes()).await
                .map_err(|e| NodeError::NetworkError(e.to_string()))?;
        } else {
            println!("[DEBUG] /whoami requested but no IP set yet");
            stream.write_all(b"unknown").await
                .map_err(|e| NodeError::NetworkError(e.to_string()))?;
        }
    }
    else if let Some(new_peer) = request.strip_prefix("/iam/") {
        handle_iam_request(new_peer.trim(), peers).await?;
    }
    else if let Some(rest) = request.strip_prefix("/peers") {
        handle_peers_request(rest, peers).await?;
    }
    else if let Ok(tx) = serde_json::from_slice::<Transaction>(request.as_bytes()) {
        handle_transaction(tx, blockchain).await?;
    }
    else if let Ok(block) = serde_json::from_slice::<Block>(request.as_bytes()) {
        handle_block(block, stream, blockchain).await?;
        return Ok(()); // Early return to avoid shutdown
    }

    stream.shutdown().await
        .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    Ok(())
}

// --- Simple HTTP Explorer ---
async fn start_http_explorer(
    blockchain: Arc<Mutex<Vec<Block>>>,
    peers: Arc<Mutex<Vec<String>>>,
) {
    let bind_ip = std::env::var("EXPLORER_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0".to_string());
    let addr = format!("{}:{}", bind_ip, EXPLORER_PORT);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => {
            println!("Explorer listening on http://{}", addr);
            l
        }
        Err(e) => {
            eprintln!("[EXPLORER] Failed to bind {}: {}", addr, e);
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                let bc = blockchain.clone();
                let pr = peers.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    match stream.read(&mut buf).await {
                        Ok(n) if n > 0 => {
                            let req = String::from_utf8_lossy(&buf[..n]).to_string();
                            let path = req.split_whitespace().nth(1).unwrap_or("/");
                            let (status, body) = handle_http_route(path, &bc, &pr).await;
                            let resp = format!(
                                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                status,
                                body.len(),
                                body
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                            let _ = stream.shutdown().await;
                        }
                        _ => {
                            let _ = stream.shutdown().await;
                        }
                    }
                });
            }
            Err(e) => eprintln!("[EXPLORER] accept error: {}", e),
        }
    }
}

async fn handle_http_route(
    path: &str,
    blockchain: &Arc<Mutex<Vec<Block>>>,
    peers: &Arc<Mutex<Vec<String>>>,
) -> (String, String) {
    if path == "/health" {
        return ("200 OK".into(), "{\"status\":\"ok\"}".into());
    }
    if path == "/height" {
        let chain = blockchain.lock().await;
        if let Some(tip) = chain.last() {
            let body = serde_json::json!({
                "height": chain.len(),
                "tip_hash": tip.hash,
                "tip_time": tip.timestamp,
            })
            .to_string();
            return ("200 OK".into(), body);
        } else {
            return ("200 OK".into(), "{\"height\":0,\"tip_hash\":\"\",\"tip_time\":0}".into());
        }
    }
    if let Some(hash) = path.strip_prefix("/block/") {
        let chain = blockchain.lock().await;
        let blk = chain.iter().find(|b| b.hash == hash);
        let body = serde_json::to_string(&blk).unwrap_or("null".into());
        return ("200 OK".into(), body);
    }
    if let Some(addr) = path.strip_prefix("/address/") {
        if let Some(rest) = addr.strip_suffix("/balance") {
            let chain = blockchain.lock().await;
            let bal = calculate_balance(rest, &chain);
            let body = serde_json::json!({ "address": rest, "balance": bal }).to_string();
            return ("200 OK".into(), body);
        }
        if let Some(rest) = addr.strip_suffix("/txs") {
            let chain = blockchain.lock().await;
            let mut txs = Vec::new();
            for b in chain.iter() {
                for tx in &b.transactions {
                    if tx.to == rest || tx.from == rest { txs.push(tx.clone()); }
                }
            }
            let body = serde_json::to_string(&txs).unwrap_or("[]".into());
            return ("200 OK".into(), body);
        }
    }
    if path == "/peers" {
        let p = peers.lock().await;
        let body = serde_json::to_string(&*p).unwrap_or("[]".into());
        return ("200 OK".into(), body);
    }
    ("404 Not Found".into(), "{\"error\":\"not found\"}".into())
}

// --- Periodic maintenance loop ---
async fn maintenance_loop(
    blockchain: Arc<Mutex<Vec<Block>>>,
    peers: Arc<Mutex<Vec<String>>>,
) {
    loop {
        sleep(Duration::from_secs(60)).await;
        // Try to sync with peers (non-force)
        sync_chain(&blockchain, &peers, false).await;

        // Try basic peer refresh: ask a couple of peers for their peer lists
        let peer_list = peers.lock().await.clone();
        let mut added = 0usize;
        for peer in peer_list.iter().take(5) {
            if let Ok(mut stream) = TcpStream::connect(peer).await {
                let _ = stream.write_all(b"/peers").await;
                let mut buf = vec![0u8; 8192];
                if let Ok(n) = stream.read(&mut buf).await {
                    if let Ok(list) = serde_json::from_slice::<Vec<String>>(&buf[..n]) {
                        let mut p = peers.lock().await;
                        for entry in list {
                            if !p.contains(&entry) && entry.ends_with(":6000") {
                                p.push(entry);
                                added += 1;
                            }
                        }
                        let _ = save_peers(&p);
                    }
                }
                let _ = stream.shutdown().await;
            }
        }
        if added > 0 {
            println!("[MAINT] Added {} peers from refresh", added);
        }
    }
}

async fn handle_iam_request(
    new_peer: &str, 
    peers: Arc<Mutex<Vec<String>>>
) -> Result<(), NodeError> {
    if new_peer.ends_with(":6000") {
        let my_addr = get_my_address().await;
        // Check if this is our own address
        if Some(new_peer) != my_addr.as_deref() {
            let mut p = peers.lock().await;
            if !p.contains(&new_peer.to_string()) {
                println!("Added peer via /iam/: {}", new_peer);
                p.push(new_peer.to_string());
                save_peers(&p)?;
            }
        } else {
            println!("[DEBUG] Ignoring /iam/ request from self: {}", new_peer);
        }
    }
    Ok(())
}

async fn handle_peers_request(
    rest: &str,
    peers: Arc<Mutex<Vec<String>>>
) -> Result<(), NodeError> {
    if !rest.is_empty() {
        if let Ok(list) = serde_json::from_str::<Vec<String>>(rest) {
            let my_addr = get_my_address().await;
            let mut p = peers.lock().await;
            let mut added_count = 0;
            
            for peer in list {
                if peer.ends_with(":6000") && 
                   !p.contains(&peer) && 
                   Some(&peer) != my_addr.as_ref() {
                    println!("Added peer from /peers: {}", peer);
                    p.push(peer);
                    added_count += 1;
                }
            }
            
            if added_count > 0 {
                save_peers(&p)?;
                println!("[DEBUG] Added {} new peers from /peers request", added_count);
            }
        }
    }
    Ok(())
}

async fn handle_transaction(
    tx: Transaction,
    blockchain: Arc<Mutex<Vec<Block>>>
) -> Result<(), NodeError> {
    let chain = blockchain.lock().await;
    if is_tx_valid(&tx, &chain).is_ok() {
        println!("✓ TX added to mempool");
        if let Ok(mut f) = OpenOptions::new()
            .create(true)
            .append(true)
            .open("mempool.json") 
        {
            let tx_json = serde_json::to_string(&tx)
                .map_err(|e| NodeError::SerializationError(e.to_string()))?;
            let _ = writeln!(f, "{}", tx_json);
        }
    } else {
        println!("✗ TX rejected (signature/balance)");
    }
    Ok(())
}

async fn handle_block(
    block: Block,
    stream: &mut TcpStream,
    blockchain: Arc<Mutex<Vec<Block>>>
) -> Result<(), NodeError> {
    println!("[DEBUG] Received block from network: {}. Starting verification...", block.hash);
    let mut chain = blockchain.lock().await;
    
    // Check if block already exists
    if chain.iter().any(|b| b.hash == block.hash) {
        println!("[DEBUG] Block {} already exists in chain. Skipping.", block.hash);
        stream.write_all(b"BLOCK_EXISTS").await
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
        stream.shutdown().await
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
        return Ok(());
    }
    
    // Validate block
    let zero = String::from("0");
    let prev_hash = chain.last().map(|b| &b.hash).unwrap_or(&zero);
    if &block.previous_hash == prev_hash && block.index == chain.len() as u64 {
        println!("[DEBUG] Block {} is valid. Adding to chain.", block.hash);
        chain.push(block.clone());
        save_chain(&chain)?;
        println!("✓ Added new block from network: {}", block.hash);
        
        // Propagate to other peers
        drop(chain); // Release lock before async operation
        broadcast_to_known_nodes(&block).await;
        
        stream.write_all(b"BLOCK_ACCEPTED").await
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    } else {
        println!("[DEBUG] Block {} rejected: doesn't fit chain.", block.hash);
        stream.write_all(b"BLOCK_REJECTED").await
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    }
    
    stream.shutdown().await
        .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    Ok(())
}

async fn bootstrap_and_discover_ip(peers: &Arc<Mutex<Vec<String>>>) {
    // Step 2: Ask bootstrap nodes for peers.json file
    println!("[STARTUP] Step 2: Requesting peers.json from bootstrap nodes...");
    let mut bootstrap_peers = Vec::new();
    
    // First, add bootstrap nodes to our initial peer list
    {
        let mut p = peers.lock().await;
        for &bootstrap_node in BOOTSTRAP_NODES {
            if !p.contains(&bootstrap_node.to_string()) {
                p.push(bootstrap_node.to_string());
                bootstrap_peers.push(bootstrap_node.to_string());
                println!("[STARTUP] Added bootstrap node to peers: {}", bootstrap_node);
            }
        }
        if let Err(e) = save_peers(&p) {
            println!("[STARTUP] ✗ Failed to save bootstrap nodes to peers: {}", e);
        }
    }
    
    for &bootstrap_node in BOOTSTRAP_NODES {
        println!("[STARTUP] Trying bootstrap node: {}", bootstrap_node);
        match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(bootstrap_node)).await {
            Ok(Ok(mut stream)) => {
                println!("[STARTUP] ✓ Connected to bootstrap node: {}", bootstrap_node);
                
                // Request peers list
                if let Err(e) = stream.write_all(b"/peers").await {
                    println!("[STARTUP] ✗ Failed to request peers from {}: {}", bootstrap_node, e);
                    continue;
                }

                let mut buf = vec![0; 8192];
                match stream.read(&mut buf).await {
                    Ok(n) => {
                        let content = String::from_utf8_lossy(&buf[..n]);
                        println!("[STARTUP] Received peers data from {}: {}", bootstrap_node, content.trim());
                        
                        match serde_json::from_slice::<Vec<String>>(&buf[..n]) {
                            Ok(peer_list) => {
                                println!("[STARTUP] ✓ Successfully parsed {} peers from {}", peer_list.len(), bootstrap_node);
                                for peer in &peer_list {
                                    if !bootstrap_peers.contains(peer) {
                                        bootstrap_peers.push(peer.clone());
                                        println!("[STARTUP] Added peer from bootstrap: {}", peer);
                                    }
                                }
                            }
                            Err(e) => {
                                println!("[STARTUP] ✗ Failed to parse peers from {}: {}", bootstrap_node, e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("[STARTUP] ✗ Failed to read response from {}: {}", bootstrap_node, e);
                    }
                }
                let _ = stream.shutdown().await;
            }
            Ok(Err(e)) => {
                println!("[STARTUP] ✗ Failed to connect to bootstrap node {}: {}", bootstrap_node, e);
            }
            Err(_) => {
                println!("[STARTUP] ✗ Timeout connecting to bootstrap node: {}", bootstrap_node);
            }
        }
    }

    // Save all discovered peers (including bootstrap nodes)
    {
        let mut p = peers.lock().await;
        for peer in &bootstrap_peers {
            if !p.contains(peer) {
                p.push(peer.clone());
            }
        }
        if let Err(e) = save_peers(&p) {
            println!("[STARTUP] ✗ Failed to save bootstrap peers: {}", e);
        } else {
            println!("[STARTUP] ✓ Saved {} peers to peers.json", p.len());
        }
    }

    // Step 3: Pick a random peer from peers.json to determine public IP
    println!("[STARTUP] Step 3: Selecting random peer to determine public IP...");
    let selected_peer = bootstrap_peers.get(0).cloned();

    let my_public_ip = if let Some(peer) = selected_peer {
        // Step 4: Determine public IP from selected peer
        println!("[STARTUP] Step 4: Determining public IP from peer: {}", peer);
        determine_ip_from_specific_peer(&peer).await
    } else {
        println!("[STARTUP] ✗ No peer selected for IP determination");
        None
    };

    if let Some(ip) = my_public_ip {
        println!("[STARTUP] ✓ Public IP determined: {}", ip);
        *OBSERVED_IP.write().await = Some(ip.clone());
        
        // Step 5: Add our IP to peers.json and remove ourselves if we match a bootstrap node
        println!("[STARTUP] Step 5: Adding our address to peers.json and cleaning up duplicates...");
        let my_address = format!("{}:{}", ip, LISTEN_PORT);
        {
            let mut p = peers.lock().await;
            
            // Remove our own address if it's already there (from bootstrap nodes)
            p.retain(|peer| peer != &my_address);
            
            // Add our address
            p.push(my_address.clone());
            
            if let Err(e) = save_peers(&p) {
                println!("[STARTUP] ✗ Failed to save updated peers: {}", e);
            } else {
                println!("[STARTUP] ✓ Added our address to peers: {}", my_address);
                println!("[STARTUP] ✓ Cleaned up duplicate addresses");
            }
        }

        // Step 6: Broadcast updated peers.json to other nodes
        println!("[STARTUP] Step 6: Broadcasting updated peers.json to network...");
        broadcast_peers_to_network(&peers, &my_address).await;
        
    } else {
        println!("[STARTUP] ⚠️ Could not determine public IP. Node will wait for incoming connections.");
    }

    println!("[STARTUP] ✓ Bootstrap and IP discovery sequence completed");
}

async fn determine_ip_from_specific_peer(peer: &str) -> Option<String> {
    println!("[STARTUP] Contacting peer {} for IP discovery...", peer);
    
    match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(peer)).await {
        Ok(Ok(mut stream)) => {
            println!("[STARTUP] ✓ Connected to peer {}", peer);
            
            if let Err(e) = stream.write_all(b"/whoami").await {
                println!("[STARTUP] ✗ Failed to send /whoami to {}: {}", peer, e);
                return None;
            }

            let mut buf = vec![0; 64];
            match stream.read(&mut buf).await {
                Ok(n) => {
                    let response = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                    println!("[STARTUP] Raw /whoami response from {}: '{}'", peer, response);
                    
                    if !response.is_empty() && response != "unknown" {
                        // Extract IP part (before colon)
                        let ip_part = response.split(':').next().unwrap_or("").to_string();
                        if !ip_part.is_empty() && is_public_ip(&ip_part) {
                            println!("[STARTUP] ✓ Got valid public IP: {}", ip_part);
                            return Some(ip_part);
                        } else {
                            println!("[STARTUP] ✗ IP '{}' is not valid or not public", ip_part);
                        }
                    } else {
                        println!("[STARTUP] ✗ Peer {} returned empty or unknown response", peer);
                    }
                }
                Err(e) => {
                    println!("[STARTUP] ✗ Failed to read /whoami response from {}: {}", peer, e);
                }
            }
            let _ = stream.shutdown().await;
        }
        Ok(Err(e)) => {
            println!("[STARTUP] ✗ Failed to connect to peer {}: {}", peer, e);
        }
        Err(_) => {
            println!("[STARTUP] ✗ Timeout connecting to peer: {}", peer);
        }
    }
    
    None
}

async fn broadcast_peers_to_network(peers: &Arc<Mutex<Vec<String>>>, my_address: &str) {
    let peer_list = peers.lock().await.clone();
    let peers_json = match serde_json::to_string(&peer_list) {
        Ok(json) => json,
        Err(e) => {
            println!("[STARTUP] ✗ Failed to serialize peers for broadcast: {}", e);
            return;
        }
    };

    println!("[STARTUP] Broadcasting to {} peers...", peer_list.len());
    let mut successful_broadcasts = 0;

    for peer in &peer_list {
        if peer == my_address {
            continue; // Don't broadcast to ourselves
        }

        println!("[STARTUP] Broadcasting peers to: {}", peer);
        match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(peer)).await {
            Ok(Ok(mut stream)) => {
                let message = format!("/peers{}", peers_json);
                match stream.write_all(message.as_bytes()).await {
                    Ok(_) => {
                        println!("[STARTUP] ✓ Successfully broadcast peers to: {}", peer);
                        successful_broadcasts += 1;
                    }
                    Err(e) => {
                        println!("[STARTUP] ✗ Failed to send peers to {}: {}", peer, e);
                    }
                }
                let _ = stream.shutdown().await;
            }
            Ok(Err(e)) => {
                println!("[STARTUP] ✗ Failed to connect for broadcast to {}: {}", peer, e);
            }
            Err(_) => {
                println!("[STARTUP] ✗ Timeout broadcasting to: {}", peer);
            }
        }
    }

    println!("[STARTUP] ✓ Broadcast completed: {}/{} successful", successful_broadcasts, peer_list.len() - 1);
}

async fn run_cli(blockchain: Arc<Mutex<Vec<Block>>>, peers: Arc<Mutex<Vec<String>>>) {
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

async fn mine_block(blockchain: &Arc<Mutex<Vec<Block>>>) {
    let mut chain = blockchain.lock().await;
    let transactions = load_valid_transactions(&chain);
    
    if transactions.is_empty() {
        println!("No valid transactions to mine");
        return;
    }
    
    let _ = std::fs::remove_file("mempool.json");
    let prev_hash = chain.last().unwrap().hash.clone();
    let miner = get_my_address().await.unwrap_or_else(|| "unknown".to_string());
    let block = Block::new(chain.len() as u64, transactions, prev_hash, miner);
    
    println!("New block: {}", block.hash);
    chain.push(block.clone());
    
    if let Err(e) = save_chain(&chain) {
        eprintln!("Failed to save chain: {}", e);
        return;
    }
    
    drop(chain); // Release lock before async operations
    broadcast_to_known_nodes(&block).await;
    sleep(Duration::from_secs(1)).await;
    // verify_and_broadcast_chain(blockchain, peers).await;
}

fn load_valid_transactions(chain: &[Block]) -> Vec<Transaction> {
    let parsed: Vec<Transaction> = std::fs::read_to_string("mempool.json")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    
    let mut balances = calculate_balances(chain);
    let mut valid_txs = Vec::new();
    
    for tx in parsed {
        if tx.from.is_empty() {
            valid_txs.push(tx);
            continue;
        }
        
        if is_tx_valid(&tx, chain).is_ok() {
            let balance = balances.entry(tx.from.clone()).or_insert(0);
            if *balance >= tx.amount as i128 {
                *balance -= tx.amount as i128;
                *balances.entry(tx.to.clone()).or_insert(0) += tx.amount as i128;
                valid_txs.push(tx);
            }
        }
    }
    
    valid_txs
}

// Utility functions
async fn get_my_address() -> Option<String> {
    OBSERVED_IP.read().await.as_ref().map(|ip| format!("{}:{}", ip, LISTEN_PORT))
}

fn is_public_ip(ip: &str) -> bool {
    !ip.starts_with("192.") && !ip.starts_with("10.") && 
    !ip.starts_with("127.") && !ip.starts_with("172.")
}

fn calculate_balance(address: &str, chain: &[Block]) -> i128 {
    let mut balance = 0i128;
    for block in chain {
        for tx in &block.transactions {
            if tx.to == address {
                balance += tx.amount as i128;
            }
            if tx.from == address {
                balance -= tx.amount as i128;
            }
        }
    }
    balance
}

fn calculate_balances(chain: &[Block]) -> HashMap<String, i128> {
    let mut balances = HashMap::new();
    for block in chain {
        for tx in &block.transactions {
            if !tx.from.is_empty() {
                *balances.entry(tx.from.clone()).or_insert(0) -= tx.amount as i128;
            }
            *balances.entry(tx.to.clone()).or_insert(0) += tx.amount as i128;
        }
    }
    balances
}

fn is_tx_valid(tx: &Transaction, chain: &[Block]) -> Result<(), NodeError> {
    // Reward transactions are always valid
    if tx.from.is_empty() && tx.signature == "reward" {
        return Ok(());
    }

    // Parse public key
    let secp = Secp256k1::new();
    let from_pubkey = tx.from.parse::<PublicKey>()
        .map_err(|_| NodeError::ValidationError("Invalid public key".to_string()))?;

    // Check balance
    let balance = calculate_balance(&tx.from, chain);
    if balance < tx.amount as i128 {
        return Err(NodeError::ValidationError("Insufficient balance".to_string()));
    }

    // Check signature
    let msg_data = format!("{}{}{}", tx.from, tx.to, tx.amount);
    let hash = Sha256::digest(msg_data.as_bytes());
    let msg = Message::from_slice(&hash)
        .map_err(|_| NodeError::ValidationError("Invalid message hash".to_string()))?;

    let sig_bytes = hex::decode(&tx.signature)
        .map_err(|_| NodeError::ValidationError("Invalid signature format".to_string()))?;
    let signature = Signature::from_compact(&sig_bytes)
        .map_err(|_| NodeError::ValidationError("Invalid signature".to_string()))?;

    // Check for replay attacks
    let already_exists = chain.iter().any(|block| {
        block.transactions.iter().any(|btx| btx.signature == tx.signature)
    });

    if already_exists {
        return Err(NodeError::ValidationError("Transaction already exists".to_string()));
    }

    secp.verify_ecdsa(msg, &signature, &from_pubkey)
        .map_err(|_| NodeError::ValidationError("Signature verification failed".to_string()))?;

    Ok(())
}

// File operations
fn save_chain(chain: &[Block]) -> Result<(), NodeError> {
    let json = serde_json::to_string_pretty(chain)
        .map_err(|e| NodeError::SerializationError(e.to_string()))?;
    std::fs::write("blockchain.json", json)
        .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    Ok(())
}

fn load_chain() -> Result<Vec<Block>, NodeError> {
    if Path::new("blockchain.json").exists() {
        let json = std::fs::read_to_string("blockchain.json")
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
        serde_json::from_str(&json)
            .map_err(|e| NodeError::SerializationError(e.to_string()))
    } else {
        Ok(vec![Block::new(0, vec![], "0".to_string(), "genesis".to_string())])
    }
}

fn load_peers() -> Result<Vec<String>, NodeError> {
    if Path::new("peers.json").exists() {
        let json = std::fs::read_to_string("peers.json")
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
        serde_json::from_str(&json)
            .map_err(|e| NodeError::SerializationError(e.to_string()))
            .or(Ok(vec![]))
    } else {
        Ok(vec![])
    }
}

fn save_peers(peers: &[String]) -> Result<(), NodeError> {
    let json = serde_json::to_string_pretty(peers)
        .map_err(|e| NodeError::SerializationError(e.to_string()))?;
    std::fs::write("peers.json", json)
        .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    Ok(())
}

// Network operations
async fn broadcast_to_known_nodes(block: &Block) {
    // Only broadcast if we know our address
    let my_addr = match get_my_address().await {
        Some(addr) => addr,
        None => {
            println!("[DEBUG] Skipping broadcast - public IP not yet determined");
            return;
        }
    };

    let peers_content = match std::fs::read_to_string("peers.json") {
        Ok(content) => content,
        Err(_) => return,
    };

    let peers: Vec<String> = match serde_json::from_str(&peers_content) {
        Ok(peers) => peers,
        Err(_) => return,
    };

    for peer in peers {
        if peer == my_addr {
            continue; // Don't send to self
        }

        println!("[DEBUG] Attempting to send block to peer: {}", peer);
        match TcpStream::connect(&peer).await {
            Ok(mut stream) => {
                if let Ok(json) = serde_json::to_string(block) {
                    let _ = stream.write_all(json.as_bytes()).await;
                    let mut resp_buf = vec![0; 64];
                    if let Ok(n) = stream.read(&mut resp_buf).await {
                        let resp = String::from_utf8_lossy(&resp_buf[..n]);
                        println!("[DEBUG] Response from peer {}: {}", peer, resp.trim());
                    }
                    let _ = stream.shutdown().await;
                    println!("[DEBUG] Block sent to peer: {}", peer);
                } else {
                    println!("[DEBUG] Failed to serialize block");
                }
            }
            Err(_) => {
                println!("[DEBUG] Failed to connect to peer: {}", peer);
            }
        }
    }
}

async fn determine_public_ip_from_peers() -> Option<String> {
    let peers = match load_peers() {
        Ok(peers) => peers,
        Err(e) => {
            println!("[DEBUG] Failed to load peers: {}", e);
            return None;
        }
    };
    
    if peers.is_empty() {
        println!("[DEBUG] No peers available to determine public IP");
        return None;
    }

    println!("[DEBUG] Loaded {} peers from file", peers.len());
    for peer in &peers {
        println!("[DEBUG] Available peer: {}", peer);
    }

    let shuffled = peers.clone();
    for peer in shuffled.into_iter().take(3) { // Try up to 3 peers
        println!("[DEBUG] Trying to get IP from peer: {}", peer);
        match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&peer)).await {
            Ok(Ok(mut stream)) => {
                println!("[DEBUG] Connected to peer {}, sending /whoami", peer);
                if let Err(e) = stream.write_all(b"/whoami").await {
                    println!("[DEBUG] Failed to send /whoami to {}: {}", peer, e);
                    continue;
                }

                let mut buf = vec![0; 64];
                match stream.read(&mut buf).await {
                    Ok(n) => {
                        let response = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                        println!("[DEBUG] Raw response from {}: '{}'", peer, response);
                        
                        if !response.is_empty() {
                            // Extract just the IP part (before the colon)
                            let ip_part = response.split(':').next().unwrap_or("").to_string();
                            println!("[DEBUG] Extracted IP: '{}'", ip_part);
                            
                            if !ip_part.is_empty() && is_public_ip(&ip_part) {
                                println!("[DEBUG] Got valid public IP from peer {}: {}", peer, ip_part);
                                return Some(ip_part);
                            } else {
                                println!("[DEBUG] IP '{}' is not valid or not public", ip_part);
                            }
                        } else {
                            println!("[DEBUG] Peer {} returned empty response", peer);
                        }
                    }
                    Err(e) => {
                        println!("[DEBUG] Failed to read response from {}: {}", peer, e);
                    }
                }
                let _ = stream.shutdown().await;
            }
            Ok(Err(e)) => {
                println!("[DEBUG] Failed to connect to peer {}: {}", peer, e);
            }
            Err(_) => {
                println!("[DEBUG] Timeout connecting to peer: {}", peer);
            }
        }
    }

    println!("[DEBUG] Failed to get IP from any peer");
    None
}

async fn sync_chain(blockchain: &Arc<Mutex<Vec<Block>>>, peers: &Arc<Mutex<Vec<String>>>, force: bool) {
    let peer_list = peers.lock().await.clone();
    if peer_list.is_empty() {
        println!("No peers available for sync");
        return;
    }

    let sample: Vec<_> = peer_list.into_iter().take(3).collect();

    for peer in sample {
        if let Ok(mut stream) = TcpStream::connect(&peer).await {
            let _ = stream.write_all(b"/chain").await;
            let mut buffer = vec![0; 16384];
            if let Ok(n) = stream.read(&mut buffer).await {
                if let Ok(peer_chain) = serde_json::from_slice::<Vec<Block>>(&buffer[..n]) {
                    if peer_chain.len() > blockchain.lock().await.len() || force {
                        let mut local = blockchain.lock().await;
                        *local = peer_chain;
                        if let Err(e) = save_chain(&local) {
                            eprintln!("Failed to save chain: {}", e);
                        } else {
                            println!("✓ Sync completed with {} (force={})", peer, force);
                        }
                        return;
                    }
                }
            }
        }
    }
    println!("✗ Sync failed - no suitable peers");
}

// CLI command implementations
async fn print_chain(blockchain: &Arc<Mutex<Vec<Block>>>) {
    let chain = blockchain.lock().await;
    for block in chain.iter() {
        println!("#{} hash: {}", block.index, block.hash);
    }
}

async fn list_peers(peers: &Arc<Mutex<Vec<String>>>) {
    let peer_list = peers.lock().await;
    for peer in peer_list.iter() {
        let status = check_peer_online(peer).await;
        println!("{} ({})", peer, if status { "online" } else { "offline" });
    }
}

async fn check_peer_online(peer: &str) -> bool {
    peer.to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .and_then(|addr| StdTcpStream::connect_timeout(&addr, Duration::from_millis(300)).ok())
        .is_some()
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
    
    // Check peers in parallel for better performance
    let mut online_peers = Vec::new();
    for peer in p.iter() {
        if check_peer_online(peer).await {
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
    
    // Check in-memory peers
    let memory_peers = peers.lock().await;
    println!("In-memory peers ({}): {:?}", memory_peers.len(), *memory_peers);
    drop(memory_peers);
    
    // Check peers file
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
    
    // Check current observed IP
    if let Some(ip) = OBSERVED_IP.read().await.as_ref() {
        println!("Current observed IP: {}", ip);
        println!("My full address: {}:{}", ip, LISTEN_PORT);
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

// UPnP setup functions
async fn setup_upnp(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    match try_igd_upnp(port).await {
        Ok(_) => return Ok(()),
        Err(e) => eprintln!("[DEBUG] IGD UPnP failed: {} – trying easy_upnp fallback", e),
    }

    let cfg = Arc::new(EasyConfig {
        address: None,
        port,
        protocol: easy_upnp::PortMappingProtocol::TCP,
        duration: 3600,
        comment: "lofswap node".to_string(),
    });

    // Setup cleanup handler
    {
        let cfg_for_cleanup = cfg.clone();
        if let Err(e) = ctrlc::set_handler(move || {
            let cleanup_cfg = easy_upnp::UpnpConfig {
                address: cfg_for_cleanup.address.clone(),
                port: cfg_for_cleanup.port,
                protocol: cfg_for_cleanup.protocol,
                duration: cfg_for_cleanup.duration,
                comment: cfg_for_cleanup.comment.clone(),
            };
            for result in delete_ports(std::iter::once(cleanup_cfg)) {
                match result {
                    Ok(_) => println!("🔌 Easy UPnP: port {} removed", port),
                    Err(e) => eprintln!("⚠️ Easy UPnP: error removing port: {}", e),
                }
            }
            std::process::exit(0);
        }) {
            eprintln!("Failed to set SIGINT handler: {}", e);
        }
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
                println!("✓ Port {} forwarded (Easy UPnP fallback)", port);
                return Ok(());
            }
            Err(e) => eprintln!("⚠️ Easy UPnP: port forwarding error: {}", e),
        }
    }

    Err("Failed to forward port through any UPnP mechanism".into())
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

    println!("✓ Port {} forwarded to {} (IGD)", port, socket);
    Ok(())
}
