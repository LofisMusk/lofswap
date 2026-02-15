use std::{fs::OpenOptions, io::Write, sync::Arc, time::Duration};

use blockchain_core::{Block, CHAIN_ID, Transaction};
use local_ip_address::local_ip;
use public_ip;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    time::{sleep, timeout},
};

use crate::{
    ACTIVE_CONNECTIONS, BOOTSTRAP_NODES, BUFFER_SIZE, LISTEN_PORT, MAX_CONNECTIONS, NODE_ID,
    NODE_VERSION, OBSERVED_IP,
    chain::{
        calculate_balance, is_tx_valid, load_peers, next_nonce_for_address, prune_mempool,
        save_chain, save_peers, validate_block, validate_chain,
    },
    errors::NodeError,
    storage::{data_path, ensure_parent_dir},
};

fn debug_log(msg: &str) {
    if cfg!(debug_assertions) {
        println!("[DEBUG] {}", msg);
    }
}

fn maint_log(msg: &str) {
    if cfg!(debug_assertions) {
        println!("[MAINT] {}", msg);
    }
}

const PEER_GOSSIP_LIMIT: usize = 16;
const HANDSHAKE_TIMEOUT_SECS: u64 = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PeerInfo {
    pub public_ip: Option<String>,
    pub port: u16,
    pub node_id: String,
    pub version: String,
    #[serde(default)]
    pub chain_id: String,
    #[serde(default)]
    pub peers: Vec<String>,
    #[serde(default)]
    pub observed_ip: Option<String>,
}

pub async fn start_tcp_server(
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
                    if ACTIVE_CONNECTIONS.load(std::sync::atomic::Ordering::Relaxed)
                        >= MAX_CONNECTIONS
                    {
                        debug_log(&format!(
                            "Max connections reached, dropping connection from {}",
                            addr
                        ));
                        continue;
                    }

                    ACTIVE_CONNECTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    if addr.port() == LISTEN_PORT {
                        let ip = addr.ip().to_string();
                        if is_public_ip(&ip) {
                            if OBSERVED_IP.read().await.is_none() {
                                debug_log(&format!(
                                    "Setting public IP from incoming connection: {}",
                                    ip
                                ));
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
                            debug_log(&format!("Connection handling error: {}", e));
                        }
                        ACTIVE_CONNECTIONS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    });
                }
                Err(e) => debug_log(&format!("Failed to accept connection: {}", e)),
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
    let n = stream
        .read(&mut buf)
        .await
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
    let request = if request.starts_with("GET ") {
        request.split_whitespace().nth(1).unwrap_or("").to_string()
    } else {
        request.to_string()
    };
    if request.trim() == "/ping" {
        stream
            .write_all(b"pong")
            .await
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    } else if let Some(addr) = request.strip_prefix("/balance/") {
        let addr = addr.trim();
        let chain = blockchain.lock().await;
        let balance = calculate_balance(addr, &chain);
        stream
            .write_all(balance.to_string().as_bytes())
            .await
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    } else if let Some(addr) = request.strip_prefix("/nonce/") {
        let addr = addr.trim();
        let chain = blockchain.lock().await;
        let nonce = next_nonce_for_address(addr, &chain);
        stream
            .write_all(nonce.to_string().as_bytes())
            .await
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    } else if request.trim() == "/peers" {
        let peers = peers.lock().await;
        let peers_json = serde_json::to_string(&*peers)
            .map_err(|e| NodeError::SerializationError(e.to_string()))?;
        stream
            .write_all(peers_json.as_bytes())
            .await
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    } else if request.trim() == "/chain" {
        let chain = blockchain.lock().await;
        let json = serde_json::to_string(&*chain)
            .map_err(|e| NodeError::SerializationError(e.to_string()))?;
        stream
            .write_all(json.as_bytes())
            .await
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    } else if request.trim() == "/chain-hash" {
        let chain = blockchain.lock().await;
        let json = serde_json::to_string(&*chain)
            .map_err(|e| NodeError::SerializationError(e.to_string()))?;
        let hash = Sha256::digest(json.as_bytes());
        stream
            .write_all(hex::encode(hash).as_bytes())
            .await
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    } else if request.trim() == "/whoami" || request.trim() == "/peer-info" {
        respond_with_peer_info(stream, &peers).await?;
    } else if let Some(id) = request.strip_prefix("/resolve-ip/") {
        handle_resolve_ip_request(id.trim(), stream).await?;
    } else if let Some(new_peer) = request.strip_prefix("/iam/") {
        handle_iam_request(new_peer.trim(), peers).await?;
    } else if let Some(rest) = request.strip_prefix("/peers") {
        handle_peers_request(rest, peers).await?;
    } else if let Ok(tx) = serde_json::from_slice::<Transaction>(request.as_bytes()) {
        handle_transaction(tx, stream, blockchain).await?;
    } else if let Ok(block) = serde_json::from_slice::<Block>(request.as_bytes()) {
        handle_block(block, stream, blockchain, peers).await?;
        return Ok(());
    }

    stream
        .shutdown()
        .await
        .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    Ok(())
}

async fn respond_with_peer_info(
    stream: &mut TcpStream,
    peers: &Arc<Mutex<Vec<String>>>,
) -> Result<(), NodeError> {
    let observed_ip = stream.peer_addr().ok().map(|addr| addr.ip().to_string());
    let public_ip = OBSERVED_IP.read().await.clone();
    let mut peer_snapshot = peers.lock().await.clone();
    if let Some(ref ip) = public_ip {
        let self_addr = format!("{}:{}", ip, LISTEN_PORT);
        peer_snapshot.retain(|peer| peer != &self_addr);
    }
    {
        let mut rng = rand::rng();
        peer_snapshot.shuffle(&mut rng);
    }
    peer_snapshot.truncate(PEER_GOSSIP_LIMIT);

    let info = PeerInfo {
        public_ip,
        port: LISTEN_PORT,
        node_id: NODE_ID.clone(),
        version: NODE_VERSION.to_string(),
        chain_id: CHAIN_ID.to_string(),
        peers: peer_snapshot,
        observed_ip,
    };

    let payload =
        serde_json::to_vec(&info).map_err(|e| NodeError::SerializationError(e.to_string()))?;
    stream
        .write_all(&payload)
        .await
        .map_err(|e| NodeError::NetworkError(e.to_string()))
}

async fn handle_resolve_ip_request(id: &str, stream: &mut TcpStream) -> Result<(), NodeError> {
    // Use the remote socket address as the caller's observed public IP.
    match stream.peer_addr() {
        Ok(addr) => {
            let ip = addr.ip().to_string();
            debug_log(&format!(
                "/resolve-ip for id '{}' resolved caller IP as {}",
                id, ip
            ));
            stream
                .write_all(ip.as_bytes())
                .await
                .map_err(|e| NodeError::NetworkError(e.to_string()))?;
        }
        Err(e) => {
            debug_log(&format!(
                "Failed to get peer addr for /resolve-ip (id='{}'): {}",
                id, e
            ));
            stream
                .write_all(b"unknown")
                .await
                .map_err(|e| NodeError::NetworkError(e.to_string()))?;
        }
    }
    Ok(())
}

async fn handle_iam_request(
    new_peer: &str,
    peers: Arc<Mutex<Vec<String>>>,
) -> Result<(), NodeError> {
    if new_peer.ends_with(":6000") {
        let my_addr = get_my_address().await;
        if Some(new_peer) != my_addr.as_deref() {
            let mut p = peers.lock().await;
            if !p.contains(&new_peer.to_string()) {
                println!("Added peer via /iam/: {}", new_peer);
                p.push(new_peer.to_string());
                save_peers(&p)?;
            }
        } else {
            debug_log(&format!("Ignoring /iam/ request from self: {}", new_peer));
        }
    }
    Ok(())
}

async fn handle_peers_request(rest: &str, peers: Arc<Mutex<Vec<String>>>) -> Result<(), NodeError> {
    if !rest.is_empty() {
        if let Ok(list) = serde_json::from_str::<Vec<String>>(rest) {
            let my_addr = get_my_address().await;
            let mut p = peers.lock().await;
            let mut added_count = 0;

            for peer in list {
                if peer.ends_with(":6000") && !p.contains(&peer) && Some(&peer) != my_addr.as_ref()
                {
                    println!("Added peer from /peers: {}", peer);
                    p.push(peer);
                    added_count += 1;
                }
            }

            if added_count > 0 {
                save_peers(&p)?;
                debug_log(&format!(
                    "Added {} new peers from /peers request",
                    added_count
                ));
            }
        }
    }
    Ok(())
}

async fn handle_transaction(
    tx: Transaction,
    stream: &mut TcpStream,
    blockchain: Arc<Mutex<Vec<Block>>>,
) -> Result<(), NodeError> {
    let chain = blockchain.lock().await;
    match is_tx_valid(&tx, &chain) {
        Ok(()) => {
            println!("TX added to mempool");
            let path = data_path("mempool.json");
            let file = ensure_parent_dir(&path)
                .and_then(|_| OpenOptions::new().create(true).append(true).open(&path))
                .or_else(|_| {
                    OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("mempool.json")
                });

            if let Ok(mut f) = file {
                let tx_json = serde_json::to_string(&tx)
                    .map_err(|e| NodeError::SerializationError(e.to_string()))?;
                let _ = writeln!(f, "{}", tx_json);
            }
            stream
                .write_all(b"ok")
                .await
                .map_err(|e| NodeError::NetworkError(e.to_string()))?;
        }
        Err(e) => {
            let reason = e.to_string();
            println!("TX rejected: {}", reason);
            let msg = format!("reject: {}", reason);
            stream
                .write_all(msg.as_bytes())
                .await
                .map_err(|e| NodeError::NetworkError(e.to_string()))?;
        }
    }
    Ok(())
}

async fn handle_block(
    block: Block,
    stream: &mut TcpStream,
    blockchain: Arc<Mutex<Vec<Block>>>,
    peers: Arc<Mutex<Vec<String>>>,
) -> Result<(), NodeError> {
    let mut chain = blockchain.lock().await;
    let expected_index = chain.len() as u64;
    if block.index != expected_index {
        println!(
            "Received block with invalid index (got {}, expected {})",
            block.index, expected_index
        );
        stream
            .write_all(b"invalid index")
            .await
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
        drop(chain);
        let bc = blockchain.clone();
        let peers_for_sync = peers.clone();
        tokio::spawn(async move {
            sync_chain(&bc, &peers_for_sync, false, false).await;
        });
        return Ok(());
    }

    let prev = chain.last();
    if let Err(e) = validate_block(&block, prev, &chain) {
        println!("Rejected block {}: {}", block.hash, e);
        stream
            .write_all(b"invalid block")
            .await
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
        return Ok(());
    }

    println!("Received new block {}", block.hash);
    chain.push(block.clone());
    save_chain(&chain)?;
    if let Err(e) = prune_mempool(&chain) {
        eprintln!("Failed to prune mempool after accepting block: {}", e);
    }
    drop(chain);
    broadcast_to_known_nodes(&block).await;
    stream
        .write_all(b"accepted")
        .await
        .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    Ok(())
}

pub async fn maintenance_loop(blockchain: Arc<Mutex<Vec<Block>>>, peers: Arc<Mutex<Vec<String>>>) {
    loop {
        sleep(Duration::from_secs(60)).await;
        sync_chain(&blockchain, &peers, false, false).await;

        let peer_list = peers.lock().await.clone();
        let my_addr = get_my_address().await;
        let mut added = 0usize;
        for peer in peer_list.iter().take(5) {
            if Some(peer.as_str()) == my_addr.as_deref() {
                continue;
            }
            let _ = handshake_with_peer(peer, &peers).await;
            if let Ok(mut stream) = TcpStream::connect(peer).await {
                let _ = stream.write_all(b"/peers").await;
                let mut buf = vec![0u8; 8192];
                if let Ok(n) = stream.read(&mut buf).await {
                    if let Ok(list) = serde_json::from_slice::<Vec<String>>(&buf[..n]) {
                        let mut p = peers.lock().await;
                        for entry in list {
                            if !p.contains(&entry)
                                && entry.ends_with(":6000")
                                && Some(entry.as_str()) != my_addr.as_deref()
                            {
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
            maint_log(&format!("Added {} peers from refresh", added));
        }

        let current = peers.lock().await.clone();
        let my_addr = get_my_address().await;
        let mut alive = Vec::with_capacity(current.len());
        for peer in current.iter() {
            if Some(peer) == my_addr.as_ref() {
                alive.push(peer.clone());
                continue;
            }
            if ping_peer(peer).await {
                alive.push(peer.clone());
            }
        }
        if alive.len() != current.len() {
            let removed = current.len().saturating_sub(alive.len());
            {
                let mut p = peers.lock().await;
                *p = alive;
                let _ = save_peers(&p);
            }
            maint_log(&format!("Removed {} dead peers", removed));
        }
    }
}

pub async fn bootstrap_and_discover_ip(peers: &Arc<Mutex<Vec<String>>>) {
    println!("[STARTUP] Step 2: Requesting peers.json from bootstrap nodes...");
    let mut bootstrap_peers = Vec::new();

    {
        let mut p = peers.lock().await;
        for &bootstrap_node in BOOTSTRAP_NODES {
            if !p.contains(&bootstrap_node.to_string()) {
                p.push(bootstrap_node.to_string());
                bootstrap_peers.push(bootstrap_node.to_string());
                println!(
                    "[STARTUP] Added bootstrap node to peers: {}",
                    bootstrap_node
                );
            }
        }
        if let Err(e) = save_peers(&p) {
            println!("[STARTUP] Failed to save bootstrap nodes to peers: {}", e);
        }
    }

    for &bootstrap_node in BOOTSTRAP_NODES {
        println!("[STARTUP] Trying bootstrap node: {}", bootstrap_node);
        match timeout(Duration::from_secs(5), TcpStream::connect(bootstrap_node)).await {
            Ok(Ok(mut stream)) => {
                println!("[STARTUP] Connected to bootstrap node: {}", bootstrap_node);

                if let Err(e) = stream.write_all(b"/peers").await {
                    println!(
                        "[STARTUP] Failed to request peers from {}: {}",
                        bootstrap_node, e
                    );
                    continue;
                }

                let mut buf = vec![0; 8192];
                match stream.read(&mut buf).await {
                    Ok(n) => {
                        let content = String::from_utf8_lossy(&buf[..n]);
                        println!(
                            "[STARTUP] Received peers data from {}: {}",
                            bootstrap_node,
                            content.trim()
                        );

                        match serde_json::from_slice::<Vec<String>>(&buf[..n]) {
                            Ok(peer_list) => {
                                println!(
                                    "[STARTUP] Successfully parsed {} peers from {}",
                                    peer_list.len(),
                                    bootstrap_node
                                );
                                for peer in &peer_list {
                                    if !bootstrap_peers.contains(peer) {
                                        bootstrap_peers.push(peer.clone());
                                        println!("[STARTUP] Added peer from bootstrap: {}", peer);
                                    }
                                }
                            }
                            Err(e) => {
                                println!(
                                    "[STARTUP] Failed to parse peers from {}: {}",
                                    bootstrap_node, e
                                );
                            }
                        }
                    }
                    Err(e) => {
                        println!(
                            "[STARTUP] Failed to read response from {}: {}",
                            bootstrap_node, e
                        );
                    }
                }
                let _ = stream.shutdown().await;
            }
            Ok(Err(e)) => {
                println!(
                    "[STARTUP] Failed to connect to bootstrap node {}: {}",
                    bootstrap_node, e
                );
            }
            Err(_) => {
                println!(
                    "[STARTUP] Timeout connecting to bootstrap node: {}",
                    bootstrap_node
                );
            }
        }
    }

    {
        let mut p = peers.lock().await;
        for peer in &bootstrap_peers {
            if !p.contains(peer) {
                p.push(peer.clone());
            }
        }
        if let Err(e) = save_peers(&p) {
            println!("[STARTUP] Failed to save bootstrap peers: {}", e);
        } else {
            println!("[STARTUP] Saved {} peers to peers.json", p.len());
        }
    }

    println!("[STARTUP] Step 3: Handshaking with bootstrap peers to determine our public IP...");
    {
        let mut has_ip = OBSERVED_IP.read().await.is_some();
        if !has_ip {
            for peer in &bootstrap_peers {
                let _ = handshake_with_peer(peer, peers).await;
                has_ip = OBSERVED_IP.read().await.is_some();
                if has_ip {
                    break;
                }
            }
        }
    }

    let observed_ip = OBSERVED_IP.read().await.clone();

    if let Some(ip) = observed_ip {
        println!("[STARTUP] Public IP determined via peers: {}", ip);
        println!(
            "[STARTUP] Step 4: Adding our address to peers.json and cleaning up duplicates..."
        );
        let my_address = format!("{}:{}", ip, LISTEN_PORT);
        {
            let mut p = peers.lock().await;
            p.retain(|peer| peer != &my_address);
            p.push(my_address.clone());

            if let Err(e) = save_peers(&p) {
                println!("[STARTUP] Failed to save updated peers: {}", e);
            } else {
                println!("[STARTUP] Added our address to peers: {}", my_address);
                println!("[STARTUP] Cleaned up duplicate addresses");
            }
        }

        println!("[STARTUP] Step 5: Broadcasting updated peers.json to network...");
        broadcast_peers_to_network(peers, &my_address).await;
    } else {
        println!(
            "[STARTUP] Could not determine public IP from peers. Node will wait for incoming connections."
        );
    }

    println!("[STARTUP] Bootstrap and IP discovery sequence completed");
}

async fn broadcast_peers_to_network(peers: &Arc<Mutex<Vec<String>>>, my_address: &str) {
    let peer_list = peers.lock().await.clone();
    let peers_json = match serde_json::to_string(&peer_list) {
        Ok(json) => json,
        Err(e) => {
            println!("[STARTUP] Failed to serialize peers for broadcast: {}", e);
            return;
        }
    };

    println!("[STARTUP] Broadcasting to {} peers...", peer_list.len());
    let mut successful_broadcasts = 0;

    for peer in &peer_list {
        if peer == my_address {
            continue;
        }

        println!("[STARTUP] Broadcasting peers to: {}", peer);
        match timeout(Duration::from_secs(3), TcpStream::connect(peer)).await {
            Ok(Ok(mut stream)) => {
                let message = format!("/peers{}", peers_json);
                match stream.write_all(message.as_bytes()).await {
                    Ok(_) => {
                        println!("[STARTUP] Successfully broadcast peers to: {}", peer);
                        successful_broadcasts += 1;
                    }
                    Err(e) => {
                        println!("[STARTUP] Failed to send peers to {}: {}", peer, e);
                    }
                }
                let _ = stream.shutdown().await;
            }
            Ok(Err(e)) => {
                println!(
                    "[STARTUP] Failed to connect for broadcast to {}: {}",
                    peer, e
                );
            }
            Err(_) => {
                println!("[STARTUP] Timeout broadcasting to: {}", peer);
            }
        }
    }

    println!(
        "[STARTUP] Broadcast completed: {}/{} successful",
        successful_broadcasts,
        peer_list.len() - 1
    );
}

pub async fn broadcast_to_known_nodes(block: &Block) {
    let my_addr = match get_my_address().await {
        Some(addr) => addr,
        None => {
            debug_log("Skipping broadcast - public IP not yet determined");
            return;
        }
    };

    let peers: Vec<String> = load_peers().unwrap_or_default();

    for peer in peers {
        if peer == my_addr {
            continue;
        }

        debug_log(&format!("Attempting to send block to peer: {}", peer));
        match TcpStream::connect(&peer).await {
            Ok(mut stream) => {
                if let Ok(json) = serde_json::to_string(block) {
                    let _ = stream.write_all(json.as_bytes()).await;
                    let mut resp_buf = vec![0; 64];
                    if let Ok(n) = stream.read(&mut resp_buf).await {
                        let resp = String::from_utf8_lossy(&resp_buf[..n]);
                        debug_log(&format!("Response from peer {}: {}", peer, resp.trim()));
                    }
                    let _ = stream.shutdown().await;
                    debug_log(&format!("Block sent to peer: {}", peer));
                } else {
                    debug_log("Failed to serialize block");
                }
            }
            Err(_) => {
                debug_log(&format!("Failed to connect to peer: {}", peer));
            }
        }
    }
}

pub async fn handshake_with_peer(peer: &str, peers: &Arc<Mutex<Vec<String>>>) -> Option<PeerInfo> {
    let info = fetch_peer_info_once(peer).await?;
    integrate_peer_info_from_handshake(peer, &info, peers).await;
    Some(info)
}

async fn fetch_peer_info_once(peer: &str) -> Option<PeerInfo> {
    debug_log(&format!("Initiating handshake with {}", peer));
    match timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        TcpStream::connect(peer),
    )
    .await
    {
        Ok(Ok(mut stream)) => {
            if let Err(e) = stream.write_all(b"/whoami").await {
                debug_log(&format!("Failed to send /whoami to {}: {}", peer, e));
                let _ = stream.shutdown().await;
                return None;
            }
            let mut buf = vec![0; BUFFER_SIZE];
            let info = match stream.read(&mut buf).await {
                Ok(0) => None,
                Ok(n) => parse_peer_info(&buf[..n]),
                Err(e) => {
                    debug_log(&format!(
                        "Failed to read handshake data from {}: {}",
                        peer, e
                    ));
                    None
                }
            };
            let _ = stream.shutdown().await;
            info
        }
        Ok(Err(e)) => {
            debug_log(&format!("Handshake connect error for {}: {}", peer, e));
            None
        }
        Err(_) => {
            debug_log(&format!("Handshake timed out while connecting to {}", peer));
            None
        }
    }
}

fn parse_peer_info(bytes: &[u8]) -> Option<PeerInfo> {
    if bytes.is_empty() {
        return None;
    }
    if let Ok(info) = serde_json::from_slice::<PeerInfo>(bytes) {
        return Some(info);
    }

    let text = String::from_utf8_lossy(bytes).trim().to_string();
    if text.is_empty() || text == "unknown" {
        return None;
    }
    let mut parts = text.split(':');
    let ip = parts.next()?.to_string();
    let port = parts
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(LISTEN_PORT);
    Some(PeerInfo {
        public_ip: Some(ip),
        port,
        node_id: String::new(),
        version: String::new(),
        chain_id: String::new(),
        peers: Vec::new(),
        observed_ip: None,
    })
}

fn chain_total_work(chain: &[Block]) -> u128 {
    chain.iter().fold(0u128, |acc, block| {
        let shift = (block.difficulty as u32).min(63);
        acc.saturating_add(1u128 << shift)
    })
}

fn chain_tip_hash(chain: &[Block]) -> &str {
    chain.last().map(|b| b.hash.as_str()).unwrap_or("")
}

fn prefer_chain(candidate: &[Block], current: &[Block]) -> bool {
    if candidate.is_empty() {
        return false;
    }
    let candidate_work = chain_total_work(candidate);
    let current_work = chain_total_work(current);
    if candidate_work != current_work {
        return candidate_work > current_work;
    }
    if candidate.len() != current.len() {
        return candidate.len() > current.len();
    }
    let cand_tip = chain_tip_hash(candidate);
    let curr_tip = chain_tip_hash(current);
    if curr_tip.is_empty() {
        return !cand_tip.is_empty();
    }
    // Deterministic equal-work tie-break: lower tip hash wins.
    cand_tip < curr_tip
}

async fn integrate_peer_info_from_handshake(
    original_addr: &str,
    info: &PeerInfo,
    peers: &Arc<Mutex<Vec<String>>>,
) {
    if info.chain_id != CHAIN_ID {
        debug_log(&format!(
            "Ignoring peer {} with mismatched chain_id '{}'",
            original_addr, info.chain_id
        ));
        return;
    }

    if let Some(observed) = info.observed_ip.as_ref() {
        if !observed.is_empty() && is_public_ip(observed) {
            let mut lock = OBSERVED_IP.write().await;
            if lock.as_ref() != Some(observed) {
                debug_log(&format!(
                    "Learned our public IP ({}) from handshake with {}",
                    observed, original_addr
                ));
                *lock = Some(observed.clone());
            }
        }
    }

    let peer_addr = info
        .public_ip
        .as_ref()
        .map(|ip| format!("{}:{}", ip, info.port))
        .unwrap_or_else(|| original_addr.to_string());
    let self_addr = {
        OBSERVED_IP
            .read()
            .await
            .as_ref()
            .map(|ip| format!("{}:{}", ip, LISTEN_PORT))
    };
    if self_addr.as_deref() == Some(peer_addr.as_str()) {
        return;
    }

    let mut peers_guard = peers.lock().await;
    if !peers_guard.contains(&peer_addr) {
        debug_log(&format!(
            "Added peer {} via handshake (node_id={})",
            peer_addr, info.node_id
        ));
        peers_guard.push(peer_addr.clone());
        if let Err(e) = save_peers(&peers_guard) {
            eprintln!(
                "Failed to save peers after handshake with {}: {}",
                peer_addr, e
            );
        }
    }
}

pub async fn determine_public_ip_from_peers() -> Option<String> {
    let peers = match load_peers() {
        Ok(peers) => peers,
        Err(e) => {
            debug_log(&format!("Failed to load peers: {}", e));
            return None;
        }
    };

    if peers.is_empty() {
        debug_log("No peers available to determine public IP");
        return None;
    }

    debug_log(&format!("Loaded {} peers from file", peers.len()));
    for peer in peers.iter().take(5) {
        debug_log(&format!("Trying to learn our IP via {}", peer));
        if let Some(info) = fetch_peer_info_once(peer).await {
            if let Some(observed) = info.observed_ip.filter(|ip| !ip.is_empty()) {
                debug_log(&format!(
                    "Peer {} sees us as {} -> using as public IP",
                    peer, observed
                ));
                return Some(observed);
            }
        }
    }
    None
}

pub async fn sync_chain(
    blockchain: &Arc<Mutex<Vec<Block>>>,
    peers: &Arc<Mutex<Vec<String>>>,
    force: bool,
    verbose: bool,
) {
    let log = |msg: &str| {
        if verbose {
            println!("{}", msg);
        }
    };

    let (local_snapshot, local_valid) = {
        let local = blockchain.lock().await;
        match validate_chain(&local) {
            Ok(_) => (local.clone(), true),
            Err(e) => {
                log(&format!("[SYNC] Local chain failed validation: {}", e));
                (local.clone(), false)
            }
        }
    };

    let peer_list = peers.lock().await.clone();
    if peer_list.is_empty() {
        log("Sync failed - no peers");
        return;
    }

    let my_addr = get_my_address().await;
    log(&format!(
        "[SYNC] Attempting to sync with {} peers...",
        peer_list.len()
    ));
    let mut best_peer_chain: Option<Vec<Block>> = None;
    let mut best_peer_addr: Option<String> = None;

    for peer in peer_list {
        if Some(peer.as_str()) == my_addr.as_deref() {
            continue;
        }
        log(&format!("[SYNC] Connecting to {}", peer));
        let Some(info) = handshake_with_peer(&peer, peers).await else {
            continue;
        };
        if info.chain_id != CHAIN_ID {
            log(&format!(
                "[SYNC] Skipping {} due to chain id mismatch ({})",
                peer, info.chain_id
            ));
            continue;
        }
        if let Ok(mut stream) = TcpStream::connect(&peer).await {
            log("[SYNC] Requesting chain");
            if stream.write_all(b"/chain").await.is_err() {
                continue;
            }
            let mut buffer = vec![0u8; 65536];
            if let Ok(n) = stream.read(&mut buffer).await {
                if let Ok(peer_chain) = serde_json::from_slice::<Vec<Block>>(&buffer[..n]) {
                    if let Err(e) = validate_chain(&peer_chain) {
                        log(&format!(
                            "[SYNC] Rejecting invalid chain from {}: {}",
                            peer, e
                        ));
                        continue;
                    }
                    let better = if force || !local_valid {
                        match &best_peer_chain {
                            Some(current_best) => prefer_chain(&peer_chain, current_best),
                            None => true,
                        }
                    } else {
                        let baseline: &[Block] = best_peer_chain
                            .as_deref()
                            .unwrap_or(local_snapshot.as_slice());
                        prefer_chain(&peer_chain, baseline)
                    };
                    if better {
                        best_peer_addr = Some(peer.clone());
                        best_peer_chain = Some(peer_chain);
                    }
                }
            }
        }
    }

    let Some(candidate) = best_peer_chain else {
        log("Sync failed - no suitable peers");
        return;
    };

    let source_peer = best_peer_addr.unwrap_or_else(|| "unknown".to_string());
    let mut local = blockchain.lock().await;
    let replace = if force {
        true
    } else {
        !validate_chain(&local).is_ok() || prefer_chain(&candidate, &local)
    };
    if !replace {
        log("Sync finished - local chain already preferred");
        return;
    }

    let old_len = local.len();
    *local = candidate;
    if let Err(e) = save_chain(&local) {
        eprintln!("Failed to save chain: {}", e);
    } else if let Err(e) = prune_mempool(&local) {
        eprintln!("Failed to prune mempool after sync: {}", e);
    } else if verbose {
        println!("Sync completed with {} (force={})", source_peer, force);
        println!("[SYNC] Reorg: {} -> {}", old_len, local.len());
    } else {
        println!(
            "[SYNC] Background sync updated from {} ({} -> {})",
            source_peer,
            old_len,
            local.len()
        );
    }
}

pub async fn ping_peer(peer: &str) -> bool {
    // Avoid pinging ourselves by comparing the target
    // peer's IP with the public IP from the library.
    if let Some(ip) = public_ip::addr().await {
        let my_ip = ip.to_string();
        if let Some(target_ip) = peer.split(':').next() {
            if target_ip == my_ip {
                debug_log(&format!("Skipping ping to self ({} == {})", peer, my_ip));
                return false;
            }
        }
    } else if let Some(my_addr) = get_my_address().await {
        // Fallback: compare full address if we have one.
        if peer == my_addr {
            debug_log(&format!("Skipping ping to self by address match: {}", peer));
            return false;
        }
    }
    match timeout(Duration::from_millis(500), TcpStream::connect(peer)).await {
        Ok(Ok(mut stream)) => {
            if stream.write_all(b"/ping").await.is_ok() {
                let mut buf = [0u8; 8];
                if let Ok(n) = stream.read(&mut buf).await {
                    return &buf[..n] == b"pong";
                }
            }
            false
        }
        _ => false,
    }
}

pub async fn get_my_address() -> Option<String> {
    // 1) Prefer any IP we already observed from the network.
    if let Some(ip) = OBSERVED_IP.read().await.as_ref() {
        return Some(format!("{}:{}", ip, LISTEN_PORT));
    }

    // 2) Try to get our public IP from the external library.
    if let Some(ip) = public_ip::addr().await {
        return Some(format!("{}:{}", ip, LISTEN_PORT));
    }

    // 3) Fallback to local/private IP if nothing else is known.
    if let Ok(ip) = local_ip() {
        return Some(format!("{}:{}", ip, LISTEN_PORT));
    }

    None
}

pub fn is_public_ip(ip: &str) -> bool {
    !ip.starts_with("192.")
        && !ip.starts_with("10.")
        && !ip.starts_with("127.")
        && !ip.starts_with("172.")
}
