use std::{fs::OpenOptions, io::Write, sync::Arc, time::Duration};

use blockchain_core::{Block, Transaction};
use local_ip_address::local_ip;
use public_ip;
use rand::RngCore;
use serde_json;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    time::{sleep, timeout},
};

use crate::{
    ACTIVE_CONNECTIONS, BOOTSTRAP_NODES, BUFFER_SIZE, LISTEN_PORT, MAX_CONNECTIONS, OBSERVED_IP,
    chain::{calculate_balance, is_tx_valid, load_peers, save_chain, save_peers},
    errors::NodeError,
    storage::{data_path, ensure_parent_dir},
};

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
                        println!(
                            "[DEBUG] Max connections reached, dropping connection from {}",
                            addr
                        );
                        continue;
                    }

                    ACTIVE_CONNECTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    if addr.port() == LISTEN_PORT {
                        let ip = addr.ip().to_string();
                        if is_public_ip(&ip) {
                            if OBSERVED_IP.read().await.is_none() {
                                println!(
                                    "[DEBUG] Setting public IP from incoming connection: {}",
                                    ip
                                );
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
                        ACTIVE_CONNECTIONS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
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
    } else if let Some(id) = request.strip_prefix("/resolve-ip/") {
        handle_resolve_ip_request(id.trim(), stream).await?;
    } else if request.trim() == "/whoami" {
        if let Some(ip) = OBSERVED_IP.read().await.as_ref() {
            let response = format!("{}:{}", ip, LISTEN_PORT);
            println!("[DEBUG] Responding to /whoami with: {}", response);
            stream
                .write_all(response.as_bytes())
                .await
                .map_err(|e| NodeError::NetworkError(e.to_string()))?;
        } else {
            println!("[DEBUG] /whoami requested but no IP set yet");
            stream
                .write_all(b"unknown")
                .await
                .map_err(|e| NodeError::NetworkError(e.to_string()))?;
        }
    } else if let Some(new_peer) = request.strip_prefix("/iam/") {
        handle_iam_request(new_peer.trim(), peers).await?;
    } else if let Some(rest) = request.strip_prefix("/peers") {
        handle_peers_request(rest, peers).await?;
    } else if let Ok(tx) = serde_json::from_slice::<Transaction>(request.as_bytes()) {
        handle_transaction(tx, blockchain).await?;
    } else if let Ok(block) = serde_json::from_slice::<Block>(request.as_bytes()) {
        handle_block(block, stream, blockchain).await?;
        return Ok(());
    }

    stream
        .shutdown()
        .await
        .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    Ok(())
}

async fn handle_resolve_ip_request(id: &str, stream: &mut TcpStream) -> Result<(), NodeError> {
    // Use the remote socket address as the caller's observed public IP.
    match stream.peer_addr() {
        Ok(addr) => {
            let ip = addr.ip().to_string();
            println!(
                "[DEBUG] /resolve-ip for id '{}' resolved caller IP as {}",
                id, ip
            );
            stream
                .write_all(ip.as_bytes())
                .await
                .map_err(|e| NodeError::NetworkError(e.to_string()))?;
        }
        Err(e) => {
            println!(
                "[DEBUG] Failed to get peer addr for /resolve-ip (id='{}'): {}",
                id, e
            );
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
            println!("[DEBUG] Ignoring /iam/ request from self: {}", new_peer);
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
                println!(
                    "[DEBUG] Added {} new peers from /peers request",
                    added_count
                );
            }
        }
    }
    Ok(())
}

async fn handle_transaction(
    tx: Transaction,
    blockchain: Arc<Mutex<Vec<Block>>>,
) -> Result<(), NodeError> {
    let chain = blockchain.lock().await;
    if is_tx_valid(&tx, &chain).is_ok() {
        println!("TX added to mempool");
        let path = data_path("mempool.json");
        let file = ensure_parent_dir(&path)
            .and_then(|_| {
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
            })
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
    } else {
        println!("TX rejected (signature/balance)");
    }
    Ok(())
}

async fn handle_block(
    block: Block,
    stream: &mut TcpStream,
    blockchain: Arc<Mutex<Vec<Block>>>,
) -> Result<(), NodeError> {
    let mut chain = blockchain.lock().await;
    if block.index == chain.len() as u64 {
        println!("Received new block {}", block.hash);
        chain.push(block.clone());
        save_chain(&chain)?;
        drop(chain);
        broadcast_to_known_nodes(&block).await;
        stream
            .write_all(b"accepted")
            .await
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    } else {
        println!(
            "Received block with invalid index (got {}, expected {})",
            block.index,
            chain.len()
        );
        stream
            .write_all(b"invalid index")
            .await
            .map_err(|e| NodeError::NetworkError(e.to_string()))?;
    }
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
            println!("[MAINT] Added {} peers from refresh", added);
        }

        let current = peers.lock().await.clone();
        let mut alive = Vec::with_capacity(current.len());
        for peer in current.iter() {
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
            println!("[MAINT] Removed {} dead peers", removed);
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
                println!(
                    "[STARTUP] Connected to bootstrap node: {}",
                    bootstrap_node
                );

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

    println!("[STARTUP] Step 3: Selecting random peer to determine public IP...");
    let selected_peer = bootstrap_peers.get(0).cloned();

    let my_public_ip = if let Some(peer) = selected_peer {
        println!(
            "[STARTUP] Step 4: Determining public IP from peer: {}",
            peer
        );
        determine_ip_from_specific_peer(&peer).await
    } else {
        println!("[STARTUP] No peer selected for IP determination");
        None
    };

    if let Some(ip) = my_public_ip {
        println!("[STARTUP] Public IP determined: {}", ip);
        *OBSERVED_IP.write().await = Some(ip.clone());

        println!(
            "[STARTUP] Step 5: Adding our address to peers.json and cleaning up duplicates..."
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

        println!("[STARTUP] Step 6: Broadcasting updated peers.json to network...");
        broadcast_peers_to_network(peers, &my_address).await;
    } else {
        println!(
            "[STARTUP] Could not determine public IP. Node will wait for incoming connections."
        );
    }

    println!("[STARTUP] Bootstrap and IP discovery sequence completed");
}

async fn determine_ip_from_specific_peer(peer: &str) -> Option<String> {
    println!("[STARTUP] Contacting peer {} for IP discovery...", peer);

    // Step 1: generate a temporary unique ID for this resolution attempt.
    let mut rng = rand::rng();
    let mut id_bytes = [0u8; 16];
    rng.fill_bytes(&mut id_bytes);
    let temp_id = hex::encode(id_bytes);
    println!(
        "[STARTUP] Using temporary ID {} for public IP resolution",
        temp_id
    );

    // Step 2: ask the chosen peer what IP it sees for this ID.
    let observed_ip_from_peer =
        match timeout(Duration::from_secs(3), TcpStream::connect(peer)).await {
            Ok(Ok(mut stream)) => {
                println!("[STARTUP] Connected to peer {} for /resolve-ip", peer);

                let msg = format!("/resolve-ip/{}", temp_id);
                if let Err(e) = stream.write_all(msg.as_bytes()).await {
                    println!("[STARTUP] Failed to send /resolve-ip to {}: {}", peer, e);
                    let _ = stream.shutdown().await;
                    return None;
                }

                let mut buf = vec![0; 64];
                let result = match stream.read(&mut buf).await {
                    Ok(n) => {
                        let response = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                        println!(
                            "[STARTUP] Raw /resolve-ip response from {}: '{}'",
                            peer, response
                        );
                        if response.is_empty() || response == "unknown" {
                            None
                        } else {
                            Some(response)
                        }
                    }
                    Err(e) => {
                        println!(
                            "[STARTUP] Failed to read /resolve-ip response from {}: {}",
                            peer, e
                        );
                        None
                    }
                };
                let _ = stream.shutdown().await;
                result
            }
            Ok(Err(e)) => {
                println!(
                    "[STARTUP] Failed to connect to peer {} for /resolve-ip: {}",
                    peer, e
                );
                None
            }
            Err(_) => {
                println!(
                    "[STARTUP] Timeout connecting to peer {} for /resolve-ip",
                    peer
                );
                None
            }
        };

    let observed_ip_from_peer = match observed_ip_from_peer {
        Some(ip) => ip,
        None => {
            println!(
                "[STARTUP] Peer {} could not provide a usable IP for id {}",
                peer, temp_id
            );
            return None;
        }
    };

    // Step 3: ask the public-ip library for our public IP.
    let lib_ip_opt = public_ip::addr().await;
    let lib_ip = match lib_ip_opt {
        Some(ip) => ip.to_string(),
        None => {
            println!(
                "[STARTUP] public-ip library could not determine an IP for id {}",
                temp_id
            );
            return None;
        }
    };

    println!(
        "[STARTUP] IP from peer {}: {} ; IP from public-ip: {}",
        peer, observed_ip_from_peer, lib_ip
    );

    // Step 4: compare results.
    // Primary case: both sources agree exactly.
    if observed_ip_from_peer == lib_ip {
        println!(
            "[STARTUP] IP resolution successful for id {}: {}",
            temp_id, lib_ip
        );
        return Some(lib_ip);
    }

    // NAT / local-network case:
    // - Peer might see our *private* or router IP (e.g. 192.168.x.x),
    // - public-ip library sees our true public/WAN IP.
    // In that case we still trust the library result, since the peer
    // cannot know our internal address beyond what the router exposes.
    if !is_public_ip(&observed_ip_from_peer) && is_public_ip(&lib_ip) {
        println!(
            "[STARTUP] Peer {} reported non-public IP '{}' while public-ip reported '{}'. \
             Treating public-ip result as canonical for id {}.",
            peer, observed_ip_from_peer, lib_ip, temp_id
        );
        return Some(lib_ip);
    }

    // Anything else is treated as a mismatch.
    println!(
        "[STARTUP] IP resolution mismatch for id {} (peer: {}, public-ip: {})",
        temp_id, observed_ip_from_peer, lib_ip
    );
    None
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
            println!("[DEBUG] Skipping broadcast - public IP not yet determined");
            return;
        }
    };

    let peers: Vec<String> = load_peers().unwrap_or_default();

    for peer in peers {
        if peer == my_addr {
            continue;
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

pub async fn determine_public_ip_from_peers() -> Option<String> {
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
    for peer in shuffled.into_iter().take(3) {
        println!("[DEBUG] Trying to get IP from peer: {}", peer);
        match timeout(Duration::from_secs(3), TcpStream::connect(&peer)).await {
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
                            let ip_part = response.split(':').next().unwrap_or("").to_string();
                            println!("[DEBUG] Extracted IP: '{}'", ip_part);

                            if !ip_part.is_empty() && is_public_ip(&ip_part) {
                                println!(
                                    "[DEBUG] Got valid public IP from peer {}: {}",
                                    peer, ip_part
                                );
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
            }
            Ok(Err(e)) => {
                println!("[DEBUG] Failed to connect to peer {}: {}", peer, e);
            }
            Err(_) => {
                println!("[DEBUG] Timeout connecting to peer {}", peer);
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
    for peer in peer_list {
        if Some(peer.as_str()) == my_addr.as_deref() {
            continue;
        }
        log(&format!("[SYNC] Connecting to {}", peer));
        if let Ok(mut stream) = TcpStream::connect(&peer).await {
            log("[SYNC] Requesting chain");
            if stream.write_all(b"/chain").await.is_err() {
                continue;
            }
            let mut buffer = vec![0u8; 65536];
            if let Ok(n) = stream.read(&mut buffer).await {
                if let Ok(peer_chain) = serde_json::from_slice::<Vec<Block>>(&buffer[..n]) {
                    if peer_chain.len() > blockchain.lock().await.len() || force {
                        let mut local = blockchain.lock().await;
                        *local = peer_chain;
                        if let Err(e) = save_chain(&local) {
                            eprintln!("Failed to save chain: {}", e);
                        } else {
                            if verbose {
                                println!("Sync completed with {} (force={})", peer, force);
                            } else {
                                println!("[SYNC] Background sync updated from {}", peer);
                            }
                        }
                        return;
                    }
                }
            }
        }
    }
    log("Sync failed - no suitable peers");
}

pub async fn ping_peer(peer: &str) -> bool {
    // Avoid pinging ourselves by comparing the target
    // peer's IP with the public IP from the library.
    if let Some(ip) = public_ip::addr().await {
        let my_ip = ip.to_string();
        if let Some(target_ip) = peer.split(':').next() {
            if target_ip == my_ip {
                println!("[DEBUG] Skipping ping to self ({} == {})", peer, my_ip);
                return false;
            }
        }
    } else if let Some(my_addr) = get_my_address().await {
        // Fallback: compare full address if we have one.
        if peer == my_addr {
            println!("[DEBUG] Skipping ping to self by address match: {}", peer);
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
