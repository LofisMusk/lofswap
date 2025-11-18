use std::sync::Arc;

use blockchain_core::Block;
use local_ip_address::local_ip;
use rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Mutex,
};
use serde_json;

use crate::{
    chain::{calculate_balance, save_peers},
    miner::mine_block,
    p2p::ping_peer,
    wallet::{
        build_tx,
        broadcast_tx_payload,
        export_wallet_dat_bytes,
        latest_transaction,
        read_mempool,
        secret_key_from_bytes,
        try_broadcast_pending,
        wallet_info_json,
        wallet_keys_json,
        wallet_load_default,
        wallet_pending_count,
        wallet_remove_default,
        wallet_save_default,
    },
    EXPLORER_PORT,
    OBSERVED_IP,
};
use crate::ui::UI_HTML;

pub async fn start_http_explorer(
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
                    let mut buf = vec![0u8; 16384];
                    match stream.read(&mut buf).await {
                        Ok(n) if n > 0 => {
                            let req = String::from_utf8_lossy(&buf[..n]).to_string();
                            let mut parts = req.split_whitespace();
                            let method = parts.next().unwrap_or("GET");
                            let path = parts.next().unwrap_or("/");

                            let body = if method == "POST" || method == "PUT" || method == "DELETE" {
                                if let Some(idx) = req.find("\r\n\r\n") {
                                    req[(idx + 4)..].to_string()
                                } else {
                                    String::new()
                                }
                            } else {
                                String::new()
                            };

                            let (status, content_type, bytes) =
                                if method == "GET" && (path == "/" || path == "/index.html") {
                                    ("200 OK".to_string(), "text/html".to_string(), UI_HTML.as_bytes().to_vec())
                                } else if method == "GET" && path == "/wallet/export-dat" {
                                    let data = export_wallet_dat_bytes();
                                    match data {
                                        Some(b) => ("200 OK".into(), "application/octet-stream".into(), b),
                                        None => (
                                            "404 Not Found".into(),
                                            "application/json".into(),
                                            br#"{"error":"no wallet"}"#.to_vec(),
                                        ),
                                    }
                                } else if method == "GET" {
                                    let (s, body) = handle_http_route(path, &bc, &pr).await;
                                    (s, "application/json".into(), body.into_bytes())
                                } else if method == "POST" || method == "PUT" || method == "DELETE" {
                                    let (s, body) =
                                        handle_http_mutating_route(method, path, &body, &bc, &pr).await;
                                    (s, "application/json".into(), body.into_bytes())
                                } else {
                                    (
                                        "405 Method Not Allowed".into(),
                                        "text/plain".into(),
                                        b"method not allowed".to_vec(),
                                    )
                                };

                            let resp = format!(
                                "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                status,
                                content_type,
                                bytes.len()
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                            let _ = stream.write_all(&bytes).await;
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
    if path == "/ping" {
        return ("200 OK".into(), "pong".into());
    }
    if path == "/mempool" {
        let list = read_mempool();
        let body = serde_json::to_string(&list).unwrap_or("[]".into());
        return ("200 OK".into(), body);
    }
    if path == "/chain/latest-tx" {
        let chain = blockchain.lock().await;
        let tx = latest_transaction(&chain);
        let body = serde_json::to_string(&tx).unwrap_or("null".into());
        return ("200 OK".into(), body);
    }
    if path == "/node/ip" {
        let pub_ip = OBSERVED_IP.read().await.clone();
        let priv_ip = local_ip().ok().map(|ip| ip.to_string());
        let body = serde_json::json!({ "public": pub_ip, "private": priv_ip }).to_string();
        return ("200 OK".into(), body);
    }
    if path == "/peers/status" {
        let list = peers.lock().await.clone();
        let mut status = Vec::new();
        for p in list.iter() {
            let online = ping_peer(p).await;
            status.push(serde_json::json!({"peer": p, "online": online}));
        }
        let body = serde_json::json!({"list": status}).to_string();
        return ("200 OK".into(), body);
    }
    if path.starts_with("/wallet/") {
        if path == "/wallet/info" {
            let body = wallet_info_json();
            return ("200 OK".into(), body);
        }
        if let Some(q) = path.strip_prefix("/wallet/keys") {
            let confirmed = q.contains("confirm=true");
            let body = wallet_keys_json(confirmed);
            return ("200 OK".into(), body);
        }
        if path == "/wallet/pending-count" {
            let count = wallet_pending_count();
            let body = serde_json::json!({"count": count}).to_string();
            return ("200 OK".into(), body);
        }
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
                    if tx.to == rest || tx.from == rest {
                        txs.push(tx.clone());
                    }
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
    if path == "/chain" {
        let chain = blockchain.lock().await;
        let body = serde_json::to_string(&*chain).unwrap_or("[]".into());
        return ("200 OK".into(), body);
    }

    ("404 Not Found".into(), "{\"error\":\"not found\"}".into())
}

async fn handle_http_mutating_route(
    method: &str,
    path: &str,
    body: &str,
    blockchain: &Arc<Mutex<Vec<Block>>>,
    peers: &Arc<Mutex<Vec<String>>>,
) -> (String, String) {
    if method == "POST" && path == "/peers/add" {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
            if let Some(peer) = v.get("peer").and_then(|x| x.as_str()) {
                let mut p = peers.lock().await;
                if !p.contains(&peer.to_string()) {
                    p.push(peer.to_string());
                    let _ = save_peers(&p);
                }
                return ("200 OK".into(), "{\"ok\":true}".into());
            }
        }
        return ("400 Bad Request".into(), "{\"error\":\"invalid peer\"}".into());
    }
    if method == "POST" && path == "/peers/remove" {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
            if let Some(peer) = v.get("peer").and_then(|x| x.as_str()) {
                let mut p = peers.lock().await;
                p.retain(|x| x != peer);
                let _ = save_peers(&p);
                return ("200 OK".into(), "{\"ok\":true}".into());
            }
        }
        return ("400 Bad Request".into(), "{\"error\":\"invalid peer\"}".into());
    }
    if method == "POST" && path == "/mine" {
        let bc = blockchain.clone();
        tokio::spawn(async move {
            mine_block(&bc).await;
        });
        return ("200 OK".into(), "{\"status\":\"started\"}".into());
    }
    if method == "POST" && path == "/wallet/create" {
        let secp = Secp256k1::new();
        let mut rng = rand::rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let sk = SecretKey::from_byte_array(bytes).expect("rng produced invalid bytes");
        let pk = PublicKey::from_secret_key(&secp, &sk);
        wallet_save_default(&sk);
        let body = serde_json::json!({"public_key": pk.to_string()}).to_string();
        return ("200 OK".into(), body);
    }
    if method == "DELETE" && path == "/wallet" {
        wallet_remove_default();
        return ("200 OK".into(), "{\"ok\":true}".into());
    }
    if method == "POST" && path == "/wallet/import-priv" {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
            if let Some(h) = v.get("priv_hex").and_then(|x| x.as_str()) {
                if let Ok(bytes) = hex::decode(h) {
                    if let Some(sk) = secret_key_from_bytes(bytes) {
                        wallet_save_default(&sk);
                        return ("200 OK".into(), "{\"ok\":true}".into());
                    }
                }
            }
        }
        return ("400 Bad Request".into(), "{\"error\":\"invalid hex\"}".into());
    }
    if method == "POST" && path == "/wallet/import-dat" {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
            if let Some(h) = v.get("dat_hex").and_then(|x| x.as_str()) {
                if let Ok(bytes) = hex::decode(h) {
                    if let Some(sk) = secret_key_from_bytes(bytes) {
                        wallet_save_default(&sk);
                        return ("200 OK".into(), "{\"ok\":true}".into());
                    }
                }
            }
        }
        return ("400 Bad Request".into(), "{\"error\":\"invalid dat\"}".into());
    }
    if method == "POST" && path == "/wallet/send" {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
            if let (Some(to), Some(amount)) = (
                v.get("to").and_then(|x| x.as_str()),
                v.get("amount").and_then(|x| x.as_u64()),
            ) {
                let minp = v.get("min_peers").and_then(|x| x.as_u64()).unwrap_or(2) as usize;
                if let Some(sk) = wallet_load_default() {
                    let tx = build_tx(&sk, to, amount);
                    let payload = serde_json::to_vec(&tx).unwrap_or_default();
                    let (ok, total) = broadcast_tx_payload(&payload, minp);
                    let message = if ok < minp {
                        format!("queued: sent {}/{}", ok, total)
                    } else {
                        format!("sent to {}/{}", ok, total)
                    };
                    let body =
                        serde_json::json!({ "ok": true, "message": message }).to_string();
                    return ("200 OK".into(), body);
                }
            }
        }
        return ("400 Bad Request".into(), "{\"error\":\"invalid or no wallet\"}".into());
    }
    if method == "POST" && path == "/wallet/flush" {
        let sent = try_broadcast_pending(2);
        let body = serde_json::json!({ "sent": sent }).to_string();
        return ("200 OK".into(), body);
    }

    ("404 Not Found".into(), "{\"error\":\"not found\"}".into())
}
