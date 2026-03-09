use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
struct AppState {
    data_dir: PathBuf,
    peer_timeout: Duration,
    max_peers: usize,
    refresh_interval: Duration,
    self_peer: Option<String>,
    cache: Arc<RwLock<Cache>>,
}

/// Single shared cache — written by the background refresh task,
/// read (zero-copy Arc clone) by every handler.
/// Using RwLock so concurrent reads never block each other.
#[derive(Default, Clone)]
struct Cache {
    chain: Vec<Value>,
    telemetry: Telemetry,
    peer_status: Vec<Value>, // pre-computed, includes rtt/height/status
    ready: bool,             // false until first refresh completes
}

#[derive(Serialize, Default, Clone)]
struct Telemetry {
    peers_total: usize,
    peers_sampled: usize,
    ping_ok: usize,
    chain_ok: usize,
    candidates: usize,
    consensus_height: usize,
    consensus_hash: Option<String>,
    height_min: usize,
    height_max: usize,
    height_median: usize,
    height_local: usize,
}

// ──────────────────────────────────────────────
// Env helpers
// ──────────────────────────────────────────────

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    env::var(key)
        .ok()
        .and_then(|v| v.parse::<T>().ok())
        .unwrap_or(default)
}

fn env_or_string(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

// ──────────────────────────────────────────────
// Filesystem helpers
// ──────────────────────────────────────────────

fn data_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(name)
}

fn read_json_file(path: &Path, default: Value) -> Value {
    match fs::read_to_string(path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or(default),
        Err(_) => default,
    }
}

fn read_lines_json(path: &Path) -> Vec<Value> {
    let mut out = Vec::new();
    if let Ok(contents) = fs::read_to_string(path) {
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(val) = serde_json::from_str::<Value>(line) {
                out.push(val);
            }
        }
    }
    out
}

fn load_peers(dir: &Path, self_peer: Option<&str>) -> Vec<String> {
    let path = data_path(dir, "peers.json");
    let json = read_json_file(&path, Value::Array(vec![]));
    let mut peers = match json {
        Value::Array(list) => list
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect::<Vec<_>>(),
        _ => vec![],
    };
    if let Some(sp) = self_peer {
        if !sp.is_empty() && !peers.iter().any(|p| p == sp) {
            peers.insert(0, sp.to_string());
        }
    }
    peers
}

// ──────────────────────────────────────────────
// TCP helpers
// ──────────────────────────────────────────────

fn tcp_request(peer: &str, payload: &str, timeout: Duration) -> Option<String> {
    let mut parts = peer.rsplitn(2, ':');
    let port = parts.next()?.parse::<u16>().ok()?;
    let host = parts.next()?;
    let addr: SocketAddr = format!("{}:{}", host, port).parse().ok()?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    stream.write_all(payload.as_bytes()).ok()?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    if buf.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&buf).to_string())
}

fn tcp_request_timed(
    peer: &str,
    payload: &str,
    timeout: Duration,
) -> Option<(String, Duration)> {
    let mut parts = peer.rsplitn(2, ':');
    let port = parts.next()?.parse::<u16>().ok()?;
    let host = parts.next()?;
    let addr: SocketAddr = format!("{}:{}", host, port).parse().ok()?;
    let start = Instant::now();
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    stream.write_all(payload.as_bytes()).ok()?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    if buf.is_empty() {
        return None;
    }
    Some((String::from_utf8_lossy(&buf).to_string(), start.elapsed()))
}

fn ping_peer_timed(peer: &str, timeout: Duration) -> Option<Duration> {
    tcp_request_timed(peer, "/ping", timeout)
        .and_then(|(s, dur)| if s.trim() == "pong" { Some(dur) } else { None })
}

fn chain_from_peer(peer: &str, timeout: Duration) -> Option<Vec<Value>> {
    let resp = tcp_request(peer, "/chain", timeout)?;
    match serde_json::from_str::<Value>(&resp).ok()? {
        Value::Array(arr) => Some(arr),
        _ => None,
    }
}

// ──────────────────────────────────────────────
// Consensus logic  (runs in spawn_blocking)
// ──────────────────────────────────────────────

fn chain_hash(chain: &[Value]) -> String {
    let json = serde_json::to_string(chain).unwrap_or_default();
    let mut h = Sha256::new();
    h.update(json.as_bytes());
    hex::encode(h.finalize())
}

fn median(mut v: Vec<usize>) -> usize {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    let m = v.len() / 2;
    if v.len() % 2 == 1 { v[m] } else { (v[m - 1] + v[m]) / 2 }
}

/// Full refresh: contacts all peers, picks consensus chain.
/// This is the **only** place that does I/O — called exclusively from the
/// background task inside spawn_blocking.
fn do_full_refresh(
    data_dir: &Path,
    self_peer: Option<&str>,
    peer_timeout: Duration,
    max_peers: usize,
) -> (Vec<Value>, Telemetry, Vec<Value>) {
    // ── local chain ──────────────────────────────────
    let local_val = read_json_file(
        &data_path(data_dir, "blockchain.json"),
        Value::Array(vec![]),
    );
    let local_chain: Vec<Value> = match local_val {
        Value::Array(list) => list,
        _ => vec![],
    };

    // ── peer list ────────────────────────────────────
    let peers_all = load_peers(data_dir, self_peer);
    let peers: Vec<String> = peers_all.iter().take(max_peers).cloned().collect();

    // ── probe peers ──────────────────────────────────
    let mut chains: Vec<(String, Vec<Value>)> = vec![("local".into(), local_chain.clone())];
    let mut heights: Vec<usize> = vec![local_chain.len()];
    let mut ping_ok = 0usize;
    let mut chain_ok = 0usize;
    let mut peer_status_list: Vec<Value> = Vec::new();
    let now_ts = now_ms();

    for peer in &peers {
        let mut status = "offline".to_string();
        let mut online = false;
        let mut rtt_ms: Option<i64> = None;
        let mut last_seen: Option<i64> = None;
        let mut peer_height: Option<usize> = None;

        if let Some(rtt) = ping_peer_timed(peer, peer_timeout) {
            online = true;
            ping_ok += 1;
            rtt_ms = Some(rtt.as_millis() as i64);
            last_seen = Some(now_ts);
            status = "online".to_string();
        }

        if online {
            if let Some(peer_chain) = chain_from_peer(peer, peer_timeout) {
                chain_ok += 1;
                peer_height = Some(peer_chain.len());
                heights.push(peer_chain.len());
                chains.push((peer.clone(), peer_chain));
            }
        }

        peer_status_list.push(serde_json::json!({
            "peer": peer,
            "status": status,
            "online": online,
            "rtt_ms": rtt_ms,
            "last_seen": last_seen,
            "height": peer_height,
        }));
    }

    // ── consensus chain ───────────────────────────────
    let consensus = if chains.is_empty() {
        vec![]
    } else {
        let max_len = chains.iter().map(|c| c.1.len()).max().unwrap_or(0);
        let candidates: Vec<_> = chains.iter().filter(|c| c.1.len() == max_len).collect();
        if candidates.len() == 1 {
            candidates[0].1.clone()
        } else {
            let mut counts = std::collections::HashMap::<String, usize>::new();
            for c in &candidates {
                *counts.entry(chain_hash(&c.1)).or_insert(0) += 1;
            }
            let best = counts.iter().max_by_key(|(_, v)| *v).map(|(k, _)| k.clone()).unwrap_or_default();
            candidates.iter().find(|c| chain_hash(&c.1) == best).map(|c| c.1.clone()).unwrap_or_default()
        }
    };

    let consensus_hash = if consensus.is_empty() { None } else { Some(chain_hash(&consensus)) };

    // update peer statuses with consensus info
    let c_height = consensus.len();
    for p in peer_status_list.iter_mut() {
        if let Some(h) = p.get("height").and_then(|v| v.as_u64()) {
            if c_height > 0 && (h as usize) + 1 < c_height {
                if p.get("online").and_then(|v| v.as_bool()) == Some(true) {
                    p["status"] = Value::String("syncing".into());
                }
            }
        }
    }

    let telemetry = Telemetry {
        peers_total: peers_all.len(),
        peers_sampled: peers.len(),
        ping_ok,
        chain_ok,
        candidates: chains.iter().filter(|c| c.1.len() == chains.iter().map(|x| x.1.len()).max().unwrap_or(0)).count(),
        consensus_height: c_height,
        consensus_hash,
        height_min: heights.iter().copied().min().unwrap_or(0),
        height_max: heights.iter().copied().max().unwrap_or(0),
        height_median: median(heights.clone()),
        height_local: local_chain.len(),
    };

    (consensus, telemetry, peer_status_list)
}

// ──────────────────────────────────────────────
// Background refresh task
// ──────────────────────────────────────────────

async fn start_background_refresh(state: Arc<AppState>) {
    loop {
        let data_dir = state.data_dir.clone();
        let self_peer = state.self_peer.clone();
        let peer_timeout = state.peer_timeout;
        let max_peers = state.max_peers;

        let result = tokio::task::spawn_blocking(move || {
            do_full_refresh(&data_dir, self_peer.as_deref(), peer_timeout, max_peers)
        })
        .await;

        match result {
            Ok((chain, telemetry, peer_status)) => {
                let mut cache = state.cache.write().unwrap();
                cache.chain = chain;
                cache.telemetry = telemetry;
                cache.peer_status = peer_status;
                cache.ready = true;
            }
            Err(e) => {
                eprintln!("[refresh] spawn_blocking panicked: {:?}", e);
            }
        }

        tokio::time::sleep(state.refresh_interval).await;
    }
}

// ──────────────────────────────────────────────
// Shared helpers
// ──────────────────────────────────────────────

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn cors_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("Access-Control-Allow-Origin", HeaderValue::from_static("*"));
    h.insert("Access-Control-Allow-Methods", HeaderValue::from_static("GET, OPTIONS"));
    h.insert("Access-Control-Allow-Headers", HeaderValue::from_static("Content-Type"));
    h.insert("Cache-Control", HeaderValue::from_static("no-store"));
    h
}

fn json_response<T: Serialize>(status: StatusCode, payload: T) -> Response {
    (status, cors_headers(), Json(payload)).into_response()
}

fn average_block_time_sec(chain: &[Value], sample: usize) -> Option<f64> {
    let ts: Vec<i64> = chain
        .iter()
        .rev()
        .take(sample)
        .filter_map(|b| b.get("timestamp").and_then(|v| v.as_i64()))
        .collect();
    if ts.len() < 2 {
        return None;
    }
    let diffs: Vec<f64> = ts.windows(2).map(|w| (w[0] - w[1]).abs() as f64).filter(|d| *d > 0.0).collect();
    if diffs.is_empty() {
        return None;
    }
    Some(diffs.iter().sum::<f64>() / diffs.len() as f64 / 1000.0)
}

fn estimate_hashrate(difficulty: i64, avg_block_time_sec: Option<f64>) -> Option<String> {
    let avg = avg_block_time_sec?;
    if avg <= 0.0 || difficulty < 0 { return None; }
    let rate = 16f64.powi(difficulty as i32) / avg;
    let (v, u) = if rate >= 1e12 { (rate / 1e12, "TH/s") }
        else if rate >= 1e9 { (rate / 1e9, "GH/s") }
        else if rate >= 1e6 { (rate / 1e6, "MH/s") }
        else if rate >= 1e3 { (rate / 1e3, "KH/s") }
        else { (rate, "H/s") };
    Some(format!("{:.2} {}", v, u))
}

fn find_tx_in_chain(chain: &[Value], txid: &str) -> Option<Value> {
    for block in chain {
        let idx = block.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let bhash = block.get("hash").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        if let Some(Value::Array(txs)) = block.get("transactions") {
            for tx in txs {
                if tx.get("txid").and_then(|v| v.as_str()) == Some(txid) {
                    let mut obj = tx.clone();
                    if let Value::Object(ref mut m) = obj {
                        m.insert("blockIndex".into(), Value::Number(idx.into()));
                        m.insert("blockHash".into(), Value::String(bhash.clone()));
                    }
                    return Some(obj);
                }
            }
        }
    }
    None
}

fn confirming_nodes_for_block(block_idx: usize, peers: &[Value], local_height: usize) -> usize {
    let mut count = if local_height >= block_idx { 1 } else { 0 };
    for p in peers {
        if p.get("online").and_then(|v| v.as_bool()) != Some(true) { continue; }
        let h = p.get("height").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        if h >= block_idx { count += 1; }
    }
    count
}

async fn options_handler() -> Response {
    (StatusCode::NO_CONTENT, cors_headers(), ()).into_response()
}

async fn health(State(state): State<Arc<AppState>>) -> Response {
    let cache = state.cache.read().unwrap();
    let mut obj = serde_json::to_value(&cache.telemetry)
        .unwrap_or(Value::Object(Default::default()));
    if let Value::Object(ref mut m) = obj {
        m.insert("status".into(), Value::String("ok".into()));
        m.insert("ready".into(), Value::Bool(cache.ready));
    }
    json_response(StatusCode::OK, obj)
}

async fn telemetry(State(state): State<Arc<AppState>>) -> Response {
    let cache = state.cache.read().unwrap();
    json_response(StatusCode::OK, cache.telemetry.clone())
}

async fn peers(State(state): State<Arc<AppState>>) -> Response {
    let peers_list = load_peers(&state.data_dir, state.self_peer.as_deref());
    json_response(StatusCode::OK, peers_list)
}

async fn peers_status(State(state): State<Arc<AppState>>) -> Response {
    let cache = state.cache.read().unwrap();
    json_response(StatusCode::OK, serde_json::json!({ "list": cache.peer_status }))
}

async fn mempool(State(state): State<Arc<AppState>>) -> Response {
    let path = data_path(&state.data_dir, "mempool.json");
    json_response(StatusCode::OK, read_lines_json(&path))
}

async fn chain_handler(State(state): State<Arc<AppState>>) -> Response {
    let cache = state.cache.read().unwrap();
    json_response(StatusCode::OK, cache.chain.clone())
}

async fn height(State(state): State<Arc<AppState>>) -> Response {
    let cache = state.cache.read().unwrap();
    let chain = &cache.chain;
    if let Some(last) = chain.last() {
        let tip_hash = last.get("hash").and_then(|v| v.as_str()).unwrap_or("");
        let tip_time = last.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
        return json_response(StatusCode::OK, serde_json::json!({
            "height": chain.len(),
            "tip_hash": tip_hash,
            "tip_time": tip_time,
        }));
    }
    json_response(StatusCode::OK, serde_json::json!({ "height": 0, "tip_hash": "", "tip_time": 0 }))
}

async fn latest_tx(State(state): State<Arc<AppState>>) -> Response {
    let cache = state.cache.read().unwrap();
    let tx = cache.chain.iter().rev().find_map(|b| {
        b.get("transactions").and_then(|v| v.as_array()).and_then(|arr| arr.last().cloned())
    });
    json_response(StatusCode::OK, tx.unwrap_or(Value::Null))
}

async fn block_by_hash(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Response {
    let cache = state.cache.read().unwrap();
    // support lookup by hash OR by block index number
    let block = cache.chain.iter().find(|b| {
        b.get("hash").and_then(|v| v.as_str()) == Some(hash.as_str())
        || b.get("index").and_then(|v| v.as_u64()).map(|i| i.to_string()) == Some(hash.clone())
    }).cloned();
    match block {
        Some(b) => json_response(StatusCode::OK, b),
        None => json_response(StatusCode::NOT_FOUND, serde_json::json!({ "error": "block not found", "hash": hash })),
    }
}

async fn api_tx(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(txid): axum::extract::Path<String>,
) -> Response {
    let cache = state.cache.read().unwrap();
    let chain = &cache.chain;
    let peers = &cache.peer_status;
    let local_height = cache.telemetry.height_local;
    let consensus_height = cache.telemetry.consensus_height;

    if let Some(tx_with_block) = find_tx_in_chain(chain, &txid) {
        let block_idx = tx_with_block.get("blockIndex").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let block_hash = tx_with_block.get("blockHash").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let conf_nodes = confirming_nodes_for_block(block_idx, peers, local_height);
        let confirmations = consensus_height.saturating_sub(block_idx);

        return json_response(StatusCode::OK, serde_json::json!({
            "txid": txid,
            "from": tx_with_block.get("from").cloned().unwrap_or(Value::Null),
            "to": tx_with_block.get("to").cloned().unwrap_or(Value::Null),
            "amount": tx_with_block.get("amount").cloned().unwrap_or(Value::Null),
            // C-01: raw ECDSA signature NIE jest zwracana przez API (private key recovery risk)
            "timestamp": tx_with_block.get("timestamp").cloned().unwrap_or(Value::Null),
            "blockIndex": block_idx,
            "blockHash": block_hash,
            "confirmations": confirmations,
            "confirmingNodes": conf_nodes,
            "lastChecked": now_ms(),
        }));
    }

    json_response(StatusCode::NOT_FOUND, serde_json::json!({ "error": "tx not found", "txid": txid }))
}

async fn api_tx_recent(State(state): State<Arc<AppState>>) -> Response {
    let cache = state.cache.read().unwrap();
    let chain = &cache.chain;
    let peers = &cache.peer_status;
    let local_height = cache.telemetry.height_local;
    let consensus_height = cache.telemetry.consensus_height;

    let mut list: Vec<Value> = Vec::new();
    for block in chain.iter().rev().take(20) {
        let idx = block.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let bhash = block.get("hash").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        if let Some(Value::Array(txs)) = block.get("transactions") {
            for tx in txs {
                let conf_nodes = confirming_nodes_for_block(idx, peers, local_height);
                let confirmations = consensus_height.saturating_sub(idx);
                list.push(serde_json::json!({
                    "txid": tx.get("txid").cloned().unwrap_or(Value::Null),
                    "from": tx.get("from").cloned().unwrap_or(Value::Null),
                    "to": tx.get("to").cloned().unwrap_or(Value::Null),
                    "amount": tx.get("amount").cloned().unwrap_or(Value::Null),
                    // C-01: signature pominięta (private key recovery risk)
                    "timestamp": tx.get("timestamp").cloned().unwrap_or(Value::Null),
                    "blockIndex": idx,
                    "blockHash": bhash,
                    "confirmations": confirmations,
                    "confirmingNodes": conf_nodes,
                }));
            }
        }
    }

    // newest first
    list.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
        let tb = b.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
        tb.cmp(&ta)
    });

    json_response(StatusCode::OK, serde_json::json!({ "transactions": list }))
}

async fn api_network(State(state): State<Arc<AppState>>) -> Response {
    let cache = state.cache.read().unwrap();
    let chain = &cache.chain;
    let tele = &cache.telemetry;

    let difficulty = chain.last()
        .and_then(|b| b.get("difficulty"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let avg_block_time = average_block_time_sec(chain, 20);
    let hash_rate = estimate_hashrate(difficulty, avg_block_time);
    let total_txs: usize = chain.iter()
        .filter_map(|b| b.get("transactions").and_then(|v| v.as_array()))
        .map(|arr| arr.len())
        .sum();
    let active_peers = cache.peer_status.iter()
        .filter(|p| p.get("online").and_then(|v| v.as_bool()) == Some(true))
        .count();

    json_response(StatusCode::OK, serde_json::json!({
        "chainHeight": tele.consensus_height,
        "activePeers": active_peers,
        "totalPeers": tele.peers_total,
        "difficulty": difficulty,
        "hashRate": hash_rate,
        "avgBlockTimeSec": avg_block_time,
        "totalTransactions": total_txs,
        "lastUpdated": now_ms(),
    }))
}

async fn api_peers(State(state): State<Arc<AppState>>) -> Response {
    let cache = state.cache.read().unwrap();
    let peers = cache.peer_status.iter().map(|p| {
        serde_json::json!({
            "address": p.get("peer").cloned().unwrap_or(Value::Null),
            "status": p.get("status").cloned().unwrap_or(Value::String("offline".into())),
            "lastSeen": p.get("last_seen").cloned().unwrap_or(Value::Null),
            "rttMs": p.get("rtt_ms").cloned().unwrap_or(Value::Null),
            "height": p.get("height").cloned().unwrap_or(Value::Null),
            "online": p.get("online").cloned().unwrap_or(Value::Bool(false)),
        })
    }).collect::<Vec<_>>();
    json_response(StatusCode::OK, serde_json::json!({ "peers": peers }))
}

async fn peer_detail(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(peer_addr): axum::extract::Path<String>,
) -> Response {
    let (chain, tele, cached_status) = {
        let cache = state.cache.read().unwrap();
        let status = cache.peer_status.iter().find(|p| {
            p.get("peer").and_then(|v| v.as_str()) == Some(peer_addr.as_str())
        }).cloned();
        (cache.chain.clone(), cache.telemetry.clone(), status)
    };

    let mut blocks_mined = 0usize;
    let mut mined_blocks: Vec<Value> = Vec::new();
    let mut last_block = Value::Null;
    let mut first_ts: Option<i64> = None;
    let mut last_ts: Option<i64> = None;

    for block in &chain {
        if block.get("miner").and_then(|v| v.as_str()) == Some(peer_addr.as_str()) {
            blocks_mined += 1;
            let idx = block.get("index").and_then(|v| v.as_i64()).unwrap_or(0);
            let ts = block.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
            first_ts = Some(first_ts.map_or(ts, |f| f.min(ts)));
            last_ts = Some(last_ts.map_or(ts, |l| l.max(ts)));
            if last_ts == Some(ts) { last_block = block.clone(); }
            mined_blocks.push(serde_json::json!({
                "index": idx,
                "hash": block.get("hash").cloned().unwrap_or(Value::Null),
                "timestamp": ts,
            }));
        }
    }

    let now = now_ms();
    // use cached status (no extra I/O)
    let (status, online, rtt_ms, last_seen, peer_height) = if let Some(p) = cached_status {
        (
            p.get("status").and_then(|v| v.as_str()).unwrap_or("offline").to_string(),
            p.get("online").and_then(|v| v.as_bool()).unwrap_or(false),
            p.get("rtt_ms").cloned().unwrap_or(Value::Null),
            p.get("last_seen").cloned().unwrap_or(Value::Null),
            p.get("height").cloned().unwrap_or(Value::Null),
        )
    } else {
        ("offline".into(), false, Value::Null, Value::Null, Value::Null)
    };

    json_response(StatusCode::OK, serde_json::json!({
        "peer": peer_addr,
        "status": status,
        "online": online,
        "rtt_ms": rtt_ms,
        "last_seen": last_seen,
        "peer_height": peer_height,
        "consensus_height": tele.consensus_height,
        "blocks_mined": blocks_mined,
        "first_mined_ts": first_ts,
        "last_mined_ts": last_ts,
        "uptime_sec": first_ts.map(|ts| (now - ts).max(0) / 1000),
        "last_block": last_block,
        "mined_blocks": mined_blocks,
    }))
}

async fn address_balance(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(addr): axum::extract::Path<String>,
) -> Response {
    let cache = state.cache.read().unwrap();
    let mut bal = 0i64;
    for block in &cache.chain {
        if let Some(Value::Array(txs)) = block.get("transactions") {
            for tx in txs {
                if let Some(obj) = tx.as_object() {
                    let amount = obj.get("amount").and_then(|v| v.as_i64()).unwrap_or(0);
                    if obj.get("from").and_then(|v| v.as_str()) == Some(addr.as_str()) { bal -= amount; }
                    if obj.get("to").and_then(|v| v.as_str()) == Some(addr.as_str()) { bal += amount; }
                }
            }
        }
    }
    json_response(StatusCode::OK, serde_json::json!({ "address": addr, "balance": bal }))
}

async fn address_txs(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(addr): axum::extract::Path<String>,
) -> Response {
    let cache = state.cache.read().unwrap();
    let addr = addr.as_str();
    let txs: Vec<Value> = cache
        .chain
        .iter()
        .flat_map(|block| {
            block
                .get("transactions")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
        })
        .filter(|tx| {
            tx.get("from").and_then(|v| v.as_str()) == Some(addr)
                || tx.get("to").and_then(|v| v.as_str()) == Some(addr)
        })
        .cloned()
        .collect();
    json_response(StatusCode::OK, txs)
}

async fn node_ip() -> Response {
    let ip = if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            sock.local_addr().ok().map(|a| Value::String(a.ip().to_string())).unwrap_or(Value::Null)
        } else { Value::Null }
    } else { Value::Null };
    json_response(StatusCode::OK, serde_json::json!({ "public": Value::Null, "private": ip }))
}

// ──────────────────────────────────────────────
// L2 handlers
// ──────────────────────────────────────────────
// L2 handlers
// ──────────────────────────────────────────────

/// Odczytuje plik JSON z data_dir lub zwraca pusty array/null
fn read_l2_file(dir: &Path, name: &str) -> Value {
    let path = dir.join(name);
    match fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or(Value::Array(vec![])),
        Err(_) => Value::Array(vec![]),
    }
}

/// GET /api/l2/status — skrócone podsumowanie L2
async fn api_l2_status(State(state): State<Arc<AppState>>) -> Response {
    let commitments = read_l2_file(&state.data_dir, "l2_commitments.json");
    let bridge = read_l2_file(&state.data_dir, "l2_bridge_outputs.json");
    let bonds = read_l2_file(&state.data_dir, "l2_sequencer_bonds.json");
    let l2_state = read_l2_file(&state.data_dir, "l2_state.json");

    let total_commitments = commitments.as_array().map(|a| a.len()).unwrap_or(0);
    let soft_count = commitments.as_array().map(|a| {
        a.iter().filter(|c| c.get("state").and_then(|v| v.as_str()) == Some("soft")).count()
    }).unwrap_or(0);
    let hard_count = commitments.as_array().map(|a| {
        a.iter().filter(|c| c.get("state").and_then(|v| v.as_str()) == Some("hard")).count()
    }).unwrap_or(0);
    let fraud_count = commitments.as_array().map(|a| {
        a.iter().filter(|c| c.get("state").and_then(|v| v.as_str()) == Some("fraud")).count()
    }).unwrap_or(0);
    let locked_outputs = bridge.as_array().map(|a| {
        a.iter().filter(|o| o.get("state").and_then(|v| v.as_str()) == Some("locked")).count()
    }).unwrap_or(0);
    let unlocked_outputs = bridge.as_array().map(|a| {
        a.iter().filter(|o| o.get("state").and_then(|v| v.as_str()) == Some("unlocked")).count()
    }).unwrap_or(0);

    json_response(StatusCode::OK, serde_json::json!({
        "l2_height": l2_state.get("height").cloned().unwrap_or(Value::Number(0.into())),
        "state_root": l2_state.get("state_root").cloned().unwrap_or(Value::Null),
        "tip_hash": l2_state.get("tip_hash").cloned().unwrap_or(Value::Null),
        "commitments": {
            "total": total_commitments,
            "soft": soft_count,
            "hard": hard_count,
            "fraud": fraud_count,
        },
        "bridge_outputs": {
            "locked": locked_outputs,
            "unlocked": unlocked_outputs,
        },
        "sequencer_bonds": bonds.as_array().map(|a| a.len()).unwrap_or(0),
        "last_updated": now_ms(),
    }))
}

/// GET /api/l2/commitments — lista wszystkich commitmentów
async fn api_l2_commitments(State(state): State<Arc<AppState>>) -> Response {
    let commitments = read_l2_file(&state.data_dir, "l2_commitments.json");
    json_response(StatusCode::OK, serde_json::json!({ "commitments": commitments }))
}

/// GET /api/l2/commitment/:height
async fn api_l2_commitment_by_height(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(height): axum::extract::Path<u64>,
) -> Response {
    let commitments = read_l2_file(&state.data_dir, "l2_commitments.json");
    let found = commitments.as_array().and_then(|arr| {
        arr.iter().find(|c| {
            c.get("l2_height").and_then(|v| v.as_u64()) == Some(height)
        }).cloned()
    });
    match found {
        Some(c) => json_response(StatusCode::OK, c),
        None => json_response(StatusCode::NOT_FOUND, serde_json::json!({
            "error": "commitment not found", "l2_height": height
        })),
    }
}

/// GET /api/l2/bridge — wszystkie bridge outputs
async fn api_l2_bridge(State(state): State<Arc<AppState>>) -> Response {
    let outputs = read_l2_file(&state.data_dir, "l2_bridge_outputs.json");
    json_response(StatusCode::OK, serde_json::json!({ "outputs": outputs }))
}

/// GET /api/l2/bridge/:id — konkretny bridge output
async fn api_l2_bridge_output(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let outputs = read_l2_file(&state.data_dir, "l2_bridge_outputs.json");
    let found = outputs.as_array().and_then(|arr| {
        arr.iter().find(|o| {
            o.get("id").and_then(|v| v.as_str()) == Some(id.as_str())
        }).cloned()
    });
    match found {
        Some(o) => json_response(StatusCode::OK, o),
        None => json_response(StatusCode::NOT_FOUND, serde_json::json!({
            "error": "output not found", "id": id
        })),
    }
}

/// GET /api/l2/chain — lista bloków L2
async fn api_l2_chain(State(state): State<Arc<AppState>>) -> Response {
    let chain = read_l2_file(&state.data_dir, "l2_chain.json");
    json_response(StatusCode::OK, serde_json::json!({ "blocks": chain }))
}

/// GET /api/l2/balances — salda kont L2
async fn api_l2_balances(State(state): State<Arc<AppState>>) -> Response {
    let l2_state = read_l2_file(&state.data_dir, "l2_state.json");
    let balances = l2_state.get("balances").cloned().unwrap_or(Value::Object(Default::default()));
    json_response(StatusCode::OK, serde_json::json!({
        "balances": balances,
        "height": l2_state.get("height").cloned().unwrap_or(Value::Number(0.into())),
        "state_root": l2_state.get("state_root").cloned().unwrap_or(Value::Null),
    }))
}

// ──────────────────────────────────────────────
// Main
// ──────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let data_dir = env_or_string("DATA_DIR", "data");
    let bind = env_or_string("EXPLORER_API_BIND", "0.0.0.0");
    let port = env_or("EXPLORER_API_PORT", 7000u16);
    // How long to wait for a single peer TCP operation
    let peer_timeout = Duration::from_secs_f32(env_or("PEER_TIMEOUT", 2.0f32));
    // How many peers to probe per refresh cycle
    let max_peers = env_or("MAX_PEERS", 8usize);
    // How often the background task refreshes the cache (seconds)
    // Default 10s — you can set it lower (e.g. 5) for more freshness
    // at the cost of more TCP connections per minute.
    let refresh_interval = Duration::from_secs_f32(env_or("REFRESH_INTERVAL", 10.0f32));

    let state = Arc::new(AppState {
        data_dir: PathBuf::from(data_dir),
        peer_timeout,
        max_peers,
        refresh_interval,
        self_peer: env::var("EXPLORER_SELF_PEER").ok().filter(|v| !v.trim().is_empty()),
        cache: Arc::new(RwLock::new(Cache::default())),
    });

    // ── kick off background refresh immediately ──
    {
        // do first refresh synchronously before we start serving,
        // so the very first HTTP request never hits an empty cache.
        let data_dir = state.data_dir.clone();
        let sp = state.self_peer.clone();
        let pt = state.peer_timeout;
        let mp = state.max_peers;
        println!("Explorer API: initial cache fill (connecting to peers)...");
        let (chain, telemetry, peer_status) = tokio::task::spawn_blocking(move || {
            do_full_refresh(&data_dir, sp.as_deref(), pt, mp)
        })
        .await
        .unwrap_or_default();
        {
            let mut cache = state.cache.write().unwrap();
            cache.chain = chain;
            cache.telemetry = telemetry;
            cache.peer_status = peer_status;
            cache.ready = true;
        }
        println!("Explorer API: initial cache fill complete.");
    }

    // ── start periodic background refresh ───────
    tokio::spawn(start_background_refresh(state.clone()));

    // ── build router ────────────────────────────
    let app = Router::new()
        // legacy / compat routes
        .route("/health",               get(health).options(options_handler))
        .route("/telemetry",            get(telemetry).options(options_handler))
        .route("/peers",                get(peers).options(options_handler))
        .route("/peers/status",         get(peers_status).options(options_handler))
        .route("/mempool",              get(mempool).options(options_handler))
        .route("/chain",                get(chain_handler).options(options_handler))
        .route("/chain/latest-tx",      get(latest_tx).options(options_handler))
        .route("/height",               get(height).options(options_handler))
        .route("/block/:hash",          get(block_by_hash).options(options_handler))
        .route("/node/ip",              get(node_ip).options(options_handler))
        // api/v1 routes (used by new explorer)
        .route("/api/block/:hash",      get(block_by_hash).options(options_handler))
        .route("/api/tx/:txid",         get(api_tx).options(options_handler))
        .route("/api/transactions/recent", get(api_tx_recent).options(options_handler))
        .route("/api/peers",            get(api_peers).options(options_handler))
        .route("/api/peer/:peer",       get(peer_detail).options(options_handler))
        .route("/peer/:peer",           get(peer_detail).options(options_handler))
        .route("/api/network",          get(api_network).options(options_handler))
        // address endpoints
        .route("/address/:addr/balance", get(address_balance).options(options_handler))
        .route("/address/:addr/txs",     get(address_txs).options(options_handler))
        // ── L2 endpoints ──────────────────────────────────────────────────────
        .route("/api/l2/status",                    get(api_l2_status).options(options_handler))
        .route("/api/l2/commitments",               get(api_l2_commitments).options(options_handler))
        .route("/api/l2/commitment/:height",        get(api_l2_commitment_by_height).options(options_handler))
        .route("/api/l2/bridge",                    get(api_l2_bridge).options(options_handler))
        .route("/api/l2/bridge/:id",                get(api_l2_bridge_output).options(options_handler))
        .route("/api/l2/chain",                     get(api_l2_chain).options(options_handler))
        .route("/api/l2/balances",                  get(api_l2_balances).options(options_handler))
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", bind, port).parse().unwrap();
    println!("Explorer API listening on http://{}", addr);
    println!("  PEER_TIMEOUT={}s  MAX_PEERS={}  REFRESH_INTERVAL={}s",
        peer_timeout.as_secs_f32(), max_peers, refresh_interval.as_secs_f32());

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
