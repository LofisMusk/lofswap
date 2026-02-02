use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    env,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
struct AppState {
    data_dir: PathBuf,
    peer_timeout: Duration,
    max_peers: usize,
    cache_ttl: Duration,
    cache: Arc<Mutex<Cache>>,
    self_peer: Option<String>,
}

#[derive(Default)]
struct Cache {
    ts: Option<Instant>,
    chain: Vec<Value>,
    meta: Telemetry,
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

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    env::var(key)
        .ok()
        .and_then(|v| v.parse::<T>().ok())
        .unwrap_or(default)
}

fn env_or_string(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

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
            .collect(),
        _ => vec![],
    };
    if let Some(self_peer) = self_peer {
        if !self_peer.is_empty() && !peers.iter().any(|p| p == self_peer) {
            peers.insert(0, self_peer.to_string());
        }
    }
    peers
}

fn tcp_request(peer: &str, payload: &str, timeout: Duration) -> Option<String> {
    let mut parts = peer.rsplitn(2, ':');
    let port = parts.next()?.parse::<u16>().ok()?;
    let host = parts.next()?;
    let addr = format!("{}:{}", host, port);
    let sock = addr.parse::<SocketAddr>().ok()?;
    let mut stream = TcpStream::connect_timeout(&sock, timeout).ok()?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    if stream.write_all(payload.as_bytes()).is_err() {
        return None;
    }
    let mut buf = Vec::new();
    if stream.read_to_end(&mut buf).is_err() {
        return None;
    }
    if buf.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&buf).to_string())
}

fn tcp_request_timed(peer: &str, payload: &str, timeout: Duration) -> Option<(String, Duration)> {
    let mut parts = peer.rsplitn(2, ':');
    let port = parts.next()?.parse::<u16>().ok()?;
    let host = parts.next()?;
    let addr = format!("{}:{}", host, port);
    let sock = addr.parse::<SocketAddr>().ok()?;
    let start = Instant::now();
    let mut stream = TcpStream::connect_timeout(&sock, timeout).ok()?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    if stream.write_all(payload.as_bytes()).is_err() {
        return None;
    }
    let mut buf = Vec::new();
    if stream.read_to_end(&mut buf).is_err() {
        return None;
    }
    if buf.is_empty() {
        return None;
    }
    Some((String::from_utf8_lossy(&buf).to_string(), start.elapsed()))
}

fn ping_peer(peer: &str, timeout: Duration) -> bool {
    tcp_request(peer, "/ping", timeout)
        .map(|s| s.trim() == "pong")
        .unwrap_or(false)
}

fn ping_peer_timed(peer: &str, timeout: Duration) -> Option<Duration> {
    tcp_request_timed(peer, "/ping", timeout)
        .and_then(|(s, dur)| if s.trim() == "pong" { Some(dur) } else { None })
}

fn chain_from_peer(peer: &str, timeout: Duration) -> Option<Vec<Value>> {
    let resp = tcp_request(peer, "/chain", timeout)?;
    let parsed = serde_json::from_str::<Value>(&resp).ok()?;
    if let Value::Array(arr) = parsed {
        return Some(arr);
    }
    None
}

fn chain_hash(chain: &[Value]) -> String {
    let json = serde_json::to_string(chain).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    hex::encode(hasher.finalize())
}

fn median(mut values: Vec<usize>) -> usize {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    let mid = values.len() / 2;
    if values.len() % 2 == 1 {
        values[mid]
    } else {
        (values[mid - 1] + values[mid]) / 2
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn average_block_time_sec(chain: &[Value], sample: usize) -> Option<f64> {
    let mut ts = Vec::new();
    for block in chain.iter().rev().take(sample) {
        if let Some(t) = block.get("timestamp").and_then(|v| v.as_i64()) {
            ts.push(t);
        }
    }
    if ts.len() < 2 {
        return None;
    }
    let mut diffs = Vec::new();
    for w in ts.windows(2) {
        let d = (w[0] - w[1]).abs();
        if d > 0 {
            diffs.push(d as f64);
        }
    }
    if diffs.is_empty() {
        return None;
    }
    let sum: f64 = diffs.iter().sum();
    Some((sum / diffs.len() as f64) / 1000.0)
}

fn estimate_hashrate(difficulty: i64, avg_block_time_sec: Option<f64>) -> Option<String> {
    let avg = avg_block_time_sec?;
    if avg <= 0.0 || difficulty < 0 {
        return None;
    }
    let trials = 16f64.powi(difficulty as i32);
    let rate = trials / avg;
    let (value, unit) = if rate >= 1e12 {
        (rate / 1e12, "TH/s")
    } else if rate >= 1e9 {
        (rate / 1e9, "GH/s")
    } else if rate >= 1e6 {
        (rate / 1e6, "MH/s")
    } else if rate >= 1e3 {
        (rate / 1e3, "KH/s")
    } else {
        (rate, "H/s")
    };
    Some(format!("{:.2} {}", value, unit))
}

fn consensus_state(state: &AppState) -> (Vec<Value>, Telemetry) {
    let now = Instant::now();
    {
        let cache = state.cache.lock().unwrap();
        if let Some(ts) = cache.ts {
            if now.duration_since(ts) < state.cache_ttl {
                return (cache.chain.clone(), cache.meta.clone());
            }
        }
    }

    let local_chain_val = read_json_file(&data_path(&state.data_dir, "blockchain.json"), Value::Array(vec![]));
    let local_chain = match local_chain_val {
        Value::Array(list) => list,
        _ => vec![],
    };

    let peers_all = load_peers(&state.data_dir, state.self_peer.as_deref());
    let peers = peers_all.iter().take(state.max_peers).cloned().collect::<Vec<_>>();

    let mut chains = vec![("local".to_string(), local_chain.clone())];
    let mut chain_ok = 0;
    let mut ping_ok = 0;
    let mut heights = vec![local_chain.len()];

    for peer in &peers {
        if ping_peer(peer, state.peer_timeout) {
            ping_ok += 1;
        }
        if let Some(chain) = chain_from_peer(peer, state.peer_timeout) {
            heights.push(chain.len());
            chain_ok += 1;
            chains.push((peer.clone(), chain));
        }
    }

    let chosen = if chains.is_empty() {
        vec![]
    } else {
        let max_len = chains.iter().map(|c| c.1.len()).max().unwrap_or(0);
        let candidates = chains
            .iter()
            .filter(|c| c.1.len() == max_len)
            .collect::<Vec<_>>();
        if candidates.len() == 1 {
            candidates[0].1.clone()
        } else {
            let mut counts = std::collections::HashMap::<String, usize>::new();
            for c in &candidates {
                let h = chain_hash(&c.1);
                *counts.entry(h).or_insert(0) += 1;
            }
            let best_hash = counts
                .iter()
                .max_by_key(|(_, v)| *v)
                .map(|(k, _)| k.clone())
                .unwrap_or_default();
            candidates
                .iter()
                .find(|c| chain_hash(&c.1) == best_hash)
                .map(|c| c.1.clone())
                .unwrap_or_default()
        }
    };

    let consensus_hash = if chosen.is_empty() {
        None
    } else {
        Some(chain_hash(&chosen))
    };

    let telemetry = Telemetry {
        peers_total: peers_all.len(),
        peers_sampled: peers.len(),
        ping_ok,
        chain_ok,
        candidates: chains
            .iter()
            .map(|c| c.1.len())
            .max()
            .map(|max_len| chains.iter().filter(|c| c.1.len() == max_len).count())
            .unwrap_or(0),
        consensus_height: chosen.len(),
        consensus_hash,
        height_min: heights.iter().copied().min().unwrap_or(0),
        height_max: heights.iter().copied().max().unwrap_or(0),
        height_median: median(heights.clone()),
        height_local: local_chain.len(),
    };

    let mut cache = state.cache.lock().unwrap();
    cache.ts = Some(Instant::now());
    cache.chain = chosen.clone();
    cache.meta = telemetry.clone();

    (chosen, telemetry)
}

fn peer_status_list(state: &AppState, consensus_height: usize) -> Vec<Value> {
    let peers = load_peers(&state.data_dir, state.self_peer.as_deref());
    let mut list = Vec::new();
    for peer in peers.iter().take(state.max_peers) {
        let mut status = "offline".to_string();
        let mut online = false;
        let mut rtt_ms: Option<i64> = None;
        let mut last_seen: Option<i64> = None;
        let mut peer_height: Option<usize> = None;

        if let Some(rtt) = ping_peer_timed(peer, state.peer_timeout) {
            online = true;
            rtt_ms = Some(rtt.as_millis() as i64);
            last_seen = Some(now_ms());
            status = "online".to_string();
        }

        if online {
            if let Some(chain) = chain_from_peer(peer, state.peer_timeout) {
                peer_height = Some(chain.len());
                if consensus_height > 0 && chain.len() + 1 < consensus_height {
                    status = "syncing".to_string();
                }
            }
        }

        list.push(serde_json::json!({
            "peer": peer,
            "status": status,
            "online": online,
            "rtt_ms": rtt_ms,
            "last_seen": last_seen,
            "height": peer_height
        }));
    }
    list
}

fn json_response<T: Serialize>(status: StatusCode, payload: T) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert("Access-Control-Allow-Origin", "*".parse().unwrap());
    (status, headers, Json(payload)).into_response()
}

fn telemetry_to_map(meta: &Telemetry) -> serde_json::Map<String, Value> {
    let mut map = serde_json::Map::new();
    if let Ok(Value::Object(obj)) = serde_json::to_value(meta) {
        for (k, v) in obj {
            map.insert(k, v);
        }
    }
    map
}

async fn health(State(state): State<Arc<AppState>>) -> Response {
    let (_, meta) = tokio::task::spawn_blocking(move || consensus_state(&state))
        .await
        .unwrap_or_else(|_| (Vec::new(), Telemetry::default()));
    let mut obj = telemetry_to_map(&meta);
    obj.insert("status".to_string(), Value::String("ok".to_string()));
    json_response(StatusCode::OK, Value::Object(obj))
}

async fn peers(State(state): State<Arc<AppState>>) -> Response {
    json_response(
        StatusCode::OK,
        load_peers(&state.data_dir, state.self_peer.as_deref()),
    )
}

async fn peers_status(State(state): State<Arc<AppState>>) -> Response {
    let state_clone = state.clone();
    let (_, meta) = tokio::task::spawn_blocking(move || consensus_state(&state_clone))
        .await
        .unwrap_or_else(|_| (Vec::new(), Telemetry::default()));
    let list = peer_status_list(&state, meta.consensus_height);
    json_response(StatusCode::OK, serde_json::json!({ "list": list }))
}

async fn mempool(State(state): State<Arc<AppState>>) -> Response {
    let path = data_path(&state.data_dir, "mempool.json");
    json_response(StatusCode::OK, read_lines_json(&path))
}

async fn chain(State(state): State<Arc<AppState>>) -> Response {
    let (chain, _) = tokio::task::spawn_blocking(move || consensus_state(&state))
        .await
        .unwrap_or_else(|_| (Vec::new(), Telemetry::default()));
    json_response(StatusCode::OK, chain)
}

async fn latest_tx(State(state): State<Arc<AppState>>) -> Response {
    let (chain, _) = tokio::task::spawn_blocking(move || consensus_state(&state))
        .await
        .unwrap_or_else(|_| (Vec::new(), Telemetry::default()));
    if let Some(Value::Object(block)) = chain.last() {
        if let Some(Value::Array(txs)) = block.get("transactions") {
            if let Some(last) = txs.last() {
                return json_response(StatusCode::OK, last.clone());
            }
        }
    }
    json_response(StatusCode::OK, Value::Null)
}

async fn height(State(state): State<Arc<AppState>>) -> Response {
    let (chain, _) = tokio::task::spawn_blocking(move || consensus_state(&state))
        .await
        .unwrap_or_else(|_| (Vec::new(), Telemetry::default()));
    if let Some(Value::Object(block)) = chain.last() {
        let tip_hash = block.get("hash").and_then(|v| v.as_str()).unwrap_or("");
        let tip_time = block.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
        return json_response(
            StatusCode::OK,
            serde_json::json!({
                "height": chain.len(),
                "tip_hash": tip_hash,
                "tip_time": tip_time,
            }),
        );
    }
    json_response(
        StatusCode::OK,
        serde_json::json!({ "height": 0, "tip_hash": "", "tip_time": 0 }),
    )
}

async fn node_ip() -> Response {
    let private = local_ip();
    json_response(
        StatusCode::OK,
        serde_json::json!({ "public": Value::Null, "private": private }),
    )
}

async fn address_balance(State(state): State<Arc<AppState>>, axum::extract::Path(addr): axum::extract::Path<String>) -> Response {
    let (chain, _) = tokio::task::spawn_blocking(move || consensus_state(&state))
        .await
        .unwrap_or_else(|_| (Vec::new(), Telemetry::default()));
    let bal = calculate_balance(&addr, &chain);
    json_response(
        StatusCode::OK,
        serde_json::json!({ "address": addr, "balance": bal }),
    )
}

async fn address_txs(State(state): State<Arc<AppState>>, axum::extract::Path(addr): axum::extract::Path<String>) -> Response {
    let (chain, _) = tokio::task::spawn_blocking(move || consensus_state(&state))
        .await
        .unwrap_or_else(|_| (Vec::new(), Telemetry::default()));
    let txs = collect_address_txs(&addr, &chain);
    json_response(StatusCode::OK, txs)
}

async fn telemetry(State(state): State<Arc<AppState>>) -> Response {
    let (_, meta) = tokio::task::spawn_blocking(move || consensus_state(&state))
        .await
        .unwrap_or_else(|_| (Vec::new(), Telemetry::default()));
    json_response(StatusCode::OK, meta)
}

async fn block_by_hash(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Response {
    let (chain, _) = tokio::task::spawn_blocking(move || consensus_state(&state))
        .await
        .unwrap_or_else(|_| (Vec::new(), Telemetry::default()));
    for block in chain {
        if let Value::Object(obj) = &block {
            if obj.get("hash").and_then(|v| v.as_str()) == Some(hash.as_str()) {
                return json_response(StatusCode::OK, block);
            }
        }
    }
    json_response(StatusCode::OK, Value::Null)
}

async fn api_network(State(state): State<Arc<AppState>>) -> Response {
    let state_clone = state.clone();
    let (chain, meta) = tokio::task::spawn_blocking(move || consensus_state(&state_clone))
        .await
        .unwrap_or_else(|_| (Vec::new(), Telemetry::default()));

    let consensus_height = meta.consensus_height;
    let difficulty = chain
        .last()
        .and_then(|b| b.get("difficulty"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    let avg_block_time_sec = average_block_time_sec(&chain, 20);
    let hash_rate = estimate_hashrate(difficulty, avg_block_time_sec);

    let peers_list = peer_status_list(&state, consensus_height);
    let active_peers = peers_list.iter().filter(|p| p.get("online").and_then(|v| v.as_bool()) == Some(true)).count();

    json_response(
        StatusCode::OK,
        serde_json::json!({
            "chainHeight": consensus_height,
            "activePeers": active_peers,
            "difficulty": difficulty,
            "hashRate": hash_rate,
            "avgBlockTimeSec": avg_block_time_sec,
            "lastUpdated": now_ms(),
        }),
    )
}

async fn api_peers(State(state): State<Arc<AppState>>) -> Response {
    let state_clone = state.clone();
    let (_, meta) = tokio::task::spawn_blocking(move || consensus_state(&state_clone))
        .await
        .unwrap_or_else(|_| (Vec::new(), Telemetry::default()));
    let list = peer_status_list(&state, meta.consensus_height);
    let peers = list
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "address": p.get("peer").cloned().unwrap_or(Value::Null),
                "status": p.get("status").cloned().unwrap_or(Value::String("offline".to_string())),
                "lastSeen": p.get("last_seen").cloned().unwrap_or(Value::Null),
                "rttMs": p.get("rtt_ms").cloned().unwrap_or(Value::Null),
                "height": p.get("height").cloned().unwrap_or(Value::Null)
            })
        })
        .collect::<Vec<_>>();
    json_response(StatusCode::OK, serde_json::json!({ "peers": peers }))
}

async fn peer_detail(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(peer): axum::extract::Path<String>,
) -> Response {
    let state_clone = state.clone();
    let (chain, meta) = tokio::task::spawn_blocking(move || consensus_state(&state_clone))
        .await
        .unwrap_or_else(|_| (Vec::new(), Telemetry::default()));

    let consensus_height = meta.consensus_height;
    let mut blocks_mined = 0usize;
    let mut last_block = Value::Null;
    let mut first_ts: Option<i64> = None;
    let mut last_ts: Option<i64> = None;
    let now = now_ms();
    let mut mined_blocks = Vec::new();

    for block in &chain {
        if let Some(miner) = block.get("miner").and_then(|v| v.as_str()) {
            if miner == peer {
                blocks_mined += 1;
                let idx = block.get("index").and_then(|v| v.as_i64()).unwrap_or(0);
                let ts = block.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
                if first_ts.is_none() || ts < first_ts.unwrap_or(ts) {
                    first_ts = Some(ts);
                }
                if last_ts.is_none() || ts > last_ts.unwrap_or(ts) {
                    last_ts = Some(ts);
                    last_block = block.clone();
                }
                mined_blocks.push(serde_json::json!({
                    "index": idx,
                    "hash": block.get("hash").cloned().unwrap_or(Value::Null),
                    "timestamp": ts
                }));
            }
        }
    }

    let mut status = "offline".to_string();
    let mut rtt_ms: Option<i64> = None;
    let mut last_seen: Option<i64> = None;
    let mut peer_height: Option<usize> = None;
    let mut online = false;

    if let Some(rtt) = ping_peer_timed(&peer, state.peer_timeout) {
        online = true;
        rtt_ms = Some(rtt.as_millis() as i64);
        last_seen = Some(now_ms());
        status = "online".to_string();
    }
    if online {
        if let Some(chain) = chain_from_peer(&peer, state.peer_timeout) {
            peer_height = Some(chain.len());
            if consensus_height > 0 && chain.len() + 1 < consensus_height {
                status = "syncing".to_string();
            }
        }
    }

    json_response(
        StatusCode::OK,
        serde_json::json!({
            "peer": peer,
            "status": status,
            "online": online,
            "rtt_ms": rtt_ms,
            "last_seen": last_seen,
            "peer_height": peer_height,
            "consensus_height": consensus_height,
            "blocks_mined": blocks_mined,
            "first_mined_ts": first_ts,
            "last_mined_ts": last_ts,
            "uptime_sec": first_ts.map(|ts| (now - ts).max(0) / 1000),
            "last_block": last_block,
            "mined_blocks": mined_blocks
        }),
    )
}
fn calculate_balance(addr: &str, chain: &[Value]) -> i64 {
    let mut bal = 0i64;
    for block in chain {
        let txs = block.get("transactions");
        if let Some(Value::Array(list)) = txs {
            for tx in list {
                if let Some(obj) = tx.as_object() {
                    if obj.get("from").and_then(|v| v.as_str()) == Some(addr) {
                        if let Some(amount) = obj.get("amount").and_then(|v| v.as_i64()) {
                            bal -= amount;
                        }
                    }
                    if obj.get("to").and_then(|v| v.as_str()) == Some(addr) {
                        if let Some(amount) = obj.get("amount").and_then(|v| v.as_i64()) {
                            bal += amount;
                        }
                    }
                }
            }
        }
    }
    bal
}

fn collect_address_txs(addr: &str, chain: &[Value]) -> Vec<Value> {
    let mut out = Vec::new();
    for block in chain {
        let txs = block.get("transactions");
        if let Some(Value::Array(list)) = txs {
            for tx in list {
                if let Some(obj) = tx.as_object() {
                    let from = obj.get("from").and_then(|v| v.as_str());
                    let to = obj.get("to").and_then(|v| v.as_str());
                    if from == Some(addr) || to == Some(addr) {
                        out.push(tx.clone());
                    }
                }
            }
        }
    }
    out
}

fn local_ip() -> Value {
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                return Value::String(addr.ip().to_string());
            }
        }
    }
    Value::Null
}

#[tokio::main]
async fn main() {
    let data_dir = env_or_string("DATA_DIR", "data");
    let bind = env_or_string("EXPLORER_API_BIND", "127.0.0.1");
    let port = env_or("EXPLORER_API_PORT", 7000u16);
    let peer_timeout = Duration::from_secs_f32(env_or("PEER_TIMEOUT", 2.0f32));
    let max_peers = env_or("MAX_PEERS", 8usize);
    let cache_ttl = Duration::from_secs_f32(env_or("CONSENSUS_TTL", 5.0f32));

    let state = Arc::new(AppState {
        data_dir: PathBuf::from(data_dir),
        peer_timeout,
        max_peers,
        cache_ttl,
        cache: Arc::new(Mutex::new(Cache::default())),
        self_peer: env::var("EXPLORER_SELF_PEER").ok().filter(|v| !v.trim().is_empty()),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/telemetry", get(telemetry))
        .route("/peers", get(peers))
        .route("/peers/status", get(peers_status))
        .route("/peer/:peer", get(peer_detail))
        .route("/api/peer/:peer", get(peer_detail))
        .route("/api/network", get(api_network))
        .route("/api/peers", get(api_peers))
        .route("/chain", get(chain))
        .route("/chain/latest-tx", get(latest_tx))
        .route("/block/:hash", get(block_by_hash))
        .route("/api/block/:hash", get(block_by_hash))
        .route("/height", get(height))
        .route("/mempool", get(mempool))
        .route("/node/ip", get(node_ip))
        .route("/address/:addr/balance", get(address_balance))
        .route("/address/:addr/txs", get(address_txs))
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", bind, port).parse().unwrap();
    println!("Explorer API listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
