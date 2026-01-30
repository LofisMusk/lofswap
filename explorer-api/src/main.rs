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
    time::{Duration, Instant},
};

#[derive(Clone)]
struct AppState {
    data_dir: PathBuf,
    peer_timeout: Duration,
    max_peers: usize,
    cache_ttl: Duration,
    cache: Arc<Mutex<Cache>>,
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

fn load_peers(dir: &Path) -> Vec<String> {
    let path = data_path(dir, "peers.json");
    let json = read_json_file(&path, Value::Array(vec![]));
    match json {
        Value::Array(list) => list
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => vec![],
    }
}

fn tcp_request(peer: &str, payload: &str, timeout: Duration) -> Option<String> {
    let mut parts = peer.rsplitn(2, ':');
    let port = parts.next()?.parse::<u16>().ok()?;
    let host = parts.next()?;
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect(addr).ok()?;
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

fn ping_peer(peer: &str, timeout: Duration) -> bool {
    tcp_request(peer, "/ping", timeout)
        .map(|s| s.trim() == "pong")
        .unwrap_or(false)
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

    let peers_all = load_peers(&state.data_dir);
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
    json_response(StatusCode::OK, load_peers(&state.data_dir))
}

async fn peers_status(State(state): State<Arc<AppState>>) -> Response {
    let peers = load_peers(&state.data_dir);
    let mut list = Vec::new();
    for peer in peers.iter().take(state.max_peers) {
        list.push(serde_json::json!({
            "peer": peer,
            "online": ping_peer(peer, state.peer_timeout)
        }));
    }
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
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/telemetry", get(telemetry))
        .route("/peers", get(peers))
        .route("/peers/status", get(peers_status))
        .route("/chain", get(chain))
        .route("/chain/latest-tx", get(latest_tx))
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
