use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use blockchain_core::{Block, CHAIN_ID, DEFAULT_DIFFICULTY_ZEROS, Transaction};
use local_ip_address::local_ip;
use once_cell::sync::Lazy;
use public_ip;
use rand::rand_core::Rng;
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
    NODE_PUBKEY, NODE_VERSION, OBSERVED_IP,
    chain::{
        DIFFICULTY_ADJUSTMENT_INTERVAL, DIFFICULTY_MAX_ZEROS, DIFFICULTY_MIN_ZEROS,
        TARGET_BLOCK_TIME_SECS, calculate_balance, is_tx_valid, load_peers, next_nonce_for_address,
        prune_mempool, save_chain, save_peers, validate_block, validate_chain,
    },
    errors::NodeError,
    identity::{node_id_from_pubkey_hex, pin_matches_or_insert, sign_message, verify_signature},
    mempool::insert_transaction,
    storage::{read_data_file, write_data_file},
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
const PROTOCOL_MAGIC: [u8; 4] = *b"LFS1";
const PROTOCOL_VERSION: u8 = 1;
const FRAME_HEADER_LEN: usize = 10;
const FRAME_CHECKSUM_LEN: usize = 4;
const MAX_MESSAGE_SIZE: usize = 2 * 1024 * 1024;
const MAX_TXS_PER_MESSAGE: usize = 1;
const MAX_BLOCKS_PER_MESSAGE: usize = 1;
const MAX_TXS_PER_BLOCK_MESSAGE: usize = 4096;
const MAX_PEERS_FROM_GOSSIP: usize = 32;
const MAX_NEW_PEERS_PER_GOSSIP: usize = 12;
const MAX_PEERS_PER_SUBNET_V4: usize = 8;
const MAX_PEERS_PER_SUBNET_V6: usize = 16;
const IO_READ_TIMEOUT: Duration = Duration::from_secs(5);
const IO_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const IO_CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const TX_RATE_LIMIT_PER_SEC: u32 = 20;
const BLOCK_RATE_LIMIT_PER_SEC: u32 = 5;
const PEER_RATE_LIMIT_PER_SEC: u32 = 8;
const SCORE_INVALID_FRAME: u32 = 50;
const SCORE_INVALID_TX: u32 = 20;
const SCORE_INVALID_BLOCK: u32 = 40;
const SCORE_RATE_LIMIT: u32 = 15;
const SCORE_DISCOVERY_VIOLATION: u32 = 20;
const TEMP_BAN_SCORE: u32 = 100;
const PERM_BAN_SCORE: u32 = 250;
const TEMP_BAN_SECS: u64 = 30 * 60;
const STICKY_TOTAL_TARGETS: usize = 6;
const BANLIST_FILE: &str = "banlist.json";
const PEER_PINS_FILE: &str = "peer_pins.json";
const AUTH_CLOCK_SKEW_SECS: i64 = 120;
const AUTH_CHALLENGE_TTL_SECS: u64 = 30;
const AUTH_NONCE_BYTES: usize = 16;
const HEADERS_PAGE_LIMIT: usize = 256;
const HEADERS_PAGE_LIMIT_MAX: usize = 1024;
const BLOCKS_PAGE_LIMIT: usize = 16;
const BLOCKS_PAGE_LIMIT_MAX: usize = 64;
const MAX_HEADERS_PER_SYNC: usize = 200_000;
const MAX_NETWORK_REORG_DEPTH: usize = 512;
const SYNC_BACKOFF_BASE_MS: u64 = 200;
const SYNC_BACKOFF_MAX_MS: u64 = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WireMode {
    Framed,
    Legacy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum MessageKind {
    Command = 1,
    Transaction = 2,
    Block = 3,
    Peers = 4,
    PeerInfo = 5,
    Response = 6,
    Error = 7,
    Auth = 8,
}

impl MessageKind {
    fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Command),
            2 => Some(Self::Transaction),
            3 => Some(Self::Block),
            4 => Some(Self::Peers),
            5 => Some(Self::PeerInfo),
            6 => Some(Self::Response),
            7 => Some(Self::Error),
            8 => Some(Self::Auth),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct InboundMessage {
    wire: WireMode,
    kind: MessageKind,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
enum RateKind {
    Tx,
    Block,
    Peers,
}

#[derive(Debug, Default, Clone)]
struct RateBucket {
    window_start: Option<Instant>,
    count: u32,
}

impl RateBucket {
    fn allow(&mut self, now: Instant, limit: u32) -> bool {
        if limit == 0 {
            return false;
        }
        match self.window_start {
            Some(start) if now.duration_since(start) < Duration::from_secs(1) => {
                if self.count >= limit {
                    return false;
                }
                self.count += 1;
                true
            }
            _ => {
                self.window_start = Some(now);
                self.count = 1;
                true
            }
        }
    }
}

#[derive(Debug)]
struct PeerSecurityEntry {
    score: u32,
    temp_ban_until: Option<Instant>,
    perm_banned: bool,
    tx_bucket: RateBucket,
    block_bucket: RateBucket,
    peers_bucket: RateBucket,
}

impl PeerSecurityEntry {
    fn new() -> Self {
        Self {
            score: 0,
            temp_ban_until: None,
            perm_banned: false,
            tx_bucket: RateBucket::default(),
            block_bucket: RateBucket::default(),
            peers_bucket: RateBucket::default(),
        }
    }
}

#[derive(Debug, Clone)]
struct PendingAuthChallenge {
    client_nonce: String,
    server_nonce: String,
    client_pubkey: String,
    client_node_id: String,
    issued_at: Instant,
}

#[derive(Debug, Default)]
struct SecurityState {
    peers: HashMap<String, PeerSecurityEntry>,
    perm_banned_ips: HashSet<String>,
    known_good_addrs: HashSet<String>,
    pending_auth: HashMap<String, PendingAuthChallenge>,
    peer_pins: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct PersistedBanlist {
    #[serde(default)]
    perm_banned_ips: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct PersistedPeerPins {
    #[serde(default)]
    pins: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum AuthRequest {
    ChallengeRequest {
        client_nonce: String,
        timestamp: i64,
        client_pubkey: String,
        client_node_id: String,
        signature: String,
    },
    PeerInfoRequest {
        client_nonce: String,
        server_nonce: String,
        timestamp: i64,
        client_pubkey: String,
        client_node_id: String,
        signature: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum AuthResponse {
    ChallengeResponse {
        client_nonce: String,
        server_nonce: String,
        timestamp: i64,
        server_pubkey: String,
        server_node_id: String,
        signature: String,
    },
    PeerInfoResponse {
        client_nonce: String,
        server_nonce: String,
        timestamp: i64,
        server_pubkey: String,
        server_node_id: String,
        peer_info: PeerInfo,
        signature: String,
    },
    Error {
        reason: String,
    },
}

static SECURITY_STATE: Lazy<StdMutex<SecurityState>> = Lazy::new(|| {
    let mut state = SecurityState::default();
    state.perm_banned_ips = load_permanent_bans();
    state.peer_pins = load_peer_pins();
    StdMutex::new(state)
});

fn load_permanent_bans() -> HashSet<String> {
    let Ok(Some(raw)) = read_data_file(BANLIST_FILE) else {
        return HashSet::new();
    };
    let Ok(list) = serde_json::from_str::<PersistedBanlist>(&raw) else {
        return HashSet::new();
    };
    list.perm_banned_ips.into_iter().collect()
}

fn load_peer_pins() -> HashMap<String, String> {
    let Ok(Some(raw)) = read_data_file(PEER_PINS_FILE) else {
        return HashMap::new();
    };
    let Ok(saved) = serde_json::from_str::<PersistedPeerPins>(&raw) else {
        return HashMap::new();
    };
    saved.pins
}

fn persist_permanent_bans(bans: &HashSet<String>) {
    let payload = PersistedBanlist {
        perm_banned_ips: bans.iter().cloned().collect(),
    };
    if let Ok(json) = serde_json::to_string_pretty(&payload) {
        let _ = write_data_file(BANLIST_FILE, &json);
    }
}

fn persist_peer_pins(pins: &HashMap<String, String>) {
    let payload = PersistedPeerPins { pins: pins.clone() };
    if let Ok(json) = serde_json::to_string_pretty(&payload) {
        let _ = write_data_file(PEER_PINS_FILE, &json);
    }
}

fn with_security_state<T>(f: impl FnOnce(&mut SecurityState) -> T) -> T {
    let mut guard = SECURITY_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut guard)
}

fn mark_good_peer(peer: &str) {
    let Some(normalized) = normalize_peer_address(peer) else {
        return;
    };
    with_security_state(|state| {
        state.known_good_addrs.insert(normalized);
    });
}

fn register_infraction(ip: &str, points: u32, reason: &str) {
    if ip.is_empty() || ip == "unknown" {
        return;
    }
    let mut promoted_to_perm = false;
    with_security_state(|state| {
        let now = Instant::now();
        let entry = state
            .peers
            .entry(ip.to_string())
            .or_insert_with(PeerSecurityEntry::new);
        entry.score = entry.score.saturating_add(points);
        if entry.score >= PERM_BAN_SCORE {
            entry.perm_banned = true;
            state.perm_banned_ips.insert(ip.to_string());
            promoted_to_perm = true;
        } else if entry.score >= TEMP_BAN_SCORE {
            entry.temp_ban_until = Some(now + Duration::from_secs(TEMP_BAN_SECS));
        }
    });

    if promoted_to_perm {
        with_security_state(|state| {
            persist_permanent_bans(&state.perm_banned_ips);
        });
    }

    debug_log(&format!(
        "Security infraction from {} (+{}): {}",
        ip, points, reason
    ));
}

fn ban_reason(ip: &str) -> Option<String> {
    if ip.is_empty() || ip == "unknown" {
        return None;
    }
    with_security_state(|state| {
        if state.perm_banned_ips.contains(ip) {
            return Some("permanent ban".to_string());
        }
        let now = Instant::now();
        if let Some(entry) = state.peers.get_mut(ip) {
            if entry.perm_banned {
                return Some("permanent ban".to_string());
            }
            if let Some(until) = entry.temp_ban_until {
                if until > now {
                    let left = until.saturating_duration_since(now).as_secs();
                    return Some(format!("temporary ban ({}s left)", left));
                }
                entry.temp_ban_until = None;
            }
        }
        None
    })
}

fn check_rate_limit(ip: &str, kind: RateKind) -> bool {
    if ip.is_empty() || ip == "unknown" {
        return true;
    }
    let allowed = with_security_state(|state| {
        let now = Instant::now();
        let entry = state
            .peers
            .entry(ip.to_string())
            .or_insert_with(PeerSecurityEntry::new);
        let (bucket, limit) = match kind {
            RateKind::Tx => (&mut entry.tx_bucket, TX_RATE_LIMIT_PER_SEC),
            RateKind::Block => (&mut entry.block_bucket, BLOCK_RATE_LIMIT_PER_SEC),
            RateKind::Peers => (&mut entry.peers_bucket, PEER_RATE_LIMIT_PER_SEC),
        };
        bucket.allow(now, limit)
    });

    if !allowed {
        let scope = match kind {
            RateKind::Tx => "tx",
            RateKind::Block => "block",
            RateKind::Peers => "peer-gossip",
        };
        register_infraction(
            ip,
            SCORE_RATE_LIMIT,
            &format!("rate limit exceeded for {}", scope),
        );
    }
    allowed
}

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn auth_timestamp_is_fresh(timestamp: i64) -> bool {
    let now = now_unix_secs();
    (now - timestamp).abs() <= AUTH_CLOCK_SKEW_SECS
}

fn random_nonce_hex(bytes: usize) -> String {
    let mut out = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut out);
    hex::encode(out)
}

fn challenge_map_key(remote_ip: &str, client_nonce: &str) -> String {
    format!("{}|{}", remote_ip, client_nonce)
}

fn prune_stale_challenges(state: &mut SecurityState) {
    state.pending_auth.retain(|_, pending| {
        pending.issued_at.elapsed() < Duration::from_secs(AUTH_CHALLENGE_TTL_SECS)
    });
}

fn challenge_request_signable(
    client_nonce: &str,
    timestamp: i64,
    client_pubkey: &str,
    client_node_id: &str,
) -> String {
    format!(
        "auth.challenge.request|{}|{}|{}|{}",
        client_nonce, timestamp, client_pubkey, client_node_id
    )
}

fn challenge_response_signable(
    client_nonce: &str,
    server_nonce: &str,
    timestamp: i64,
    server_pubkey: &str,
    server_node_id: &str,
) -> String {
    format!(
        "auth.challenge.response|{}|{}|{}|{}|{}",
        client_nonce, server_nonce, timestamp, server_pubkey, server_node_id
    )
}

fn peer_info_request_signable(
    client_nonce: &str,
    server_nonce: &str,
    timestamp: i64,
    client_pubkey: &str,
    client_node_id: &str,
) -> String {
    format!(
        "auth.peer_info.request|{}|{}|{}|{}|{}",
        client_nonce, server_nonce, timestamp, client_pubkey, client_node_id
    )
}

fn peer_info_response_signable(
    client_nonce: &str,
    server_nonce: &str,
    timestamp: i64,
    server_pubkey: &str,
    server_node_id: &str,
    peer_info: &PeerInfo,
) -> Option<String> {
    let peer_info_json = serde_json::to_string(peer_info).ok()?;
    Some(format!(
        "auth.peer_info.response|{}|{}|{}|{}|{}|{}",
        client_nonce, server_nonce, timestamp, server_pubkey, server_node_id, peer_info_json
    ))
}

fn pin_peer_key(peer: &str, public_key_hex: &str) -> bool {
    let Some(normalized) = normalize_peer_address(peer) else {
        return false;
    };
    let (accepted, changed) = with_security_state(|state| {
        let existed = state.peer_pins.contains_key(&normalized);
        let ok = pin_matches_or_insert(&mut state.peer_pins, &normalized, public_key_hex);
        let changed = ok && !existed;
        (ok, changed)
    });
    if accepted && changed {
        with_security_state(|state| {
            persist_peer_pins(&state.peer_pins);
        });
    }
    accepted
}

fn payload_checksum(payload: &[u8]) -> u32 {
    let digest = Sha256::digest(payload);
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
}

async fn read_exact_with_timeout(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(), NodeError> {
    match timeout(IO_READ_TIMEOUT, stream.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(NodeError::NetworkError(e.to_string())),
        Err(_) => Err(NodeError::NetworkError("read timeout".to_string())),
    }
}

async fn write_all_with_timeout(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), NodeError> {
    match timeout(IO_WRITE_TIMEOUT, stream.write_all(bytes)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(NodeError::NetworkError(e.to_string())),
        Err(_) => Err(NodeError::NetworkError("write timeout".to_string())),
    }
}

async fn shutdown_stream(stream: &mut TcpStream) {
    let _ = timeout(IO_WRITE_TIMEOUT, stream.shutdown()).await;
}

async fn send_framed_message(
    stream: &mut TcpStream,
    kind: MessageKind,
    payload: &[u8],
) -> Result<(), NodeError> {
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(NodeError::ValidationError(format!(
            "Payload too large: {} bytes",
            payload.len()
        )));
    }
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len() + FRAME_CHECKSUM_LEN);
    frame.extend_from_slice(&PROTOCOL_MAGIC);
    frame.push(PROTOCOL_VERSION);
    frame.push(kind as u8);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&payload_checksum(payload).to_be_bytes());
    write_all_with_timeout(stream, &frame).await
}

async fn send_message(
    stream: &mut TcpStream,
    wire: WireMode,
    kind: MessageKind,
    payload: &[u8],
) -> Result<(), NodeError> {
    match wire {
        WireMode::Framed => send_framed_message(stream, kind, payload).await,
        WireMode::Legacy => write_all_with_timeout(stream, payload).await,
    }
}

async fn read_framed_message(stream: &mut TcpStream) -> Result<InboundMessage, NodeError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    read_exact_with_timeout(stream, &mut header).await?;

    if header[..4] != PROTOCOL_MAGIC {
        return Err(NodeError::ValidationError(
            "Invalid protocol magic".to_string(),
        ));
    }

    let version = header[4];
    if version != PROTOCOL_VERSION {
        return Err(NodeError::ValidationError(format!(
            "Unsupported protocol version: {}",
            version
        )));
    }

    let kind = MessageKind::from_u8(header[5]).ok_or_else(|| {
        NodeError::ValidationError(format!("Unsupported message type: {}", header[5]))
    })?;

    let len = u32::from_be_bytes([header[6], header[7], header[8], header[9]]) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(NodeError::ValidationError(format!(
            "Message too large: {} bytes",
            len
        )));
    }

    let mut payload = vec![0u8; len];
    if len > 0 {
        read_exact_with_timeout(stream, &mut payload).await?;
    }

    let mut checksum = [0u8; FRAME_CHECKSUM_LEN];
    read_exact_with_timeout(stream, &mut checksum).await?;
    let expected = u32::from_be_bytes(checksum);
    let actual = payload_checksum(&payload);
    if expected != actual {
        return Err(NodeError::ValidationError(
            "Invalid frame checksum".to_string(),
        ));
    }

    Ok(InboundMessage {
        wire: WireMode::Framed,
        kind,
        payload,
    })
}

async fn read_legacy_message(stream: &mut TcpStream) -> Result<Vec<u8>, NodeError> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; BUFFER_SIZE.max(4096)];

    loop {
        match timeout(IO_READ_TIMEOUT, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                if out.len().saturating_add(n) > MAX_MESSAGE_SIZE {
                    return Err(NodeError::ValidationError(format!(
                        "Legacy message too large (>{} bytes)",
                        MAX_MESSAGE_SIZE
                    )));
                }
                out.extend_from_slice(&buf[..n]);
                if n < buf.len() {
                    break;
                }
            }
            Ok(Err(e)) => return Err(NodeError::NetworkError(e.to_string())),
            Err(_) => {
                if out.is_empty() {
                    return Err(NodeError::NetworkError("read timeout".to_string()));
                }
                break;
            }
        }
    }

    Ok(out)
}

async fn read_wire_message(stream: &mut TcpStream) -> Result<Option<InboundMessage>, NodeError> {
    let mut probe = [0u8; 4];
    let peeked = match timeout(IO_READ_TIMEOUT, stream.peek(&mut probe)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(NodeError::NetworkError(e.to_string())),
        Err(_) => return Err(NodeError::NetworkError("read timeout".to_string())),
    };

    if peeked == 0 {
        return Ok(None);
    }

    let framed_prefix_match = if peeked >= 4 {
        probe == PROTOCOL_MAGIC
    } else {
        probe[..peeked] == PROTOCOL_MAGIC[..peeked]
    };

    if framed_prefix_match {
        return read_framed_message(stream).await.map(Some);
    }

    let payload = read_legacy_message(stream).await?;
    if payload.is_empty() {
        return Ok(None);
    }
    Ok(Some(InboundMessage {
        wire: WireMode::Legacy,
        kind: MessageKind::Command,
        payload,
    }))
}

fn normalize_peer_address(peer: &str) -> Option<String> {
    let addr: SocketAddr = peer.parse().ok()?;
    if addr.port() != LISTEN_PORT {
        return None;
    }
    if addr.ip().is_unspecified() || addr.ip().is_multicast() {
        return None;
    }
    Some(addr.to_string())
}

fn peer_ip(addr: &str) -> Option<IpAddr> {
    addr.parse::<SocketAddr>().ok().map(|s| s.ip())
}

fn subnet_key(addr: &str) -> Option<String> {
    let ip = peer_ip(addr)?;
    match ip {
        IpAddr::V4(v4) => {
            let oct = v4.octets();
            Some(format!("{}.{}.{}.0/24", oct[0], oct[1], oct[2]))
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            Some(format!(
                "{:x}:{:x}:{:x}:{:x}::/64",
                seg[0], seg[1], seg[2], seg[3]
            ))
        }
    }
}

fn subnet_cap(addr: &str) -> usize {
    match peer_ip(addr) {
        Some(IpAddr::V4(_)) => MAX_PEERS_PER_SUBNET_V4,
        Some(IpAddr::V6(_)) => MAX_PEERS_PER_SUBNET_V6,
        None => 0,
    }
}

fn peers_in_subnet(peers: &[String], key: &str) -> usize {
    peers
        .iter()
        .filter_map(|p| subnet_key(p))
        .filter(|subnet| subnet == key)
        .count()
}

fn is_anchor_peer(peer: &str) -> bool {
    BOOTSTRAP_NODES
        .iter()
        .any(|anchor| normalize_peer_address(anchor).as_deref() == Some(peer) || *anchor == peer)
}

fn can_accept_peer(candidate: &str, peers: &[String]) -> bool {
    if is_anchor_peer(candidate) {
        return true;
    }
    let Some(key) = subnet_key(candidate) else {
        return false;
    };
    peers_in_subnet(peers, &key) < subnet_cap(candidate)
}

fn sticky_peer_targets(peers: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for anchor in BOOTSTRAP_NODES {
        if let Some(normalized) = normalize_peer_address(anchor) {
            if seen.insert(normalized.clone()) {
                out.push(normalized);
            }
            if out.len() >= STICKY_TOTAL_TARGETS {
                return out;
            }
        }
    }

    let known_good =
        with_security_state(|state| state.known_good_addrs.iter().cloned().collect::<Vec<_>>());
    for peer in known_good {
        if seen.insert(peer.clone()) {
            out.push(peer);
        }
        if out.len() >= STICKY_TOTAL_TARGETS {
            return out;
        }
    }

    for peer in peers {
        if seen.insert(peer.clone()) {
            out.push(peer.clone());
        }
        if out.len() >= STICKY_TOTAL_TARGETS {
            return out;
        }
    }

    out
}

fn legacy_payload(kind: MessageKind, payload: &[u8]) -> Option<Vec<u8>> {
    match kind {
        MessageKind::Peers => {
            let json = std::str::from_utf8(payload).ok()?;
            Some(format!("/peers{}", json).into_bytes())
        }
        _ => Some(payload.to_vec()),
    }
}

async fn connect_peer(peer: &str) -> Option<TcpStream> {
    match timeout(IO_CONNECT_TIMEOUT, TcpStream::connect(peer)).await {
        Ok(Ok(stream)) => Some(stream),
        _ => None,
    }
}

async fn send_only(peer: &str, kind: MessageKind, payload: &[u8]) -> bool {
    if let Some(mut stream) = connect_peer(peer).await {
        if send_framed_message(&mut stream, kind, payload)
            .await
            .is_ok()
        {
            shutdown_stream(&mut stream).await;
            mark_good_peer(peer);
            return true;
        }
        shutdown_stream(&mut stream).await;
    }
    if let Some(legacy) = legacy_payload(kind, payload) {
        if let Some(mut stream) = connect_peer(peer).await {
            if write_all_with_timeout(&mut stream, &legacy).await.is_ok() {
                shutdown_stream(&mut stream).await;
                mark_good_peer(peer);
                return true;
            }
            shutdown_stream(&mut stream).await;
        }
    }
    false
}

async fn request_framed_message(
    peer: &str,
    kind: MessageKind,
    payload: &[u8],
) -> Option<InboundMessage> {
    let mut stream = connect_peer(peer).await?;
    if send_framed_message(&mut stream, kind, payload)
        .await
        .is_err()
    {
        shutdown_stream(&mut stream).await;
        return None;
    }
    let inbound = read_wire_message(&mut stream).await.ok().flatten();
    shutdown_stream(&mut stream).await;
    if let Some(msg) = inbound {
        if msg.wire == WireMode::Framed {
            mark_good_peer(peer);
            return Some(msg);
        }
    }
    None
}

async fn request_payload(peer: &str, kind: MessageKind, payload: &[u8]) -> Option<Vec<u8>> {
    if let Some(msg) = request_framed_message(peer, kind, payload).await {
        return Some(msg.payload);
    }

    if let Some(legacy) = legacy_payload(kind, payload) {
        if let Some(mut stream) = connect_peer(peer).await {
            if write_all_with_timeout(&mut stream, &legacy).await.is_ok() {
                if let Ok(bytes) = read_legacy_message(&mut stream).await {
                    shutdown_stream(&mut stream).await;
                    mark_good_peer(peer);
                    return Some(bytes);
                }
            }
            shutdown_stream(&mut stream).await;
        }
    }

    None
}

async fn fetch_headers_page(
    peer: &str,
    from: usize,
    limit: usize,
) -> Result<Vec<BlockHeader>, String> {
    let cmd = format!(
        "/headers?from={}&limit={}",
        from,
        limit.max(1).min(HEADERS_PAGE_LIMIT_MAX)
    );
    let bytes = request_payload(peer, MessageKind::Command, cmd.as_bytes())
        .await
        .ok_or_else(|| "no headers response".to_string())?;
    serde_json::from_slice::<Vec<BlockHeader>>(&bytes)
        .map_err(|e| format!("invalid headers payload: {}", e))
}

async fn fetch_blocks_page(peer: &str, from: usize, limit: usize) -> Result<Vec<Block>, String> {
    let cmd = format!(
        "/blocks?from={}&limit={}",
        from,
        limit.max(1).min(BLOCKS_PAGE_LIMIT_MAX)
    );
    let bytes = request_payload(peer, MessageKind::Command, cmd.as_bytes())
        .await
        .ok_or_else(|| "no blocks response".to_string())?;
    serde_json::from_slice::<Vec<Block>>(&bytes)
        .map_err(|e| format!("invalid blocks payload: {}", e))
}

fn block_matches_header(block: &Block, header: &BlockHeader) -> bool {
    block.version == header.version
        && block.index == header.index
        && block.timestamp == header.timestamp
        && block.previous_hash == header.previous_hash
        && block.nonce == header.nonce
        && block.hash == header.hash
        && block.miner == header.miner
        && block.difficulty == header.difficulty
        && block.transactions.len() == header.tx_count
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PeerInfo {
    pub public_ip: Option<String>,
    pub port: u16,
    pub node_id: String,
    #[serde(default)]
    pub identity_pubkey: String,
    pub version: String,
    #[serde(default)]
    pub chain_id: String,
    #[serde(default)]
    pub peers: Vec<String>,
    #[serde(default)]
    pub observed_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BlockHeader {
    pub version: u8,
    pub index: u64,
    pub timestamp: i64,
    pub previous_hash: String,
    pub nonce: u64,
    pub hash: String,
    pub miner: String,
    pub difficulty: u32,
    pub tx_count: usize,
}

fn header_from_block(block: &Block) -> BlockHeader {
    BlockHeader {
        version: block.version,
        index: block.index,
        timestamp: block.timestamp,
        previous_hash: block.previous_hash.clone(),
        nonce: block.nonce,
        hash: block.hash.clone(),
        miner: block.miner.clone(),
        difficulty: block.difficulty,
        tx_count: block.transactions.len(),
    }
}

fn headers_from_chain(chain: &[Block]) -> Vec<BlockHeader> {
    chain.iter().map(header_from_block).collect()
}

fn headers_total_work(headers: &[BlockHeader]) -> u128 {
    headers.iter().fold(0u128, |acc, header| {
        let shift = (header.difficulty as u32).min(63);
        acc.saturating_add(1u128 << shift)
    })
}

fn headers_tip_hash(headers: &[BlockHeader]) -> &str {
    headers.last().map(|h| h.hash.as_str()).unwrap_or("")
}

fn headers_tip_timestamp(headers: &[BlockHeader]) -> i64 {
    headers.last().map(|h| h.timestamp).unwrap_or(i64::MAX)
}

fn prefer_headers(candidate: &[BlockHeader], current: &[BlockHeader]) -> bool {
    if candidate.is_empty() {
        return false;
    }
    let candidate_work = headers_total_work(candidate);
    let current_work = headers_total_work(current);
    if candidate_work != current_work {
        return candidate_work > current_work;
    }
    if candidate.len() != current.len() {
        return candidate.len() > current.len();
    }
    let cand_ts = headers_tip_timestamp(candidate);
    let curr_ts = headers_tip_timestamp(current);
    if cand_ts != curr_ts {
        return cand_ts < curr_ts;
    }
    let cand_tip = headers_tip_hash(candidate);
    let curr_tip = headers_tip_hash(current);
    if curr_tip.is_empty() {
        return !cand_tip.is_empty();
    }
    cand_tip < curr_tip
}

fn header_pow_valid(header: &BlockHeader) -> bool {
    let difficulty = header.difficulty;
    if difficulty == 0 || difficulty < DIFFICULTY_MIN_ZEROS || difficulty > DIFFICULTY_MAX_ZEROS {
        return false;
    }
    header.hash.starts_with(&"0".repeat(difficulty as usize))
}

fn expected_next_header_difficulty(headers: &[BlockHeader]) -> u32 {
    if headers.is_empty() {
        return DEFAULT_DIFFICULTY_ZEROS
            .max(DIFFICULTY_MIN_ZEROS)
            .min(DIFFICULTY_MAX_ZEROS);
    }

    let prev = match headers.last() {
        Some(h) => h,
        None => return DEFAULT_DIFFICULTY_ZEROS,
    };
    let next_index = prev.index.saturating_add(1);
    let mut next = prev
        .difficulty
        .max(DIFFICULTY_MIN_ZEROS)
        .min(DIFFICULTY_MAX_ZEROS);

    if DIFFICULTY_ADJUSTMENT_INTERVAL == 0 || next_index % DIFFICULTY_ADJUSTMENT_INTERVAL != 0 {
        return next;
    }

    let window = DIFFICULTY_ADJUSTMENT_INTERVAL as usize;
    if headers.len() < window {
        return next;
    }
    let start = &headers[headers.len() - window];
    let end = prev;
    let actual_span = end.timestamp.saturating_sub(start.timestamp).max(1);
    let target_span = TARGET_BLOCK_TIME_SECS
        .saturating_mul(DIFFICULTY_ADJUSTMENT_INTERVAL as i64)
        .max(1);

    if actual_span < target_span / 2 {
        next = next.saturating_add(1);
    } else if actual_span > target_span.saturating_mul(2) {
        next = next.saturating_sub(1);
    }

    next.max(DIFFICULTY_MIN_ZEROS).min(DIFFICULTY_MAX_ZEROS)
}

fn validate_headers_basic(headers: &[BlockHeader]) -> Result<(), String> {
    if headers.is_empty() {
        return Err("empty headers".to_string());
    }

    let genesis = Block::genesis();
    let first = &headers[0];
    if first.index != 0 || first.previous_hash != "0" {
        return Err("invalid genesis header position".to_string());
    }
    if first.hash != genesis.hash {
        return Err("genesis hash mismatch".to_string());
    }
    let expected_genesis_diff = DEFAULT_DIFFICULTY_ZEROS
        .max(DIFFICULTY_MIN_ZEROS)
        .min(DIFFICULTY_MAX_ZEROS);
    if first.difficulty != expected_genesis_diff {
        return Err(format!(
            "invalid genesis difficulty (expected {}, got {})",
            expected_genesis_diff, first.difficulty
        ));
    }
    if !header_pow_valid(first) {
        return Err("invalid genesis PoW".to_string());
    }

    for i in 1..headers.len() {
        let prev = &headers[i - 1];
        let curr = &headers[i];
        if curr.index != prev.index.saturating_add(1) {
            return Err(format!("non-contiguous header index at {}", curr.index));
        }
        if curr.previous_hash != prev.hash {
            return Err(format!("previous hash mismatch at {}", curr.index));
        }
        if curr.timestamp < prev.timestamp {
            return Err(format!("header timestamp regressed at {}", curr.index));
        }
        let expected_difficulty = expected_next_header_difficulty(&headers[..i]);
        if curr.difficulty != expected_difficulty {
            return Err(format!(
                "invalid difficulty at {} (expected {}, got {})",
                curr.index, expected_difficulty, curr.difficulty
            ));
        }
        if !header_pow_valid(curr) {
            return Err(format!("invalid PoW at {}", curr.index));
        }
    }

    Ok(())
}

fn common_ancestor_index(local: &[Block], remote_headers: &[BlockHeader]) -> Option<usize> {
    let upto = local.len().min(remote_headers.len());
    let mut ancestor = None;
    for i in 0..upto {
        if local[i].hash == remote_headers[i].hash {
            ancestor = Some(i);
        } else {
            break;
        }
    }
    ancestor
}

fn parse_range_query(
    request: &str,
    route: &str,
    default_limit: usize,
    max_limit: usize,
) -> Option<(usize, usize)> {
    let request = request.trim();
    if request == route {
        return Some((0, default_limit.max(1).min(max_limit.max(1))));
    }

    let prefix = format!("{}?", route);
    let query = request.strip_prefix(&prefix)?;
    let mut from = 0usize;
    let mut limit = default_limit.max(1).min(max_limit.max(1));

    for part in query.split('&') {
        let mut it = part.splitn(2, '=');
        let key = it.next().unwrap_or("").trim();
        let value = it.next().unwrap_or("").trim();
        if key.is_empty() {
            continue;
        }
        match key {
            "from" => {
                from = value.parse::<usize>().ok()?;
            }
            "limit" => {
                let parsed = value.parse::<usize>().ok()?;
                limit = parsed.max(1).min(max_limit.max(1));
            }
            _ => {}
        }
    }

    Some((from, limit))
}

async fn build_peer_info_snapshot(
    peers: &Arc<Mutex<Vec<String>>>,
    observed_ip: Option<String>,
) -> PeerInfo {
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
    peer_snapshot.truncate(PEER_GOSSIP_LIMIT.min(MAX_PEERS_FROM_GOSSIP));

    PeerInfo {
        public_ip,
        port: LISTEN_PORT,
        node_id: NODE_ID.clone(),
        identity_pubkey: NODE_PUBKEY.clone(),
        version: NODE_VERSION.to_string(),
        chain_id: CHAIN_ID.to_string(),
        peers: peer_snapshot,
        observed_ip,
    }
}

async fn send_auth_error(
    stream: &mut TcpStream,
    wire: WireMode,
    reason: &str,
) -> Result<(), NodeError> {
    let payload = AuthResponse::Error {
        reason: reason.to_string(),
    };
    let bytes =
        serde_json::to_vec(&payload).map_err(|e| NodeError::SerializationError(e.to_string()))?;
    send_message(stream, wire, MessageKind::Auth, &bytes).await
}

async fn handle_auth_message(
    payload: &[u8],
    stream: &mut TcpStream,
    wire: WireMode,
    remote_ip: &str,
    peers: Arc<Mutex<Vec<String>>>,
) -> Result<(), NodeError> {
    if wire != WireMode::Framed {
        register_infraction(
            remote_ip,
            SCORE_INVALID_FRAME,
            "auth attempted on legacy transport",
        );
        send_auth_error(stream, wire, "auth requires framed transport").await?;
        return Ok(());
    }

    if !check_rate_limit(remote_ip, RateKind::Peers) {
        send_auth_error(stream, wire, "auth rate limit exceeded").await?;
        return Ok(());
    }

    let req = match serde_json::from_slice::<AuthRequest>(payload) {
        Ok(req) => req,
        Err(_) => {
            register_infraction(remote_ip, SCORE_INVALID_FRAME, "malformed auth payload");
            send_auth_error(stream, wire, "malformed auth payload").await?;
            return Ok(());
        }
    };

    match req {
        AuthRequest::ChallengeRequest {
            client_nonce,
            timestamp,
            client_pubkey,
            client_node_id,
            signature,
        } => {
            if !auth_timestamp_is_fresh(timestamp) {
                register_infraction(remote_ip, SCORE_INVALID_FRAME, "stale auth challenge");
                send_auth_error(stream, wire, "stale challenge").await?;
                return Ok(());
            }
            let Some(expected_node_id) = node_id_from_pubkey_hex(&client_pubkey) else {
                register_infraction(remote_ip, SCORE_INVALID_FRAME, "invalid auth client pubkey");
                send_auth_error(stream, wire, "invalid client pubkey").await?;
                return Ok(());
            };
            if expected_node_id != client_node_id {
                register_infraction(remote_ip, SCORE_INVALID_FRAME, "client node_id mismatch");
                send_auth_error(stream, wire, "client node_id mismatch").await?;
                return Ok(());
            }

            let signable = challenge_request_signable(
                &client_nonce,
                timestamp,
                &client_pubkey,
                &client_node_id,
            );
            if !verify_signature(&client_pubkey, signable.as_bytes(), &signature) {
                register_infraction(
                    remote_ip,
                    SCORE_INVALID_FRAME,
                    "invalid challenge signature",
                );
                send_auth_error(stream, wire, "invalid challenge signature").await?;
                return Ok(());
            }

            let server_nonce = random_nonce_hex(AUTH_NONCE_BYTES);
            with_security_state(|state| {
                prune_stale_challenges(state);
                state.pending_auth.insert(
                    challenge_map_key(remote_ip, &client_nonce),
                    PendingAuthChallenge {
                        client_nonce: client_nonce.clone(),
                        server_nonce: server_nonce.clone(),
                        client_pubkey: client_pubkey.clone(),
                        client_node_id: client_node_id.clone(),
                        issued_at: Instant::now(),
                    },
                );
            });

            let response_ts = now_unix_secs();
            let response_sig = sign_message(
                challenge_response_signable(
                    &client_nonce,
                    &server_nonce,
                    response_ts,
                    &NODE_PUBKEY,
                    &NODE_ID,
                )
                .as_bytes(),
            );

            let response = AuthResponse::ChallengeResponse {
                client_nonce,
                server_nonce,
                timestamp: response_ts,
                server_pubkey: NODE_PUBKEY.clone(),
                server_node_id: NODE_ID.clone(),
                signature: response_sig,
            };
            let bytes = serde_json::to_vec(&response)
                .map_err(|e| NodeError::SerializationError(e.to_string()))?;
            send_message(stream, wire, MessageKind::Auth, &bytes).await?;
            Ok(())
        }
        AuthRequest::PeerInfoRequest {
            client_nonce,
            server_nonce,
            timestamp,
            client_pubkey,
            client_node_id,
            signature,
        } => {
            if !auth_timestamp_is_fresh(timestamp) {
                register_infraction(
                    remote_ip,
                    SCORE_INVALID_FRAME,
                    "stale peer-info auth request",
                );
                send_auth_error(stream, wire, "stale peer-info request").await?;
                return Ok(());
            }

            let key = challenge_map_key(remote_ip, &client_nonce);
            let pending = with_security_state(|state| {
                prune_stale_challenges(state);
                state.pending_auth.remove(&key)
            });
            let Some(pending) = pending else {
                register_infraction(remote_ip, SCORE_INVALID_FRAME, "missing auth challenge");
                send_auth_error(stream, wire, "no pending challenge").await?;
                return Ok(());
            };
            if pending.server_nonce != server_nonce
                || pending.client_pubkey != client_pubkey
                || pending.client_node_id != client_node_id
                || pending.client_nonce != client_nonce
            {
                register_infraction(remote_ip, SCORE_INVALID_FRAME, "auth challenge mismatch");
                send_auth_error(stream, wire, "challenge mismatch").await?;
                return Ok(());
            }

            let Some(expected_node_id) = node_id_from_pubkey_hex(&client_pubkey) else {
                register_infraction(
                    remote_ip,
                    SCORE_INVALID_FRAME,
                    "invalid peer-info client pubkey",
                );
                send_auth_error(stream, wire, "invalid client pubkey").await?;
                return Ok(());
            };
            if expected_node_id != client_node_id {
                register_infraction(
                    remote_ip,
                    SCORE_INVALID_FRAME,
                    "peer-info client node_id mismatch",
                );
                send_auth_error(stream, wire, "client node_id mismatch").await?;
                return Ok(());
            }

            let signable = peer_info_request_signable(
                &client_nonce,
                &server_nonce,
                timestamp,
                &client_pubkey,
                &client_node_id,
            );
            if !verify_signature(&client_pubkey, signable.as_bytes(), &signature) {
                register_infraction(
                    remote_ip,
                    SCORE_INVALID_FRAME,
                    "invalid peer-info request signature",
                );
                send_auth_error(stream, wire, "invalid peer-info signature").await?;
                return Ok(());
            }

            let peer_info = build_peer_info_snapshot(
                &peers,
                stream.peer_addr().ok().map(|addr| addr.ip().to_string()),
            )
            .await;
            let response_ts = now_unix_secs();
            let Some(response_signable) = peer_info_response_signable(
                &client_nonce,
                &server_nonce,
                response_ts,
                &NODE_PUBKEY,
                &NODE_ID,
                &peer_info,
            ) else {
                send_auth_error(stream, wire, "peer-info serialization error").await?;
                return Ok(());
            };

            let response = AuthResponse::PeerInfoResponse {
                client_nonce,
                server_nonce,
                timestamp: response_ts,
                server_pubkey: NODE_PUBKEY.clone(),
                server_node_id: NODE_ID.clone(),
                peer_info,
                signature: sign_message(response_signable.as_bytes()),
            };
            let bytes = serde_json::to_vec(&response)
                .map_err(|e| NodeError::SerializationError(e.to_string()))?;
            send_message(stream, wire, MessageKind::Auth, &bytes).await?;
            Ok(())
        }
    }
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
                        }

                        let peer_addr = format!("{}:{}", ip, addr.port());
                        if let Some(normalized) = normalize_peer_address(&peer_addr) {
                            let mut p = peers.lock().await;
                            if !p.contains(&normalized) && can_accept_peer(&normalized, &p) {
                                println!("Added new peer: {}", normalized);
                                p.push(normalized);
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
    let remote_ip = stream
        .peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    if let Some(reason) = ban_reason(&remote_ip) {
        debug_log(&format!(
            "Dropping connection from banned peer {} ({})",
            remote_ip, reason
        ));
        shutdown_stream(&mut stream).await;
        return Ok(());
    }

    let inbound = match read_wire_message(&mut stream).await {
        Ok(Some(message)) => message,
        Ok(None) => {
            shutdown_stream(&mut stream).await;
            return Ok(());
        }
        Err(e) => {
            register_infraction(
                &remote_ip,
                SCORE_INVALID_FRAME,
                &format!("failed to decode inbound message: {}", e),
            );
            shutdown_stream(&mut stream).await;
            return Err(e);
        }
    };

    let result = handle_inbound_message(inbound, &mut stream, &remote_ip, blockchain, peers).await;
    shutdown_stream(&mut stream).await;
    result
}

async fn handle_inbound_message(
    inbound: InboundMessage,
    stream: &mut TcpStream,
    remote_ip: &str,
    blockchain: Arc<Mutex<Vec<Block>>>,
    peers: Arc<Mutex<Vec<String>>>,
) -> Result<(), NodeError> {
    match inbound.kind {
        MessageKind::Command => {
            let request = String::from_utf8_lossy(&inbound.payload).to_string();
            handle_request(&request, stream, inbound.wire, remote_ip, blockchain, peers).await
        }
        MessageKind::Transaction => {
            if !check_rate_limit(remote_ip, RateKind::Tx) {
                let _ = send_message(
                    stream,
                    inbound.wire,
                    MessageKind::Error,
                    b"reject: tx rate limit exceeded",
                )
                .await;
                return Ok(());
            }
            if MAX_TXS_PER_MESSAGE < 1 {
                let _ = send_message(
                    stream,
                    inbound.wire,
                    MessageKind::Error,
                    b"reject: tx disabled",
                )
                .await;
                return Ok(());
            }
            if let Ok(batch) = serde_json::from_slice::<Vec<Transaction>>(&inbound.payload) {
                register_infraction(
                    remote_ip,
                    SCORE_INVALID_TX,
                    &format!(
                        "tx batch not allowed ({} > {})",
                        batch.len(),
                        MAX_TXS_PER_MESSAGE
                    ),
                );
                let _ = send_message(
                    stream,
                    inbound.wire,
                    MessageKind::Error,
                    b"reject: tx batch not allowed",
                )
                .await;
                return Ok(());
            }
            match serde_json::from_slice::<Transaction>(&inbound.payload) {
                Ok(tx) => handle_transaction(tx, stream, inbound.wire, remote_ip, blockchain).await,
                Err(_) => {
                    register_infraction(remote_ip, SCORE_INVALID_TX, "malformed tx payload");
                    let _ = send_message(
                        stream,
                        inbound.wire,
                        MessageKind::Error,
                        b"reject: malformed transaction",
                    )
                    .await;
                    Ok(())
                }
            }
        }
        MessageKind::Block => {
            if !check_rate_limit(remote_ip, RateKind::Block) {
                let _ = send_message(
                    stream,
                    inbound.wire,
                    MessageKind::Error,
                    b"reject: block rate limit exceeded",
                )
                .await;
                return Ok(());
            }
            if MAX_BLOCKS_PER_MESSAGE < 1 {
                let _ = send_message(
                    stream,
                    inbound.wire,
                    MessageKind::Error,
                    b"reject: block disabled",
                )
                .await;
                return Ok(());
            }
            if let Ok(batch) = serde_json::from_slice::<Vec<Block>>(&inbound.payload) {
                register_infraction(
                    remote_ip,
                    SCORE_INVALID_BLOCK,
                    &format!(
                        "block batch not allowed ({} > {})",
                        batch.len(),
                        MAX_BLOCKS_PER_MESSAGE
                    ),
                );
                let _ = send_message(
                    stream,
                    inbound.wire,
                    MessageKind::Error,
                    b"reject: block batch not allowed",
                )
                .await;
                return Ok(());
            }
            match serde_json::from_slice::<Block>(&inbound.payload) {
                Ok(block) => {
                    handle_block(block, stream, inbound.wire, remote_ip, blockchain, peers).await
                }
                Err(_) => {
                    register_infraction(remote_ip, SCORE_INVALID_BLOCK, "malformed block payload");
                    let _ = send_message(
                        stream,
                        inbound.wire,
                        MessageKind::Error,
                        b"reject: malformed block",
                    )
                    .await;
                    Ok(())
                }
            }
        }
        MessageKind::Peers => {
            if !check_rate_limit(remote_ip, RateKind::Peers) {
                let _ = send_message(
                    stream,
                    inbound.wire,
                    MessageKind::Error,
                    b"reject: peer gossip rate limit exceeded",
                )
                .await;
                return Ok(());
            }
            let payload = String::from_utf8_lossy(&inbound.payload).to_string();
            handle_peers_request(&payload, peers, remote_ip).await?;
            let _ = send_message(stream, inbound.wire, MessageKind::Response, b"ok").await;
            Ok(())
        }
        MessageKind::Auth => {
            handle_auth_message(&inbound.payload, stream, inbound.wire, remote_ip, peers).await
        }
        _ => {
            register_infraction(
                remote_ip,
                SCORE_INVALID_FRAME,
                "unsupported inbound message type",
            );
            let _ = send_message(
                stream,
                inbound.wire,
                MessageKind::Error,
                b"unsupported message",
            )
            .await;
            Ok(())
        }
    }
}

async fn handle_request(
    request: &str,
    stream: &mut TcpStream,
    wire: WireMode,
    remote_ip: &str,
    blockchain: Arc<Mutex<Vec<Block>>>,
    peers: Arc<Mutex<Vec<String>>>,
) -> Result<(), NodeError> {
    let request = if request.starts_with("GET ") {
        request.split_whitespace().nth(1).unwrap_or("").to_string()
    } else {
        request.to_string()
    };
    if request.trim() == "/ping" {
        send_message(stream, wire, MessageKind::Response, b"pong").await?;
    } else if let Some(addr) = request.strip_prefix("/balance/") {
        let addr = addr.trim();
        let chain = blockchain.lock().await;
        let balance = calculate_balance(addr, &chain);
        send_message(
            stream,
            wire,
            MessageKind::Response,
            balance.to_string().as_bytes(),
        )
        .await?;
    } else if let Some(addr) = request.strip_prefix("/nonce/") {
        let addr = addr.trim();
        let chain = blockchain.lock().await;
        let nonce = next_nonce_for_address(addr, &chain);
        send_message(
            stream,
            wire,
            MessageKind::Response,
            nonce.to_string().as_bytes(),
        )
        .await?;
    } else if request.trim() == "/peers" {
        let mut peer_snapshot = peers.lock().await.clone();
        peer_snapshot.retain(|peer| normalize_peer_address(peer).is_some());
        peer_snapshot.sort();
        peer_snapshot.dedup();
        {
            let mut rng = rand::rng();
            peer_snapshot.shuffle(&mut rng);
        }
        peer_snapshot.truncate(PEER_GOSSIP_LIMIT.min(MAX_PEERS_FROM_GOSSIP));
        let peers_json = serde_json::to_vec(&peer_snapshot)
            .map_err(|e| NodeError::SerializationError(e.to_string()))?;
        send_message(stream, wire, MessageKind::Peers, &peers_json).await?;
    } else if let Some((from, limit)) = parse_range_query(
        request.trim(),
        "/headers",
        HEADERS_PAGE_LIMIT,
        HEADERS_PAGE_LIMIT_MAX,
    ) {
        if !check_rate_limit(remote_ip, RateKind::Block) {
            send_message(
                stream,
                wire,
                MessageKind::Error,
                b"reject: headers rate limit exceeded",
            )
            .await?;
            return Ok(());
        }
        let chain = blockchain.lock().await;
        let headers: Vec<BlockHeader> = if from >= chain.len() {
            Vec::new()
        } else {
            let end = from.saturating_add(limit).min(chain.len());
            chain[from..end].iter().map(header_from_block).collect()
        };
        let json = serde_json::to_vec(&headers)
            .map_err(|e| NodeError::SerializationError(e.to_string()))?;
        if json.len() > MAX_MESSAGE_SIZE {
            send_message(
                stream,
                wire,
                MessageKind::Error,
                b"headers response too large",
            )
            .await?;
            return Ok(());
        }
        send_message(stream, wire, MessageKind::Response, &json).await?;
    } else if let Some((from, limit)) = parse_range_query(
        request.trim(),
        "/blocks",
        BLOCKS_PAGE_LIMIT,
        BLOCKS_PAGE_LIMIT_MAX,
    ) {
        if !check_rate_limit(remote_ip, RateKind::Block) {
            send_message(
                stream,
                wire,
                MessageKind::Error,
                b"reject: block range rate limit exceeded",
            )
            .await?;
            return Ok(());
        }
        let chain = blockchain.lock().await;
        let mut blocks: Vec<Block> = if from >= chain.len() {
            Vec::new()
        } else {
            let end = from.saturating_add(limit).min(chain.len());
            chain[from..end].to_vec()
        };
        let payload = loop {
            let json = serde_json::to_vec(&blocks)
                .map_err(|e| NodeError::SerializationError(e.to_string()))?;
            if json.len() <= MAX_MESSAGE_SIZE || blocks.is_empty() {
                break json;
            }
            blocks.pop();
        };
        send_message(stream, wire, MessageKind::Response, &payload).await?;
    } else if request.trim() == "/chain" {
        let chain = blockchain.lock().await;
        let json = serde_json::to_vec(&*chain)
            .map_err(|e| NodeError::SerializationError(e.to_string()))?;
        if json.len() > MAX_MESSAGE_SIZE {
            let msg = format!(
                "chain response too large ({} bytes > {} bytes)",
                json.len(),
                MAX_MESSAGE_SIZE
            );
            send_message(stream, wire, MessageKind::Error, msg.as_bytes()).await?;
            return Ok(());
        }
        send_message(stream, wire, MessageKind::Response, &json).await?;
    } else if request.trim() == "/chain-hash" {
        let chain = blockchain.lock().await;
        let json = serde_json::to_vec(&*chain)
            .map_err(|e| NodeError::SerializationError(e.to_string()))?;
        let hash = Sha256::digest(json.as_slice());
        send_message(
            stream,
            wire,
            MessageKind::Response,
            hex::encode(hash).as_bytes(),
        )
        .await?;
    } else if request.trim() == "/whoami" || request.trim() == "/peer-info" {
        respond_with_peer_info(stream, wire, &peers).await?;
    } else if let Some(id) = request.strip_prefix("/resolve-ip/") {
        handle_resolve_ip_request(id.trim(), stream, wire).await?;
    } else if let Some(new_peer) = request.strip_prefix("/iam/") {
        if !check_rate_limit(remote_ip, RateKind::Peers) {
            send_message(
                stream,
                wire,
                MessageKind::Error,
                b"reject: peer gossip rate limit exceeded",
            )
            .await?;
            return Ok(());
        }
        handle_iam_request(new_peer.trim(), peers, remote_ip).await?;
        send_message(stream, wire, MessageKind::Response, b"ok").await?;
    } else if let Some(rest) = request.strip_prefix("/peers") {
        if !check_rate_limit(remote_ip, RateKind::Peers) {
            send_message(
                stream,
                wire,
                MessageKind::Error,
                b"reject: peer gossip rate limit exceeded",
            )
            .await?;
            return Ok(());
        }
        handle_peers_request(rest, peers, remote_ip).await?;
        send_message(stream, wire, MessageKind::Response, b"ok").await?;
    } else if let Ok(batch) = serde_json::from_slice::<Vec<Transaction>>(request.as_bytes()) {
        register_infraction(
            remote_ip,
            SCORE_INVALID_TX,
            &format!(
                "tx batch not allowed ({} > {})",
                batch.len(),
                MAX_TXS_PER_MESSAGE
            ),
        );
        send_message(
            stream,
            wire,
            MessageKind::Error,
            b"reject: tx batch not allowed",
        )
        .await?;
    } else if let Ok(tx) = serde_json::from_slice::<Transaction>(request.as_bytes()) {
        if !check_rate_limit(remote_ip, RateKind::Tx) {
            send_message(
                stream,
                wire,
                MessageKind::Error,
                b"reject: tx rate limit exceeded",
            )
            .await?;
            return Ok(());
        }
        handle_transaction(tx, stream, wire, remote_ip, blockchain).await?;
    } else if let Ok(batch) = serde_json::from_slice::<Vec<Block>>(request.as_bytes()) {
        register_infraction(
            remote_ip,
            SCORE_INVALID_BLOCK,
            &format!(
                "block batch not allowed ({} > {})",
                batch.len(),
                MAX_BLOCKS_PER_MESSAGE
            ),
        );
        send_message(
            stream,
            wire,
            MessageKind::Error,
            b"reject: block batch not allowed",
        )
        .await?;
    } else if let Ok(block) = serde_json::from_slice::<Block>(request.as_bytes()) {
        if !check_rate_limit(remote_ip, RateKind::Block) {
            send_message(
                stream,
                wire,
                MessageKind::Error,
                b"reject: block rate limit exceeded",
            )
            .await?;
            return Ok(());
        }
        handle_block(block, stream, wire, remote_ip, blockchain, peers).await?;
    } else {
        register_infraction(remote_ip, SCORE_INVALID_FRAME, "unknown request");
        send_message(stream, wire, MessageKind::Error, b"unknown request").await?;
    }

    Ok(())
}

async fn respond_with_peer_info(
    stream: &mut TcpStream,
    wire: WireMode,
    peers: &Arc<Mutex<Vec<String>>>,
) -> Result<(), NodeError> {
    let info = build_peer_info_snapshot(
        peers,
        stream.peer_addr().ok().map(|addr| addr.ip().to_string()),
    )
    .await;

    let payload =
        serde_json::to_vec(&info).map_err(|e| NodeError::SerializationError(e.to_string()))?;
    send_message(stream, wire, MessageKind::PeerInfo, &payload).await
}

async fn handle_resolve_ip_request(
    id: &str,
    stream: &mut TcpStream,
    wire: WireMode,
) -> Result<(), NodeError> {
    // Use the remote socket address as the caller's observed public IP.
    match stream.peer_addr() {
        Ok(addr) => {
            let ip = addr.ip().to_string();
            debug_log(&format!(
                "/resolve-ip for id '{}' resolved caller IP as {}",
                id, ip
            ));
            send_message(stream, wire, MessageKind::Response, ip.as_bytes()).await?;
        }
        Err(e) => {
            debug_log(&format!(
                "Failed to get peer addr for /resolve-ip (id='{}'): {}",
                id, e
            ));
            send_message(stream, wire, MessageKind::Response, b"unknown").await?;
        }
    }
    Ok(())
}

async fn handle_iam_request(
    new_peer: &str,
    peers: Arc<Mutex<Vec<String>>>,
    remote_ip: &str,
) -> Result<(), NodeError> {
    let Some(normalized) = normalize_peer_address(new_peer) else {
        register_infraction(remote_ip, SCORE_DISCOVERY_VIOLATION, "invalid /iam address");
        return Ok(());
    };

    let announced_ip = peer_ip(&normalized).map(|ip| ip.to_string());
    if announced_ip.as_deref() != Some(remote_ip) {
        register_infraction(
            remote_ip,
            SCORE_DISCOVERY_VIOLATION,
            "peer poisoning attempt via /iam (ip mismatch)",
        );
        return Ok(());
    }

    let my_addr = get_my_address().await;
    if Some(normalized.as_str()) == my_addr.as_deref() {
        debug_log(&format!("Ignoring /iam/ request from self: {}", normalized));
        return Ok(());
    }

    let mut p = peers.lock().await;
    if !p.contains(&normalized) {
        if !can_accept_peer(&normalized, &p) {
            register_infraction(
                remote_ip,
                SCORE_DISCOVERY_VIOLATION,
                "subnet cap reached for /iam",
            );
            return Ok(());
        }
        println!("Added peer via /iam/: {}", normalized);
        p.push(normalized);
        save_peers(&p)?;
    }
    Ok(())
}

async fn handle_peers_request(
    rest: &str,
    peers: Arc<Mutex<Vec<String>>>,
    remote_ip: &str,
) -> Result<(), NodeError> {
    let payload = rest.trim();
    if payload.is_empty() {
        return Ok(());
    }

    let list = match serde_json::from_str::<Vec<String>>(payload) {
        Ok(list) => list,
        Err(_) => {
            register_infraction(
                remote_ip,
                SCORE_DISCOVERY_VIOLATION,
                "malformed /peers gossip",
            );
            return Ok(());
        }
    };

    if list.len() > MAX_PEERS_FROM_GOSSIP {
        register_infraction(
            remote_ip,
            SCORE_DISCOVERY_VIOLATION,
            "oversized /peers gossip payload",
        );
    }

    let my_addr = get_my_address().await;
    let mut p = peers.lock().await;
    let mut added_count = 0usize;
    let mut seen = HashSet::new();

    for peer in list.into_iter().take(MAX_PEERS_FROM_GOSSIP) {
        let Some(normalized) = normalize_peer_address(&peer) else {
            continue;
        };
        if Some(normalized.as_str()) == my_addr.as_deref() {
            continue;
        }
        if !seen.insert(normalized.clone()) || p.contains(&normalized) {
            continue;
        }
        if !can_accept_peer(&normalized, &p) {
            continue;
        }
        println!("Added peer from /peers: {}", normalized);
        p.push(normalized);
        added_count += 1;
        if added_count >= MAX_NEW_PEERS_PER_GOSSIP {
            break;
        }
    }

    if added_count > 0 {
        save_peers(&p)?;
        debug_log(&format!(
            "Added {} new peers from /peers request",
            added_count
        ));
    }
    Ok(())
}

async fn handle_transaction(
    tx: Transaction,
    stream: &mut TcpStream,
    wire: WireMode,
    remote_ip: &str,
    blockchain: Arc<Mutex<Vec<Block>>>,
) -> Result<(), NodeError> {
    let chain = blockchain.lock().await;
    match is_tx_valid(&tx, &chain) {
        Ok(()) => {
            drop(chain);
            match insert_transaction(tx) {
                Ok(()) => {
                    println!("TX added to mempool");
                    send_message(stream, wire, MessageKind::Response, b"ok").await?;
                }
                Err(e) => {
                    eprintln!("Failed to persist mempool transaction: {}", e);
                    send_message(
                        stream,
                        wire,
                        MessageKind::Error,
                        b"reject: mempool storage error",
                    )
                    .await?;
                }
            }
        }
        Err(e) => {
            let reason = e.to_string();
            println!("TX rejected: {}", reason);
            register_infraction(remote_ip, SCORE_INVALID_TX, &reason);
            let msg = format!("reject: {}", reason);
            send_message(stream, wire, MessageKind::Error, msg.as_bytes()).await?;
        }
    }
    Ok(())
}

async fn handle_block(
    block: Block,
    stream: &mut TcpStream,
    wire: WireMode,
    remote_ip: &str,
    blockchain: Arc<Mutex<Vec<Block>>>,
    peers: Arc<Mutex<Vec<String>>>,
) -> Result<(), NodeError> {
    if block.transactions.len() > MAX_TXS_PER_BLOCK_MESSAGE {
        register_infraction(
            remote_ip,
            SCORE_INVALID_BLOCK,
            "block exceeded max tx count per message",
        );
        send_message(
            stream,
            wire,
            MessageKind::Error,
            b"invalid block: too many txs",
        )
        .await?;
        return Ok(());
    }

    let mut chain = blockchain.lock().await;
    let expected_index = chain.len() as u64;
    if block.index != expected_index {
        println!(
            "Received block with invalid index (got {}, expected {})",
            block.index, expected_index
        );
        send_message(stream, wire, MessageKind::Error, b"invalid index").await?;
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
        register_infraction(remote_ip, SCORE_INVALID_BLOCK, &e.to_string());
        send_message(stream, wire, MessageKind::Error, b"invalid block").await?;
        drop(chain);
        let bc = blockchain.clone();
        let peers_for_sync = peers.clone();
        tokio::spawn(async move {
            sync_chain(&bc, &peers_for_sync, false, false).await;
        });
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
    send_message(stream, wire, MessageKind::Response, b"accepted").await?;
    Ok(())
}

pub async fn maintenance_loop(blockchain: Arc<Mutex<Vec<Block>>>, peers: Arc<Mutex<Vec<String>>>) {
    loop {
        sleep(Duration::from_secs(60)).await;
        sync_chain(&blockchain, &peers, false, false).await;

        let peer_list = peers.lock().await.clone();
        let my_addr = get_my_address().await;
        let mut added = 0usize;
        for peer in sticky_peer_targets(&peer_list).into_iter() {
            if Some(peer.as_str()) == my_addr.as_deref() {
                continue;
            }
            let Some(info) = handshake_with_peer(&peer, &peers).await else {
                continue;
            };
            let mut p = peers.lock().await;
            let mut seen = HashSet::new();
            for entry in info.peers.into_iter().take(MAX_PEERS_FROM_GOSSIP) {
                let Some(normalized) = normalize_peer_address(&entry) else {
                    continue;
                };
                if Some(normalized.as_str()) == my_addr.as_deref() {
                    continue;
                }
                if !seen.insert(normalized.clone()) || p.contains(&normalized) {
                    continue;
                }
                if !can_accept_peer(&normalized, &p) {
                    continue;
                }
                p.push(normalized);
                added += 1;
                if added >= MAX_NEW_PEERS_PER_GOSSIP {
                    break;
                }
            }
            if added > 0 {
                let _ = save_peers(&p);
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
            if is_anchor_peer(peer) {
                alive.push(peer.clone());
                continue;
            }
            if ping_peer(peer).await {
                alive.push(peer.clone());
            }
        }
        for &anchor in BOOTSTRAP_NODES {
            if let Some(normalized) = normalize_peer_address(anchor) {
                if !alive.contains(&normalized) {
                    alive.push(normalized);
                }
            }
        }
        alive.sort();
        alive.dedup();
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
            if let Some(normalized) = normalize_peer_address(bootstrap_node) {
                if !p.contains(&normalized) {
                    p.push(normalized.clone());
                    bootstrap_peers.push(normalized.clone());
                    println!("[STARTUP] Added bootstrap node to peers: {}", normalized);
                }
            } else if !p.contains(&bootstrap_node.to_string()) {
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
        match handshake_with_peer(bootstrap_node, peers).await {
            Some(info) => {
                println!(
                    "[STARTUP] Authenticated bootstrap node {} ({} peers announced)",
                    bootstrap_node,
                    info.peers.len()
                );
                for peer in info.peers.into_iter().take(MAX_PEERS_FROM_GOSSIP) {
                    let Some(normalized) = normalize_peer_address(&peer) else {
                        continue;
                    };
                    if !bootstrap_peers.contains(&normalized) {
                        bootstrap_peers.push(normalized.clone());
                        println!("[STARTUP] Added peer from bootstrap: {}", normalized);
                    }
                }
            }
            None => println!(
                "[STARTUP] Failed to authenticate bootstrap node: {}",
                bootstrap_node
            ),
        }
    }

    {
        let mut p = peers.lock().await;
        for peer in &bootstrap_peers {
            if !p.contains(peer) && can_accept_peer(peer, &p) {
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
    let mut gossip_snapshot: Vec<String> = peer_list
        .iter()
        .filter_map(|peer| normalize_peer_address(peer))
        .collect();
    gossip_snapshot.sort();
    gossip_snapshot.dedup();
    gossip_snapshot.truncate(MAX_PEERS_FROM_GOSSIP);

    let peers_json = match serde_json::to_vec(&gossip_snapshot) {
        Ok(json) => json,
        Err(e) => {
            println!("[STARTUP] Failed to serialize peers for broadcast: {}", e);
            return;
        }
    };

    println!("[STARTUP] Broadcasting to {} peers...", peer_list.len());
    let mut successful_broadcasts = 0;
    let total_targets = peer_list
        .iter()
        .filter(|peer| peer.as_str() != my_address)
        .count();

    for peer in &peer_list {
        if peer == my_address {
            continue;
        }

        println!("[STARTUP] Broadcasting peers to: {}", peer);
        if send_only(peer, MessageKind::Peers, &peers_json).await {
            println!("[STARTUP] Successfully broadcast peers to: {}", peer);
            successful_broadcasts += 1;
        } else {
            println!("[STARTUP] Failed to send peers to: {}", peer);
        }
    }

    println!(
        "[STARTUP] Broadcast completed: {}/{} successful",
        successful_broadcasts, total_targets
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

    let payload = match serde_json::to_vec(block) {
        Ok(payload) => payload,
        Err(_) => {
            debug_log("Failed to serialize block");
            return;
        }
    };
    if payload.len() > MAX_MESSAGE_SIZE {
        debug_log("Skipping block broadcast: block payload exceeds max message size");
        return;
    }

    for peer in peers {
        if peer == my_addr {
            continue;
        }

        debug_log(&format!("Attempting to send block to peer: {}", peer));
        if let Some(bytes) = request_payload(&peer, MessageKind::Block, &payload).await {
            let resp = String::from_utf8_lossy(&bytes);
            debug_log(&format!("Response from peer {}: {}", peer, resp.trim()));
            debug_log(&format!("Block sent to peer: {}", peer));
        } else {
            debug_log(&format!(
                "Failed to connect or send block to peer: {}",
                peer
            ));
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
    let client_nonce = random_nonce_hex(AUTH_NONCE_BYTES);
    let challenge_ts = now_unix_secs();
    let challenge_req = AuthRequest::ChallengeRequest {
        client_nonce: client_nonce.clone(),
        timestamp: challenge_ts,
        client_pubkey: NODE_PUBKEY.clone(),
        client_node_id: NODE_ID.clone(),
        signature: sign_message(
            challenge_request_signable(&client_nonce, challenge_ts, &NODE_PUBKEY, &NODE_ID)
                .as_bytes(),
        ),
    };
    let challenge_payload = serde_json::to_vec(&challenge_req).ok()?;
    let challenge_msg = request_framed_message(peer, MessageKind::Auth, &challenge_payload).await?;
    if challenge_msg.kind != MessageKind::Auth {
        debug_log(&format!(
            "{} returned non-auth message in challenge phase",
            peer
        ));
        return None;
    }
    let challenge_resp = serde_json::from_slice::<AuthResponse>(&challenge_msg.payload).ok()?;
    let (server_nonce, server_pubkey, server_node_id, server_ts, server_sig) = match challenge_resp
    {
        AuthResponse::ChallengeResponse {
            client_nonce: echoed_client_nonce,
            server_nonce,
            timestamp,
            server_pubkey,
            server_node_id,
            signature,
        } => {
            if echoed_client_nonce != client_nonce {
                debug_log(&format!(
                    "{} returned wrong client nonce in challenge response",
                    peer
                ));
                return None;
            }
            (
                server_nonce,
                server_pubkey,
                server_node_id,
                timestamp,
                signature,
            )
        }
        AuthResponse::Error { reason } => {
            debug_log(&format!(
                "{} rejected challenge handshake: {}",
                peer, reason
            ));
            return None;
        }
        _ => {
            debug_log(&format!("{} returned unexpected auth response type", peer));
            return None;
        }
    };
    if !auth_timestamp_is_fresh(server_ts) {
        debug_log(&format!("{} challenge response had stale timestamp", peer));
        return None;
    }
    if node_id_from_pubkey_hex(&server_pubkey).as_deref() != Some(server_node_id.as_str()) {
        debug_log(&format!(
            "{} challenge response had node_id/pubkey mismatch",
            peer
        ));
        return None;
    }
    let challenge_signable = challenge_response_signable(
        &client_nonce,
        &server_nonce,
        server_ts,
        &server_pubkey,
        &server_node_id,
    );
    if !verify_signature(&server_pubkey, challenge_signable.as_bytes(), &server_sig) {
        debug_log(&format!("{} challenge signature verification failed", peer));
        return None;
    }

    let peer_info_ts = now_unix_secs();
    let peer_info_req = AuthRequest::PeerInfoRequest {
        client_nonce: client_nonce.clone(),
        server_nonce: server_nonce.clone(),
        timestamp: peer_info_ts,
        client_pubkey: NODE_PUBKEY.clone(),
        client_node_id: NODE_ID.clone(),
        signature: sign_message(
            peer_info_request_signable(
                &client_nonce,
                &server_nonce,
                peer_info_ts,
                &NODE_PUBKEY,
                &NODE_ID,
            )
            .as_bytes(),
        ),
    };
    let peer_info_payload = serde_json::to_vec(&peer_info_req).ok()?;
    let peer_info_msg = request_framed_message(peer, MessageKind::Auth, &peer_info_payload).await?;
    if peer_info_msg.kind != MessageKind::Auth {
        debug_log(&format!(
            "{} returned non-auth message in peer-info phase",
            peer
        ));
        return None;
    }
    let peer_info_resp = serde_json::from_slice::<AuthResponse>(&peer_info_msg.payload).ok()?;
    let (returned_pubkey, returned_node_id, returned_ts, returned_sig, peer_info) =
        match peer_info_resp {
            AuthResponse::PeerInfoResponse {
                client_nonce: echoed_client_nonce,
                server_nonce: echoed_server_nonce,
                timestamp,
                server_pubkey,
                server_node_id,
                peer_info,
                signature,
            } => {
                if echoed_client_nonce != client_nonce || echoed_server_nonce != server_nonce {
                    debug_log(&format!(
                        "{} returned nonce mismatch in peer-info response",
                        peer
                    ));
                    return None;
                }
                (
                    server_pubkey,
                    server_node_id,
                    timestamp,
                    signature,
                    peer_info,
                )
            }
            AuthResponse::Error { reason } => {
                debug_log(&format!(
                    "{} rejected peer-info handshake: {}",
                    peer, reason
                ));
                return None;
            }
            _ => {
                debug_log(&format!(
                    "{} returned unexpected auth response in peer-info phase",
                    peer
                ));
                return None;
            }
        };
    if returned_pubkey != server_pubkey || returned_node_id != server_node_id {
        debug_log(&format!(
            "{} changed identity across handshake phases",
            peer
        ));
        return None;
    }
    if !auth_timestamp_is_fresh(returned_ts) {
        debug_log(&format!("{} peer-info response had stale timestamp", peer));
        return None;
    }
    if node_id_from_pubkey_hex(&returned_pubkey).as_deref() != Some(returned_node_id.as_str()) {
        debug_log(&format!(
            "{} peer-info response had node_id/pubkey mismatch",
            peer
        ));
        return None;
    }
    let Some(peer_info_signable) = peer_info_response_signable(
        &client_nonce,
        &server_nonce,
        returned_ts,
        &returned_pubkey,
        &returned_node_id,
        &peer_info,
    ) else {
        debug_log(&format!(
            "{} peer-info response signable build failed",
            peer
        ));
        return None;
    };
    if !verify_signature(
        &returned_pubkey,
        peer_info_signable.as_bytes(),
        &returned_sig,
    ) {
        debug_log(&format!("{} peer-info signature verification failed", peer));
        return None;
    }
    if peer_info.node_id != returned_node_id || peer_info.identity_pubkey != returned_pubkey {
        debug_log(&format!("{} peer-info identity mismatch", peer));
        return None;
    }
    if !pin_peer_key(peer, &returned_pubkey) {
        if let Some(ip) = peer_ip(peer).map(|ip| ip.to_string()) {
            register_infraction(&ip, SCORE_INVALID_FRAME, "pinned peer key mismatch");
        }
        debug_log(&format!("{} failed pinned key check", peer));
        return None;
    }

    Some(peer_info)
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

fn chain_tip_timestamp(chain: &[Block]) -> i64 {
    chain.last().map(|b| b.timestamp).unwrap_or(i64::MAX)
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
    let cand_ts = chain_tip_timestamp(candidate);
    let curr_ts = chain_tip_timestamp(current);
    if cand_ts != curr_ts {
        return cand_ts < curr_ts;
    }
    let cand_tip = chain_tip_hash(candidate);
    let curr_tip = chain_tip_hash(current);
    if curr_tip.is_empty() {
        return !cand_tip.is_empty();
    }
    // Deterministic equal-work tie-break after timestamp: lower tip hash wins.
    cand_tip < curr_tip
}

async fn integrate_peer_info_from_handshake(
    original_addr: &str,
    info: &PeerInfo,
    peers: &Arc<Mutex<Vec<String>>>,
) {
    if info.node_id.is_empty() || info.identity_pubkey.is_empty() {
        debug_log(&format!(
            "Ignoring peer {} without authenticated identity fields",
            original_addr
        ));
        return;
    }
    if node_id_from_pubkey_hex(&info.identity_pubkey).as_deref() != Some(info.node_id.as_str()) {
        debug_log(&format!(
            "Ignoring peer {} with invalid node_id/pubkey mapping",
            original_addr
        ));
        return;
    }
    if !info.chain_id.is_empty() && info.chain_id != CHAIN_ID {
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
    let Some(peer_addr) = normalize_peer_address(&peer_addr) else {
        return;
    };
    if !pin_peer_key(&peer_addr, &info.identity_pubkey) {
        if let Some(ip) = peer_ip(&peer_addr).map(|ip| ip.to_string()) {
            register_infraction(&ip, SCORE_INVALID_FRAME, "pinned key mismatch in handshake");
        }
        debug_log(&format!(
            "Ignoring peer {} due to pinned key mismatch",
            peer_addr
        ));
        return;
    }
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
    let mut changed = false;
    if !peers_guard.contains(&peer_addr) && can_accept_peer(&peer_addr, &peers_guard) {
        debug_log(&format!(
            "Added peer {} via handshake (node_id={})",
            peer_addr, info.node_id
        ));
        peers_guard.push(peer_addr.clone());
        changed = true;
    }

    let mut added_from_gossip = 0usize;
    let mut seen = HashSet::new();
    for candidate in info.peers.iter().take(MAX_PEERS_FROM_GOSSIP) {
        let Some(normalized) = normalize_peer_address(candidate) else {
            continue;
        };
        if Some(normalized.as_str()) == self_addr.as_deref() {
            continue;
        }
        if !seen.insert(normalized.clone()) || peers_guard.contains(&normalized) {
            continue;
        }
        if !can_accept_peer(&normalized, &peers_guard) {
            continue;
        }
        peers_guard.push(normalized);
        added_from_gossip += 1;
        changed = true;
        if added_from_gossip >= MAX_NEW_PEERS_PER_GOSSIP {
            break;
        }
    }

    if changed {
        if let Err(e) = save_peers(&peers_guard) {
            eprintln!(
                "Failed to save peers after handshake with {}: {}",
                peer_addr, e
            );
        }
    }

    mark_good_peer(&peer_addr);
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
    let local_headers = headers_from_chain(&local_snapshot);

    let raw_peers = peers.lock().await.clone();
    let mut peer_list = sticky_peer_targets(&raw_peers);
    for peer in raw_peers {
        if !peer_list.contains(&peer) {
            peer_list.push(peer);
        }
    }
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
    let mut best_peer_headers: Option<Vec<BlockHeader>> = None;
    let mut best_peer_addr: Option<String> = None;
    let mut consecutive_failures = 0usize;

    for peer in peer_list {
        let mut peer_failed = false;
        if Some(peer.as_str()) == my_addr.as_deref() {
            continue;
        }
        log(&format!("[SYNC] Connecting to {}", peer));
        let Some(info) = handshake_with_peer(&peer, peers).await else {
            log(&format!(
                "[SYNC] Handshake failed with {} (trying next peer)",
                peer
            ));
            let shift = (consecutive_failures.min(4)) as u32;
            let delay_ms = SYNC_BACKOFF_BASE_MS
                .saturating_mul(1u64 << shift)
                .min(SYNC_BACKOFF_MAX_MS);
            sleep(Duration::from_millis(delay_ms)).await;
            consecutive_failures = consecutive_failures.saturating_add(1);
            continue;
        };
        if !info.chain_id.is_empty() && info.chain_id != CHAIN_ID {
            log(&format!(
                "[SYNC] Skipping {} due to chain id mismatch ({})",
                peer, info.chain_id
            ));
            continue;
        }

        log("[SYNC] Downloading headers");
        let mut remote_headers: Vec<BlockHeader> = Vec::new();
        let mut headers_from = 0usize;
        loop {
            let page = match fetch_headers_page(&peer, headers_from, HEADERS_PAGE_LIMIT).await {
                Ok(page) => page,
                Err(e) => {
                    log(&format!(
                        "[SYNC] Failed to fetch headers from {}: {}",
                        peer, e
                    ));
                    peer_failed = true;
                    break;
                }
            };
            if page.is_empty() {
                break;
            }
            let expected_start = match u64::try_from(headers_from) {
                Ok(v) => v,
                Err(_) => {
                    log("[SYNC] Header index conversion overflow");
                    peer_failed = true;
                    break;
                }
            };
            if page.first().map(|h| h.index) != Some(expected_start) {
                log(&format!(
                    "[SYNC] Header paging mismatch from {} (expected start {}, got {:?})",
                    peer,
                    expected_start,
                    page.first().map(|h| h.index)
                ));
                peer_failed = true;
                break;
            }
            headers_from = headers_from.saturating_add(page.len());
            remote_headers.extend(page);
            if remote_headers.len() > MAX_HEADERS_PER_SYNC {
                log(&format!(
                    "[SYNC] Rejecting {}: too many headers (>{})",
                    peer, MAX_HEADERS_PER_SYNC
                ));
                peer_failed = true;
                break;
            }
            if headers_from >= MAX_HEADERS_PER_SYNC {
                break;
            }
            if remote_headers.len() % HEADERS_PAGE_LIMIT != 0 {
                break;
            }
        }
        if peer_failed {
            let shift = (consecutive_failures.min(4)) as u32;
            let delay_ms = SYNC_BACKOFF_BASE_MS
                .saturating_mul(1u64 << shift)
                .min(SYNC_BACKOFF_MAX_MS);
            sleep(Duration::from_millis(delay_ms)).await;
            consecutive_failures = consecutive_failures.saturating_add(1);
            continue;
        }
        if remote_headers.is_empty() {
            log(&format!("[SYNC] Peer {} returned no headers", peer));
            continue;
        }
        if let Err(reason) = validate_headers_basic(&remote_headers) {
            log(&format!(
                "[SYNC] Rejecting invalid headers from {}: {}",
                peer, reason
            ));
            peer_failed = true;
        }
        if peer_failed {
            let shift = (consecutive_failures.min(4)) as u32;
            let delay_ms = SYNC_BACKOFF_BASE_MS
                .saturating_mul(1u64 << shift)
                .min(SYNC_BACKOFF_MAX_MS);
            sleep(Duration::from_millis(delay_ms)).await;
            consecutive_failures = consecutive_failures.saturating_add(1);
            continue;
        }

        let better_by_headers = if force || !local_valid {
            match &best_peer_headers {
                Some(current_best_headers) => prefer_headers(&remote_headers, current_best_headers),
                None => true,
            }
        } else {
            let baseline = best_peer_headers
                .as_deref()
                .unwrap_or(local_headers.as_slice());
            prefer_headers(&remote_headers, baseline)
        };
        if !better_by_headers {
            log(&format!(
                "[SYNC] Skipping {}: headers do not beat current best",
                peer
            ));
            continue;
        }

        let Some(common_ancestor) = common_ancestor_index(&local_snapshot, &remote_headers) else {
            log(&format!(
                "[SYNC] Rejecting {}: no shared ancestor with local chain",
                peer
            ));
            let shift = (consecutive_failures.min(4)) as u32;
            let delay_ms = SYNC_BACKOFF_BASE_MS
                .saturating_mul(1u64 << shift)
                .min(SYNC_BACKOFF_MAX_MS);
            sleep(Duration::from_millis(delay_ms)).await;
            consecutive_failures = consecutive_failures.saturating_add(1);
            continue;
        };
        let reorg_depth = local_snapshot
            .len()
            .saturating_sub(common_ancestor.saturating_add(1));
        if !force && local_valid && reorg_depth > MAX_NETWORK_REORG_DEPTH {
            log(&format!(
                "[SYNC] Rejecting {}: reorg depth {} exceeds max {}",
                peer, reorg_depth, MAX_NETWORK_REORG_DEPTH
            ));
            continue;
        }

        let fetch_from = if force || !local_valid {
            0usize
        } else {
            common_ancestor.saturating_add(1)
        };
        let target_len = remote_headers.len();
        if fetch_from > target_len {
            continue;
        }

        let mut candidate_chain: Vec<Block> = if fetch_from == 0 {
            Vec::new()
        } else {
            local_snapshot[..fetch_from].to_vec()
        };
        let mut next_index = fetch_from;

        while next_index < target_len {
            let remaining = target_len.saturating_sub(next_index);
            let limit = remaining.min(BLOCKS_PAGE_LIMIT);
            let mut page = match fetch_blocks_page(&peer, next_index, limit).await {
                Ok(page) => page,
                Err(e) => {
                    log(&format!(
                        "[SYNC] Failed to fetch blocks from {} at {}: {}",
                        peer, next_index, e
                    ));
                    peer_failed = true;
                    break;
                }
            };
            if page.is_empty() {
                log(&format!(
                    "[SYNC] Peer {} returned empty block page at {}",
                    peer, next_index
                ));
                peer_failed = true;
                break;
            }
            if page.len() > limit {
                page.truncate(limit);
            }

            for block in page {
                if next_index >= target_len {
                    break;
                }
                let header = &remote_headers[next_index];
                if !block_matches_header(&block, header) {
                    log(&format!(
                        "[SYNC] Block/header mismatch from {} at height {}",
                        peer, next_index
                    ));
                    peer_failed = true;
                    break;
                }
                let prev = candidate_chain.last();
                if let Err(e) = validate_block(&block, prev, &candidate_chain) {
                    log(&format!(
                        "[SYNC] Invalid block from {} at height {}: {}",
                        peer, next_index, e
                    ));
                    peer_failed = true;
                    break;
                }
                candidate_chain.push(block);
                next_index = next_index.saturating_add(1);
            }

            if peer_failed {
                break;
            }
        }
        if peer_failed {
            let shift = (consecutive_failures.min(4)) as u32;
            let delay_ms = SYNC_BACKOFF_BASE_MS
                .saturating_mul(1u64 << shift)
                .min(SYNC_BACKOFF_MAX_MS);
            sleep(Duration::from_millis(delay_ms)).await;
            consecutive_failures = consecutive_failures.saturating_add(1);
            continue;
        }

        if candidate_chain.len() != target_len {
            log(&format!(
                "[SYNC] Candidate chain length mismatch from {} (got {}, expected {})",
                peer,
                candidate_chain.len(),
                target_len
            ));
            let shift = (consecutive_failures.min(4)) as u32;
            let delay_ms = SYNC_BACKOFF_BASE_MS
                .saturating_mul(1u64 << shift)
                .min(SYNC_BACKOFF_MAX_MS);
            sleep(Duration::from_millis(delay_ms)).await;
            consecutive_failures = consecutive_failures.saturating_add(1);
            continue;
        }

        if let Err(e) = validate_chain(&candidate_chain) {
            log(&format!(
                "[SYNC] Rejecting fully downloaded chain from {}: {}",
                peer, e
            ));
            let shift = (consecutive_failures.min(4)) as u32;
            let delay_ms = SYNC_BACKOFF_BASE_MS
                .saturating_mul(1u64 << shift)
                .min(SYNC_BACKOFF_MAX_MS);
            sleep(Duration::from_millis(delay_ms)).await;
            consecutive_failures = consecutive_failures.saturating_add(1);
            continue;
        }

        let better = if force || !local_valid {
            match &best_peer_chain {
                Some(current_best) => prefer_chain(&candidate_chain, current_best),
                None => true,
            }
        } else {
            let baseline: &[Block] = best_peer_chain
                .as_deref()
                .unwrap_or(local_snapshot.as_slice());
            prefer_chain(&candidate_chain, baseline)
        };
        if better {
            best_peer_addr = Some(peer.clone());
            best_peer_headers = Some(remote_headers);
            best_peer_chain = Some(candidate_chain);
            consecutive_failures = 0;
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
    if let Ok(Some(bytes)) = timeout(
        Duration::from_millis(700),
        request_payload(peer, MessageKind::Command, b"/ping"),
    )
    .await
    {
        return bytes.as_slice() == b"pong";
    }
    false
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
