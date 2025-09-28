use axum::{Router, routing::{get, post}, extract::State, Json};
use serde::{Serialize, Deserialize};
use std::net::SocketAddr;
use tokio::net::TcpListener;

use sha2::{Digest, Sha256};
use k256::ecdsa::{Signature, VerifyingKey, signature::DigestVerifier};

use crate::app::AppState;
use crate::peers::{PeersResp, MAX_PEERS_RETURNED};

use blockchain_core::Transaction;

// === GET /rpc/get_info ===
#[derive(Serialize)]
struct InfoResp {
    height: u64,
    best_key_hash: String,
    mempool: usize,
    peers: usize,
}
async fn rpc_get_info(State(st): State<AppState>) -> Json<InfoResp> {
    let peers_cnt = st.peers.lock().await.best(usize::MAX).len();
    let n = st.node.lock().await;
    Json(InfoResp {
        height: n.height(),
        best_key_hash: n.best_key_hash(),
        mempool: n.mempool.len(),
        peers: peers_cnt,
    })
}

// === GET /peers ===
async fn http_get_peers(State(st): State<AppState>) -> Json<PeersResp> {
    Json(PeersResp { peers: st.peers.lock().await.best(MAX_PEERS_RETURNED) })
}

// === POST /add-peer ===
#[derive(Deserialize)]
struct AddPeerReq { addr: String }
async fn http_add_peer(State(st): State<AppState>, Json(req): Json<AddPeerReq>) -> Json<PeersResp> {
    {
        let mut db = st.peers.lock().await;
        db.upsert(req.addr, true);
        db.save().await;
    }
    http_get_peers(State(st)).await
}

// === POST /rpc/send_tx ===
// Transakcja zgodna z Twoim Transaction { from, to, amount, fee, timestamp, signature, hash }
#[derive(Deserialize)]
struct SendTxReq {
    from: String,
    to: String,
    amount: u64,
    fee: u64,
    timestamp: i64,
    signature: String, // DER hex
    hash: String,      // hash kanonicznego payloadu (hex)
}
#[derive(Serialize)]
struct SendTxResp { accepted: bool, reason: Option<String> }

async fn rpc_send_tx(State(st): State<AppState>, Json(req): Json<SendTxReq>) -> Json<SendTxResp> {
    // 1) weryfikacja hash -> musi pasować do kanonicznego payloadu (bez signature/hash)
    let payload = canonical_tx_payload(&req.from, &req.to, req.amount, req.fee, req.timestamp);
    let mut h = Sha256::new(); h.update(&payload);
    let calc_hash = format!("{:x}", h.finalize());
    if calc_hash != req.hash {
        return Json(SendTxResp{ accepted: false, reason: Some("bad_hash".into()) });
    }

    // 2) weryfikacja podpisu (pk = `from` jako SEC1 compressed hex)
    if !verify_sig_sec1_der(&req.from, &payload, &req.signature) {
        return Json(SendTxResp{ accepted: false, reason: Some("bad_signature".into()) });
    }

    // 3) TODO: dodatkowe reguły (fee >= min, anty‑replay/nonce, limity per blok itd.)

    let mut n = st.node.lock().await;
    n.mempool.push(Transaction {
        from: req.from,
        to: req.to,
        amount: req.amount,
        fee: req.fee,
        timestamp: req.timestamp,
        signature: req.signature,
        hash: calc_hash,
    });
    Json(SendTxResp{ accepted: true, reason: None })
}

fn canonical_tx_payload(from_pk_sec1_hex: &str, to: &str, amount: u64, fee: u64, ts: i64) -> Vec<u8> {
    // Ten sam porządek pól, który portfel używa do liczenia hash/podpisu.
    serde_json::to_vec(&serde_json::json!({
        "from": from_pk_sec1_hex,
        "to": to,
        "amount": amount,
        "fee": fee,
        "timestamp": ts
    })).unwrap()
}

fn verify_sig_sec1_der(from_pk_sec1_hex: &str, payload: &[u8], sig_der_hex: &str) -> bool {
    let pk = match hex::decode(from_pk_sec1_hex) { Ok(b) => b, Err(_) => return false };
    let vk = match VerifyingKey::from_sec1_bytes(&pk) { Ok(v) => v, Err(_) => return false };

    let mut d = Sha256::new(); d.update(payload);
    let sig_bytes = match hex::decode(sig_der_hex) { Ok(b) => b, Err(_) => return false };
    let sig = match Signature::from_der(&sig_bytes) { Ok(s) => s, Err(_) => return false };

    vk.verify_digest(d, &sig).is_ok()
}

// === POST /rpc/get_balance ===
#[derive(Deserialize)]
struct BalanceReq { address: String }
#[derive(Serialize)]
struct BalanceResp { address: String, balance: u64 }

async fn rpc_get_balance(State(st): State<AppState>, Json(req): Json<BalanceReq>) -> Json<BalanceResp> {
    let bal = st.node.lock().await.get_balance(&req.address);
    Json(BalanceResp { address: req.address, balance: bal })
}

// === Serwer HTTP ===
pub async fn serve_rpc(st: AppState, bind: SocketAddr) {
    let app = Router::new()
        .route("/rpc/get_info", get(rpc_get_info))
        .route("/peers", get(http_get_peers))
        .route("/add-peer", post(http_add_peer))
        .route("/rpc/send_tx", post(rpc_send_tx))
        .route("/rpc/get_balance", post(rpc_get_balance))
        .with_state(st);

    let listener = TcpListener::bind(bind).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
