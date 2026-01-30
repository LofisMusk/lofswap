#!/usr/bin/env python3
import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

DATA_DIR = os.environ.get("DATA_DIR", "data")
LISTEN_ADDR = os.environ.get("EXPLORER_API_BIND", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("EXPLORER_API_PORT", "7000"))
PEER_TIMEOUT = float(os.environ.get("PEER_TIMEOUT", "2.0"))
MAX_PEERS = int(os.environ.get("MAX_PEERS", "8"))
CACHE_TTL = float(os.environ.get("CONSENSUS_TTL", "5.0"))

_cache_lock = threading.Lock()
_cache = {"ts": 0.0, "chain": None, "meta": None}


def data_path(name: str) -> str:
    return os.path.join(DATA_DIR, name)


def read_json_file(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def read_lines_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            items = []
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except Exception:
                    continue
            return items
    except Exception:
        return []


def load_peers():
    peers = read_json_file(data_path("peers.json"), [])
    if not isinstance(peers, list):
        return []
    return [p for p in peers if isinstance(p, str) and p]


def tcp_request(peer: str, payload: str, timeout: float):
    if ":" not in peer:
        return None
    host, port = peer.rsplit(":", 1)
    try:
        port = int(port)
    except ValueError:
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload.encode("utf-8"))
            chunks = []
            while True:
                try:
                    data = sock.recv(65536)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
            if not chunks:
                return None
            return b"".join(chunks).decode("utf-8", errors="ignore")
    except Exception:
        return None


def ping_peer(peer: str) -> bool:
    resp = tcp_request(peer, "/ping", PEER_TIMEOUT)
    return resp is not None and resp.strip() == "pong"


def chain_from_peer(peer: str):
    resp = tcp_request(peer, "/chain", PEER_TIMEOUT)
    if not resp:
        return None
    try:
        data = json.loads(resp)
        if isinstance(data, list):
            return data
    except Exception:
        return None
    return None


def chain_hash(chain):
    try:
        encoded = json.dumps(chain, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except Exception:
        encoded = json.dumps(chain).encode("utf-8")
    return _sha256(encoded)


def _sha256(buf: bytes) -> str:
    import hashlib

    return hashlib.sha256(buf).hexdigest()


def consensus_state():
    now = time.time()
    with _cache_lock:
        if _cache["chain"] is not None and now - _cache["ts"] < CACHE_TTL:
            return _cache["chain"], _cache["meta"]

    local_chain = read_json_file(data_path("blockchain.json"), [])
    if not isinstance(local_chain, list):
        local_chain = []

    all_peers = load_peers()
    peers = all_peers[:MAX_PEERS]
    chains = [("local", local_chain)]
    chains_ok = 0
    ping_ok = 0
    heights = [len(local_chain)]

    for peer in peers:
        if ping_peer(peer):
            ping_ok += 1
        chain = chain_from_peer(peer)
        if chain is not None:
            chains.append((peer, chain))
            chains_ok += 1
            heights.append(len(chain))

    if not chains:
        chosen = []
        chosen_hash = None
        candidates = []
    else:
        # choose by max length, then by most common hash
        max_len = max(len(c[1]) for c in chains)
        candidates = [(src, ch) for src, ch in chains if len(ch) == max_len]
        if len(candidates) == 1:
            chosen = candidates[0][1]
        else:
            counts = {}
            for _, ch in candidates:
                h = chain_hash(ch)
                counts[h] = counts.get(h, 0) + 1
            best_hash = max(counts, key=counts.get)
            chosen = next(ch for _, ch in candidates if chain_hash(ch) == best_hash)
        chosen_hash = chain_hash(chosen) if chosen else None

    heights_sorted = sorted(heights)
    if heights_sorted:
        mid = len(heights_sorted) // 2
        if len(heights_sorted) % 2 == 1:
            median = heights_sorted[mid]
        else:
            median = (heights_sorted[mid - 1] + heights_sorted[mid]) // 2
    else:
        median = 0

    meta = {
        "peers_total": len(all_peers),
        "peers_sampled": len(peers),
        "ping_ok": ping_ok,
        "chain_ok": chains_ok,
        "candidates": len(candidates),
        "consensus_height": len(chosen),
        "consensus_hash": chosen_hash,
        "height_min": min(heights_sorted) if heights_sorted else 0,
        "height_max": max(heights_sorted) if heights_sorted else 0,
        "height_median": median,
        "height_local": len(local_chain),
    }

    with _cache_lock:
        _cache["ts"] = time.time()
        _cache["chain"] = chosen
        _cache["meta"] = meta
    return chosen, meta


def consensus_chain():
    return consensus_state()[0]


def calculate_balance(addr: str, chain):
    bal = 0
    for block in chain:
        txs = block.get("transactions") if isinstance(block, dict) else None
        if not isinstance(txs, list):
            continue
        for tx in txs:
            if not isinstance(tx, dict):
                continue
            if tx.get("from") == addr:
                try:
                    bal -= int(tx.get("amount", 0))
                except Exception:
                    pass
            if tx.get("to") == addr:
                try:
                    bal += int(tx.get("amount", 0))
                except Exception:
                    pass
    return bal


def address_txs(addr: str, chain):
    out = []
    for block in chain:
        txs = block.get("transactions") if isinstance(block, dict) else None
        if not isinstance(txs, list):
            continue
        for tx in txs:
            if not isinstance(tx, dict):
                continue
            if tx.get("to") == addr or tx.get("from") == addr:
                out.append(tx)
    return out


def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


class Handler(BaseHTTPRequestHandler):
    server_version = "lofswap-explorer-api/0.1"

    def _send_json(self, status: int, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/health":
            _, meta = consensus_state()
            return self._send_json(200, {"status": "ok", **(meta or {})})

        if path == "/ping":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"pong")
            return

        if path == "/peers":
            return self._send_json(200, load_peers())

        if path == "/peers/status":
            status = []
            for peer in load_peers()[:MAX_PEERS]:
                status.append({"peer": peer, "online": ping_peer(peer)})
            return self._send_json(200, {"list": status})

        if path == "/mempool":
            return self._send_json(200, read_lines_json(data_path("mempool.json")))

        if path == "/chain":
            return self._send_json(200, consensus_chain())

        if path == "/chain/latest-tx":
            chain = consensus_chain()
            if chain:
                txs = chain[-1].get("transactions") if isinstance(chain[-1], dict) else None
                if isinstance(txs, list) and txs:
                    return self._send_json(200, txs[-1])
            return self._send_json(200, None)

        if path == "/height":
            chain = consensus_chain()
            if chain:
                tip = chain[-1]
                return self._send_json(200, {
                    "height": len(chain),
                    "tip_hash": tip.get("hash", "") if isinstance(tip, dict) else "",
                    "tip_time": tip.get("timestamp", 0) if isinstance(tip, dict) else 0,
                })
            return self._send_json(200, {"height": 0, "tip_hash": "", "tip_time": 0})

        if path == "/telemetry":
            _, meta = consensus_state()
            return self._send_json(200, meta or {})

        if path == "/node/ip":
            return self._send_json(200, {"public": None, "private": local_ip()})

        if path.startswith("/address/"):
            rest = path[len("/address/"):]
            if rest.endswith("/balance"):
                addr = rest[:-len("/balance")]
                chain = consensus_chain()
                bal = calculate_balance(addr, chain)
                return self._send_json(200, {"address": addr, "balance": bal})
            if rest.endswith("/txs"):
                addr = rest[:-len("/txs")]
                chain = consensus_chain()
                return self._send_json(200, address_txs(addr, chain))

        self._send_json(404, {"error": "not found"})

    def log_message(self, format, *args):
        return


def main():
    server = ThreadingHTTPServer((LISTEN_ADDR, LISTEN_PORT), Handler)
    print(f"Explorer API listening on {LISTEN_ADDR}:{LISTEN_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
