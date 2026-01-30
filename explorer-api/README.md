Lofswap Explorer API

This is a lightweight HTTP API that exposes explorer data based on the local node data and peer consensus.

Rust binary (recommended) lives in `explorer-api/src/main.rs`.
Python version (`explorer-api/server.py`) is a fallback/reference implementation.

Features
- Reads local node data from DATA_DIR (default: ./data)
- Reads peers from peers.json and queries them over P2P (/chain)
- Chooses consensus chain by max length + majority hash
- Exposes the same read endpoints the explorer UI expects

Endpoints
- GET /health
- GET /peers
- GET /peers/status
- GET /chain
- GET /chain/latest-tx
- GET /block/{hash}
- GET /height
- GET /mempool
- GET /node/ip
- GET /telemetry
- GET /address/{addr}/balance
- GET /address/{addr}/txs

Config (env)
- DATA_DIR: path to node data (default: data)
- EXPLORER_API_BIND: bind address (default: 127.0.0.1)
- EXPLORER_API_PORT: port (default: 7000)
- PEER_TIMEOUT: seconds (default: 2.0)
- MAX_PEERS: number of peers to query (default: 8)
- CONSENSUS_TTL: cache seconds (default: 5.0)
- EXPLORER_SELF_PEER: include host node in peers list (e.g. 89.168.107.239:6000)

Run
  ./server.py
