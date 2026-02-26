# Explorer

## Components

- `explorer/`
  Static explorer UI (`index.html`).
- `explorer-api/`
  Read-only HTTP API backed by local node data and peer sampling.

## Run Explorer API (Rust)

```bash
cargo run -p explorer-api
```

## Explorer API Environment Variables

- `DATA_DIR` (default: `data`)
- `EXPLORER_API_BIND` (default: `127.0.0.1`)
- `EXPLORER_API_PORT` (default: `7000`)
- `PEER_TIMEOUT` (default: `2.0` seconds)
- `MAX_PEERS` (default: `8`)
- `CONSENSUS_TTL` (default: `5.0` seconds)
- `EXPLORER_SELF_PEER` (optional `host:port`)

## Core Endpoints

- `GET /health`
- `GET /telemetry`
- `GET /peers`
- `GET /peers/status`
- `GET /peer/:peer`
- `GET /chain`
- `GET /chain/latest-tx`
- `GET /block/:hash`
- `GET /height`
- `GET /mempool`
- `GET /node/ip`
- `GET /address/:addr/balance`
- `GET /address/:addr/txs`

Additional API-style aliases also exist:

- `GET /api/network`
- `GET /api/peers`
- `GET /api/transactions/recent`
- `GET /api/tx/:txid`
- `GET /api/block/:hash`
- `GET /api/peer/:peer`

## Serve the Static Explorer

Copy `explorer/index.html` to a web server and point it to API base:

- same-origin (recommended via reverse proxy), or
- with query parameter like `?api=http://127.0.0.1:7000`

If using cross-origin hosting, configure CORS on the API layer.
