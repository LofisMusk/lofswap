# Architecture

## Workspace Layout

- `blockchain-core/`
  Shared block/transaction types, hashing, and address derivation.
- `node-cli/`
  P2P node, chain state, mempool, validation, synchronization, mining.
- `wallet-cli/`
  Interactive wallet, signing, broadcasting, peer discovery, vanity tools.
- `wallet-gui/`
  Desktop wallet backend (Rust + WRY) and frontend (`wallet-gui/frontend`).
- `explorer-api/`
  HTTP API for explorer views and network telemetry.
- `explorer/`
  Static explorer UI.

## Chain and Transaction Model

- Chain ID: `lofswap-testnet`
- Transaction kinds:
  - `Coinbase`
  - `Transfer`
- Address format: `LFS` + Base58 payload derived from SHA-256(pubkey)[0..20].
- Transfer validation includes:
  - chain ID checks
  - signature verification
  - nonce ordering
  - fee floor
  - sufficient balance (including pending mempool spend)
  - duplicate protection by signature/txid

## Consensus and Mining

- PoW difficulty target: leading zeroes (`DEFAULT_DIFFICULTY_ZEROS` in `blockchain-core`).
- Block validation checks:
  - index and previous hash linkage
  - minimum 60s block interval + median-time-based timestamp rules
  - hash and difficulty validity
  - coinbase at tx index 0
  - per-tx validity and state transitions
- Fork tie-break (equal work/height): lower block timestamp wins (then hash as deterministic fallback).
- Subsidy schedule (node implementation):
  - block subsidy: `10`

## Mempool Model (Node)

- Mempool persistence files:
  - `mempool_snapshot.json`
  - compatibility mirror `mempool.json`
- Built-in controls:
  - size cap
  - per-sender cap
  - max age
  - deduplication by signature/txid

## Networking

Node P2P uses TCP with command-style request paths and framed messages.

Common request paths include:

- `/ping`
- `/balance/{address}`
- `/nonce/{address}`
- `/peers`
- `/headers?from={i}&limit={n}`
- `/blocks?from={i}&limit={n}`
- `/chain`
- `/chain-hash`
- `/whoami` / `/peer-info`

Wallet components connect to peers (bootstrap + local defaults) and broadcast signed transactions.

## Persistence Model

Node data is rooted at `DATA_DIR` (default `data/`).

Wallet CLI stores wallet + cache files in current working directory.

Wallet GUI stores wallet + cache in an app data directory (`GUI_APP_DATA_DIR` or platform default).
