# Lofswap

Lofswap is a production/audit-ready Proof-of-Work blockchain designed to enable cross-chain swaps (e.g., BTC → SOL) via a secure protocol and supporting infrastructure. This repo contains the core node, wallet CLI, and GUI app.

## What is in this repo
- `blockchain-core/` Core data structures and hashing logic
- `node-cli/` P2P node (TCP 6000)
- `wallet-cli/` Wallet CLI for creating/sending transactions
- `gui-app/` Desktop UI client
- `docs/` Notes, TODOs, changelog

## Quick start (local)
Build the workspace:
```
cargo build -r
```

Run the node:
```
./target/release/node-cli
```

## CLI quality of life
- Interactive history with arrow-up/arrow-down via Rustyline
- Non-interactive mode remains supported for containers and pipes

## Consensus and safety behavior
- **Block validation**: index, previous hash, timestamp monotonicity, hash correctness, and PoW difficulty are verified before acceptance.
- **Transaction validation**: ECDSA signatures are verified; balances are checked (including pending mempool for new txs); duplicate signatures/txids across the chain are rejected.
- **Reorg policy**: on sync, the node replaces the local chain only when a **longer, fully valid** chain is received. Invalid chains are rejected. The node logs reorg height changes.
- **Proof-of-work**: hashes must match the block header and satisfy the difficulty target (leading zeros).
- **Debug logging**: `[DEBUG]` and `[MAINT]` messages are compiled only in debug builds. Release builds do not print these logs.

## Operational safety notes
- `node-cli` listens on TCP `6000`
- Use systemd to supervise and restart on failure
- Keep `DATA_DIR` on persistent storage to avoid chain loss