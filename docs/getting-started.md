# Getting Started

## Prerequisites

- Rust toolchain (Cargo)
- Node.js + npm (required for `wallet-gui/frontend`)

## Build the Workspace

```bash
cargo build -r
```

## Run Core Components

### Node

```bash
cargo run -p node-cli
```

`node-cli` listens on TCP `6000` by default.

### Wallet CLI

```bash
cargo run -p wallet-cli
```

This starts an interactive REPL (`help` to list commands).

### Wallet GUI

Build and run with helper scripts:

- macOS:

```bash
./Start-LofSwap-Wallet.command
```

- Linux:

```bash
./Start-LofSwap-Wallet.sh
```

- Windows (PowerShell):

```powershell
./Start-LofSwap-Wallet.ps1
```

Or run directly from Cargo after frontend build:

```bash
cd wallet-gui/frontend
npm install
npm run build
cd ../..
cargo run -p wallet-gui
```

## First Local Smoke Test

1. Start a node:

```bash
cargo run -p node-cli
```

2. In a second terminal, start wallet CLI:

```bash
cargo run -p wallet-cli
```

3. In wallet CLI:

```text
create-wallet
default-wallet
balance
```

## Important Token Emission Note

- Faucet is disabled in v2.
- New LFS is created only as coinbase reward in mined blocks.
- Current miner logic mines only when there is at least one valid mempool transaction.

That means a fully isolated fresh network cannot self-bootstrap balances without either:

- receiving a valid transaction from an already funded address/chain, or
- changing miner behavior for local dev (for example, permitting coinbase-only blocks).

## Useful Commands

```bash
cargo test
cargo test -p node-cli
cargo test -p wallet-cli
cargo check
```

## Next Docs

- [`architecture.md`](./architecture.md)
- [`node-cli.md`](./node-cli.md)
- [`wallet-cli.md`](./wallet-cli.md)
