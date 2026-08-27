# LofSwap

![LofSwap logo](lofswap-logo.png)

LofSwap is a Proof-of-Work blockchain for trust-minimised cross-chain swaps, with a node, CLI wallet, desktop wallet GUI, and explorer stack.

Transfers between LofSwap participants are settled by the chain itself; cross-chain trades (for example `USDC (Ethereum) -> USDC (Solana)`) are settled with hashed timelock contracts, so no bridge or custodian ever holds the funds.

## Documentation

- [Docs Index](docs/README.md)
- [Getting Started](docs/getting-started.md)
- [Architecture](docs/architecture.md)
- [Cross-Chain Swaps](docs/cross-chain-swaps.md)
- [Foreign Legs (EVM / Solana contracts)](contracts/README.md)
- [Node CLI](docs/node-cli.md)
- [Wallet CLI](docs/wallet-cli.md)
- [Desktop Wallet](docs/wallet-gui.md)
- [Explorer](docs/explorer.md)

## Workspace

- `blockchain-core/` shared chain and transaction types
- `node-cli/` P2P node and miner
- `wallet-cli/` interactive wallet CLI
- `wallet-gui/` native desktop wallet (egui)
- `explorer/` static explorer UI
- `explorer-api/` explorer HTTP API
- `contracts/evm/` HTLC escrow for EVM chains (Ethereum, BNB Chain, …)
- `contracts/solana/` HTLC escrow program for Solana

## Quick Start

```bash
cargo build -r
cargo run -p node-cli
```

For full setup and component guides, use the docs links above.
