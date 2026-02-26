# LofSwap

![LofSwap logo](lofswap-logo.png)

LofSwap is a Proof-of-Work blockchain project with a node, CLI wallet, desktop wallet GUI, and explorer stack.

## Documentation

- [Docs Index](docs/README.md)
- [Getting Started](docs/getting-started.md)
- [Architecture](docs/architecture.md)
- [Node CLI](docs/node-cli.md)
- [Wallet CLI](docs/wallet-cli.md)
- [Wallet GUI](docs/wallet-gui.md)
- [Explorer](docs/explorer.md)

## Workspace

- `blockchain-core/` shared chain and transaction types
- `node-cli/` P2P node and miner
- `wallet-cli/` interactive wallet CLI
- `wallet-gui/` desktop wallet application
- `explorer/` static explorer UI
- `explorer-api/` explorer HTTP API

## Quick Start

```bash
cargo build -r
cargo run -p node-cli
```

For full setup and component guides, use the docs links above.
