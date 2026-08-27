# LofSwap Documentation

This folder contains project documentation for development, local testing, and operations.

## Documents

- [`getting-started.md`](./getting-started.md)
  Quick setup, build, and first-run flows.
- [`architecture.md`](./architecture.md)
  Workspace layout, protocol model, and consensus behavior.
- [`cross-chain-swaps.md`](./cross-chain-swaps.md)
  HTLC atomic swap protocol, transaction kinds, wallet commands, and endpoints.
- [`../contracts/README.md`](../contracts/README.md)
  The foreign legs: EVM (Ethereum, BNB Chain, …) and Solana escrow contracts.
- [`node-cli.md`](./node-cli.md)
  Node runtime flags, commands, API routes, mining, and data files.
- [`wallet-cli.md`](./wallet-cli.md)
  Wallet CLI command reference, env vars, and storage details.
- [`wallet-gui.md`](./wallet-gui.md)
  Desktop wallet: what it does, how it talks to nodes, and where it stores keys.
- [`deploy-free.md`](./deploy-free.md)
  Getting a reachable node onto the internet without paying for hosting.
- [`explorer.md`](./explorer.md)
  Explorer UI and Explorer API setup and endpoint reference.

## Recommended Reading Order

1. [`getting-started.md`](./getting-started.md)
2. [`architecture.md`](./architecture.md)
3. The component guide you are actively working on.

## Source of Truth

The source code is the canonical reference. These docs summarize the behavior currently implemented in this repository.
