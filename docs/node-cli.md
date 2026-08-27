# Node CLI

## Run

```bash
cargo run -p node-cli
```

Release binary:

```bash
./target/release/node-cli
```

## Startup Flags

- `--no-upnp`
  Skip UPnP port mapping.
- `--no-peer-exchange`
  Skip bootstrap peer exchange and public IP discovery.
- `--miner <LFS_ADDRESS>` (or `--miner=LFS_ADDRESS`)
  Enable continuous auto-mining to the provided reward address.
- `--peer <HOST:PORT>` (or `--peer=HOST:PORT`, repeatable)
  Seed nodes to sync from, overriding the compiled-in list. Host names are
  resolved to addresses at startup. Must be port `6000`.
- `--fullnode`
  Currently parsed; reserved behavior.

## Environment Variables

- `DATA_DIR`
  Node data directory. Default: `data`.
- `LOFSWAP_BOOTSTRAP`
  Comma-separated seed nodes, used when `--peer` is not given. Overrides the
  compiled-in list.
- `BIND_ADDR`
  Bind IP for TCP server. Default: `0.0.0.0`.
- `MINER_REWARD_ADDRESS`
  Explicit destination address for coinbase rewards.
- `LOFSWAP_WALLET_PASSPHRASE`
  Used when miner tries to load a local encrypted wallet as reward fallback.

## Interactive Commands

When running, node CLI supports:

- `mine <LFS_ADDRESS>`
- `sync`
- `print-chain`
- `list-peers`
- `add-peer <address:port>`
- `remove-peer <address:port>`
- `remove-offline-peers`
- `clear-chain`
- `print-mempool`
- `print-swaps` (cross-chain HTLC swaps and their state)
- `get-publicip`
- `print-my-addr`
- `debug-peers`
- `exit`

## Mining Behavior

- Auto-miner runs continuously only when started with `--miner <LFS_ADDRESS>`.
- Manual mining requires explicit reward address: `mine <LFS_ADDRESS>`.
- Mining works even with empty mempool (coinbase-only block).
- Coinbase amount = `block_subsidy(height) + fees_sum`.
- Difficulty retarget keeps average block time near `60s` (no fixed 60s sleep timer).

Subsidy parameters:

- Block subsidy: `10`

## P2P Request Paths

Common paths accepted by node request handler:

- `/ping`
- `/balance/{address}`
- `/nonce/{address}`
- `/peers`
- `/headers?from={index}&limit={count}`
- `/blocks?from={index}&limit={count}`
- `/chain`
- `/chain-hash`
- `/swap/{swap_id|escrow}`
- `/swaps`
- `/swaps/open`
- `/swaps/address/{address}`
- `/whoami`
- `/peer-info`
- `/resolve-ip/{id}`
- `/iam/{peer}`
- `/peers{json}` (peer gossip payload)

Node also accepts single `Transaction` and single `Block` JSON payloads over TCP.

## Data Files (`DATA_DIR`)

- `blockchain.json`
- `chain_db/`
- `state_snapshot.json`
- `peers.json`
- `mempool_snapshot.json`
- `mempool.json`
- `node_identity_ed25519.key`
- `banlist.json`
- `peer_pins.json`
- `wallet_mempool.json` (if wallet-broadcast fallback writes here)

## Notes

- Default listen port: `6000`. It is not configurable: peers announced on any
  other port are rejected.
- Seed nodes are taken from `--peer`, then `LOFSWAP_BOOTSTRAP`, then the list
  compiled into `DEFAULT_BOOTSTRAP_NODES`.
- Proof of work runs on a blocking thread, so a mining node keeps answering
  peers and wallets while it hashes.
- `clear-chain` wipes chain storage; use with care.
- To put a node on the public internet, see [`deploy-free.md`](./deploy-free.md).
