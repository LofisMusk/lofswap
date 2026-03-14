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
- `--fullnode`
  Currently parsed; reserved behavior.

## Environment Variables

- `DATA_DIR`
  Node data directory. Default: `data`.
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

- Default listen port: `6100`.
- Bootstrap peers are compiled in (`89.168.107.239:6100`, `79.76.116.108:6100`).
- `clear-chain` wipes chain storage; use with care.
