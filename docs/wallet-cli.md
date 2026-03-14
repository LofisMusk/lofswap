# Wallet CLI

## Run

```bash
cargo run -p wallet-cli
```

The wallet runs as an interactive REPL.

To force the wallet onto the L2 node network, start it with:

```bash
cargo run -p wallet-cli -- --l2
```

`--l2` switches bootstrap discovery and the default local node hint to the L2 network on port `6100`. On the `l2` branch this matches the default network; on `main` it overrides the default main-network peers.

## Environment Variables

- `LOFSWAP_WALLET_PASSPHRASE`
  Wallet encryption passphrase (if unset, CLI prompts).
- `LOFSWAP_WALLET_MNEMONIC_PASSPHRASE`
  Optional BIP39 passphrase used with mnemonic recovery/derivation.
- `LOFSWAP_ALLOW_PRIVATE_KEY_EXPORT`
  Must equal `YES_I_UNDERSTAND` to allow `export-priv`.
- `WALLET_LOCAL_PORT`
  Local node port hint (default `6100`).
- `WALLET_LOCAL_NODE`
  Explicit local node address hint (for example `127.0.0.1:6100`).

## Storage Files

- `.default_wallet.keystore.json` (encrypted default wallet)
- `.default_wallet` (legacy plaintext format; migrated when possible)
- `wallet_mempool.json` (locally queued pending tx)
- `wallet_raw_signed.json` (raw signed tx cache)
- `wallet-cache/peers_cache.json` (default peer cache)
- `wallet-cache/peers_cache_l2.json` (peer cache used when `--l2` selects a non-default network profile)

## Command Reference

- `help`
- `create-wallet [startswith <prefix>] [endswith <suffix>] [cpu [workers]|gpu [workers]|opencl [workers]]`
- `gpu-info`
- `opencl-info`
- `gpu-test [adapter_index]`
- `gpu-pubkey-hash-test [adapter_index] [count]`
- `gpu-pipeline-test [adapter_index] [chunks] [workgroups]`
- `gpu-vanity-probe [adapter_index] [chunks] [workgroups] [prefix|-] [suffix|-]`
- `gpu-vanity-job-test [adapter_index] [chunks] [workgroups] [prefix|-] [suffix|-] [max_hits] [stop_after_hits]`
- `recover-mnemonic <seed words...>`
- `import-priv <hex>`
- `import-dat <file>`
- `export-dat <file>`
- `export-priv`
- `default-wallet`
- `send <to?> <amount> [n=2]`
- `send-priv <priv> <to> <amount> [n=2]`
- `sign-raw <to> <amount>`
- `sign-raw-priv <priv> <to> <amount>`
- `send-raw <sig|txid> [n=2]`
- `raw_tx`
- `force-send <signature>`
- `balance [address]`
- `faucet [address]`
- `tx-history [address]`
- `tx-info <txid|signature>`
- `list-peers`
- `print-mempool`
- `exit`

## Important Emission Note

`faucet` is disabled in hard-fork v2. New LFS is emitted only via coinbase in mined blocks.

## Typical Flow

```text
create-wallet
default-wallet
balance
send <destination> <amount>
tx-history
```

If broadcast quorum is not met, wallet keeps transactions in local pending storage and retries when peers are available.
