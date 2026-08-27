# Desktop Wallet

`wallet-gui` is the LofSwap desktop wallet: a single native binary that draws
its own interface with [egui](https://github.com/emilk/egui). There is no
browser engine, no bundled web assets and no node toolchain — `cargo run` is
the whole build.

```bash
cargo run -r -p wallet-gui
```

## What it does

- **Onboarding** — create a wallet (12-word recovery phrase), import a raw
  secp256k1 key in hex, or import a `.dat` key file from the CLI wallet.
- **Unlock** — the keystore is encrypted with Argon2id (128 MiB, 4 passes) and
  XChaCha20-Poly1305. Optionally the passphrase is kept in the OS credential
  store, gated behind Touch ID on macOS.
- **Dashboard** — spendable balance, peer and chain status, recent activity.
- **Send** — the transaction is signed locally and pushed straight to peers;
  it only counts as sent once the configured number of them accept it.
- **Receive** — address, QR code and public key.
- **Activity** — every transaction touching the address, filterable and
  searchable, with confirmation counts.
- **Settings** — passphrase, biometric unlock, key reveal and export, minimum
  broadcast peers, local node, seed nodes, keystore export, wallet deletion.

## Design

The interface is drawn from the design canvas in [`wallet-gui/design/`](../wallet-gui/design):
one `.dc.html` artboard per screen plus `Tokens.dc.html`, which is the palette,
type ramp and metric sheet that [`src/theme.rs`](../wallet-gui/src/theme.rs)
mirrors. Change a token there and in `theme.rs` together.

Icons are painted with egui's `Painter` from the shape tables in
[`src/icons.rs`](../wallet-gui/src/icons.rs) — no SVG rasteriser, no icon font.
Space Grotesk and JetBrains Mono are embedded from `wallet-gui/assets/fonts`
(both SIL OFL 1.1, see the licence file next to them).

## How it talks to the network

Nodes answer plain text requests over TCP on port 6000. The wallet uses:

| Request | Used for |
| --- | --- |
| `/ping` | deciding which peers are reachable |
| `/balance/<address>` | the spendable balance |
| `/nonce/<address>` | the next transaction nonce |
| `/headers?from=&limit=` | the current chain tip |
| `/blocks?from=&limit=` | scanning for this wallet's transactions |
| a JSON transaction | broadcasting |

The chain scan is incremental and cached under `wallet-cache/tx-index-*.json`,
so a restart resumes where it left off rather than re-reading the chain.
Header and block requests are spaced out deliberately: nodes allow five per
second per IP and hand out infraction points above that.

Everything above runs on a worker thread. The UI thread never holds the secret
key, never opens a socket and never runs Argon2id.

## Peers

The wallet tries, in order: the configured local node, the seed nodes, then
peers that answered before. Seed nodes come from the first of these that is
set:

1. the **Seed nodes** list in Settings (one `host:port` per line),
2. the `LOFSWAP_BOOTSTRAP` environment variable (comma-separated),
3. the addresses compiled into the release.

Host names are resolved through DNS, so a seed node can be named rather than
pinned to an IP address. See [Running a node for free](deploy-free.md) if the
network has no reachable nodes.

## Environment variables

- `GUI_APP_DATA_DIR` — override the wallet's data directory.
- `LOFSWAP_BOOTSTRAP` — comma-separated seed nodes.
- `LOFSWAP_WALLET_MNEMONIC_PASSPHRASE` — optional BIP-39 passphrase applied
  when deriving a key from a new recovery phrase.

## Where the files live

- macOS: `~/Library/Application Support/LofSwap Wallet`
- Windows: `%APPDATA%\LofSwap Wallet`
- Linux: `$XDG_DATA_HOME/LofSwap Wallet` (or `~/.local/share/LofSwap Wallet`)

A wallet left in a `wallet-gui-data` directory by an older build is still
picked up when the per-user location has no keystore.

Inside that directory:

- `.default_wallet.keystore.json` — the encrypted keystore
- `.default_wallet` — a legacy plaintext key, migrated on first unlock
- `.default_wallet.biometric_enabled` — marker for credential-store unlock
- `wallet-cache/peers_cache.json` — peers that answered
- `wallet-cache/gui_settings.json` — settings
- `wallet-cache/tx-index-*.json` — the incremental chain scan

## Recovery phrases are not BIP-44

The key is derived from the recovery phrase with HKDF-SHA256, not BIP32/BIP44.
Restoring a LofSwap phrase in MetaMask, Ledger or Trezor produces a *different*
key and an empty balance. The wallet says so on the screen that shows the
phrase; restore it in a LofSwap wallet.
