# Wallet GUI

## Overview

`wallet-gui` is a Rust desktop app (Winit + WRY) with a frontend built from `wallet-gui/frontend`.

## Launch Options

### Helper Scripts

- macOS: `./Start-LofSwap-Wallet.command`
- Linux: `./Start-LofSwap-Wallet.sh`
- Windows PowerShell: `./Start-LofSwap-Wallet.ps1`

These scripts build frontend assets, build `wallet-gui`, prepare runtime assets, then launch.

### Manual

```bash
cd wallet-gui/frontend
npm install
npm run build
cd ../..
cargo run -p wallet-gui
```

## Environment Variables

- `GUI_APP_DEV_URL`
  If set, GUI loads frontend from this dev server URL.
- `GUI_APP_DIST_DIR`
  Override path to built frontend dist (`index.html` required).
- `GUI_APP_DATA_DIR`
  Override app data directory for wallet/cache files.
- `LOFSWAP_WALLET_MNEMONIC_PASSPHRASE`
  Optional mnemonic passphrase.
- `WALLET_LOCAL_PORT`
  Local node port hint (default `6000`).
- `WALLET_LOCAL_NODE`
  Explicit local node endpoint hint.

## Runtime Data Location

- If `GUI_APP_DATA_DIR` is set, that path is used.
- On macOS default: `~/Library/Application Support/LofSwap Wallet`
- Otherwise default: `<current working dir>/wallet-gui-data`

## Stored Files

- `.default_wallet.keystore.json`
- `.default_wallet` (legacy fallback)
- `.default_wallet.biometric_enabled`
- `wallet-cache/peers_cache.json`
- `wallet-cache/gui_settings.json`

## Security Notes

- Encrypted wallet storage is default.
- Legacy plaintext wallet migration is supported.
- macOS Touch ID flow is supported when biometric mode is enabled.

## Networking Notes

GUI wallet uses discovered peers + local candidates (`127.0.0.1:6000`, `localhost:6000` unless overridden) to query balances and broadcast transactions.
