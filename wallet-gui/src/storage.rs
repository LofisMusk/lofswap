//! Where the wallet keeps its files, and the settings it persists there.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

pub const DATA_DIR_ENV: &str = "GUI_APP_DATA_DIR";
pub const ENCRYPTED_WALLET: &str = ".default_wallet.keystore.json";
pub const LEGACY_WALLET: &str = ".default_wallet";
pub const BIOMETRIC_MARKER: &str = ".default_wallet.biometric_enabled";

const CACHE_DIR: &str = "wallet-cache";
const PEER_CACHE_FILE: &str = "peers_cache.json";
const SETTINGS_FILE: &str = "gui_settings.json";
const APP_DIR_NAME: &str = "LofSwap Wallet";

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

pub fn data_dir() -> &'static Path {
    DATA_DIR.get_or_init(resolve_data_dir)
}

fn resolve_data_dir() -> PathBuf {
    if let Some(explicit) = env::var_os(DATA_DIR_ENV) {
        return PathBuf::from(explicit);
    }

    // The webview build stored wallets next to the working directory unless a
    // launcher script exported GUI_APP_DATA_DIR. Prefer the per-user location,
    // but keep using a working-directory wallet when that is the one that
    // actually holds a keystore.
    let platform = platform_data_dir();
    let legacy = PathBuf::from("wallet-gui-data");
    if let Some(platform) = platform {
        if !platform.join(ENCRYPTED_WALLET).exists()
            && !platform.join(LEGACY_WALLET).exists()
            && (legacy.join(ENCRYPTED_WALLET).exists() || legacy.join(LEGACY_WALLET).exists())
        {
            return legacy;
        }
        return platform;
    }
    legacy
}

fn platform_data_dir() -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        let home = env::var_os("HOME")?;
        Some(
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join(APP_DIR_NAME),
        )
    } else if cfg!(target_os = "windows") {
        let appdata = env::var_os("APPDATA")?;
        Some(PathBuf::from(appdata).join(APP_DIR_NAME))
    } else {
        let base = env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share"))
            })?;
        Some(base.join(APP_DIR_NAME))
    }
}

pub fn ensure_dirs() {
    let _ = fs::create_dir_all(data_dir());
    let _ = fs::create_dir_all(cache_dir());
}

pub fn data_path(file: &str) -> PathBuf {
    data_dir().join(file)
}

pub fn cache_dir() -> PathBuf {
    data_dir().join(CACHE_DIR)
}

pub fn encrypted_wallet_path() -> PathBuf {
    data_path(ENCRYPTED_WALLET)
}

pub fn legacy_wallet_path() -> PathBuf {
    data_path(LEGACY_WALLET)
}

pub fn biometric_marker_path() -> PathBuf {
    data_path(BIOMETRIC_MARKER)
}

pub fn peer_cache_path() -> PathBuf {
    cache_dir().join(PEER_CACHE_FILE)
}

pub fn wallet_exists() -> bool {
    encrypted_wallet_path().exists() || legacy_wallet_path().exists()
}

// ---------------------------------------------------------------- settings --

pub const DEFAULT_MIN_BROADCAST_PEERS: usize = 2;
pub const MAX_MIN_BROADCAST_PEERS: usize = 8;
pub const DEFAULT_LOCAL_PORT: u16 = 6000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub min_broadcast_peers: usize,
    /// Node tried first for balances and broadcasts.
    pub local_node: String,
    /// Seed nodes used when no local node answers. Empty means "use the
    /// addresses compiled into the binary".
    pub bootstrap_peers: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            min_broadcast_peers: DEFAULT_MIN_BROADCAST_PEERS,
            local_node: format!("127.0.0.1:{DEFAULT_LOCAL_PORT}"),
            bootstrap_peers: Vec::new(),
        }
    }
}

impl Settings {
    pub fn load() -> Self {
        ensure_dirs();
        let mut settings: Self = fs::read_to_string(settings_path())
            .ok()
            .and_then(|body| serde_json::from_str(&body).ok())
            .unwrap_or_default();
        settings.normalize();
        settings
    }

    pub fn save(&self) -> Result<(), String> {
        ensure_dirs();
        let body = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize settings: {e}"))?;
        fs::write(settings_path(), body).map_err(|e| format!("failed to write settings: {e}"))
    }

    pub fn normalize(&mut self) {
        self.min_broadcast_peers = self.min_broadcast_peers.clamp(1, MAX_MIN_BROADCAST_PEERS);
        self.local_node = self.local_node.trim().to_owned();
        if self.local_node.is_empty() {
            self.local_node = format!("127.0.0.1:{DEFAULT_LOCAL_PORT}");
        }
        self.bootstrap_peers.retain(|peer| !peer.trim().is_empty());
    }
}

fn settings_path() -> PathBuf {
    cache_dir().join(SETTINGS_FILE)
}
