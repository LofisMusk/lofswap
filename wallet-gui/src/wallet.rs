//! Keystore operations: create, import, unlock, re-encrypt, export, delete.
//!
//! All of it runs on the worker thread — Argon2id at 128 MiB takes long enough
//! to drop frames if it ran on the UI thread.

use std::fs;

use base64::Engine;
use blockchain_core::{
    pubkey_to_address,
    wallet_keystore::{
        DEFAULT_DERIVATION_PATH, WalletSecretPayload, decrypt_secret_key,
        derive_secret_key_from_mnemonic, encrypt_secret_key, generate_mnemonic_12,
        load_keystore_file, payload_secret_key_bytes, save_keystore_file,
    },
};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

use crate::storage;

pub const MNEMONIC_PASSPHRASE_ENV: &str = "LOFSWAP_WALLET_MNEMONIC_PASSPHRASE";

/// The key material for an open wallet. Only the worker thread holds one.
#[derive(Clone)]
pub struct Unlocked {
    pub secret_key: SecretKey,
    pub public_key: String,
    pub address: String,
}

impl Unlocked {
    pub fn from_secret_key(secret_key: SecretKey) -> Self {
        let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret_key).to_string();
        let address = pubkey_to_address(&public_key);
        Self {
            secret_key,
            public_key,
            address,
        }
    }
}

fn mnemonic_passphrase() -> String {
    std::env::var(MNEMONIC_PASSPHRASE_ENV)
        .map(|value| value.trim().to_owned())
        .unwrap_or_default()
}

/// Generate a fresh wallet and write its keystore. Returns the recovery phrase.
pub fn create(passphrase: &str) -> Result<(Unlocked, String), String> {
    let passphrase = check_passphrase(passphrase)?;
    let mnemonic = generate_mnemonic_12()?;
    let derived = derive_secret_key_from_mnemonic(
        &mnemonic,
        &mnemonic_passphrase(),
        DEFAULT_DERIVATION_PATH,
    )?;
    let secret_key = SecretKey::from_byte_array(derived)
        .map_err(|_| "derived secret key is invalid for secp256k1".to_owned())?;
    save(&secret_key, Some(&mnemonic), passphrase)?;
    Ok((Unlocked::from_secret_key(secret_key), mnemonic))
}

/// Import a raw 32-byte secp256k1 key given as hex.
pub fn import_private_key(private_key_hex: &str, passphrase: &str) -> Result<Unlocked, String> {
    let passphrase = check_passphrase(passphrase)?;
    let decoded = hex::decode(private_key_hex.trim())
        .map_err(|_| "private key must be 64 hex characters".to_owned())?;
    import_bytes(&decoded, passphrase)
}

/// Import a raw `.dat` key file as written by the CLI wallet.
pub fn import_dat(bytes: &[u8], passphrase: &str) -> Result<Unlocked, String> {
    let passphrase = check_passphrase(passphrase)?;
    // Older exports were base64 text rather than raw bytes; accept both.
    if bytes.len() != 32
        && let Ok(text) = std::str::from_utf8(bytes)
    {
        let trimmed = text.trim();
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(trimmed) {
            return import_bytes(&decoded, passphrase);
        }
        if let Ok(decoded) = hex::decode(trimmed) {
            return import_bytes(&decoded, passphrase);
        }
    }
    import_bytes(bytes, passphrase)
}

fn import_bytes(bytes: &[u8], passphrase: &str) -> Result<Unlocked, String> {
    if bytes.len() != 32 {
        return Err(format!("expected a 32-byte key, got {} bytes", bytes.len()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(bytes);
    let secret_key = SecretKey::from_byte_array(key)
        .map_err(|_| "key is not a valid secp256k1 secret".to_owned())?;
    save(&secret_key, None, passphrase)?;
    Ok(Unlocked::from_secret_key(secret_key))
}

/// Open the stored keystore, migrating a legacy plaintext wallet on the way.
pub fn unlock(passphrase: &str) -> Result<Unlocked, String> {
    let payload = load_payload(passphrase)?;
    let key_bytes = payload_secret_key_bytes(&payload)?;
    let secret_key = SecretKey::from_byte_array(key_bytes)
        .map_err(|_| "stored secret key is invalid for secp256k1".to_owned())?;
    Ok(Unlocked::from_secret_key(secret_key))
}

/// Re-encrypt the keystore under a new passphrase, keeping the recovery phrase.
pub fn change_passphrase(current: &str, new: &str) -> Result<Unlocked, String> {
    let new = check_passphrase(new)?;
    let payload = load_payload(current)?;
    let key_bytes = payload_secret_key_bytes(&payload)?;
    let derivation_path = if payload.derivation_path.trim().is_empty() {
        DEFAULT_DERIVATION_PATH
    } else {
        payload.derivation_path.as_str()
    };
    let keystore = encrypt_secret_key(
        &key_bytes,
        payload.mnemonic.as_deref(),
        Some(derivation_path),
        new,
    )?;
    save_keystore_file(&storage::encrypted_wallet_path(), &keystore)?;
    let _ = fs::remove_file(storage::legacy_wallet_path());

    let secret_key = SecretKey::from_byte_array(key_bytes)
        .map_err(|_| "stored secret key is invalid for secp256k1".to_owned())?;
    Ok(Unlocked::from_secret_key(secret_key))
}

pub struct SecretExport {
    pub private_key_hex: String,
    pub dat_base64: String,
    pub mnemonic: Option<String>,
}

/// Reveal the secret material behind the keystore. Requires the passphrase.
pub fn export_secret(passphrase: &str) -> Result<SecretExport, String> {
    let payload = load_payload(passphrase)?;
    let key_bytes = payload_secret_key_bytes(&payload)?;
    Ok(SecretExport {
        private_key_hex: hex::encode(key_bytes),
        dat_base64: base64::engine::general_purpose::STANDARD.encode(key_bytes),
        mnemonic: payload.mnemonic.clone(),
    })
}

/// Remove every trace of the wallet from this machine.
pub fn delete() -> Result<(), String> {
    for path in [
        storage::encrypted_wallet_path(),
        storage::legacy_wallet_path(),
        storage::biometric_marker_path(),
    ] {
        if let Err(err) = fs::remove_file(&path)
            && err.kind() != std::io::ErrorKind::NotFound
        {
            return Err(format!("failed to delete {}: {err}", path.display()));
        }
    }
    Ok(())
}

fn check_passphrase(passphrase: &str) -> Result<&str, String> {
    let trimmed = passphrase.trim();
    if trimmed.is_empty() {
        return Err("a wallet passphrase is required".to_owned());
    }
    Ok(trimmed)
}

fn save(secret_key: &SecretKey, mnemonic: Option<&str>, passphrase: &str) -> Result<(), String> {
    storage::ensure_dirs();
    let keystore = encrypt_secret_key(
        &secret_key.secret_bytes(),
        mnemonic,
        Some(DEFAULT_DERIVATION_PATH),
        passphrase,
    )?;
    save_keystore_file(&storage::encrypted_wallet_path(), &keystore)?;
    let _ = fs::remove_file(storage::legacy_wallet_path());
    Ok(())
}

fn load_payload(passphrase: &str) -> Result<WalletSecretPayload, String> {
    let passphrase = check_passphrase(passphrase)?;
    let encrypted = storage::encrypted_wallet_path();
    if encrypted.exists() {
        let keystore = load_keystore_file(&encrypted)?;
        return decrypt_secret_key(&keystore, passphrase);
    }

    let legacy = storage::legacy_wallet_path();
    if legacy.exists() {
        // Plaintext wallets from the very first releases: read the key, write a
        // proper keystore, then carry on as if it had always been encrypted.
        let body = fs::read_to_string(&legacy)
            .map_err(|e| format!("failed to read the legacy wallet file: {e}"))?;
        let bytes = hex::decode(body.trim())
            .map_err(|_| "the legacy wallet file is not 32 bytes of hex".to_owned())?;
        if bytes.len() != 32 {
            return Err("the legacy wallet key must be exactly 32 bytes".to_owned());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        let secret_key = SecretKey::from_byte_array(key)
            .map_err(|_| "the legacy wallet key is invalid for secp256k1".to_owned())?;
        save(&secret_key, None, passphrase)?;
        let keystore = load_keystore_file(&encrypted)?;
        return decrypt_secret_key(&keystore, passphrase);
    }

    Err("no wallet has been created on this machine yet".to_owned())
}
