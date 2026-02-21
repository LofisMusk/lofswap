use std::{fs::OpenOptions, io::Write, path::Path};

use argon2::{Algorithm, Argon2, Params, Version};
use bip39::{Language, Mnemonic};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use chrono::Utc;
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

const KEYSTORE_VERSION: u8 = 1;
const CIPHER_NAME: &str = "xchacha20poly1305";
const KDF_NAME: &str = "argon2id";
const KEYSTORE_AAD: &[u8] = b"lofswap-keystore-v1";
const KDF_MEMORY_KIB: u32 = 64 * 1024;
const KDF_TIME_COST: u32 = 3;
const KDF_PARALLELISM: u32 = 1;
const KDF_SALT_LEN: usize = 16;
const CIPHER_NONCE_LEN: usize = 24;
pub const DEFAULT_DERIVATION_PATH: &str = "m/44'/1412'/0'/0/0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub salt_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeystore {
    pub version: u8,
    pub cipher: String,
    pub kdf: String,
    pub kdf_params: KdfParams,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSecretPayload {
    pub secret_key_hex: String,
    #[serde(default)]
    pub mnemonic: Option<String>,
    #[serde(default)]
    pub derivation_path: String,
    pub created_at: i64,
}

fn derive_kdf_key(
    password: &str,
    params: &KdfParams,
    out_key: &mut [u8; 32],
) -> Result<(), String> {
    let salt = hex::decode(&params.salt_hex).map_err(|e| format!("invalid kdf salt: {}", e))?;
    let argon_params = Params::new(
        params.memory_kib,
        params.time_cost,
        params.parallelism,
        Some(out_key.len()),
    )
    .map_err(|e| format!("invalid argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    argon2
        .hash_password_into(password.as_bytes(), &salt, out_key)
        .map_err(|e| format!("argon2id failed: {}", e))
}

pub fn generate_mnemonic_12() -> Result<String, String> {
    let mut entropy = [0u8; 16];
    rand::rng().fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| format!("mnemonic generation failed: {}", e))?
        .to_string();
    entropy.zeroize();
    Ok(mnemonic)
}

pub fn derive_secret_key_from_mnemonic(
    mnemonic: &str,
    mnemonic_passphrase: &str,
    derivation_path: &str,
) -> Result<[u8; 32], String> {
    let parsed = Mnemonic::parse_in_normalized(Language::English, mnemonic)
        .map_err(|e| format!("invalid mnemonic: {}", e))?;
    let seed = parsed.to_seed_normalized(mnemonic_passphrase);
    let path = if derivation_path.trim().is_empty() {
        DEFAULT_DERIVATION_PATH
    } else {
        derivation_path
    };
    let salt = format!("{}|{}", crate::CHAIN_ID, path);
    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), &seed);
    let mut out = [0u8; 32];
    hkdf.expand(b"lofswap-wallet-secp256k1", &mut out)
        .map_err(|_| "hkdf derivation failed".to_string())?;
    if out.iter().all(|b| *b == 0) {
        out[31] = 1;
    }
    Ok(out)
}

pub fn encrypt_secret_key(
    secret_key_bytes: &[u8; 32],
    mnemonic: Option<&str>,
    derivation_path: Option<&str>,
    password: &str,
) -> Result<EncryptedKeystore, String> {
    if password.is_empty() {
        return Err("wallet passphrase cannot be empty".to_string());
    }

    let mut salt = [0u8; KDF_SALT_LEN];
    let mut nonce = [0u8; CIPHER_NONCE_LEN];
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce);

    let params = KdfParams {
        memory_kib: KDF_MEMORY_KIB,
        time_cost: KDF_TIME_COST,
        parallelism: KDF_PARALLELISM,
        salt_hex: hex::encode(salt),
    };

    let mut key = [0u8; 32];
    derive_kdf_key(password, &params, &mut key)?;

    let nonce_hex = hex::encode(nonce);
    let payload = WalletSecretPayload {
        secret_key_hex: hex::encode(secret_key_bytes),
        mnemonic: mnemonic.map(|m| m.to_string()),
        derivation_path: derivation_path
            .unwrap_or(DEFAULT_DERIVATION_PATH)
            .to_string(),
        created_at: Utc::now().timestamp(),
    };

    let mut plaintext = serde_json::to_vec(&payload)
        .map_err(|e| format!("keystore serialize payload failed: {}", e))?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: KEYSTORE_AAD,
            },
        )
        .map_err(|_| "keystore encryption failed".to_string())?;

    plaintext.zeroize();
    key.zeroize();
    salt.zeroize();
    nonce.zeroize();

    Ok(EncryptedKeystore {
        version: KEYSTORE_VERSION,
        cipher: CIPHER_NAME.to_string(),
        kdf: KDF_NAME.to_string(),
        kdf_params: params,
        nonce_hex,
        ciphertext_hex: hex::encode(ciphertext),
    })
}

pub fn decrypt_secret_key(
    keystore: &EncryptedKeystore,
    password: &str,
) -> Result<WalletSecretPayload, String> {
    if keystore.version != KEYSTORE_VERSION {
        return Err(format!("unsupported keystore version {}", keystore.version));
    }
    if keystore.cipher != CIPHER_NAME {
        return Err(format!("unsupported keystore cipher {}", keystore.cipher));
    }
    if keystore.kdf != KDF_NAME {
        return Err(format!("unsupported keystore kdf {}", keystore.kdf));
    }
    if password.is_empty() {
        return Err("wallet passphrase cannot be empty".to_string());
    }

    let nonce = hex::decode(&keystore.nonce_hex).map_err(|e| format!("invalid nonce: {}", e))?;
    if nonce.len() != CIPHER_NONCE_LEN {
        return Err("invalid nonce length".to_string());
    }
    let ciphertext =
        hex::decode(&keystore.ciphertext_hex).map_err(|e| format!("invalid ciphertext: {}", e))?;

    let mut key = [0u8; 32];
    derive_kdf_key(password, &keystore.kdf_params, &mut key)?;

    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: KEYSTORE_AAD,
            },
        )
        .map_err(|_| "keystore decryption failed (wrong passphrase?)".to_string())?;
    key.zeroize();

    let payload = serde_json::from_slice::<WalletSecretPayload>(&plaintext)
        .map_err(|e| format!("invalid keystore payload: {}", e))?;
    plaintext.zeroize();
    Ok(payload)
}

pub fn save_keystore_file(path: &Path, keystore: &EncryptedKeystore) -> Result<(), String> {
    let body = serde_json::to_string_pretty(keystore)
        .map_err(|e| format!("serialize keystore failed: {}", e))?;
    let mut opts = OpenOptions::new();
    opts.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .map_err(|e| format!("keystore write failed: {}", e))?;
    file.write_all(body.as_bytes())
        .map_err(|e| format!("keystore write failed: {}", e))
}

pub fn load_keystore_file(path: &Path) -> Result<EncryptedKeystore, String> {
    let body = std::fs::read_to_string(path).map_err(|e| format!("keystore read failed: {}", e))?;
    serde_json::from_str::<EncryptedKeystore>(&body)
        .map_err(|e| format!("keystore parse failed: {}", e))
}

pub fn payload_secret_key_bytes(payload: &WalletSecretPayload) -> Result<[u8; 32], String> {
    let decoded = hex::decode(payload.secret_key_hex.trim())
        .map_err(|e| format!("invalid secret key hex: {}", e))?;
    if decoded.len() != 32 {
        return Err("invalid secret key length".to_string());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}
