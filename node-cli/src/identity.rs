use std::collections::HashMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use once_cell::sync::Lazy;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::storage::{read_data_file, write_data_file};

const IDENTITY_KEY_FILE: &str = "node_identity_ed25519.key";

#[derive(Clone)]
pub struct NodeIdentity {
    secret_key: [u8; 32],
    pub public_key_hex: String,
    pub node_id: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct IdentityPayload {
    #[serde(default)]
    secret_key_hex: String,
    #[serde(default)]
    public_key_hex: String,
    #[serde(default)]
    node_id: String,
}

pub static NODE_IDENTITY: Lazy<NodeIdentity> = Lazy::new(load_or_create_identity);

fn keypair_from_secret(secret_key: &[u8; 32]) -> (SigningKey, VerifyingKey) {
    let signing = SigningKey::from_bytes(secret_key);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

fn node_id_from_pubkey_bytes(pubkey: &[u8]) -> String {
    hex::encode(Sha256::digest(pubkey))
}

fn load_or_create_identity() -> NodeIdentity {
    if let Ok(Some(raw)) = read_data_file(IDENTITY_KEY_FILE) {
        if let Ok(payload) = serde_json::from_str::<IdentityPayload>(&raw) {
            if let Ok(bytes) = hex::decode(payload.secret_key_hex.trim()) {
                if bytes.len() == 32 {
                    let mut secret = [0u8; 32];
                    secret.copy_from_slice(&bytes);
                    let (_signing, verifying) = keypair_from_secret(&secret);
                    let public_bytes = verifying.to_bytes();
                    let public_key_hex = hex::encode(public_bytes);
                    let node_id = node_id_from_pubkey_bytes(&public_bytes);
                    return NodeIdentity {
                        secret_key: secret,
                        public_key_hex,
                        node_id,
                    };
                }
            }
        }
    }

    let mut secret = [0u8; 32];
    rand::rng().fill_bytes(&mut secret);
    let (_signing, verifying) = keypair_from_secret(&secret);
    let public_bytes = verifying.to_bytes();
    let public_key_hex = hex::encode(public_bytes);
    let node_id = node_id_from_pubkey_bytes(&public_bytes);

    let payload = IdentityPayload {
        secret_key_hex: hex::encode(secret),
        public_key_hex: public_key_hex.clone(),
        node_id: node_id.clone(),
    };

    if let Ok(serialized) = serde_json::to_string_pretty(&payload) {
        if let Err(e) = write_data_file(IDENTITY_KEY_FILE, &serialized) {
            eprintln!("[STARTUP] Failed to persist node identity key: {}", e);
        }
    }

    NodeIdentity {
        secret_key: secret,
        public_key_hex,
        node_id,
    }
}

pub fn node_id() -> String {
    NODE_IDENTITY.node_id.clone()
}

pub fn public_key_hex() -> String {
    NODE_IDENTITY.public_key_hex.clone()
}

pub fn sign_message(message: &[u8]) -> String {
    let (signing, _verifying) = keypair_from_secret(&NODE_IDENTITY.secret_key);
    let signature = signing.sign(message);
    hex::encode(signature.to_bytes())
}

pub fn verify_signature(public_key_hex: &str, message: &[u8], signature_hex: &str) -> bool {
    let Ok(pub_bytes) = hex::decode(public_key_hex.trim()) else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(signature_hex.trim()) else {
        return false;
    };
    let Ok(pub_arr) = <[u8; 32]>::try_from(pub_bytes.as_slice()) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
        return false;
    };
    let Ok(verifying) = VerifyingKey::from_bytes(&pub_arr) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_arr);
    verifying.verify(message, &signature).is_ok()
}

pub fn node_id_from_pubkey_hex(public_key_hex: &str) -> Option<String> {
    let bytes = hex::decode(public_key_hex.trim()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    Some(node_id_from_pubkey_bytes(&bytes))
}

pub fn pin_matches_or_insert(
    pins: &mut HashMap<String, String>,
    peer: &str,
    public_key_hex: &str,
) -> bool {
    if let Some(existing) = pins.get(peer) {
        existing == public_key_hex
    } else {
        pins.insert(peer.to_string(), public_key_hex.to_string());
        true
    }
}
