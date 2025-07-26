// src/vanity.rs
use crate::crypto::{generate_keypair, public_key_to_lofswap_address};
use secp256k1::{Keypair, PublicKey};
use rand::rngs::OsRng;
use rayon::prelude::*;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::Instant;

pub struct VanityResult {
    pub address: String,
    pub keypair: Keypair,
}

pub fn generate_vanity_address(
    starts_with: Option<&str>,
    ends_with: Option<&str>,
    max_attempts: Option<u64>,
) -> VanityResult {
    let found = Arc::new(AtomicBool::new(false));
    let start_time = Instant::now();

    (0..)
        .into_par_iter()
        .take_while(|_| !found.load(Ordering::Relaxed))
        .map(|_| {
            let mut csprng = OsRng;
            let keypair = generate_keypair(&mut csprng);
            let address = public_key_to_lofswap_address(&keypair.public);
            (address, keypair)
        })
        .filter_map(|(address, keypair)| {
            let valid = starts_with.map_or(true, |prefix| address.starts_with(prefix))
                && ends_with.map_or(true, |suffix| address.ends_with(suffix));

            if valid {
                found.store(true, Ordering::Relaxed);
                Some(VanityResult { address, keypair })
            } else {
                None
            }
        })
        .next()
        .expect("Could not generate matching vanity address")
}

// src/crypto.rs
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, SECRET_KEY_LENGTH};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use bs58;

pub fn generate_keypair(rng: &mut OsRng) -> Keypair {
    Keypair::generate(rng)
}

pub fn public_key_to_lofswap_address(pubkey: &PublicKey) -> String {
    let hash = Sha256::digest(pubkey.as_bytes());
    let address = bs58::encode(&hash[..20]).into_string();
    format!("LFS{}", address)
}
