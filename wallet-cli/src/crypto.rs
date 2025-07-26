use secp256k1::{Keypair, PublicKey};
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