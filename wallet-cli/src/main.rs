mod crypto;
mod vanity;

use clap::{App, Arg, ArgMatches};
use vanity::generate_vanity_address;
use std::fs::File;
use std::io::Write;
use secp256k1::Keypair;

fn save_wallet(keypair: &Keypair, address: &str) {
    let wallet_json = serde_json::json!({
        "private_key": base64::encode(keypair.secret.to_bytes()),
        "public_key": base64::encode(keypair.public.as_bytes()),
        "address": address
    });

    let mut file = File::create("wallet.json").expect("Could not create wallet.json");
    file.write_all(wallet_json.to_string().as_bytes()).expect("Could not write wallet.json");
    println!("✅ Wallet saved to wallet.json");
}

fn main() {
    let matches = App::new("wallet-cli")
        .version("1.0")
        .about("Lofswap wallet CLI")
        .arg(Arg::new("starts-with")
            .long("starts-with")
            .takes_value(true)
            .help("Desired prefix for the address"))
        .arg(Arg::new("ends-with")
            .long("ends-with")
            .takes_value(true)
            .help("Desired suffix for the address"))
        .get_matches();

    let starts_with = matches.value_of("starts-with");
    let ends_with = matches.value_of("ends-with");

    println!("🔄 Generating vanity address...");
    let result = generate_vanity_address(starts_with, ends_with, None);
    println!("✅ Found vanity address: {}", result.address);

    save_wallet(&result.keypair, &result.address);
}
