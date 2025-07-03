// === /wallet-cli/src/main.rs ===
use blockchain_core::Transaction;
use rand::seq::IndexedRandom;
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message};
use sha2::Digest;
use rand::{thread_rng, seq::SliceRandom};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write, Read};
use std::net::TcpStream;
use std::collections::HashSet;
use hex;
use serde_json;

fn create_wallet() {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut thread_rng());
    println!("Private Key: {}", hex::encode(secret_key.secret_bytes()));
    println!("Public Key: {}", public_key);
}

fn export_wallet(private_key: &str, filename: &str) {
    if let Ok(bytes) = hex::decode(private_key) {
        if let Ok(mut file) = File::create(filename) {
            if file.write_all(&bytes).is_ok() {
                println!("✓ Portfel zapisany do pliku: {}", filename);
                return;
            }
        }
    }
    println!("✗ Nie udało się zapisać portfela");
}

fn import_wallet(key: &str) {
    let secret_key = SecretKey::from_slice(&hex::decode(key).unwrap()).unwrap();
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    println!("Public Key: {}", public_key);
}

fn send_tx(from_priv: &str, to: &str, amount: u64, peers: usize) {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&hex::decode(from_priv).unwrap()).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    let tx_content = format!("{}{}{}", public_key, to, amount);
    let hash = sha2::Sha256::digest(tx_content.as_bytes());
    let msg = Message::from_slice(&hash).unwrap();
    let sig = secp.sign_ecdsa(msg, &secret_key);
    let tx = Transaction {
        from: format!("{}", public_key),
        to: to.to_string(),
        amount,
        signature: hex::encode(sig.serialize_compact()),
    };

    let json = serde_json::to_string(&tx).unwrap();

    if let Ok(file) = File::open("nodes.txt") {
        let reader = BufReader::new(file);
        let all_nodes: Vec<String> = reader.lines().flatten().collect();
        let mut rng = thread_rng();
        let mut sent_to = HashSet::new();

        for node in all_nodes.choose_multiple(&mut rng, peers) {
            if sent_to.contains(node) {
                continue;
            }

            if let Ok(mut stream) = TcpStream::connect(node.trim()) {
                let _ = stream.write_all(json.as_bytes());
                println!("✓ Transakcja wysłana do noda: {}", node.trim());
                sent_to.insert(node.clone());
            }
        }

        if sent_to.is_empty() {
            println!("✗ Nie udało się połączyć z żadnym nodem z nodes.txt");
        }
    } else {
        println!("✗ Brak pliku nodes.txt");
    }
}

fn show_balance(address: &str) {
    let query = format!("/balance/{}", address);
    if let Ok(file) = File::open("nodes.txt") {
        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            if let Ok(mut stream) = TcpStream::connect(line.trim()) {
                let _ = stream.write_all(query.as_bytes());
                let mut buf = String::new();
                if let Ok(_) = stream.read_to_string(&mut buf) {
                    println!("Saldo portfela {}: {}", address, buf.trim());
                    return;
                }
            }
        }
        println!("✗ Nie udało się odczytać salda z żadnego noda");
    } else {
        println!("✗ Brak pliku nodes.txt");
    }
}

fn faucet_transfer(address: &str) {
    let tx = Transaction {
        from: String::from(""),
        to: address.to_string(),
        amount: 1000,
        signature: String::from("reward"),
    };

    let json = serde_json::to_string(&tx).unwrap();
    if let Ok(file) = File::open("nodes.txt") {
        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            if let Ok(mut stream) = TcpStream::connect(line.trim()) {
                let _ = stream.write_all(json.as_bytes());
                println!("✓ Przelano 1000 tokenów do portfela: {}", address);
                return;
            }
        }
        println!("✗ Nie udało się połączyć z żadnym nodem z nodes.txt");
    } else {
        println!("✗ Brak pliku nodes.txt");
    }
}

fn load_default_wallet() -> Option<SecretKey> {
    if let Ok(hex_str) = std::fs::read_to_string(".default_wallet") {
        if let Ok(bytes) = hex::decode(hex_str.trim()) {
            return SecretKey::from_slice(&bytes).ok();
        }
    }
    None
}

fn main() {
    use std::sync::{Arc, Mutex};
    use std::thread;

    let peer_count = Arc::new(Mutex::new(0));
    let count_clone = Arc::clone(&peer_count);

    println!("Wallet CLI – dostępne polecenia: create-wallet, import-wallet <priv>, import-wallet <plik>, export-wallet <priv> <plik>, default-wallet, send <to> <amount> [peers], balance [address], faucet <address>, exit");
    loop {
        print!("> ");
        let _ = io::stdout().flush();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            let args: Vec<&str> = input.trim().split_whitespace().collect();
            if args.is_empty() {
                continue;
            }
            match args[0] {
                "--help" | "help" => {
                    println!("Dostępne polecenia:");
                    println!("  create-wallet");
                    println!("  import-wallet <privatny_klucz>");
                    println!("  import-wallet <plik.dat>");
                    println!("  export-wallet <privatny_klucz> <plik.dat>");
                    println!("  default-wallet");
                    println!("  send <adres_docelowy> <ilość> [liczba_node'ów]");
                    println!("  balance [adres_publiczny]");
                    println!("  faucet <adres_publiczny>");
                    println!("  exit");
                },
                "default-wallet" => {
                    if let Some(sk) = load_default_wallet() {
                        let secp = Secp256k1::new();
                        let pk = PublicKey::from_secret_key(&secp, &sk);
                        println!("Domyślny portfel:");
                        println!("Private Key: {}", hex::encode(sk.secret_bytes()));
                        println!("Public Key: {}", pk);
                    } else {
                        println!("Brak ustawionego domyślnego portfela.");
                    }
                },
                "import-wallet" if args.len() == 2 => {
                    if let Ok(mut file) = File::open(args[1]) {
                        let mut buf = Vec::new();
                        if file.read_to_end(&mut buf).is_ok() {
                            if let Ok(sk) = SecretKey::from_slice(&buf) {
                                std::fs::write(".default_wallet", hex::encode(sk.secret_bytes())).unwrap();
                                let secp = Secp256k1::new();
                                let pk = PublicKey::from_secret_key(&secp, &sk);
                                println!("✓ Portfel z pliku zaimportowany i ustawiony jako domyślny:");
                                println!("Public Key: {}", pk);
                            }
                        }
                    }
                },
                "export-wallet" if args.len() == 3 => export_wallet(args[1], args[2]),
                "create-wallet" => {
                    if std::path::Path::new(".default_wallet").exists() {
                        println!("⚠️  Domyślny portfel już istnieje. Jeśli go nie zapiszesz, środki mogą przepaść.");
                    }
                    let secp = Secp256k1::new();
                    let (secret_key, public_key) = secp.generate_keypair(&mut thread_rng());
                    std::fs::write(".default_wallet", hex::encode(secret_key.secret_bytes())).unwrap();
                    println!("Private Key: {}", hex::encode(secret_key.secret_bytes()));
                    println!("Public Key: {}", public_key);
                },
                "import-wallet" if args.len() == 2 => {
                    let secret_key = SecretKey::from_slice(&hex::decode(args[1]).unwrap()).unwrap();
                    let secp = Secp256k1::new();
                    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
                    std::fs::write(".default_wallet", hex::encode(secret_key.secret_bytes())).unwrap();
                    println!("Public Key: {}", public_key);
                },
                "send" if args.len() >= 3 => {
                    let peers = if args.len() >= 4 {
                        args[3].parse().unwrap_or(2)
                    } else {
                        2
                    };
                    let to = args[1];
                    let amount = args[2].parse().unwrap_or(0);
                    if let Some(sk) = load_default_wallet() {
                        send_tx(&hex::encode(sk.secret_bytes()), to, amount, peers);
                    } else {
                        println!("✗ Brak załadowanego domyślnego portfela.");
                    }
                },
                "balance" if args.len() == 2 => show_balance(args[1]),
                "balance" => {
                    if let Some(sk) = load_default_wallet() {
                        let secp = Secp256k1::new();
                        let pk = PublicKey::from_secret_key(&secp, &sk);
                        show_balance(&format!("{}", pk));
                    } else {
                        println!("✗ Brak załadowanego domyślnego portfela.");
                    }
                },
                "export-wallet" if args.len() == 3 => export_wallet(args[1], args[2]),
                "create-wallet" => create_wallet(),
                "import-wallet" if args.len() == 2 => import_wallet(args[1]),
                "send" if args.len() >= 4 => {
                    let peers = if args.len() >= 5 {
                        args[4].parse().unwrap_or(2)
                    } else {
                        2
                    };
                    send_tx(args[1], args[2], args[3].parse().unwrap_or(0), peers)
                },
                "balance" if args.len() == 2 => show_balance(args[1]),
                "faucet" if args.len() == 2 => faucet_transfer(args[1]),
                "exit" => break,
                _ => println!("Nieznane polecenie lub błędne argumenty"),
            }
        }
    }
}