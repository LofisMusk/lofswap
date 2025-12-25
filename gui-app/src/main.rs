use blockchain_core::{Block, Transaction};
use eframe::{egui, NativeOptions};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Default, Clone, Serialize, Deserialize)]
struct NodeIp {
    pub r#public: Option<String>,
    pub private: Option<String>,
}

struct App {
    status: String,
    node_child: Option<Child>,
    last_refresh: Instant,
    // Node state
    peers: Vec<String>,
    peers_status: Vec<(String, bool)>,
    mempool: Vec<Transaction>,
    latest_tx: Option<Transaction>,
    height: usize,
    chain: Vec<Block>,
    ip: NodeIp,
    // Wallet state
    public_key: Option<String>,
    show_priv: bool,
    private_key: Option<String>,
    address: Option<String>,
    balance: Option<i128>,
    history: Vec<Transaction>,
    pending_count: usize,
    // Inputs
    peer_input: String,
    to_input: String,
    amount_input: String,
    import_priv_input: String,
}

impl App {
    fn new() -> Self {
        Self::default()
    }
}

impl Default for App {
    fn default() -> Self {
        Self {
            status: String::new(),
            node_child: None,
            last_refresh: Instant::now() - Duration::from_secs(10),
            peers: Vec::new(),
            peers_status: Vec::new(),
            mempool: Vec::new(),
            latest_tx: None,
            height: 0,
            chain: Vec::new(),
            ip: NodeIp::default(),
            public_key: None,
            show_priv: false,
            private_key: None,
            address: None,
            balance: None,
            history: Vec::new(),
            pending_count: 0,
            peer_input: String::new(),
            to_input: String::new(),
            amount_input: String::new(),
            import_priv_input: String::new(),
        }
    }
}

fn main() -> eframe::Result<()> {
    // Try to spawn the node-cli process
    let child = spawn_node().ok();
    let native = NativeOptions::default();
    eframe::run_native(
        "Lofswap – Node & Wallet",
        native,
        Box::new(move |_cc| {
            let mut app = App::new();
            app.status = "Starting node…".into();
            app.node_child = child;
            Ok(Box::new(app))
        }),
    )
}

fn spawn_node() -> anyhow::Result<Child> {
    // Prefer finding "node-cli" on PATH, else fallback to target/debug
    let mut tried = vec![];
    let candidates = [
        "node-cli",
        "./target/debug/node-cli",
        "./target/release/node-cli",
    ];
    for c in candidates {
        tried.push(c.to_string());
        let mut cmd = Command::new(c);
        cmd.env("EXPLORER_BIND_ADDR", "127.0.0.1");
        cmd.env("BIND_ADDR", "0.0.0.0");
        cmd.arg("--no-peer-exchange");
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Ok(child) = cmd.spawn() {
            return Ok(child);
        }
    }
    anyhow::bail!(format!("failed to start node-cli. Tried: {:?}", tried))
}

fn http_request(method: &str, path: &str, body: Option<&[u8]>) -> Option<Vec<u8>> {
    let addr: SocketAddr = "127.0.0.1:7000".parse().ok()?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(2_000)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(2_000)));
    let body_bytes: &[u8] = body.unwrap_or(&[]);
    let headers =
        format!(
        "{} {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n{}\r\n",
        method,
        path,
        body_bytes.len(),
        if body.is_some() { "Content-Type: application/json\r\n" } else { "" }
    );
    if stream.write_all(headers.as_bytes()).is_err() {
        return None;
    }
    if !body_bytes.is_empty() {
        if stream.write_all(body_bytes).is_err() {
            return None;
        }
    }
    let mut buf = Vec::new();
    if stream.read_to_end(&mut buf).is_err() {
        return None;
    }
    // Split headers and body
    fn find_double_crlf(data: &[u8]) -> Option<usize> {
        let pat = b"\r\n\r\n";
        if data.len() < 4 {
            return None;
        }
        for i in 0..=data.len() - 4 {
            if &data[i..i + 4] == pat {
                return Some(i);
            }
        }
        None
    }
    if let Some(i) = find_double_crlf(&buf) {
        Some(buf[i + 4..].to_vec())
    } else {
        Some(buf)
    }
}

fn http_get_json<T: for<'de> Deserialize<'de>>(path: &str) -> Option<T> {
    let b = http_request("GET", path, None)?;
    serde_json::from_slice(&b).ok()
}
fn http_post_json<B: Serialize, T: for<'de> Deserialize<'de>>(path: &str, body: &B) -> Option<T> {
    let payload = serde_json::to_vec(body).ok()?;
    let b = http_request("POST", path, Some(&payload))?;
    serde_json::from_slice(&b).ok()
}
fn http_post(path: &str) -> bool {
    http_request("POST", path, Some(&[])).is_some()
}
fn http_delete(path: &str) -> bool {
    http_request("DELETE", path, None).is_some()
}
fn http_get_bytes(path: &str) -> Option<Vec<u8>> {
    http_request("GET", path, None)
}

fn base58(bytes: &[u8]) -> String {
    const ALPH: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits = vec![0u8];
    for &b in bytes {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            let v = (*d as u32) * 256 + carry;
            *d = (v % 58) as u8;
            carry = v / 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    digits
        .iter()
        .rev()
        .map(|&d| ALPH[d as usize] as char)
        .collect::<String>()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn derive_address(pubkey: &str) -> String {
    let hash = sha256(pubkey.as_bytes());
    format!("LFS{}", base58(&hash[..20]))
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // periodic refresh
        if self.last_refresh.elapsed() > Duration::from_millis(750) {
            // Node data
            self.peers = http_get_json::<Vec<String>>("/peers").unwrap_or_default();
            #[derive(Deserialize)]
            struct PeerStatus {
                peer: String,
                online: bool,
            }
            #[derive(Deserialize)]
            struct PeerStatusList {
                list: Vec<PeerStatus>,
            }
            self.peers_status = http_get_json::<PeerStatusList>("/peers/status")
                .map(|x| x.list.into_iter().map(|p| (p.peer, p.online)).collect())
                .unwrap_or_default();
            self.mempool = http_get_json::<Vec<Transaction>>("/mempool").unwrap_or_default();
            self.latest_tx =
                http_get_json::<Option<Transaction>>("/chain/latest-tx").unwrap_or(None);
            #[derive(Deserialize)]
            struct Height {
                height: usize,
            }
            self.height = http_get_json::<Height>("/height")
                .map(|h| h.height)
                .unwrap_or(0);
            self.chain = http_get_json::<Vec<Block>>("/chain").unwrap_or_default();
            self.ip = http_get_json::<NodeIp>("/node/ip").unwrap_or_default();

            // Wallet
            #[derive(Deserialize)]
            struct Info {
                public_key: Option<String>,
            }
            let info = http_get_json::<Info>("/wallet/info").unwrap_or(Info { public_key: None });
            self.public_key = info.public_key.clone();
            if let Some(pk) = info.public_key {
                let addr = derive_address(&pk);
                self.address = Some(addr.clone());
                #[derive(Deserialize)]
                struct Bal {
                    balance: i128,
                }
                self.balance =
                    http_get_json::<Bal>(&format!("/address/{}/balance", addr)).map(|b| b.balance);
                self.history = http_get_json::<Vec<Transaction>>(&format!("/address/{}/txs", addr))
                    .unwrap_or_default();
            } else {
                self.address = None;
                self.balance = None;
                self.history.clear();
            }
            #[derive(Deserialize)]
            struct PC {
                count: usize,
            }
            self.pending_count = http_get_json::<PC>("/wallet/pending-count")
                .map(|p| p.count)
                .unwrap_or(0);

            self.status.clear();
            self.last_refresh = Instant::now();
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Lofswap – Node & Wallet");
                if !self.status.is_empty() {
                    ui.label(self.status.clone());
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Refresh").clicked() {
                        self.last_refresh = Instant::now() - Duration::from_secs(999);
                    }
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.columns(2, |cols| {
                // Node column
                let ui = &mut cols[0];
                ui.group(|ui| {
                    ui.heading("Node");
                    ui.horizontal(|ui| {
                        if ui.button("Mine block").clicked() { let _ = http_post("/mine"); }
                        ui.label(format!("Peers: {}", self.peers.len()));
                    });
                    if let Some(pubip) = &self.ip.r#public { ui.label(format!("Public IP: {}", pubip)); }
                    if let Some(privip) = &self.ip.private { ui.label(format!("Private IP: {}", privip)); }

                    ui.separator();
                    ui.label("Peers");
                    ui.horizontal(|ui| {
                        ui.text_edit_singleline(&mut self.peer_input);
                        if ui.button("Add").clicked() { let body = serde_json::json!({"peer": self.peer_input}); let _: Option<serde_json::Value> = http_post_json("/peers/add", &body); }
                        if ui.button("Remove").clicked() { let body = serde_json::json!({"peer": self.peer_input}); let _: Option<serde_json::Value> = http_post_json("/peers/remove", &body); }
                    });
                    egui::ScrollArea::vertical().id_source("peers_scroll").max_height(140.0).show(ui, |ui| {
                        for (peer, online) in self.peers_status.iter() {
                            ui.label(format!("{}  {}", if *online {"[online]"} else {"[off]"}, peer));
                        }
                    });

                    ui.separator();
                    ui.label("Mempool");
                    egui::ScrollArea::vertical().id_source("mempool_scroll").max_height(140.0).show(ui, |ui| {
                        for tx in &self.mempool { ui.label(format!("{} -> {}  amount: {}", if tx.from.is_empty(){"(reward)"} else {&tx.from}, tx.to, tx.amount)); }
                    });

                    ui.separator();
                    ui.label(format!("Height: {}", self.height));
                    if let Some(tx) = &self.latest_tx { ui.label(format!("Latest TX: {} -> {} ({})", tx.from, tx.to, tx.amount)); }
                });

                // Wallet column
                let ui = &mut cols[1];
                ui.group(|ui| {
                    ui.heading("Wallet");
                    ui.horizontal(|ui| {
                        if ui.button("Create").clicked() { let _: Option<serde_json::Value> = http_post_json("/wallet/create", &serde_json::json!({})); }
                        if ui.button("Remove").clicked() { let _ = http_delete("/wallet"); }
                        if ui.button("Export .dat").clicked() {
                            if let Some(path) = rfd::FileDialog::new().set_title("Save wallet.dat").set_file_name("wallet.dat").save_file() {
                                if let Some(bytes) = http_get_bytes("/wallet/export-dat") {
                                    let _ = std::fs::write(path, bytes);
                                }
                            }
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.text_edit_singleline(&mut self.import_priv_input);
                        if ui.button("Import private hex").clicked() { let body = serde_json::json!({"priv_hex": self.import_priv_input}); let _: Option<serde_json::Value> = http_post_json("/wallet/import-priv", &body); }
                    });
                    if ui.button("Import .dat file").clicked() {
                        if let Some(path) = rfd::FileDialog::new().set_title("Open wallet.dat").pick_file() {
                            if let Ok(bytes) = std::fs::read(path) {
                                let hex = bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                                let body = serde_json::json!({"dat_hex": hex}); let _: Option<serde_json::Value> = http_post_json("/wallet/import-dat", &body);
                            }
                        }
                    }

                    ui.separator();
                    if let Some(pk) = &self.public_key { ui.label(format!("Public: {}", pk)); }
                    if ui.button("Reveal keys…").clicked() { self.show_priv = true; }
                    if self.show_priv {
                        #[derive(Deserialize)] struct Keys { public_key: Option<String>, private_key: Option<String> }
                        if let Some(k) = http_get_json::<Keys>("/wallet/keys?confirm=true") { self.private_key = k.private_key; }
                        if let Some(sk) = &self.private_key { ui.monospace(format!("Private: {}", sk)); }
                    }
                    if let Some(addr) = &self.address { ui.label(format!("Address: {}", addr)); }
                    if let Some(bal) = self.balance { ui.label(format!("Balance: {}", bal)); }

                    ui.separator();
                    ui.label("Send transaction");
                    ui.horizontal(|ui| {
                        ui.text_edit_singleline(&mut self.to_input);
                        ui.text_edit_singleline(&mut self.amount_input);
                        if ui.button("Send").clicked() {
                            if let Ok(amt) = self.amount_input.parse::<u64>() {
                                let body = serde_json::json!({"to": self.to_input, "amount": amt, "min_peers": 2});
                                let _: Option<serde_json::Value> = http_post_json("/wallet/send", &body);
                            }
                        }
                    });
                    if ui.button(format!("Flush pending ({} queued)", self.pending_count)).clicked() { let _: Option<serde_json::Value> = http_post_json("/wallet/flush", &serde_json::json!({})); }

                    ui.separator();
                    ui.label("History");
                    egui::ScrollArea::vertical().id_source("history_scroll").max_height(160.0).show(ui, |ui| {
                        if let Some(addr) = &self.address {
                            for tx in &self.history {
                                let dir = if tx.to == *addr {"IN"} else {"OUT"};
                                ui.label(format!("{}  {}  amount:{}", dir, if dir=="IN" { &tx.from } else { &tx.to }, tx.amount));
                            }
                        }
                    });
                });
            });
        });
    }
}
