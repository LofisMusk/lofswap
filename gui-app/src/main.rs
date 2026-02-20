use blockchain_core::{pubkey_to_address, Block, Transaction, TxKind, CHAIN_ID};
use chrono::Utc;
use eframe::{egui, CreationContext, NativeOptions};
use rand::{seq::IndexedRandom, RngCore};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::{Duration, Instant},
};

const BOOTSTRAP_NODES: &[&str] = &["89.168.107.239:6000", "79.76.116.108:6000"];
const DEFAULT_WALLET: &str = ".default_wallet";
const MEMPOOL_FILE: &str = "wallet_mempool.json";
const WALLET_CACHE_DIR: &str = "wallet-cache";
const PEER_CACHE_FILE: &str = "wallet-cache/peers_cache.json";
const CONNECT_TIMEOUT: Duration = Duration::from_millis(900);
const WHOAMI_TIMEOUT: Duration = Duration::from_millis(350);
const REFRESH_CONNECT_TIMEOUT: Duration = Duration::from_millis(250);
const PROBE_TIMEOUT: Duration = Duration::from_millis(120);
const OFFLINE_GRACE: Duration = Duration::from_secs(10);
const REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const MIN_BROADCAST_PEERS: usize = 2;
const MAX_EVENT_LOG: usize = 8;
const DEFAULT_TX_FEE: u64 = 1;

#[derive(Clone)]
struct HistoryRow {
    direction: &'static str,
    counterparty: String,
    amount: u64,
    timestamp: i64,
    txid: String,
}

#[derive(Default)]
struct WalletSnapshot {
    pubkey: Option<String>,
    privkey: Option<String>,
    address: Option<String>,
    balance: Option<i128>,
}

#[derive(Clone)]
struct RefreshRequest {
    id: u64,
    peers: Vec<String>,
    address: Option<String>,
    discover: bool,
}

struct RefreshResult {
    id: u64,
    discovered_peers: Vec<String>,
    online_peers: Vec<String>,
    balance: Option<i128>,
    history: Vec<HistoryRow>,
}

struct PeerStore {
    peers: Vec<String>,
    offline_since: HashMap<String, Instant>,
}

impl PeerStore {
    fn load() -> Self {
        let _ = fs::create_dir_all(WALLET_CACHE_DIR);

        let mut peers: Vec<String> = BOOTSTRAP_NODES.iter().map(|p| p.to_string()).collect();

        let local_port = std::env::var("WALLET_LOCAL_PORT")
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(6000);
        let local_node = std::env::var("WALLET_LOCAL_NODE")
            .ok()
            .unwrap_or_else(|| format!("127.0.0.1:{local_port}"));

        if is_valid_peer(&local_node) && !peers.contains(&local_node) {
            peers.push(local_node);
        }

        if let Ok(contents) = fs::read_to_string(peer_cache_path()) {
            if let Ok(cached) = serde_json::from_str::<Vec<String>>(&contents) {
                for p in cached {
                    if is_valid_peer(&p) && !peers.contains(&p) {
                        peers.push(p);
                    }
                }
            }
        }

        Self {
            peers,
            offline_since: HashMap::new(),
        }
    }

    fn save(&self) {
        let _ = fs::create_dir_all(WALLET_CACHE_DIR);
        let body = serde_json::to_string_pretty(&self.peers).unwrap_or_default();
        let _ = fs::write(peer_cache_path(), body);
    }

    fn as_slice(&self) -> &[String] {
        &self.peers
    }

    fn add_peer(&mut self, peer: &str) -> Result<(), String> {
        if !is_valid_peer(peer) {
            return Err("invalid peer format (expected ip:port)".to_string());
        }
        let entry = peer.to_string();
        if !self.peers.contains(&entry) {
            self.peers.push(entry);
        }
        Ok(())
    }

    fn remove_peer(&mut self, peer: &str) {
        self.peers.retain(|p| p != peer);
        self.offline_since.remove(peer);
    }

    fn discover(&mut self) {
        let candidates: Vec<String> = self
            .peers
            .iter()
            .cloned()
            .chain(BOOTSTRAP_NODES.iter().map(|p| p.to_string()))
            .collect();

        for peer in candidates {
            let Some(bytes) = send_request(&peer, b"/peers", REFRESH_CONNECT_TIMEOUT) else {
                continue;
            };
            let Ok(list) = serde_json::from_slice::<Vec<String>>(&bytes) else {
                continue;
            };
            for item in list {
                if is_valid_peer(&item) && !self.peers.contains(&item) {
                    self.peers.push(item);
                }
            }
        }
    }

    fn refresh_online(&mut self) -> Vec<String> {
        let mut online = Vec::new();
        let mut to_remove = Vec::new();

        for peer in self.peers.clone() {
            if probe_peer_with_timeout(&peer, PROBE_TIMEOUT) {
                online.push(peer.clone());
                self.offline_since.remove(&peer);
            } else {
                let since = self
                    .offline_since
                    .entry(peer.clone())
                    .or_insert_with(Instant::now);
                if since.elapsed() >= OFFLINE_GRACE {
                    to_remove.push(peer);
                }
            }
        }

        if !to_remove.is_empty() {
            self.peers.retain(|p| !to_remove.contains(p));
            for peer in to_remove {
                self.offline_since.remove(&peer);
            }
        }

        online
    }

    fn online_peers(&mut self) -> Vec<String> {
        self.discover();
        dedupe_peers_by_identity(self.refresh_online())
    }
}

enum PeerIdentity {
    SameChain(String),
    DifferentChain,
    Unknown,
}

struct WalletApp {
    peers: PeerStore,
    online_peers: Vec<String>,
    wallet: WalletSnapshot,
    history: Vec<HistoryRow>,
    events: Vec<String>,
    last_refresh: Instant,

    peer_input: String,
    to_input: String,
    amount_input: String,
    min_peers_input: String,
    import_priv_input: String,
    show_private: bool,

    refresh_tx: Sender<RefreshRequest>,
    refresh_rx: Receiver<RefreshResult>,
    refresh_in_flight: bool,
    pending_refresh_id: Option<u64>,
    next_refresh_id: u64,
}

impl WalletApp {
    fn new(cc: &CreationContext<'_>) -> Self {
        apply_theme(&cc.egui_ctx);

        let (refresh_tx, worker_rx) = mpsc::channel::<RefreshRequest>();
        let (worker_tx, refresh_rx) = mpsc::channel::<RefreshResult>();
        spawn_refresh_worker(worker_rx, worker_tx);

        let mut app = Self {
            peers: PeerStore::load(),
            online_peers: Vec::new(),
            wallet: WalletSnapshot::default(),
            history: Vec::new(),
            events: Vec::new(),
            last_refresh: Instant::now() - REFRESH_INTERVAL,
            peer_input: String::new(),
            to_input: String::new(),
            amount_input: String::new(),
            min_peers_input: MIN_BROADCAST_PEERS.to_string(),
            import_priv_input: String::new(),
            show_private: false,
            refresh_tx,
            refresh_rx,
            refresh_in_flight: false,
            pending_refresh_id: None,
            next_refresh_id: 1,
        };
        app.reload_wallet();
        app.refresh_all(true);
        app
    }

    fn push_event(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        self.events.insert(0, msg);
        self.events.truncate(MAX_EVENT_LOG);
    }

    fn reload_wallet(&mut self) {
        self.wallet.privkey = None;
        if let Some(sk) = load_default_wallet() {
            let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
            self.wallet.pubkey = Some(pk.to_string());
            self.wallet.address = Some(pubkey_to_address(&pk.to_string()));
            if self.show_private {
                self.wallet.privkey = Some(hex::encode(sk.secret_bytes()));
            }
        } else {
            self.wallet.pubkey = None;
            self.wallet.address = None;
            self.wallet.balance = None;
            self.history.clear();
        }
    }

    fn poll_refresh_results(&mut self) {
        while let Ok(result) = self.refresh_rx.try_recv() {
            if self.pending_refresh_id != Some(result.id) {
                continue;
            }
            self.refresh_in_flight = false;
            self.pending_refresh_id = None;

            let mut new_peer_added = false;
            for peer in result.discovered_peers {
                if is_valid_peer(&peer) && !self.peers.peers.contains(&peer) {
                    self.peers.peers.push(peer);
                    new_peer_added = true;
                }
            }
            if new_peer_added {
                self.peers.save();
            }

            self.online_peers = result.online_peers;
            self.wallet.balance = result.balance;
            self.history = result.history;
        }
    }

    fn refresh_all(&mut self, force: bool) {
        self.poll_refresh_results();

        if !force && self.last_refresh.elapsed() < REFRESH_INTERVAL {
            return;
        }
        if self.refresh_in_flight {
            return;
        }

        let id = self.next_refresh_id;
        self.next_refresh_id = self.next_refresh_id.saturating_add(1);

        let request = RefreshRequest {
            id,
            peers: self.peers.as_slice().to_vec(),
            address: self.wallet.address.clone(),
            discover: force,
        };

        if self.refresh_tx.send(request).is_ok() {
            self.refresh_in_flight = true;
            self.pending_refresh_id = Some(id);
            self.last_refresh = Instant::now();
        }
    }

    fn create_wallet(&mut self) {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        match SecretKey::from_byte_array(bytes) {
            Ok(sk) => {
                save_default_wallet(&sk);
                self.show_private = false;
                self.reload_wallet();
                self.push_event("Created new wallet and set it as default");
            }
            Err(_) => self.push_event("Failed to create wallet"),
        }
    }

    fn remove_wallet(&mut self) {
        let _ = fs::remove_file(DEFAULT_WALLET);
        self.show_private = false;
        self.reload_wallet();
        self.push_event("Removed default wallet");
    }

    fn import_private_hex(&mut self) {
        let raw = self.import_priv_input.trim();
        let Ok(bytes) = hex::decode(raw) else {
            self.push_event("Invalid hex in private key field");
            return;
        };
        let mut arr = [0u8; 32];
        if bytes.len() != 32 {
            self.push_event("Private key must be exactly 32 bytes");
            return;
        }
        arr.copy_from_slice(&bytes);
        match SecretKey::from_byte_array(arr) {
            Ok(sk) => {
                save_default_wallet(&sk);
                self.show_private = false;
                self.import_priv_input.clear();
                self.reload_wallet();
                self.push_event("Imported private key and set wallet as default");
            }
            Err(_) => self.push_event("Invalid private key value"),
        }
    }

    fn import_dat_file(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Import wallet .dat")
            .pick_file()
        else {
            return;
        };
        let Ok(bytes) = fs::read(path) else {
            self.push_event("Failed to read .dat file");
            return;
        };
        if bytes.len() != 32 {
            self.push_event(".dat file must contain 32 raw bytes");
            return;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        match SecretKey::from_byte_array(arr) {
            Ok(sk) => {
                save_default_wallet(&sk);
                self.show_private = false;
                self.reload_wallet();
                self.push_event("Imported wallet from .dat file");
            }
            Err(_) => self.push_event("Invalid key data in .dat file"),
        }
    }

    fn export_dat_file(&mut self) {
        let Some(sk) = load_default_wallet() else {
            self.push_event("No default wallet to export");
            return;
        };
        let Some(path) = rfd::FileDialog::new()
            .set_title("Export wallet .dat")
            .set_file_name("wallet.dat")
            .save_file()
        else {
            return;
        };
        match fs::write(path, sk.secret_bytes()) {
            Ok(_) => self.push_event("Exported wallet .dat"),
            Err(_) => self.push_event("Failed to write .dat file"),
        }
    }

    fn send_transaction(&mut self) {
        let to = self.to_input.trim().to_string();
        if to.is_empty() {
            self.push_event("Destination address is required");
            return;
        }

        let amount = match self.amount_input.trim().parse::<u64>() {
            Ok(v) if v > 0 => v,
            _ => {
                self.push_event("Amount must be a positive integer");
                return;
            }
        };

        let min_peers = self
            .min_peers_input
            .trim()
            .parse::<usize>()
            .ok()
            .unwrap_or(MIN_BROADCAST_PEERS)
            .max(MIN_BROADCAST_PEERS);

        let Some(sk) = load_default_wallet() else {
            self.push_event("No default wallet loaded");
            return;
        };

        let tx = build_tx(&mut self.peers, &sk, &to, amount);
        let outcome = broadcast_transaction(&mut self.peers, &tx, min_peers);
        self.push_event(outcome);
        self.amount_input.clear();
        self.refresh_all(true);
    }

    fn faucet_me(&mut self) {
        self.push_event("Faucet is disabled in hard-fork v2 (coinbase-only emission).");
        self.refresh_all(true);
    }

    fn flush_pending(&mut self) {
        let status = flush_pending_transactions(&mut self.peers, MIN_BROADCAST_PEERS);
        self.push_event(status);
        self.refresh_all(true);
    }
}

fn spawn_refresh_worker(rx: Receiver<RefreshRequest>, tx: Sender<RefreshResult>) {
    thread::spawn(move || {
        while let Ok(req) = rx.recv() {
            let discovered_peers = if req.discover {
                discover_peers_from_candidates(&req.peers, REFRESH_CONNECT_TIMEOUT)
            } else {
                Vec::new()
            };

            let mut all_peers = req.peers.clone();
            for peer in &discovered_peers {
                if is_valid_peer(peer) && !all_peers.contains(peer) {
                    all_peers.push(peer.clone());
                }
            }

            let probed_online: Vec<String> = all_peers
                .iter()
                .filter(|p| probe_peer_with_timeout(p, PROBE_TIMEOUT))
                .cloned()
                .collect();
            let online_peers = dedupe_peers_by_identity_with_timeout(probed_online, WHOAMI_TIMEOUT);

            let balance = req.address.as_deref().and_then(|addr| {
                fetch_balance_from_peer_list(&online_peers, addr, REFRESH_CONNECT_TIMEOUT)
            });
            let history = req
                .address
                .as_deref()
                .map(|addr| {
                    fetch_history_from_peer_list(&online_peers, addr, REFRESH_CONNECT_TIMEOUT)
                })
                .unwrap_or_default();

            let result = RefreshResult {
                id: req.id,
                discovered_peers,
                online_peers,
                balance,
                history,
            };
            let _ = tx.send(result);
        }
    });
}

impl eframe::App for WalletApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.refresh_all(false);

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading(
                    egui::RichText::new("Lofswap Wallet")
                        .size(28.0)
                        .color(egui::Color32::from_rgb(130, 245, 210)),
                );
                ui.add_space(10.0);
                ui.label(
                    egui::RichText::new(format!("Network: {CHAIN_ID}"))
                        .color(egui::Color32::from_rgb(145, 180, 255)),
                );
                if self.refresh_in_flight {
                    ui.label(
                        egui::RichText::new("Syncing...")
                            .color(egui::Color32::from_rgb(255, 210, 120)),
                    );
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Refresh").clicked() {
                        self.refresh_all(true);
                        self.push_event("Manual refresh completed");
                    }
                });
            });
            ui.add_space(4.0);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            paint_bg(ui);

            let narrow = ui.available_width() < 940.0;
            if narrow {
                draw_wallet_card(ui, self);
                ui.add_space(10.0);
                draw_send_card(ui, self);
                ui.add_space(10.0);
                draw_network_card(ui, self);
                ui.add_space(10.0);
                draw_activity_card(ui, self);
            } else {
                ui.columns(2, |cols| {
                    draw_wallet_card(&mut cols[0], self);
                    cols[0].add_space(10.0);
                    draw_send_card(&mut cols[0], self);

                    draw_network_card(&mut cols[1], self);
                    cols[1].add_space(10.0);
                    draw_activity_card(&mut cols[1], self);
                });
            }
        });

        // Keep repainting at a low cadence so background refresh results can be applied.
        ctx.request_repaint_after(Duration::from_millis(120));
    }
}

fn apply_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = egui::Color32::from_rgb(10, 14, 24);
    style.visuals.window_fill = egui::Color32::from_rgb(10, 14, 24);
    style.visuals.extreme_bg_color = egui::Color32::from_rgb(15, 20, 34);
    style.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(17, 24, 40);
    style.visuals.widgets.active.bg_fill = egui::Color32::from_rgb(24, 34, 58);
    style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(27, 39, 65);
    style.visuals.hyperlink_color = egui::Color32::from_rgb(100, 208, 255);
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 7.0);
    ctx.set_style(style);
}

fn paint_bg(ui: &mut egui::Ui) {
    let rect = ui.max_rect();
    let mut mesh = egui::Mesh::default();

    let top = egui::Color32::from_rgb(13, 21, 38);
    let bottom = egui::Color32::from_rgb(8, 12, 20);

    let idx = mesh.vertices.len() as u32;
    mesh.colored_vertex(rect.left_top(), top);
    mesh.colored_vertex(rect.right_top(), top);
    mesh.colored_vertex(rect.right_bottom(), bottom);
    mesh.colored_vertex(rect.left_bottom(), bottom);
    mesh.add_triangle(idx, idx + 1, idx + 2);
    mesh.add_triangle(idx, idx + 2, idx + 3);

    ui.painter().add(egui::Shape::mesh(mesh));
}

fn card(ui: &mut egui::Ui, title: &str, add_contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::group(ui.style())
        .fill(egui::Color32::from_rgb(14, 22, 38))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(38, 58, 96)))
        .show(ui, |ui| {
            ui.heading(
                egui::RichText::new(title)
                    .size(19.0)
                    .color(egui::Color32::from_rgb(196, 221, 255)),
            );
            ui.add_space(6.0);
            add_contents(ui);
        });
}

fn draw_wallet_card(ui: &mut egui::Ui, app: &mut WalletApp) {
    card(ui, "Wallet", |ui| {
        ui.horizontal_wrapped(|ui| {
            if ui
                .add(
                    egui::Button::new("Create Wallet")
                        .fill(egui::Color32::from_rgb(24, 115, 84))
                        .stroke(egui::Stroke::NONE),
                )
                .clicked()
            {
                app.create_wallet();
            }
            if ui.button("Remove Wallet").clicked() {
                app.remove_wallet();
            }
            if ui.button("Import .dat").clicked() {
                app.import_dat_file();
            }
            if ui.button("Export .dat").clicked() {
                app.export_dat_file();
            }
        });

        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut app.import_priv_input)
                    .hint_text("Private key hex (64 chars)")
                    .desired_width(260.0),
            );
            if ui.button("Import Hex").clicked() {
                app.import_private_hex();
            }
        });

        ui.separator();

        if let Some(pk) = &app.wallet.pubkey {
            ui.label(format!("Public Key: {pk}"));
        } else {
            ui.label("No default wallet loaded");
        }

        if let Some(addr) = &app.wallet.address {
            ui.monospace(format!("Address: {addr}"));
        }

        if let Some(bal) = app.wallet.balance {
            ui.label(
                egui::RichText::new(format!("Balance: {bal} LFS"))
                    .size(20.0)
                    .color(egui::Color32::from_rgb(130, 245, 210)),
            );
        }

        ui.horizontal(|ui| {
            let reveal_label = if app.show_private {
                "Hide Private"
            } else {
                "Reveal Private"
            };
            if ui.button(reveal_label).clicked() {
                app.show_private = !app.show_private;
                app.reload_wallet();
            }
            if ui.button("Faucet Me").clicked() {
                app.faucet_me();
            }
        });

        if app.show_private {
            if let Some(privkey) = &app.wallet.privkey {
                ui.monospace(format!("Private: {privkey}"));
            }
        }
    });
}

fn draw_send_card(ui: &mut egui::Ui, app: &mut WalletApp) {
    card(ui, "Send", |ui| {
        ui.label("Destination");
        ui.add(
            egui::TextEdit::singleline(&mut app.to_input)
                .hint_text("LFS... recipient")
                .desired_width(f32::INFINITY),
        );

        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut app.amount_input)
                    .hint_text("Amount")
                    .desired_width(120.0),
            );
            ui.add(
                egui::TextEdit::singleline(&mut app.min_peers_input)
                    .hint_text("Min peers")
                    .desired_width(90.0),
            );
            if ui
                .add(
                    egui::Button::new(
                        egui::RichText::new("Send Transaction")
                            .strong()
                            .color(egui::Color32::BLACK),
                    )
                    .fill(egui::Color32::from_rgb(109, 228, 255)),
                )
                .clicked()
            {
                app.send_transaction();
            }
        });

        ui.horizontal(|ui| {
            ui.label(format!(
                "Pending queue: {}",
                load_pending_transactions().len()
            ));
            if ui.button("Flush Pending").clicked() {
                app.flush_pending();
            }
        });
    });
}

fn draw_network_card(ui: &mut egui::Ui, app: &mut WalletApp) {
    card(ui, "Network", |ui| {
        ui.horizontal(|ui| {
            ui.label(format!("Known peers: {}", app.peers.as_slice().len()));
            ui.label(format!("Online: {}", app.online_peers.len()));
        });

        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut app.peer_input)
                    .hint_text("ip:port")
                    .desired_width(180.0),
            );
            if ui.button("Add").clicked() {
                let peer = app.peer_input.trim().to_string();
                if peer.is_empty() {
                    app.push_event("Peer input is empty");
                } else {
                    match app.peers.add_peer(&peer) {
                        Ok(_) => {
                            app.peers.save();
                            app.peer_input.clear();
                            app.refresh_all(true);
                            app.push_event("Peer added");
                        }
                        Err(e) => app.push_event(e),
                    }
                }
            }
            if ui.button("Remove").clicked() {
                let peer = app.peer_input.trim().to_string();
                if !peer.is_empty() {
                    app.peers.remove_peer(&peer);
                    app.peers.save();
                    app.refresh_all(true);
                    app.push_event("Peer removed");
                }
            }
        });

        ui.separator();
        egui::ScrollArea::vertical()
            .id_salt("peer-list")
            .max_height(180.0)
            .show(ui, |ui| {
                for peer in app.peers.as_slice() {
                    let online = app.online_peers.contains(peer);
                    let marker = if online { "[online]" } else { "[offline]" };
                    let color = if online {
                        egui::Color32::from_rgb(118, 232, 170)
                    } else {
                        egui::Color32::from_rgb(200, 130, 130)
                    };
                    ui.label(egui::RichText::new(format!("{marker} {peer}")).color(color));
                }
            });
    });
}

fn draw_activity_card(ui: &mut egui::Ui, app: &mut WalletApp) {
    card(ui, "Activity", |ui| {
        ui.label("Recent transactions");
        egui::ScrollArea::vertical()
            .id_salt("history-list")
            .max_height(180.0)
            .show(ui, |ui| {
                if app.history.is_empty() {
                    ui.label("No transactions for this wallet yet");
                } else {
                    for row in app.history.iter().take(30) {
                        let color = if row.direction == "IN" {
                            egui::Color32::from_rgb(118, 232, 170)
                        } else {
                            egui::Color32::from_rgb(255, 191, 120)
                        };
                        ui.horizontal_wrapped(|ui| {
                            ui.label(egui::RichText::new(row.direction).color(color).strong());
                            ui.label(format!("{} LFS", row.amount));
                            ui.label(format!("with {}", row.counterparty));
                            ui.label(format!("ts {}", row.timestamp));
                        });
                        ui.small(format!("txid {}", row.txid));
                        ui.separator();
                    }
                }
            });

        ui.add_space(6.0);
        ui.label("Events");
        egui::ScrollArea::vertical()
            .id_salt("event-log")
            .max_height(120.0)
            .show(ui, |ui| {
                if app.events.is_empty() {
                    ui.label("No events yet");
                } else {
                    for line in &app.events {
                        ui.label(line);
                    }
                }
            });
    });
}

fn save_default_wallet(sk: &SecretKey) {
    let _ = fs::write(DEFAULT_WALLET, hex::encode(sk.secret_bytes()));
}

fn load_default_wallet() -> Option<SecretKey> {
    fs::read_to_string(DEFAULT_WALLET)
        .ok()
        .and_then(|h| hex::decode(h.trim()).ok())
        .and_then(|bytes| {
            if bytes.len() != 32 {
                return None;
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            SecretKey::from_byte_array(arr).ok()
        })
}

fn peer_cache_path() -> PathBuf {
    PathBuf::from(PEER_CACHE_FILE)
}

fn is_valid_peer(peer: &str) -> bool {
    peer.parse::<SocketAddr>().is_ok()
}

fn probe_peer_with_timeout(peer: &str, timeout: Duration) -> bool {
    let Ok(sock) = peer.parse::<SocketAddr>() else {
        return false;
    };
    TcpStream::connect_timeout(&sock, timeout).is_ok()
}

fn send_request(peer: &str, payload: &[u8], timeout: Duration) -> Option<Vec<u8>> {
    let sock: SocketAddr = peer.parse().ok()?;
    let mut stream = TcpStream::connect_timeout(&sock, timeout).ok()?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    stream.write_all(payload).ok()?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    Some(buf)
}

fn send_tx_and_get_reply(peer: &str, payload: &[u8]) -> std::io::Result<Option<String>> {
    let sock: SocketAddr = peer
        .parse()
        .map_err(|_| std::io::Error::other("bad peer"))?;
    let mut stream = TcpStream::connect_timeout(&sock, CONNECT_TIMEOUT)?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1200)));
    stream.write_all(payload)?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    if buf.is_empty() {
        Ok(None)
    } else {
        Ok(Some(String::from_utf8_lossy(&buf).trim().to_string()))
    }
}

fn discover_peers_from_candidates(candidates: &[String], timeout: Duration) -> Vec<String> {
    let mut discovered = Vec::new();
    for peer in candidates.iter().take(12) {
        let Some(bytes) = send_request(peer, b"/peers", timeout) else {
            continue;
        };
        let Ok(list) = serde_json::from_slice::<Vec<String>>(&bytes) else {
            continue;
        };
        for item in list {
            if is_valid_peer(&item) && !discovered.contains(&item) {
                discovered.push(item);
            }
        }
    }
    discovered
}

fn fetch_balance_from_peer_list(peers: &[String], addr: &str, timeout: Duration) -> Option<i128> {
    let query = format!("/balance/{addr}");
    for peer in peers {
        let Some(bytes) = send_request(peer, query.as_bytes(), timeout) else {
            continue;
        };
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        if let Ok(balance) = text.trim().parse::<i128>() {
            return Some(balance);
        }
    }
    None
}

fn fetch_chain_from_peer_list(peers: &[String], timeout: Duration) -> Option<Vec<Block>> {
    for peer in peers {
        let Some(bytes) = send_request(peer, b"/chain", timeout) else {
            continue;
        };
        if let Ok(chain) = serde_json::from_slice::<Vec<Block>>(&bytes) {
            return Some(chain);
        }
    }
    None
}

fn fetch_history_from_peer_list(
    peers: &[String],
    addr: &str,
    timeout: Duration,
) -> Vec<HistoryRow> {
    let Some(chain) = fetch_chain_from_peer_list(peers, timeout) else {
        return Vec::new();
    };
    let target = normalize_tx_addr(addr);
    let mut rows = Vec::new();

    for block in &chain {
        for tx in &block.transactions {
            let from = normalize_tx_addr(&tx.from);
            let to = normalize_tx_addr(&tx.to);
            if from != target && to != target {
                continue;
            }
            let (direction, counterparty) = if to == target {
                ("IN", from)
            } else {
                ("OUT", to)
            };
            rows.push(HistoryRow {
                direction,
                counterparty,
                amount: tx.amount,
                timestamp: tx.timestamp,
                txid: if tx.txid.is_empty() {
                    tx.compute_txid()
                } else {
                    tx.txid.clone()
                },
            });
        }
    }

    rows.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    rows
}

fn peer_identity_with_timeout(peer: &str, timeout: Duration) -> PeerIdentity {
    let Some(bytes) = send_request(peer, b"/whoami", timeout) else {
        return PeerIdentity::Unknown;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return PeerIdentity::Unknown;
    };
    let Some(chain_id) = value.get("chain_id").and_then(|v| v.as_str()) else {
        return PeerIdentity::Unknown;
    };
    if chain_id != CHAIN_ID {
        return PeerIdentity::DifferentChain;
    }
    let Some(node_id) = value.get("node_id").and_then(|v| v.as_str()) else {
        return PeerIdentity::Unknown;
    };
    PeerIdentity::SameChain(node_id.to_string())
}

fn dedupe_peers_by_identity(peers: Vec<String>) -> Vec<String> {
    dedupe_peers_by_identity_with_timeout(peers, WHOAMI_TIMEOUT)
}

fn dedupe_peers_by_identity_with_timeout(peers: Vec<String>, timeout: Duration) -> Vec<String> {
    let mut deduped: Vec<String> = Vec::new();
    let mut node_to_idx: HashMap<String, usize> = HashMap::new();

    for peer in peers {
        match peer_identity_with_timeout(&peer, timeout) {
            PeerIdentity::SameChain(node_id) => {
                if let Some(&idx) = node_to_idx.get(&node_id) {
                    let existing = &deduped[idx];
                    if is_loopback(&peer) && !is_loopback(existing) {
                        deduped[idx] = peer;
                    }
                    continue;
                }
                node_to_idx.insert(node_id, deduped.len());
                deduped.push(peer);
            }
            PeerIdentity::DifferentChain => continue,
            PeerIdentity::Unknown => {
                if !deduped.contains(&peer) {
                    deduped.push(peer);
                }
            }
        }
    }

    deduped
}

fn is_loopback(peer: &str) -> bool {
    peer.parse::<SocketAddr>()
        .map(|sock| sock.ip().is_loopback())
        .unwrap_or(false)
}

fn normalize_tx_addr(addr: &str) -> String {
    if addr.is_empty() {
        String::new()
    } else if addr.starts_with("LFS") {
        addr.to_string()
    } else {
        pubkey_to_address(addr)
    }
}

fn load_pending_transactions() -> Vec<Transaction> {
    let Ok(content) = fs::read_to_string(MEMPOOL_FILE) else {
        return Vec::new();
    };
    serde_json::Deserializer::from_str(&content)
        .into_iter::<Transaction>()
        .filter_map(Result::ok)
        .collect()
}

fn save_pending_transactions(pending: &[Transaction]) {
    let body = pending
        .iter()
        .filter_map(|tx| serde_json::to_string(tx).ok())
        .collect::<Vec<_>>()
        .join("\n");
    let _ = fs::write(MEMPOOL_FILE, body);
}

fn append_pending_transaction(tx: &Transaction) {
    if let Ok(line) = serde_json::to_string(tx) {
        let _ = OpenOptions::new()
            .append(true)
            .create(true)
            .open(MEMPOOL_FILE)
            .and_then(|mut f| writeln!(f, "{line}"));
    }
}

fn is_already_known_reject(reason: &str) -> bool {
    let lowered = reason.to_ascii_lowercase();
    lowered.contains("transaction already exists") || lowered.contains("duplicate transaction")
}

fn fetch_next_nonce_from_peers(peers: &mut PeerStore, from_addr: &str) -> Option<u64> {
    let query = format!("/nonce/{from_addr}");
    let mut best = None;
    for peer in peers.online_peers() {
        let Some(bytes) = send_request(&peer, query.as_bytes(), CONNECT_TIMEOUT) else {
            continue;
        };
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        if let Ok(nonce) = text.trim().parse::<u64>() {
            best = Some(best.map_or(nonce, |prev: u64| prev.max(nonce)));
        }
    }
    best
}

fn next_nonce_fallback_from_local(from_addr: &str) -> u64 {
    let mut next = 0u64;
    let mut pending_nonces = HashSet::new();
    for tx in load_pending_transactions() {
        if normalize_tx_addr(&tx.from) == from_addr {
            pending_nonces.insert(tx.nonce);
        }
    }
    while pending_nonces.contains(&next) {
        next = next.saturating_add(1);
    }
    next
}

fn build_tx(peers: &mut PeerStore, sk: &SecretKey, to: &str, amount: u64) -> Transaction {
    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, sk);
    let ts = Utc::now().timestamp();
    let from_addr = pubkey_to_address(&pk.to_string());
    let nonce = fetch_next_nonce_from_peers(peers, &from_addr)
        .unwrap_or_else(|| next_nonce_fallback_from_local(&from_addr));

    let preimage = format!(
        "{}|{}|{:?}|{}|{}|{}|{}|{}|{}",
        3,
        CHAIN_ID,
        TxKind::Transfer,
        pk,
        to,
        amount,
        DEFAULT_TX_FEE,
        ts,
        nonce
    );
    let hash = Sha256::digest(preimage.as_bytes());
    let sig = secp.sign_ecdsa(Message::from_digest(hash.into()), sk);

    let mut tx = Transaction {
        version: 3,
        chain_id: CHAIN_ID.to_string(),
        kind: TxKind::Transfer,
        timestamp: ts,
        from: from_addr,
        to: to.to_string(),
        amount,
        fee: DEFAULT_TX_FEE,
        signature: hex::encode(sig.serialize_compact()),
        pubkey: pk.to_string(),
        nonce,
        txid: String::new(),
    };
    tx.txid = tx.compute_txid();
    tx
}

fn broadcast_transaction(peers: &mut PeerStore, tx: &Transaction, min_peers: usize) -> String {
    let required = min_peers.max(MIN_BROADCAST_PEERS);
    let online = peers.online_peers();

    if online.is_empty() {
        append_pending_transaction(tx);
        return "No reachable peers: queued transaction locally".to_string();
    }
    if online.len() < required {
        append_pending_transaction(tx);
        return format!("Only {} peer(s) online; queued transaction", online.len());
    }

    let payload = serde_json::to_vec(tx).unwrap_or_default();
    let mut rng = rand::rng();
    let selected: Vec<String> = online
        .choose_multiple(&mut rng, required)
        .cloned()
        .collect();

    let mut ok = 0usize;
    for peer in selected {
        match send_tx_and_get_reply(&peer, &payload) {
            Ok(Some(reply)) => {
                if let Some(reason) = reply.strip_prefix("reject: ") {
                    if is_already_known_reject(reason) {
                        ok += 1;
                    } else {
                        return format!("Transaction rejected by {peer}: {reason}");
                    }
                } else {
                    ok += 1;
                }
            }
            Ok(None) => ok += 1,
            Err(_) => {}
        }
    }

    if ok >= required {
        let _ = flush_pending_transactions(peers, required);
        format!("Transaction sent to {ok}/{required} peers")
    } else {
        append_pending_transaction(tx);
        format!("Only {ok}/{required} accepted; queued transaction")
    }
}

fn flush_pending_transactions(peers: &mut PeerStore, min_peers: usize) -> String {
    let required = min_peers.max(MIN_BROADCAST_PEERS);
    let online = peers.online_peers();
    if online.len() < required {
        return format!(
            "Waiting for more peers before flush (online: {}, required: {})",
            online.len(),
            required
        );
    }

    let mut pending = load_pending_transactions();
    if pending.is_empty() {
        return "No pending transactions".to_string();
    }

    let before = pending.len();
    pending.retain(|tx| {
        let payload = serde_json::to_vec(tx).unwrap_or_default();
        let mut ok = 0usize;
        for peer in &online {
            match send_tx_and_get_reply(peer, &payload) {
                Ok(Some(reply)) => {
                    if let Some(reason) = reply.strip_prefix("reject: ") {
                        if is_already_known_reject(reason) {
                            ok += 1;
                        } else {
                            return false;
                        }
                    } else {
                        ok += 1;
                    }
                }
                Ok(None) => ok += 1,
                Err(_) => {}
            }
            if ok >= required {
                return false;
            }
        }
        true
    });

    save_pending_transactions(&pending);
    let sent = before.saturating_sub(pending.len());
    format!("Flushed {sent} pending tx(s), {} remaining", pending.len())
}

fn main() -> eframe::Result<()> {
    let native = NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([860.0, 620.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Lofswap Wallet",
        native,
        Box::new(|cc| Ok(Box::new(WalletApp::new(cc)))),
    )
}
