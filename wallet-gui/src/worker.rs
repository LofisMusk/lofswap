//! The background thread that owns the key and does everything that blocks.
//!
//! The UI thread never holds the secret key, never opens a socket and never
//! runs Argon2id; it sends [`Cmd`]s and renders whatever [`Event`]s come back.

use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::thread;
use std::time::{Duration, Instant};

use crate::biometric;
use crate::net::{self, PeerStore, TxIndex, WalletTx};
use crate::storage::Settings;
use crate::wallet::{self, Unlocked};

/// How often the wallet re-probes peers and refreshes the balance.
const REFRESH_INTERVAL: Duration = Duration::from_secs(20);
/// While the chain scan is catching up, keep pulling without waiting.
const CATCHUP_INTERVAL: Duration = Duration::from_millis(400);

pub enum Cmd {
    Refresh,
    Create {
        passphrase: String,
        biometric: bool,
    },
    ImportPrivateKey {
        private_key_hex: String,
        passphrase: String,
        biometric: bool,
    },
    ImportDat {
        bytes: Vec<u8>,
        passphrase: String,
        biometric: bool,
    },
    Unlock {
        passphrase: String,
    },
    UnlockBiometric,
    Lock,
    ChangePassphrase {
        current: String,
        new: String,
    },
    SetBiometric {
        enabled: bool,
        passphrase: String,
    },
    RevealSecret {
        passphrase: String,
    },
    Send {
        to: String,
        amount: u64,
    },
    DeleteWallet,
    ApplySettings(Settings),
}

/// Which slow operation is in flight, so the UI can disable the right button.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Job {
    Unlocking,
    Creating,
    Importing,
    Sending,
    Rekeying,
    Revealing,
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub peers_known: usize,
    pub peers_online: usize,
    pub balance: Option<u64>,
    pub tip_height: Option<u64>,
    pub scanned_to: u64,
    pub scanning: bool,
    pub txs: Vec<WalletTx>,
    pub refreshed_at: Option<i64>,
}

pub struct Secrets {
    pub private_key_hex: String,
    pub dat_base64: String,
    pub mnemonic: Option<String>,
}

pub enum Event {
    Started(Job),
    Finished(Job),
    /// A wallet was created; the recovery phrase must be shown once.
    Created {
        mnemonic: String,
    },
    Opened {
        address: String,
        public_key: String,
    },
    Locked,
    Deleted,
    Snapshot(Snapshot),
    Sent {
        txid: String,
        peers: usize,
    },
    Secrets(Secrets),
    /// Something worth telling the user that is not an error.
    Notice(String),
    Error(String),
}

pub struct Worker {
    commands: Sender<Cmd>,
    events: Receiver<Event>,
}

impl Worker {
    pub fn spawn(ctx: egui::Context, settings: Settings) -> Self {
        let (cmd_tx, cmd_rx) = channel();
        let (event_tx, event_rx) = channel();
        thread::Builder::new()
            .name("lofswap-wallet-net".to_owned())
            .spawn(move || State::new(ctx, settings, event_tx).run(cmd_rx))
            .expect("spawning the wallet worker thread");
        Self {
            commands: cmd_tx,
            events: event_rx,
        }
    }

    pub fn send(&self, cmd: Cmd) {
        // The worker only stops when the app does, so a closed channel means
        // the process is on its way out.
        let _ = self.commands.send(cmd);
    }

    pub fn drain(&self) -> Vec<Event> {
        self.events.try_iter().collect()
    }
}

struct State {
    ctx: egui::Context,
    events: Sender<Event>,
    settings: Settings,
    peers: PeerStore,
    unlocked: Option<Unlocked>,
    index: Option<TxIndex>,
    snapshot: Snapshot,
    /// Kept so enabling biometric unlock later does not ask for the
    /// passphrase again in the same session.
    session_passphrase: Option<String>,
    next_refresh: Instant,
}

impl State {
    fn new(ctx: egui::Context, settings: Settings, events: Sender<Event>) -> Self {
        let peers = PeerStore::new(&settings);
        Self {
            ctx,
            events,
            settings,
            peers,
            unlocked: None,
            index: None,
            snapshot: Snapshot::default(),
            session_passphrase: None,
            next_refresh: Instant::now(),
        }
    }

    fn emit(&self, event: Event) {
        if self.events.send(event).is_ok() {
            self.ctx.request_repaint();
        }
    }

    fn run(mut self, commands: Receiver<Cmd>) {
        loop {
            let wait = self
                .next_refresh
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(250));
            match commands.recv_timeout(wait) {
                Ok(cmd) => self.handle(cmd),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            if Instant::now() >= self.next_refresh {
                self.refresh();
            }
        }
    }

    fn handle(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Refresh => self.refresh(),
            Cmd::Create {
                passphrase,
                biometric,
            } => {
                self.emit(Event::Started(Job::Creating));
                match wallet::create(&passphrase) {
                    Ok((unlocked, mnemonic)) => {
                        self.apply_biometric_preference(biometric, &passphrase);
                        self.emit(Event::Created { mnemonic });
                        self.open(unlocked, passphrase);
                    }
                    Err(err) => self.emit(Event::Error(err)),
                }
                self.emit(Event::Finished(Job::Creating));
            }
            Cmd::ImportPrivateKey {
                private_key_hex,
                passphrase,
                biometric,
            } => {
                self.emit(Event::Started(Job::Importing));
                match wallet::import_private_key(&private_key_hex, &passphrase) {
                    Ok(unlocked) => {
                        self.apply_biometric_preference(biometric, &passphrase);
                        self.open(unlocked, passphrase);
                    }
                    Err(err) => self.emit(Event::Error(err)),
                }
                self.emit(Event::Finished(Job::Importing));
            }
            Cmd::ImportDat {
                bytes,
                passphrase,
                biometric,
            } => {
                self.emit(Event::Started(Job::Importing));
                match wallet::import_dat(&bytes, &passphrase) {
                    Ok(unlocked) => {
                        self.apply_biometric_preference(biometric, &passphrase);
                        self.open(unlocked, passphrase);
                    }
                    Err(err) => self.emit(Event::Error(err)),
                }
                self.emit(Event::Finished(Job::Importing));
            }
            Cmd::Unlock { passphrase } => {
                self.emit(Event::Started(Job::Unlocking));
                match wallet::unlock(&passphrase) {
                    Ok(unlocked) => {
                        // If biometric unlock was on but the credential went
                        // missing, put it back now that we have the passphrase.
                        if biometric::enabled()
                            && matches!(biometric::load(), Err(biometric::ReadError::NoEntry))
                            && let Err(err) = biometric::store(&passphrase)
                        {
                            self.emit(Event::Notice(format!(
                                "Unlocked, but {} could not be refreshed: {err}",
                                biometric::label()
                            )));
                        }
                        self.open(unlocked, passphrase);
                    }
                    Err(err) => self.emit(Event::Error(err)),
                }
                self.emit(Event::Finished(Job::Unlocking));
            }
            Cmd::UnlockBiometric => {
                self.emit(Event::Started(Job::Unlocking));
                match biometric::unlock_passphrase() {
                    Ok(passphrase) => match wallet::unlock(&passphrase) {
                        Ok(unlocked) => self.open(unlocked, passphrase),
                        Err(err) => self.emit(Event::Error(err)),
                    },
                    Err(biometric::ReadError::NoEntry) => {
                        self.emit(Event::Error(format!(
                            "{} is enabled but nothing is stored yet. Unlock with your passphrase once, then try again.",
                            biometric::label()
                        )));
                    }
                    Err(biometric::ReadError::Failed(err)) => self.emit(Event::Error(err)),
                }
                self.emit(Event::Finished(Job::Unlocking));
            }
            Cmd::Lock => {
                self.unlocked = None;
                self.index = None;
                self.session_passphrase = None;
                self.snapshot = Snapshot {
                    peers_known: self.snapshot.peers_known,
                    peers_online: self.snapshot.peers_online,
                    tip_height: self.snapshot.tip_height,
                    ..Snapshot::default()
                };
                self.emit(Event::Locked);
            }
            Cmd::ChangePassphrase { current, new } => {
                self.emit(Event::Started(Job::Rekeying));
                match wallet::change_passphrase(&current, &new) {
                    Ok(unlocked) => {
                        if biometric::enabled()
                            && let Err(err) = biometric::store(&new)
                        {
                            self.emit(Event::Notice(format!(
                                "Passphrase changed, but {} could not be updated: {err}",
                                biometric::label()
                            )));
                        }
                        self.session_passphrase = Some(new);
                        self.unlocked = Some(unlocked);
                        self.emit(Event::Notice("Passphrase changed.".to_owned()));
                    }
                    Err(err) => self.emit(Event::Error(err)),
                }
                self.emit(Event::Finished(Job::Rekeying));
            }
            Cmd::SetBiometric {
                enabled,
                passphrase,
            } => {
                let passphrase = if passphrase.is_empty() {
                    self.session_passphrase.clone().unwrap_or_default()
                } else {
                    passphrase
                };
                if enabled && passphrase.is_empty() {
                    self.emit(Event::Error(format!(
                        "Unlock with your passphrase before turning on {}.",
                        biometric::label()
                    )));
                    return;
                }
                match biometric::set_enabled(enabled, &passphrase) {
                    Ok(()) => self.emit(Event::Notice(if enabled {
                        format!("{} unlock is on.", biometric::label())
                    } else {
                        format!("{} unlock is off.", biometric::label())
                    })),
                    Err(err) => self.emit(Event::Error(err)),
                }
            }
            Cmd::RevealSecret { passphrase } => {
                self.emit(Event::Started(Job::Revealing));
                match wallet::export_secret(&passphrase) {
                    Ok(export) => self.emit(Event::Secrets(Secrets {
                        private_key_hex: export.private_key_hex,
                        dat_base64: export.dat_base64,
                        mnemonic: export.mnemonic,
                    })),
                    Err(err) => self.emit(Event::Error(err)),
                }
                self.emit(Event::Finished(Job::Revealing));
            }
            Cmd::Send { to, amount } => {
                self.emit(Event::Started(Job::Sending));
                self.send_transfer(&to, amount);
                self.emit(Event::Finished(Job::Sending));
            }
            Cmd::DeleteWallet => match wallet::delete() {
                Ok(()) => {
                    let _ = biometric::clear();
                    self.unlocked = None;
                    self.index = None;
                    self.session_passphrase = None;
                    self.snapshot = Snapshot::default();
                    self.emit(Event::Deleted);
                }
                Err(err) => self.emit(Event::Error(err)),
            },
            Cmd::ApplySettings(settings) => {
                self.settings = settings;
                self.peers.reconfigure(&self.settings);
                self.next_refresh = Instant::now();
            }
        }
    }

    fn open(&mut self, unlocked: Unlocked, passphrase: String) {
        self.index = Some(TxIndex::load(&unlocked.address));
        self.emit(Event::Opened {
            address: unlocked.address.clone(),
            public_key: unlocked.public_key.clone(),
        });
        self.unlocked = Some(unlocked);
        self.session_passphrase = Some(passphrase);
        self.next_refresh = Instant::now();
    }

    fn apply_biometric_preference(&mut self, enable: bool, passphrase: &str) {
        if !enable {
            return;
        }
        if let Err(err) = biometric::set_enabled(true, passphrase) {
            self.emit(Event::Notice(format!(
                "Wallet saved, but {} could not be enabled: {err}",
                biometric::label()
            )));
        }
    }

    fn send_transfer(&mut self, to: &str, amount: u64) {
        let Some(wallet) = self.unlocked.clone() else {
            self.emit(Event::Error("The wallet is locked.".to_owned()));
            return;
        };
        if amount == 0 {
            self.emit(Event::Error("Enter an amount above zero.".to_owned()));
            return;
        }
        if !to.starts_with("LFS") || to.len() < 20 {
            self.emit(Event::Error(
                "That does not look like a LofSwap address.".to_owned(),
            ));
            return;
        }

        self.peers.refresh();
        let online = self.peers.online().to_vec();
        if online.is_empty() {
            self.emit(Event::Error(
                "No peers are reachable, so the transaction cannot be broadcast.".to_owned(),
            ));
            return;
        }

        let nonce = net::best_next_nonce(&online, &wallet.address);
        let tx = match net::build_transfer(&wallet.secret_key, to, amount, nonce) {
            Ok(tx) => tx,
            Err(err) => {
                self.emit(Event::Error(err));
                return;
            }
        };

        match net::broadcast(&online, &tx, self.settings.min_broadcast_peers) {
            Ok(result) => {
                self.emit(Event::Sent {
                    txid: tx.txid.clone(),
                    peers: result.accepted_by.len(),
                });
                self.next_refresh = Instant::now();
            }
            Err(err) => self.emit(Event::Error(err)),
        }
    }

    fn refresh(&mut self) {
        self.peers.refresh();
        let online = self.peers.online().to_vec();
        self.snapshot.peers_known = self.peers.known();
        self.snapshot.peers_online = online.len();
        self.snapshot.refreshed_at = Some(chrono::Utc::now().timestamp());

        let mut catching_up = false;

        if let (Some(wallet), Some(index)) = (self.unlocked.clone(), self.index.as_mut()) {
            self.snapshot.balance = online
                .iter()
                .find_map(|peer| net::balance(peer, &wallet.address));

            if let Some(peer) = online.first() {
                let known_tip = self.snapshot.tip_height.unwrap_or(0);
                if let Some(tip) = net::tip_height(peer, known_tip) {
                    if tip < known_tip {
                        // The chain we are following got shorter: a reorg, or a
                        // peer with a different history. Re-read from the fork.
                        index.rewind_to(tip);
                    }
                    self.snapshot.tip_height = Some(tip);
                }

                if let Some(step) = net::scan_step(peer, index) {
                    catching_up = !step.caught_up;
                    if step.blocks_read > 0 || step.caught_up {
                        index.save();
                    }
                    if step.caught_up && index.scanned_to > 0 {
                        self.snapshot.tip_height = Some(index.scanned_to - 1);
                    }
                }
            }

            let mut txs = index.txs.clone();
            txs.sort_by(|a, b| {
                b.block_index
                    .cmp(&a.block_index)
                    .then(b.timestamp.cmp(&a.timestamp))
            });
            self.snapshot.txs = txs;
            self.snapshot.scanned_to = index.scanned_to;
            self.snapshot.scanning = catching_up;
        } else {
            self.snapshot.balance = None;
            self.snapshot.txs.clear();
            self.snapshot.scanning = false;
        }

        self.next_refresh = Instant::now()
            + if catching_up {
                CATCHUP_INTERVAL
            } else {
                REFRESH_INTERVAL
            };
        self.emit(Event::Snapshot(self.snapshot.clone()));
    }
}
