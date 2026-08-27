//! Application state, window chrome and routing.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use egui::{Align, CornerRadius, Layout, Sense, Stroke, StrokeKind, Vec2};

use crate::icons::{self, Icon};
use crate::screens;
use crate::storage::{self, Settings};
use crate::theme::*;
use crate::widgets::*;
use crate::worker::{Cmd, Event, Job, Secrets, Snapshot, Worker};
use crate::{APP_TITLE, APP_VERSION};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Onboarding,
    CreateWallet,
    ImportPrivateKey,
    ImportDat,
    Recovery,
    Unlock,
    Wallet,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Dashboard,
    Send,
    Receive,
    Activity,
    Settings,
}

impl Route {
    const ALL: [(Route, &'static str, Icon); 5] = [
        (Route::Dashboard, "Dashboard", Icon::Grid),
        (Route::Send, "Send", Icon::ArrowUp),
        (Route::Receive, "Receive", Icon::ArrowDown),
        (Route::Activity, "Activity", Icon::Activity),
        (Route::Settings, "Settings", Icon::Sliders),
    ];

    fn title(self) -> (&'static str, &'static str) {
        match self {
            Route::Dashboard => ("Dashboard", "Balances and activity for this wallet"),
            Route::Send => ("Send LFS", "Signed locally, broadcast peer to peer"),
            Route::Receive => ("Receive LFS", "Your address on lofswap-testnet"),
            Route::Activity => ("Activity", "Every transaction touching this address"),
            Route::Settings => ("Settings", "Security, peers and local storage"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ActivityFilter {
    All,
    Received,
    Sent,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Modal {
    ChangePassphrase,
    RevealSecret,
    ConfirmDelete,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    Info,
    Success,
    Error,
}

pub struct Toast {
    pub message: String,
    pub kind: ToastKind,
    pub shown_at: Instant,
}

/// Every text field on every screen.
#[derive(Default)]
pub struct Forms {
    pub passphrase: String,
    pub passphrase_confirm: String,
    pub biometric_opt_in: bool,
    pub private_key: String,
    pub dat_name: Option<String>,
    pub dat_bytes: Option<Vec<u8>>,
    pub unlock_passphrase: String,
    pub send_to: String,
    pub send_amount: String,
    pub search: String,
    pub local_node: String,
    pub bootstrap_peers: String,
    pub current_passphrase: String,
    pub new_passphrase: String,
    pub new_passphrase_confirm: String,
    pub reveal_passphrase: String,
}

pub struct App {
    pub worker: Worker,
    pub settings: Settings,
    pub snapshot: Snapshot,

    pub stage: Stage,
    pub route: Route,
    pub address: Option<String>,
    pub public_key: Option<String>,

    pub forms: Forms,
    pub filter: ActivityFilter,
    pub modal: Option<Modal>,
    pub revealed: Option<Secrets>,
    pub recovery_words: Vec<String>,
    pub recovery_acknowledged: bool,
    pub biometric_enabled: bool,

    pub jobs: HashSet<Job>,
    pub toast: Option<Toast>,
    /// QR modules for the current address, computed once per address.
    pub qr: Option<(String, Vec<bool>, usize)>,
    logo_texture: Option<egui::TextureHandle>,
}

const TOAST_LIFETIME: Duration = Duration::from_secs(6);

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        crate::theme::install(&cc.egui_ctx);

        let settings = Settings::load();
        let worker = Worker::spawn(cc.egui_ctx.clone(), settings.clone());
        let stage = if storage::wallet_exists() {
            Stage::Unlock
        } else {
            Stage::Onboarding
        };

        let forms = Forms {
            local_node: settings.local_node.clone(),
            bootstrap_peers: settings.bootstrap_peers.join("\n"),
            ..Forms::default()
        };

        Self {
            worker,
            settings,
            snapshot: Snapshot::default(),
            stage,
            route: Route::Dashboard,
            address: None,
            public_key: None,
            forms,
            filter: ActivityFilter::All,
            modal: None,
            revealed: None,
            recovery_words: Vec::new(),
            recovery_acknowledged: false,
            biometric_enabled: crate::biometric::enabled(),
            jobs: HashSet::new(),
            toast: None,
            qr: None,
            logo_texture: None,
        }
    }

    pub fn busy(&self, job: Job) -> bool {
        self.jobs.contains(&job)
    }

    pub fn notify(&mut self, kind: ToastKind, message: impl Into<String>) {
        self.toast = Some(Toast {
            message: message.into(),
            kind,
            shown_at: Instant::now(),
        });
    }

    pub fn lock(&mut self) {
        self.worker.send(Cmd::Lock);
    }

    fn handle_events(&mut self) {
        for event in self.worker.drain() {
            match event {
                Event::Started(job) => {
                    self.jobs.insert(job);
                }
                Event::Finished(job) => {
                    self.jobs.remove(&job);
                }
                Event::Created { mnemonic } => {
                    self.recovery_words = mnemonic.split_whitespace().map(str::to_owned).collect();
                    self.recovery_acknowledged = false;
                    self.stage = Stage::Recovery;
                }
                Event::Opened {
                    address,
                    public_key,
                } => {
                    self.qr = None;
                    self.address = Some(address);
                    self.public_key = Some(public_key);
                    self.biometric_enabled = crate::biometric::enabled();
                    // The recovery screen owns the transition after a create.
                    if self.stage != Stage::Recovery {
                        self.stage = Stage::Wallet;
                        self.route = Route::Dashboard;
                    }
                    self.clear_secrets();
                }
                Event::Locked => {
                    self.address = None;
                    self.public_key = None;
                    self.revealed = None;
                    self.qr = None;
                    self.stage = Stage::Unlock;
                    self.clear_secrets();
                }
                Event::Deleted => {
                    self.address = None;
                    self.public_key = None;
                    self.revealed = None;
                    self.qr = None;
                    self.biometric_enabled = false;
                    self.stage = Stage::Onboarding;
                    self.clear_secrets();
                    self.notify(ToastKind::Info, "Wallet deleted from this machine.");
                }
                Event::Snapshot(snapshot) => self.snapshot = snapshot,
                Event::Sent { txid, peers } => {
                    self.forms.send_to.clear();
                    self.forms.send_amount.clear();
                    self.route = Route::Activity;
                    self.notify(
                        ToastKind::Success,
                        format!("Sent to {peers} peers · {}", &txid[..txid.len().min(16)]),
                    );
                }
                Event::Secrets(secrets) => {
                    self.forms.reveal_passphrase.clear();
                    self.revealed = Some(secrets);
                }
                Event::Notice(message) => {
                    self.biometric_enabled = crate::biometric::enabled();
                    self.notify(ToastKind::Info, message);
                }
                Event::Error(message) => self.notify(ToastKind::Error, message),
            }
        }
    }

    /// Wipe passphrases out of the UI as soon as they are no longer needed.
    fn clear_secrets(&mut self) {
        self.forms.passphrase.clear();
        self.forms.passphrase_confirm.clear();
        self.forms.unlock_passphrase.clear();
        self.forms.private_key.clear();
        self.forms.current_passphrase.clear();
        self.forms.new_passphrase.clear();
        self.forms.new_passphrase_confirm.clear();
        self.forms.reveal_passphrase.clear();
        self.forms.dat_bytes = None;
        self.forms.dat_name = None;
    }
}

impl eframe::App for App {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        BG.to_normalized_gamma_f32()
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.handle_events();

        if let Some(toast) = &self.toast {
            if toast.shown_at.elapsed() > TOAST_LIFETIME {
                self.toast = None;
            } else {
                ui.ctx().request_repaint_after(Duration::from_millis(250));
            }
        }

        match self.stage {
            Stage::Wallet => self.wallet_shell(ui),
            _ => {
                egui::CentralPanel::no_frame()
                    .frame(egui::Frame::NONE.fill(BG))
                    .show(ui, |ui| {
                        centred(ui, |ui| match self.stage {
                            Stage::Onboarding => screens::onboarding(self, ui),
                            Stage::CreateWallet => screens::create_wallet(self, ui),
                            Stage::ImportPrivateKey => screens::import_private_key(self, ui),
                            Stage::ImportDat => screens::import_dat(self, ui),
                            Stage::Recovery => screens::recovery(self, ui),
                            Stage::Unlock => screens::unlock(self, ui),
                            Stage::Wallet => {}
                        });
                    });
            }
        }

        let ctx = ui.ctx().clone();
        self.show_modal(&ctx);
        self.show_toast(&ctx);
    }
}

/// Centre a fixed-width column in the window, the way the onboarding and
/// unlock artboards are laid out. An anchored area is used because its size
/// comes from its content, which is what makes true vertical centring
/// possible in one pass.
fn centred(ui: &mut egui::Ui, contents: impl FnOnce(&mut egui::Ui)) {
    egui::Area::new(egui::Id::new("setup-column"))
        .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
        .show(ui.ctx(), |ui| {
            ui.set_max_width(560.0);
            ui.vertical_centered(|ui| contents(ui));
        });
}

impl App {
    fn wallet_shell(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("rail")
            .exact_size(RAIL_WIDTH)
            .resizable(false)
            .drag_to_open(false)
            .frame(egui::Frame::NONE.fill(SURFACE).inner_margin(egui::Margin {
                left: 16,
                right: 16,
                top: 22,
                bottom: 18,
            }))
            .show(ui, |ui| self.rail(ui));

        egui::Panel::top("top-bar")
            .exact_size(TOP_BAR_HEIGHT)
            .resizable(false)
            .drag_to_open(false)
            .frame(
                egui::Frame::NONE
                    .fill(BG)
                    .inner_margin(egui::Margin::symmetric(CONTENT_PAD as i8, 0)),
            )
            .show(ui, |ui| self.top_bar(ui));

        egui::CentralPanel::no_frame()
            .frame(
                egui::Frame::NONE
                    .fill(BG)
                    .inner_margin(egui::Margin::same(CONTENT_PAD as i8)),
            )
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = GAP;
                // A short window scrolls rather than clipping the last card.
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| match self.route {
                        Route::Dashboard => screens::dashboard(self, ui),
                        Route::Send => screens::send(self, ui),
                        Route::Receive => screens::receive(self, ui),
                        Route::Activity => screens::activity(self, ui),
                        Route::Settings => screens::settings(self, ui),
                    });
            });
    }

    fn rail(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(6.0);
            self.logo(ui, 30.0);
            ui.add_space(11.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 1.0;
                text(ui, "LofSwap", semibold(15.0), TEXT);
                caps_colored(ui, "Wallet", TEXT_FAINT);
            });
        });
        ui.add_space(24.0);

        ui.spacing_mut().item_spacing.y = 3.0;
        for (route, label, icon) in Route::ALL {
            if self.nav_item(ui, route, label, icon).clicked() {
                self.route = route;
            }
        }

        let footer_height = 100.0;
        let remaining = ui.available_height() - footer_height;
        if remaining > 0.0 {
            ui.add_space(remaining);
        }
        divider(ui);
        ui.add_space(8.0);
        self.network_footer(ui);
    }

    fn nav_item(&self, ui: &mut egui::Ui, route: Route, label: &str, icon: Icon) -> egui::Response {
        let selected = self.route == route;
        let (rect, response) =
            ui.allocate_exact_size(Vec2::new(ui.available_width(), NAV_HEIGHT), Sense::click());
        if ui.is_rect_visible(rect) {
            let painter = ui.painter();
            if selected {
                painter.rect_filled(rect, CornerRadius::same(RADIUS_CONTROL), ACCENT_BG);
                painter.rect_filled(
                    egui::Rect::from_min_max(
                        egui::pos2(rect.left(), rect.top() + 8.0),
                        egui::pos2(rect.left() + 2.0, rect.bottom() - 8.0),
                    ),
                    CornerRadius::same(1),
                    ACCENT_LIT,
                );
            } else if response.hovered() {
                painter.rect_filled(rect, CornerRadius::same(RADIUS_CONTROL), SURFACE_HI);
            }

            let icon_rect = egui::Rect::from_min_size(
                egui::pos2(rect.left() + 14.0, rect.center().y - 9.0),
                Vec2::splat(18.0),
            );
            let colour = if selected {
                ACCENT_LIT
            } else if response.hovered() {
                TEXT_DIM
            } else {
                TEXT_MUTED
            };
            icons::paint(painter, icon, icon_rect, colour, 1.6);
            painter.text(
                egui::pos2(icon_rect.right() + 12.0, rect.center().y),
                egui::Align2::LEFT_CENTER,
                label,
                if selected { medium(14.0) } else { body(14.0) },
                if selected { TEXT } else { TEXT_MUTED },
            );
        }
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    }

    fn network_footer(&mut self, ui: &mut egui::Ui) {
        ui.spacing_mut().item_spacing.y = 9.0;
        ui.horizontal(|ui| {
            let online = self.snapshot.peers_online;
            status_dot(ui, if online > 0 { POSITIVE } else { DANGER });
            let label = match online {
                0 => "no peers reachable".to_owned(),
                1 => "1 peer online".to_owned(),
                n => format!("{n} peers online"),
            };
            text(ui, label, body(12.0), TEXT_DIM);
        });

        egui::containers::Sides::new().height(16.0).show(
            ui,
            |ui| {
                text(ui, "Height", body(12.0), TEXT_FAINT);
            },
            |ui| {
                let height = match self.snapshot.tip_height {
                    Some(height) => grouped(height),
                    None => "—".to_owned(),
                };
                text(ui, height, mono_medium(12.0), TEXT_MUTED);
            },
        );
        egui::containers::Sides::new().height(16.0).show(
            ui,
            |ui| {
                text(ui, "Chain", body(12.0), TEXT_FAINT);
            },
            |ui| {
                text(ui, blockchain_core::CHAIN_ID, body(12.0), TEXT_MUTED);
            },
        );
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        let (title, subtitle) = self.route.title();
        let rect = ui.max_rect();

        // The title block is painted rather than laid out so it sits exactly
        // on the bar's centre line whatever the controls beside it do.
        let painter = ui.painter();
        painter.text(
            egui::pos2(rect.left(), rect.center().y - 11.0),
            egui::Align2::LEFT_CENTER,
            title,
            semibold(19.0),
            TEXT,
        );
        painter.text(
            egui::pos2(rect.left(), rect.center().y + 12.0),
            egui::Align2::LEFT_CENTER,
            subtitle,
            body(12.0),
            TEXT_MUTED,
        );

        ui.allocate_ui_with_layout(rect.size(), Layout::right_to_left(Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = GAP_SM;
            if icon_button(ui, Icon::Lock, 34.0)
                .on_hover_text("Lock the wallet")
                .clicked()
            {
                self.lock();
            }
            if icon_button(ui, Icon::Refresh, 34.0)
                .on_hover_text("Check the peers again now")
                .clicked()
            {
                self.worker.send(Cmd::Refresh);
            }
            if let Some(address) = self.address.clone()
                && self.address_chip(ui, &address).clicked()
            {
                ui.ctx().copy_text(address);
                self.notify(ToastKind::Success, "Address copied.");
            }
        });
    }

    fn address_chip(&self, ui: &mut egui::Ui, address: &str) -> egui::Response {
        let short = short_address(address);
        let galley = ui
            .painter()
            .layout_no_wrap(short, mono_medium(12.0), TEXT_DIM);
        let width = galley.size().x + 24.0 + 15.0;
        let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 34.0), Sense::click());
        if ui.is_rect_visible(rect) {
            let painter = ui.painter();
            painter.rect(
                rect,
                CornerRadius::same(RADIUS_CONTROL),
                if response.hovered() {
                    SURFACE_HI
                } else {
                    SURFACE
                },
                Stroke::new(1.0, LINE),
                StrokeKind::Inside,
            );
            painter.galley(
                egui::pos2(rect.left() + 12.0, rect.center().y - galley.size().y / 2.0),
                galley,
                TEXT_DIM,
            );
            icons::paint(
                painter,
                Icon::Copy,
                egui::Rect::from_center_size(
                    egui::pos2(rect.right() - 19.0, rect.center().y),
                    Vec2::splat(15.0),
                ),
                if response.hovered() { TEXT } else { TEXT_MUTED },
                1.6,
            );
        }
        response.on_hover_text("Copy the full address")
    }

    fn show_toast(&mut self, ctx: &egui::Context) {
        let Some(toast) = &self.toast else { return };
        let (accent, icon) = match toast.kind {
            ToastKind::Info => (TEXT_DIM, Icon::Alert),
            ToastKind::Success => (POSITIVE, Icon::Check),
            ToastKind::Error => (DANGER, Icon::Alert),
        };
        let message = toast.message.clone();

        let mut dismissed = false;
        egui::Area::new(egui::Id::new("toast"))
            .anchor(egui::Align2::CENTER_BOTTOM, Vec2::new(0.0, -24.0))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                let frame = egui::Frame::NONE
                    .fill(SURFACE_HI)
                    .stroke(Stroke::new(1.0, LINE_STRONG))
                    .corner_radius(CornerRadius::same(RADIUS_CONTROL))
                    .inner_margin(egui::Margin::symmetric(16, 12));
                let response = frame
                    .show(ui, |ui| {
                        ui.set_max_width(560.0);
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 10.0;
                            let (rect, _) =
                                ui.allocate_exact_size(Vec2::splat(16.0), Sense::hover());
                            icons::paint(ui.painter(), icon, rect, accent, 1.8);
                            text(ui, message, body(13.0), TEXT);
                        });
                    })
                    .response;
                if response.interact(Sense::click()).clicked() {
                    dismissed = true;
                }
            });
        if dismissed {
            self.toast = None;
        }
    }

    fn show_modal(&mut self, ctx: &egui::Context) {
        let Some(modal) = self.modal else { return };
        let response = egui::Modal::new(egui::Id::new("wallet-modal"))
            .backdrop_color(egui::Color32::from_black_alpha(180))
            .frame(card_frame(CARD_PAD))
            .show(ctx, |ui| {
                ui.set_width(420.0);
                ui.spacing_mut().item_spacing.y = GAP;
                match modal {
                    Modal::ChangePassphrase => screens::change_passphrase_modal(self, ui),
                    Modal::RevealSecret => screens::reveal_modal(self, ui),
                    Modal::ConfirmDelete => screens::delete_modal(self, ui),
                }
            });
        if response.should_close() {
            self.close_modal();
        }
    }

    pub fn close_modal(&mut self) {
        self.modal = None;
        self.revealed = None;
        self.forms.current_passphrase.clear();
        self.forms.new_passphrase.clear();
        self.forms.new_passphrase_confirm.clear();
        self.forms.reveal_passphrase.clear();
    }

    /// Write the settings to disk and let the worker pick them up.
    pub fn persist_settings(&mut self) {
        self.settings.normalize();
        self.forms.local_node = self.settings.local_node.clone();
        if let Err(err) = self.settings.save() {
            self.notify(ToastKind::Error, err);
            return;
        }
        self.worker.send(Cmd::ApplySettings(self.settings.clone()));
    }

    pub fn version_line(&self) -> String {
        format!("{APP_TITLE} {APP_VERSION}")
    }

    /// The brand mark, uploaded to the GPU once and reused at every size.
    pub fn logo(&mut self, ui: &mut egui::Ui, size: f32) {
        let texture = self.logo_texture.get_or_insert_with(|| {
            let image = match eframe::icon_data::from_png_bytes(crate::APP_MARK_PNG) {
                Ok(icon) => egui::ColorImage::from_rgba_unmultiplied(
                    [icon.width as usize, icon.height as usize],
                    &icon.rgba,
                ),
                Err(_) => egui::ColorImage::filled([1, 1], egui::Color32::TRANSPARENT),
            };
            ui.ctx()
                .load_texture("lofswap-mark", image, egui::TextureOptions::LINEAR)
        });
        ui.add(egui::Image::from_texture(&*texture).fit_to_exact_size(Vec2::splat(size)));
    }
}
