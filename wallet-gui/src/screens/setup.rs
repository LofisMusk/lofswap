//! First run and unlock: onboarding, wallet creation, imports, the recovery
//! phrase, and the unlock screen every later launch starts on.

use egui::{CornerRadius, Sense, Stroke, StrokeKind, Ui, Vec2};

use crate::app::{App, Stage, ToastKind};
use crate::biometric;
use crate::icons::{self, Icon};
use crate::theme::*;
use crate::widgets::*;
use crate::worker::{Cmd, Job};

pub fn onboarding(app: &mut App, ui: &mut Ui) {
    ui.spacing_mut().item_spacing.y = 0.0;
    app.logo(ui, 64.0);
    ui.add_space(16.0);
    text(ui, "Set up your wallet", semibold(26.0), TEXT);
    ui.add_space(7.0);
    wrapped(
        ui,
        "Keys are generated and encrypted on this machine. Nothing is uploaded, and no \
         account is created anywhere.",
        400.0,
    );
    ui.add_space(28.0);

    ui.spacing_mut().item_spacing.y = 12.0;
    column(ui, 520.0, |ui| {
        if option_card(
            ui,
            Icon::Plus,
            "Create a new wallet",
            "Generates a 12-word recovery phrase and a fresh keystore.",
            true,
        )
        .clicked()
        {
            app.stage = Stage::CreateWallet;
        }
        if option_card(
            ui,
            Icon::Key,
            "Import a private key",
            "Paste a 32-byte secp256k1 key in hex.",
            false,
        )
        .clicked()
        {
            app.stage = Stage::ImportPrivateKey;
        }
        if option_card(
            ui,
            Icon::File,
            "Import a .dat file",
            "Restore a raw key file exported from the CLI wallet.",
            false,
        )
        .clicked()
        {
            app.stage = Stage::ImportDat;
        }
    });

    ui.add_space(28.0);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 10.0;
        chip(
            ui,
            blockchain_core::CHAIN_ID,
            TEXT_MUTED,
            egui::Color32::TRANSPARENT,
            LINE,
        );
        text(ui, app.version_line(), body(12.0), TEXT_FAINT);
    });
}

pub fn create_wallet(app: &mut App, ui: &mut Ui) {
    setup_header(
        app,
        ui,
        "Choose a passphrase",
        "It encrypts the keystore on this machine. There is no way to reset it.",
    );

    column(ui, 420.0, |ui| {
        card(ui, CARD_PAD, |ui| {
            ui.spacing_mut().item_spacing.y = GAP;
            labelled_field(
                ui,
                "Passphrase",
                Field::new(&mut app.forms.passphrase)
                    .password()
                    .hint("at least 8 characters"),
            );
            labelled_field(
                ui,
                "Confirm passphrase",
                Field::new(&mut app.forms.passphrase_confirm).password(),
            );

            if biometric::supported() {
                biometric_opt_in(ui, &mut app.forms.biometric_opt_in);
            }

            let ready = app.forms.passphrase.trim().len() >= 8
                && app.forms.passphrase == app.forms.passphrase_confirm;
            let busy = app.busy(Job::Creating);
            if Button::new(
                if busy { "Creating…" } else { "Create wallet" },
                ButtonKind::Primary,
            )
            .width(ui.available_width())
            .enabled(ready && !busy)
            .show(ui)
            .clicked()
            {
                app.worker.send(Cmd::Create {
                    passphrase: app.forms.passphrase.clone(),
                    biometric: app.forms.biometric_opt_in,
                });
            }

            if !app.forms.passphrase_confirm.is_empty()
                && app.forms.passphrase != app.forms.passphrase_confirm
            {
                text(ui, "The two passphrases do not match.", body(12.0), DANGER);
            } else if !app.forms.passphrase.is_empty() && app.forms.passphrase.trim().len() < 8 {
                text(ui, "Use at least 8 characters.", body(12.0), TEXT_MUTED);
            }
        });
    });

    back_link(app, ui);
}

pub fn import_private_key(app: &mut App, ui: &mut Ui) {
    setup_header(
        app,
        ui,
        "Import a private key",
        "The key is encrypted with your passphrase before it touches the disk.",
    );

    column(ui, 460.0, |ui| {
        card(ui, CARD_PAD, |ui| {
            ui.spacing_mut().item_spacing.y = GAP;
            labelled_field(
                ui,
                "Private key (hex)",
                Field::new(&mut app.forms.private_key)
                    .monospace()
                    .hint("64 hexadecimal characters"),
            );
            labelled_field(
                ui,
                "Passphrase",
                Field::new(&mut app.forms.passphrase).password(),
            );
            if biometric::supported() {
                biometric_opt_in(ui, &mut app.forms.biometric_opt_in);
            }

            let ready =
                app.forms.private_key.trim().len() == 64 && !app.forms.passphrase.trim().is_empty();
            let busy = app.busy(Job::Importing);
            if Button::new(
                if busy {
                    "Importing…"
                } else {
                    "Import wallet"
                },
                ButtonKind::Primary,
            )
            .width(ui.available_width())
            .enabled(ready && !busy)
            .show(ui)
            .clicked()
            {
                app.worker.send(Cmd::ImportPrivateKey {
                    private_key_hex: app.forms.private_key.clone(),
                    passphrase: app.forms.passphrase.clone(),
                    biometric: app.forms.biometric_opt_in,
                });
            }
        });
    });

    back_link(app, ui);
}

pub fn import_dat(app: &mut App, ui: &mut Ui) {
    setup_header(
        app,
        ui,
        "Import a .dat file",
        "The raw key file the CLI wallet writes, or a base64 export of it.",
    );

    column(ui, 460.0, |ui| {
        card(ui, CARD_PAD, |ui| {
            ui.spacing_mut().item_spacing.y = GAP;

            caps(ui, "Key file");
            let picked = app.forms.dat_name.is_some();
            let chosen = app
                .forms
                .dat_name
                .clone()
                .unwrap_or_else(|| "No file chosen".to_owned());
            egui::containers::Sides::new().show(
                ui,
                |ui| {
                    text(
                        ui,
                        chosen,
                        mono(13.0),
                        if picked { TEXT } else { TEXT_FAINT },
                    );
                },
                |ui| {
                    if Button::new("Choose file", ButtonKind::Secondary)
                        .icon(Icon::File)
                        .small()
                        .show(ui)
                        .clicked()
                        && let Some(path) = rfd::FileDialog::new()
                            .set_title("Select a LofSwap key file")
                            .add_filter("Key file", &["dat", "txt"])
                            .pick_file()
                    {
                        match std::fs::read(&path) {
                            Ok(bytes) => {
                                app.forms.dat_name = path
                                    .file_name()
                                    .map(|name| name.to_string_lossy().into_owned());
                                app.forms.dat_bytes = Some(bytes);
                            }
                            Err(err) => {
                                app.notify(
                                    ToastKind::Error,
                                    format!("Could not read that file: {err}"),
                                );
                            }
                        }
                    }
                },
            );

            labelled_field(
                ui,
                "Passphrase",
                Field::new(&mut app.forms.passphrase).password(),
            );
            if biometric::supported() {
                biometric_opt_in(ui, &mut app.forms.biometric_opt_in);
            }

            let ready = app.forms.dat_bytes.is_some() && !app.forms.passphrase.trim().is_empty();
            let busy = app.busy(Job::Importing);
            if Button::new(
                if busy {
                    "Importing…"
                } else {
                    "Import wallet"
                },
                ButtonKind::Primary,
            )
            .width(ui.available_width())
            .enabled(ready && !busy)
            .show(ui)
            .clicked()
                && let Some(bytes) = app.forms.dat_bytes.clone()
            {
                app.worker.send(Cmd::ImportDat {
                    bytes,
                    passphrase: app.forms.passphrase.clone(),
                    biometric: app.forms.biometric_opt_in,
                });
            }
        });
    });

    back_link(app, ui);
}

pub fn recovery(app: &mut App, ui: &mut Ui) {
    ui.spacing_mut().item_spacing.y = 0.0;
    text(ui, "Write down your recovery phrase", semibold(24.0), TEXT);
    ui.add_space(7.0);
    wrapped(
        ui,
        "These twelve words rebuild your key if this machine is lost. Anyone who reads \
         them owns your coins.",
        440.0,
    );
    ui.add_space(22.0);

    column(ui, 560.0, |ui| {
        card(ui, 20.0, |ui| {
            egui::Grid::new("recovery-words")
                .num_columns(3)
                .spacing(Vec2::splat(10.0))
                .show(ui, |ui| {
                    for (index, word) in app.recovery_words.iter().enumerate() {
                        recovery_word(ui, index + 1, word);
                        if index % 3 == 2 {
                            ui.end_row();
                        }
                    }
                });
        });

        ui.add_space(GAP);
        card(ui, 16.0, |ui| {
            ui.horizontal_top(|ui| {
                ui.spacing_mut().item_spacing.x = 12.0;
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(18.0), Sense::hover());
                icons::paint(ui.painter(), Icon::Alert, rect, WARNING, 1.6);
                ui.vertical(|ui| {
                    ui.style_mut().visuals.override_text_color = Some(TEXT_MUTED);
                    ui.label(
                        egui::RichText::new(
                            "LofSwap derives its key from this phrase with HKDF, not BIP32/BIP44. \
                             Restoring it in MetaMask, Ledger or Trezor produces a different key \
                             and an empty balance — restore it in a LofSwap wallet.",
                        )
                        .font(body(12.0)),
                    );
                });
            });
        });

        ui.add_space(GAP);
        let acknowledged = app.recovery_acknowledged;
        let (ticked, action) = egui::containers::Sides::new().height(BUTTON_HEIGHT).show(
            ui,
            |ui| {
                ui.spacing_mut().item_spacing.x = 12.0;
                let mut ticked = acknowledged;
                checkbox(ui, &mut ticked);
                text(
                    ui,
                    "I have written the phrase down offline",
                    body(13.0),
                    TEXT_DIM,
                );
                ticked
            },
            |ui| {
                let mut action = None;
                if Button::new("Continue", ButtonKind::Primary)
                    .width(150.0)
                    .enabled(acknowledged)
                    .show(ui)
                    .clicked()
                {
                    action = Some(true);
                }
                if Button::new("Copy phrase", ButtonKind::Ghost)
                    .icon(Icon::Copy)
                    .show(ui)
                    .clicked()
                {
                    action = Some(false);
                }
                action
            },
        );
        app.recovery_acknowledged = ticked;
        match action {
            Some(true) => {
                app.recovery_words.clear();
                app.stage = Stage::Wallet;
            }
            Some(false) => {
                ui.ctx().copy_text(app.recovery_words.join(" "));
                app.notify(
                    ToastKind::Success,
                    "Recovery phrase copied to the clipboard.",
                );
            }
            None => {}
        }
    });
}

pub fn unlock(app: &mut App, ui: &mut Ui) {
    ui.spacing_mut().item_spacing.y = 0.0;
    app.logo(ui, 56.0);
    ui.add_space(14.0);
    text(ui, "Welcome back", semibold(22.0), TEXT);
    ui.add_space(5.0);
    text(
        ui,
        "Unlock the keystore on this machine",
        body(13.0),
        TEXT_MUTED,
    );
    ui.add_space(26.0);

    let busy = app.busy(Job::Unlocking);
    column(ui, 400.0, |ui| {
        card(ui, CARD_PAD, |ui| {
            ui.spacing_mut().item_spacing.y = GAP;
            let field = labelled_field(
                ui,
                "Passphrase",
                Field::new(&mut app.forms.unlock_passphrase).password(),
            );
            let submitted = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

            let ready = !app.forms.unlock_passphrase.is_empty() && !busy;
            if (Button::new(
                if busy { "Unlocking…" } else { "Unlock" },
                ButtonKind::Primary,
            )
            .width(ui.available_width())
            .enabled(ready)
            .show(ui)
            .clicked()
                || (submitted && ready))
                && ready
            {
                app.worker.send(Cmd::Unlock {
                    passphrase: app.forms.unlock_passphrase.clone(),
                });
            }

            if app.biometric_enabled {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 12.0;
                    let width = (ui.available_width() - 40.0) / 2.0;
                    rule(ui, width);
                    text(ui, "OR", body(11.0), TEXT_FAINT);
                    rule(ui, width);
                });
                if Button::new(
                    &format!("Use {}", biometric::label()),
                    ButtonKind::Secondary,
                )
                .icon(Icon::Lock)
                .width(ui.available_width())
                .enabled(!busy)
                .show(ui)
                .clicked()
                {
                    app.worker.send(Cmd::UnlockBiometric);
                }
            }
        });
    });

    ui.add_space(GAP);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        text(ui, blockchain_core::CHAIN_ID, body(12.0), TEXT_FAINT);
        text(ui, "·", body(12.0), TEXT_FAINT);
        text(ui, app.version_line(), body(12.0), TEXT_FAINT);
    });
}

// ----------------------------------------------------------------- pieces ---

fn setup_header(app: &mut App, ui: &mut Ui, title: &str, subtitle: &str) {
    ui.spacing_mut().item_spacing.y = 0.0;
    app.logo(ui, 52.0);
    ui.add_space(14.0);
    text(ui, title, semibold(22.0), TEXT);
    ui.add_space(6.0);
    wrapped(ui, subtitle, 420.0);
    ui.add_space(24.0);
}

fn back_link(app: &mut App, ui: &mut Ui) {
    ui.add_space(GAP);
    if Button::new("Back", ButtonKind::Ghost)
        .icon(Icon::Back)
        .small()
        .show(ui)
        .clicked()
    {
        app.forms.passphrase.clear();
        app.forms.passphrase_confirm.clear();
        app.forms.private_key.clear();
        app.forms.dat_bytes = None;
        app.forms.dat_name = None;
        app.stage = Stage::Onboarding;
    }
}

fn wrapped(ui: &mut Ui, value: &str, width: f32) {
    ui.scope(|ui| {
        ui.set_max_width(width);
        ui.style_mut().visuals.override_text_color = Some(TEXT_MUTED);
        ui.label(egui::RichText::new(value).font(body(13.0)));
    });
}

fn rule(ui: &mut Ui, width: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width.max(1.0), 1.0), Sense::hover());
    ui.painter().rect_filled(rect, CornerRadius::ZERO, LINE);
}

fn biometric_opt_in(ui: &mut Ui, value: &mut bool) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 12.0;
        checkbox(ui, value);
        text(
            ui,
            format!("Also unlock with {}", biometric::label()),
            body(13.0),
            TEXT_DIM,
        );
    });
}

fn checkbox(ui: &mut Ui, value: &mut bool) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(20.0), Sense::click());
    if response.clicked() {
        *value = !*value;
    }
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        painter.rect(
            rect,
            CornerRadius::same(5),
            if *value { ACCENT } else { SURFACE_HI },
            Stroke::new(1.0, if *value { ACCENT } else { LINE_STRONG }),
            StrokeKind::Inside,
        );
        if *value {
            icons::paint(painter, Icon::Check, rect.shrink(4.0), ON_ACCENT, 2.2);
        }
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn recovery_word(ui: &mut Ui, index: usize, word: &str) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(170.0, 42.0), Sense::hover());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        painter.rect(
            rect,
            CornerRadius::same(RADIUS_CONTROL),
            SURFACE_HI,
            Stroke::new(1.0, LINE),
            StrokeKind::Inside,
        );
        painter.text(
            egui::pos2(rect.left() + 14.0, rect.center().y),
            egui::Align2::LEFT_CENTER,
            index.to_string(),
            mono(11.0),
            TEXT_FAINT,
        );
        painter.text(
            egui::pos2(rect.left() + 40.0, rect.center().y),
            egui::Align2::LEFT_CENTER,
            word,
            medium(14.0),
            TEXT,
        );
    }
}

fn option_card(
    ui: &mut Ui,
    icon: Icon,
    title: &str,
    description: &str,
    primary: bool,
) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 76.0), Sense::click());
    if ui.is_rect_visible(rect) {
        let hovered = response.hovered();
        let fill = if primary {
            ACCENT_BG
        } else if hovered {
            SURFACE_HI
        } else {
            SURFACE
        };
        let border = if primary {
            egui::Color32::from_rgb(0x3a, 0x12, 0x20)
        } else if hovered {
            LINE_STRONG
        } else {
            LINE
        };
        let painter = ui.painter();
        painter.rect(
            rect,
            CornerRadius::same(RADIUS_CARD),
            fill,
            Stroke::new(1.0, border),
            StrokeKind::Inside,
        );

        let badge = egui::Rect::from_min_size(
            egui::pos2(rect.left() + 18.0, rect.center().y - 20.0),
            Vec2::splat(40.0),
        );
        painter.rect(
            badge,
            CornerRadius::same(10),
            SURFACE_HI,
            Stroke::new(1.0, LINE),
            StrokeKind::Inside,
        );
        icons::paint(
            painter,
            icon,
            badge.shrink(10.0),
            if primary { ACCENT_LIT } else { TEXT_DIM },
            1.6,
        );

        let text_left = badge.right() + 16.0;
        painter.text(
            egui::pos2(text_left, rect.center().y - 10.0),
            egui::Align2::LEFT_CENTER,
            title,
            semibold(14.0),
            TEXT,
        );
        painter.text(
            egui::pos2(text_left, rect.center().y + 10.0),
            egui::Align2::LEFT_CENTER,
            description,
            body(12.0),
            TEXT_MUTED,
        );
        icons::paint(
            painter,
            Icon::Chevron,
            egui::Rect::from_center_size(
                egui::pos2(rect.right() - 26.0, rect.center().y),
                Vec2::splat(16.0),
            ),
            TEXT_FAINT,
            1.6,
        );
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}
