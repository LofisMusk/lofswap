//! The three dialogs: change passphrase, reveal secrets, delete wallet.

use egui::{CornerRadius, Sense, Stroke, Ui, Vec2};

use crate::app::{App, ToastKind};
use crate::icons::{self, Icon};
use crate::theme::*;
use crate::widgets::*;
use crate::worker::{Cmd, Job};

pub fn change_passphrase_modal(app: &mut App, ui: &mut Ui) {
    heading(ui, Icon::Shield, "Change passphrase");
    body_text(
        ui,
        "The keystore is re-encrypted in place. Your address, key and recovery phrase \
         stay the same.",
    );

    labelled_field(
        ui,
        "Current passphrase",
        Field::new(&mut app.forms.current_passphrase).password(),
    );
    labelled_field(
        ui,
        "New passphrase",
        Field::new(&mut app.forms.new_passphrase).password(),
    );
    labelled_field(
        ui,
        "Confirm new passphrase",
        Field::new(&mut app.forms.new_passphrase_confirm).password(),
    );

    let matching = app.forms.new_passphrase == app.forms.new_passphrase_confirm;
    if !app.forms.new_passphrase_confirm.is_empty() && !matching {
        text(ui, "The new passphrases do not match.", body(12.0), DANGER);
    }

    let busy = app.busy(Job::Rekeying);
    let ready = !app.forms.current_passphrase.is_empty()
        && app.forms.new_passphrase.trim().len() >= 8
        && matching
        && !busy;

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 10.0;
        if Button::new(
            if busy { "Working…" } else { "Change" },
            ButtonKind::Primary,
        )
        .enabled(ready)
        .show(ui)
        .clicked()
        {
            app.worker.send(Cmd::ChangePassphrase {
                current: app.forms.current_passphrase.clone(),
                new: app.forms.new_passphrase.clone(),
            });
            app.close_modal();
        }
        if Button::new("Cancel", ButtonKind::Ghost).show(ui).clicked() {
            app.close_modal();
        }
    });
}

pub fn reveal_modal(app: &mut App, ui: &mut Ui) {
    heading(ui, Icon::Key, "Reveal private key");

    if app.revealed.is_none() {
        warning(
            ui,
            "Anyone who sees this key owns the wallet. Make sure nobody is watching your \
             screen and that this window is not being recorded.",
        );
        labelled_field(
            ui,
            "Passphrase",
            Field::new(&mut app.forms.reveal_passphrase).password(),
        );

        let busy = app.busy(Job::Revealing);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            if Button::new(
                if busy { "Decrypting…" } else { "Reveal" },
                ButtonKind::Primary,
            )
            .enabled(!app.forms.reveal_passphrase.is_empty() && !busy)
            .show(ui)
            .clicked()
            {
                app.worker.send(Cmd::RevealSecret {
                    passphrase: app.forms.reveal_passphrase.clone(),
                });
            }
            if Button::new("Cancel", ButtonKind::Ghost).show(ui).clicked() {
                app.close_modal();
            }
        });
        return;
    }

    let secrets = app.revealed.as_ref().expect("checked above");
    let private_key = secrets.private_key_hex.clone();
    let dat = secrets.dat_base64.clone();
    let mnemonic = secrets.mnemonic.clone();

    secret_block(ui, "Private key (hex)", &private_key);
    secret_block(ui, "Raw key, base64 (.dat)", &dat);
    if let Some(mnemonic) = &mnemonic {
        secret_block(ui, "Recovery phrase", mnemonic);
    }

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 10.0;
        if Button::new("Copy private key", ButtonKind::Secondary)
            .icon(Icon::Copy)
            .show(ui)
            .clicked()
        {
            ui.ctx().copy_text(private_key.clone());
            app.notify(ToastKind::Success, "Private key copied to the clipboard.");
        }
        if Button::new("Save .dat file", ButtonKind::Ghost)
            .icon(Icon::File)
            .show(ui)
            .clicked()
        {
            save_dat(app, &private_key);
        }
        if Button::new("Done", ButtonKind::Ghost).show(ui).clicked() {
            app.close_modal();
        }
    });
}

fn save_dat(app: &mut App, private_key_hex: &str) {
    let Ok(bytes) = hex::decode(private_key_hex) else {
        app.notify(ToastKind::Error, "The revealed key is not valid hex.");
        return;
    };
    let Some(path) = rfd::FileDialog::new()
        .set_title("Save the raw key file")
        .set_file_name("lofswap-wallet.dat")
        .save_file()
    else {
        return;
    };
    match std::fs::write(&path, bytes) {
        Ok(()) => app.notify(
            ToastKind::Success,
            format!("Key written to {}", path.display()),
        ),
        Err(err) => app.notify(ToastKind::Error, format!("Could not write the file: {err}")),
    }
}

pub fn delete_modal(app: &mut App, ui: &mut Ui) {
    heading(ui, Icon::Trash, "Delete this wallet");
    warning(
        ui,
        "The keystore and the credential-store entry are removed from this machine. \
         Without your recovery phrase or a keystore backup the coins are gone for good.",
    );
    if let Some(address) = app.address.clone() {
        text(ui, address, mono(12.0), TEXT_MUTED);
    }

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 10.0;
        if Button::new("Delete wallet", ButtonKind::Danger)
            .icon(Icon::Trash)
            .show(ui)
            .clicked()
        {
            app.worker.send(Cmd::DeleteWallet);
            app.close_modal();
        }
        if Button::new("Keep it", ButtonKind::Ghost).show(ui).clicked() {
            app.close_modal();
        }
    });
}

// ------------------------------------------------------------------ bits ----

fn heading(ui: &mut Ui, icon: Icon, title: &str) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 9.0;
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(18.0), Sense::hover());
        icons::paint(ui.painter(), icon, rect, TEXT_DIM, 1.6);
        text(ui, title, semibold(16.0), TEXT);
    });
}

fn body_text(ui: &mut Ui, value: &str) {
    ui.scope(|ui| {
        ui.style_mut().visuals.override_text_color = Some(TEXT_MUTED);
        ui.label(egui::RichText::new(value).font(body(12.0)));
    });
}

fn warning(ui: &mut Ui, value: &str) {
    let frame = egui::Frame::NONE
        .fill(SURFACE_HI)
        .stroke(Stroke::new(1.0, LINE))
        .corner_radius(CornerRadius::same(RADIUS_CONTROL))
        .inner_margin(egui::Margin::same(14));
    frame.show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = 12.0;
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(18.0), Sense::hover());
            icons::paint(ui.painter(), Icon::Alert, rect, WARNING, 1.6);
            ui.scope(|ui| {
                ui.style_mut().visuals.override_text_color = Some(TEXT_MUTED);
                ui.label(egui::RichText::new(value).font(body(12.0)));
            });
        });
    });
}

fn secret_block(ui: &mut Ui, label: &str, value: &str) {
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 8.0;
        caps(ui, label);
        let frame = egui::Frame::NONE
            .fill(SURFACE_HI)
            .stroke(Stroke::new(1.0, LINE))
            .corner_radius(CornerRadius::same(RADIUS_CONTROL))
            .inner_margin(egui::Margin::same(12));
        frame.show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.style_mut().visuals.override_text_color = Some(TEXT);
            ui.label(egui::RichText::new(value).font(mono(12.0)));
        });
    });
}
