//! The unlocked wallet: dashboard, send, receive, activity and settings.

use chrono::{DateTime, Local, Utc};
use egui::{Color32, CornerRadius, Rect, Sense, Stroke, StrokeKind, Ui, Vec2};

use crate::app::{ActivityFilter, App, Modal, Route, ToastKind};
use crate::biometric;
use crate::icons::{self, Icon};
use crate::net::{self, WalletTx};
use crate::storage::MAX_MIN_BROADCAST_PEERS;
use crate::theme::*;
use crate::widgets::*;
use crate::worker::{Cmd, Job};

const RECENT_ROWS: usize = 4;

// -------------------------------------------------------------- dashboard ---

pub fn dashboard(app: &mut App, ui: &mut Ui) {
    balance_card(app, ui);
    stat_row(app, ui);
    recent_activity(app, ui);
}

fn balance_card(app: &mut App, ui: &mut Ui) {
    let balance = match app.snapshot.balance {
        Some(balance) => grouped(balance),
        None => "—".to_owned(),
    };
    let (dot_colour, status) = sync_status(app);

    let go = card(ui, CARD_PAD, |ui| {
        egui::containers::Sides::new()
            .show(
                ui,
                |ui| {
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 10.0;
                        caps(ui, "Spendable balance");
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 10.0;
                            text(ui, balance, mono_medium(40.0), TEXT);
                            text(ui, "LFS", medium(18.0), TEXT_DIM);
                        });
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 8.0;
                            status_dot(ui, dot_colour);
                            text(ui, status, body(13.0), TEXT_MUTED);
                        });
                    });
                },
                |ui| {
                    let mut go = None;
                    if Button::new("Receive", ButtonKind::Secondary)
                        .icon(Icon::ArrowDown)
                        .width(128.0)
                        .show(ui)
                        .clicked()
                    {
                        go = Some(Route::Receive);
                    }
                    if Button::new("Send", ButtonKind::Primary)
                        .icon(Icon::ArrowUp)
                        .width(118.0)
                        .show(ui)
                        .clicked()
                    {
                        go = Some(Route::Send);
                    }
                    go
                },
            )
            .1
    });
    if let Some(route) = go {
        app.route = route;
    }
}

fn sync_status(app: &App) -> (Color32, String) {
    if app.snapshot.peers_online == 0 {
        return (
            DANGER,
            "No peers reachable — add a seed node in Settings".to_owned(),
        );
    }
    if app.snapshot.scanning {
        return (
            WARNING,
            format!(
                "Reading the chain — block {}",
                grouped(app.snapshot.scanned_to)
            ),
        );
    }
    match app.snapshot.refreshed_at {
        Some(at) => (POSITIVE, format!("Up to date · checked {}", ago(at))),
        None => (WARNING, "Contacting peers…".to_owned()),
    }
}

fn stat_row(app: &mut App, ui: &mut Ui) {
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = GAP;
        let width = (ui.available_width() - 2.0 * GAP) / 3.0;
        let peers = format!(
            "{} / {}",
            app.snapshot.peers_online, app.snapshot.peers_known
        );
        stat_tile(ui, width, "Network", &peers, "peers reachable", {
            if app.snapshot.peers_online > 0 {
                POSITIVE
            } else {
                DANGER
            }
        });
        let height = app
            .snapshot
            .tip_height
            .map(grouped)
            .unwrap_or_else(|| "—".to_owned());
        stat_tile(
            ui,
            width,
            "Chain height",
            &height,
            blockchain_core::CHAIN_ID,
            TEXT_FAINT,
        );
        stat_tile(
            ui,
            width,
            "Network fee",
            &format!("{} LFS", net::DEFAULT_TX_FEE),
            "flat, per transaction",
            TEXT_FAINT,
        );
    });
}

fn stat_tile(ui: &mut Ui, width: f32, label: &str, value: &str, meta: &str, meta_colour: Color32) {
    column(ui, width, |ui| {
        card(ui, 18.0, |ui| {
            ui.spacing_mut().item_spacing.y = 9.0;
            caps(ui, label);
            text(ui, value, mono_medium(22.0), TEXT);
            text(ui, meta, body(12.0), meta_colour);
        });
    });
}

fn recent_activity(app: &mut App, ui: &mut Ui) {
    let txs: Vec<WalletTx> = app.snapshot.txs.iter().take(RECENT_ROWS).cloned().collect();
    card(ui, 18.0, |ui| {
        egui::containers::Sides::new().show(
            ui,
            |ui| {
                text(ui, "Recent activity", semibold(15.0), TEXT);
            },
            |ui| {
                if link(ui, "View all").clicked() {
                    app.route = Route::Activity;
                }
            },
        );
        ui.add_space(GAP_XS);

        if txs.is_empty() {
            empty_state(
                ui,
                if app.snapshot.scanning {
                    "Reading the chain — transactions appear as blocks are scanned."
                } else {
                    "No transactions for this address yet."
                },
            );
            return;
        }

        ui.spacing_mut().item_spacing.y = 0.0;
        for (index, tx) in txs.iter().enumerate() {
            activity_row(ui, tx, app.snapshot.tip_height);
            if index + 1 < txs.len() {
                divider(ui);
            }
        }
    });
}

/// One row of the dashboard's activity list, painted in a single 58px band so
/// the four pieces of text land exactly where the design puts them.
fn activity_row(ui: &mut Ui, tx: &WalletTx, tip: Option<u64>) {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 54.0), Sense::hover());
    if !ui.is_rect_visible(rect) {
        return;
    }
    let painter = ui.painter();

    let badge = Rect::from_min_size(
        egui::pos2(rect.left() + 4.0, rect.center().y - 16.0),
        Vec2::splat(32.0),
    );
    painter.rect(
        badge,
        CornerRadius::same(RADIUS_CONTROL),
        SURFACE_HI,
        Stroke::new(1.0, LINE),
        StrokeKind::Inside,
    );
    icons::paint(
        painter,
        if tx.incoming {
            Icon::ArrowDown
        } else {
            Icon::ArrowUp
        },
        badge.shrink(8.0),
        if tx.incoming { POSITIVE } else { TEXT_DIM },
        1.6,
    );

    let left = badge.right() + 14.0;
    painter.text(
        egui::pos2(left, rect.center().y - 9.0),
        egui::Align2::LEFT_CENTER,
        direction_label(tx),
        medium(13.0),
        TEXT,
    );
    if tx.coinbase {
        painter.text(
            egui::pos2(left, rect.center().y + 10.0),
            egui::Align2::LEFT_CENTER,
            format!("newly mined in block {}", grouped(tx.block_index)),
            body(12.0),
            TEXT_FAINT,
        );
    } else {
        painter.text(
            egui::pos2(left, rect.center().y + 10.0),
            egui::Align2::LEFT_CENTER,
            short_address(&tx.counterparty),
            mono(12.0),
            TEXT_MUTED,
        );
    }

    let right = rect.right() - 4.0;
    painter.text(
        egui::pos2(right, rect.center().y - 9.0),
        egui::Align2::RIGHT_CENTER,
        format!(
            "{}{} LFS",
            if tx.incoming { "+" } else { "−" },
            grouped(tx.amount)
        ),
        mono_medium(14.0),
        if tx.incoming { POSITIVE } else { TEXT },
    );
    painter.text(
        egui::pos2(right, rect.center().y + 10.0),
        egui::Align2::RIGHT_CENTER,
        format!("{} · {}", ago(tx.timestamp), confirmations(tx, tip)),
        body(11.0),
        TEXT_FAINT,
    );

    response.on_hover_text(&tx.txid);
}

fn direction_label(tx: &WalletTx) -> &'static str {
    if tx.coinbase {
        "Mining reward"
    } else if tx.incoming {
        "Received"
    } else {
        "Sent"
    }
}

fn confirmations(tx: &WalletTx, tip: Option<u64>) -> String {
    match tip {
        Some(tip) if tip >= tx.block_index => {
            format!("{} conf", tip - tx.block_index + 1)
        }
        _ => "pending".to_owned(),
    }
}

// ------------------------------------------------------------------- send ---

pub fn send(app: &mut App, ui: &mut Ui) {
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = GAP;
        let side_width = 316.0;
        let form_width = (ui.available_width() - side_width - GAP).max(360.0);

        column(ui, form_width, |ui| send_form(app, ui));
        column(ui, side_width, |ui| {
            ui.spacing_mut().item_spacing.y = GAP;
            send_sidebar(app, ui);
        });
    });
}

fn send_form(app: &mut App, ui: &mut Ui) {
    let balance = app.snapshot.balance.unwrap_or(0);
    let amount = app.forms.send_amount.trim().parse::<u64>().ok();
    let total = amount.map(|value| value + net::DEFAULT_TX_FEE);

    card(ui, CARD_PAD, |ui| {
        ui.spacing_mut().item_spacing.y = 18.0;
        labelled_field(
            ui,
            "Recipient address",
            Field::new(&mut app.forms.send_to).monospace().hint("LFS…"),
        );

        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = 14.0;
            let field_width = ui.available_width() - 88.0;
            column(ui, field_width, |ui| {
                labelled_field(
                    ui,
                    "Amount",
                    Field::new(&mut app.forms.send_amount)
                        .monospace()
                        .suffix("LFS")
                        .hint("0"),
                );
            });
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 8.0;
                caps(ui, " ");
                if Button::new("Max", ButtonKind::Secondary)
                    .width(74.0)
                    .enabled(balance > net::DEFAULT_TX_FEE)
                    .show(ui)
                    .clicked()
                {
                    app.forms.send_amount = (balance - net::DEFAULT_TX_FEE).to_string();
                }
            });
        });

        divider(ui);
        ui.spacing_mut().item_spacing.y = 10.0;
        summary_row(ui, "Amount", &amounted(amount), TEXT_DIM, body(13.0));
        summary_row(
            ui,
            "Network fee",
            &format!("{} LFS", net::DEFAULT_TX_FEE),
            TEXT_DIM,
            body(13.0),
        );
        divider(ui);
        summary_row(ui, "Total debit", &amounted(total), TEXT, medium(14.0));

        let affordable = total.is_some_and(|total| total <= balance);
        let addressed = app.forms.send_to.trim().starts_with("LFS");
        let busy = app.busy(Job::Sending);
        let ready = affordable
            && addressed
            && amount.is_some_and(|value| value > 0)
            && app.snapshot.peers_online > 0
            && !busy;

        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 12.0;
            if Button::new(
                if busy {
                    "Broadcasting…"
                } else {
                    "Sign & broadcast"
                },
                ButtonKind::Primary,
            )
            .icon(Icon::ArrowUp)
            .enabled(ready)
            .show(ui)
            .clicked()
            {
                app.worker.send(Cmd::Send {
                    to: app.forms.send_to.trim().to_owned(),
                    amount: amount.unwrap_or(0),
                });
            }
            if Button::new("Clear", ButtonKind::Ghost).show(ui).clicked() {
                app.forms.send_to.clear();
                app.forms.send_amount.clear();
            }
        });

        if !app.forms.send_amount.trim().is_empty() && amount.is_none() {
            text(ui, "Amounts are whole LFS.", body(12.0), DANGER);
        } else if total.is_some() && !affordable {
            text(
                ui,
                format!("That is more than the {} LFS available.", grouped(balance)),
                body(12.0),
                DANGER,
            );
        } else if !app.forms.send_to.trim().is_empty() && !addressed {
            text(ui, "LofSwap addresses start with LFS.", body(12.0), DANGER);
        }
    });
}

fn amounted(value: Option<u64>) -> String {
    match value {
        Some(value) => format!("{} LFS", grouped(value)),
        None => "—".to_owned(),
    }
}

fn summary_row(ui: &mut Ui, label: &str, value: &str, colour: Color32, font: egui::FontId) {
    egui::containers::Sides::new().height(18.0).show(
        ui,
        |ui| {
            text(
                ui,
                label,
                font.clone(),
                if colour == TEXT { TEXT } else { TEXT_MUTED },
            );
        },
        |ui| {
            text(ui, value, mono_medium(font.size + 1.0), colour);
        },
    );
}

fn send_sidebar(app: &mut App, ui: &mut Ui) {
    card(ui, 18.0, |ui| {
        ui.spacing_mut().item_spacing.y = 12.0;
        caps(ui, "Sending from");
        let address = app.address.clone().unwrap_or_default();
        text(ui, short_address(&address), mono(12.0), TEXT_DIM);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            text(
                ui,
                app.snapshot
                    .balance
                    .map(grouped)
                    .unwrap_or_else(|| "—".to_owned()),
                mono_medium(22.0),
                TEXT,
            );
            text(ui, "LFS spendable", body(13.0), TEXT_MUTED);
        });
    });

    card(ui, 18.0, |ui| {
        ui.spacing_mut().item_spacing.y = 14.0;
        section_header(ui, Icon::Peers, "Broadcast");
        paragraph(
            ui,
            "The signed transaction is pushed to peers directly — there is no relay \
             server. It counts as sent once enough of them accept it.",
        );
        let label_width = (ui.available_width() - 120.0).max(80.0);
        egui::containers::Sides::new().show(
            ui,
            |ui| {
                column(ui, label_width, |ui| {
                    text(ui, "Minimum peers", body(13.0), TEXT_DIM);
                });
            },
            |ui| {
                let mut value = app.settings.min_broadcast_peers;
                stepper(ui, &mut value, 1, MAX_MIN_BROADCAST_PEERS);
                if value != app.settings.min_broadcast_peers {
                    app.settings.min_broadcast_peers = value;
                    app.persist_settings();
                }
            },
        );
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            let online = app.snapshot.peers_online;
            status_dot(ui, if online > 0 { POSITIVE } else { DANGER });
            text(
                ui,
                format!("{online} reachable right now"),
                body(12.0),
                TEXT_MUTED,
            );
        });
    });
}

// ---------------------------------------------------------------- receive ---

pub fn receive(app: &mut App, ui: &mut Ui) {
    let address = app.address.clone().unwrap_or_default();
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = GAP;
        let qr_width = 244.0;
        let detail_width = (ui.available_width() - qr_width - GAP).max(320.0);
        column(ui, qr_width, |ui| {
            card(ui, 24.0, |ui| {
                ui.vertical_centered(|ui| {
                    ui.spacing_mut().item_spacing.y = 18.0;
                    qr_code(app, ui, &address, 196.0);
                    text(ui, "Scan to fill in this address", body(12.0), TEXT_FAINT);
                });
            });
        });

        column(ui, detail_width, |ui| {
            ui.spacing_mut().item_spacing.y = GAP;
            card(ui, CARD_PAD, |ui| {
                ui.spacing_mut().item_spacing.y = 14.0;
                caps(ui, "Your receiving address");
                boxed_mono(ui, &address);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    if Button::new("Copy address", ButtonKind::Primary)
                        .icon(Icon::Copy)
                        .show(ui)
                        .clicked()
                    {
                        ui.ctx().copy_text(address.clone());
                        app.notify(ToastKind::Success, "Address copied.");
                    }
                    if let Some(public_key) = app.public_key.clone()
                        && Button::new("Copy public key", ButtonKind::Ghost)
                            .icon(Icon::Eye)
                            .show(ui)
                            .clicked()
                    {
                        ui.ctx().copy_text(public_key);
                        app.notify(ToastKind::Success, "Public key copied.");
                    }
                });
            });

            card(ui, 18.0, |ui| {
                ui.horizontal_top(|ui| {
                    ui.spacing_mut().item_spacing.x = 12.0;
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(18.0), Sense::hover());
                    icons::paint(ui.painter(), Icon::Alert, rect, WARNING, 1.6);
                    paragraph(
                        ui,
                        &format!(
                            "This address only accepts LFS on {}. Coins sent from any other \
                             chain are unrecoverable. It is derived from your key, never \
                             changes, and is safe to reuse.",
                            blockchain_core::CHAIN_ID
                        ),
                    );
                });
            });

            card(ui, 18.0, |ui| {
                ui.spacing_mut().item_spacing.y = 12.0;
                caps(ui, "Waiting for incoming transfers");
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(16.0), Sense::hover());
                    icons::paint(ui.painter(), Icon::Refresh, rect, TEXT_MUTED, 1.6);
                    text(
                        ui,
                        format!(
                            "Polling {} peers every 20 seconds",
                            app.snapshot.peers_online
                        ),
                        body(13.0),
                        TEXT_DIM,
                    );
                });
                text(
                    ui,
                    format!("Derivation path {}", net::DERIVATION_PATH),
                    mono(11.0),
                    TEXT_FAINT,
                );
            });
        });
    });
}

fn qr_code(app: &mut App, ui: &mut Ui, address: &str, size: f32) {
    if app
        .qr
        .as_ref()
        .is_none_or(|(cached, _, _)| cached != address)
    {
        app.qr = qrcode::QrCode::new(address.as_bytes()).ok().map(|code| {
            let width = code.width();
            let modules = code
                .to_colors()
                .into_iter()
                .map(|colour| colour == qrcode::Color::Dark)
                .collect();
            (address.to_owned(), modules, width)
        });
    }

    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size + 32.0), Sense::hover());
    let painter = ui.painter();
    painter.rect(
        rect,
        CornerRadius::same(10),
        BG,
        Stroke::new(1.0, LINE_STRONG),
        StrokeKind::Inside,
    );

    let Some((_, modules, width)) = &app.qr else {
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            "no address",
            body(12.0),
            TEXT_FAINT,
        );
        return;
    };

    let cell = size / *width as f32;
    let origin = rect.min + Vec2::splat(16.0);
    for (index, dark) in modules.iter().enumerate() {
        if !dark {
            continue;
        }
        let x = (index % width) as f32;
        let y = (index / width) as f32;
        painter.rect_filled(
            egui::Rect::from_min_size(
                origin + Vec2::new(x * cell, y * cell),
                Vec2::splat(cell.ceil()),
            ),
            CornerRadius::ZERO,
            Color32::WHITE,
        );
    }
}

fn boxed_mono(ui: &mut Ui, value: &str) {
    let frame = egui::Frame::NONE
        .fill(SURFACE_HI)
        .stroke(Stroke::new(1.0, LINE))
        .corner_radius(CornerRadius::same(RADIUS_CONTROL))
        .inner_margin(egui::Margin::same(14));
    frame.show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.style_mut().visuals.override_text_color = Some(TEXT);
        ui.label(egui::RichText::new(value).font(mono(15.0)));
    });
}

// --------------------------------------------------------------- activity ---

pub fn activity(app: &mut App, ui: &mut Ui) {
    let search = app.forms.search.trim().to_lowercase();
    let filter = app.filter;
    let tip = app.snapshot.tip_height;
    let rows: Vec<WalletTx> = app
        .snapshot
        .txs
        .iter()
        .filter(|tx| match filter {
            ActivityFilter::All => true,
            ActivityFilter::Received => tx.incoming,
            ActivityFilter::Sent => !tx.incoming,
        })
        .filter(|tx| {
            search.is_empty()
                || tx.counterparty.to_lowercase().contains(&search)
                || tx.txid.to_lowercase().contains(&search)
        })
        .cloned()
        .collect();
    let total = app.snapshot.txs.len();

    let scanning = app.snapshot.scanning;
    let scanned_to = app.snapshot.scanned_to;
    // Split the borrow up front: the two halves of the row touch different
    // fields, which the closures on their own could not prove.
    let selected_filter = &mut app.filter;
    let search_text = &mut app.forms.search;

    card(ui, 18.0, |ui| {
        egui::containers::Sides::new().show(
            ui,
            |ui| {
                ui.spacing_mut().item_spacing.x = GAP_XS;
                for (value, label) in [
                    (ActivityFilter::All, "All"),
                    (ActivityFilter::Received, "Received"),
                    (ActivityFilter::Sent, "Sent"),
                ] {
                    let selected = *selected_filter == value;
                    let clicked = chip(
                        ui,
                        label,
                        if selected { TEXT } else { TEXT_MUTED },
                        if selected { ACCENT_BG } else { SURFACE_HI },
                        if selected {
                            Color32::from_rgb(0x3a, 0x12, 0x20)
                        } else {
                            LINE
                        },
                    )
                    .clicked();
                    if clicked {
                        *selected_filter = value;
                    }
                }
            },
            |ui| {
                Field::new(search_text)
                    .hint("Address or transaction id")
                    .leading(Icon::Search)
                    .compact()
                    .width(260.0)
                    .show(ui);
            },
        );
        ui.add_space(GAP_SM);

        table_header(ui);
        if rows.is_empty() {
            empty_state(
                ui,
                if total == 0 {
                    "Nothing has touched this address yet."
                } else {
                    "No transactions match that filter."
                },
            );
            return;
        }

        // Leave room for the footer line below the table.
        let table_height = (ui.available_height() - 46.0).max(120.0);
        egui::ScrollArea::vertical()
            .auto_shrink([false, true])
            .max_height(table_height)
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                for (index, tx) in rows.iter().enumerate() {
                    table_row(ui, tx, tip);
                    if index + 1 < rows.len() {
                        divider(ui);
                    }
                }
            });

        ui.add_space(GAP_SM);
        egui::containers::Sides::new().show(
            ui,
            |ui| {
                text(
                    ui,
                    format!(
                        "Showing {} of {total} transactions on this chain",
                        rows.len()
                    ),
                    body(12.0),
                    TEXT_FAINT,
                );
            },
            |ui| {
                if scanning {
                    text(
                        ui,
                        format!("scanning · block {}", grouped(scanned_to)),
                        body(12.0),
                        WARNING,
                    );
                }
            },
        );
    });
}

const COLUMNS: [f32; 4] = [108.0, 124.0, 84.0, 184.0];

fn table_header(ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 12.0;
        ui.add_space(14.0);
        sized(ui, COLUMNS[0], |ui| {
            caps(ui, "Type");
        });
        let flexible = ui.available_width() - COLUMNS[1..].iter().sum::<f32>() - 12.0 * 3.0 - 14.0;
        sized(ui, flexible.max(120.0), |ui| {
            caps(ui, "Counterparty");
        });
        sized(ui, COLUMNS[1], |ui| {
            caps(ui, "Amount");
        });
        sized(ui, COLUMNS[2], |ui| {
            caps(ui, "Height");
        });
        sized(ui, COLUMNS[3], |ui| {
            caps(ui, "Time");
        });
    });
    ui.add_space(GAP_SM);
    divider(ui);
}

fn table_row(ui: &mut Ui, tx: &WalletTx, tip: Option<u64>) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 12.0;
        ui.set_min_height(46.0);
        ui.add_space(14.0);

        sized(ui, COLUMNS[0], |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(15.0), Sense::hover());
                icons::paint(
                    ui.painter(),
                    if tx.incoming {
                        Icon::ArrowDown
                    } else {
                        Icon::ArrowUp
                    },
                    rect,
                    if tx.incoming { POSITIVE } else { TEXT_MUTED },
                    1.6,
                );
                text(ui, direction_label(tx), body(13.0), TEXT_DIM);
            });
        });

        let flexible = ui.available_width() - COLUMNS[1..].iter().sum::<f32>() - 12.0 * 3.0 - 14.0;
        sized(ui, flexible.max(120.0), |ui| {
            if tx.coinbase {
                text(ui, "newly mined", body(12.0), TEXT_FAINT);
            } else {
                text(ui, short_address(&tx.counterparty), mono(12.0), TEXT_MUTED)
                    .on_hover_text(&tx.counterparty);
            }
        });
        sized(ui, COLUMNS[1], |ui| {
            text(
                ui,
                format!(
                    "{}{} LFS",
                    if tx.incoming { "+" } else { "−" },
                    grouped(tx.amount)
                ),
                mono_medium(13.0),
                if tx.incoming { POSITIVE } else { TEXT },
            );
        });
        sized(ui, COLUMNS[2], |ui| {
            text(ui, grouped(tx.block_index), mono(12.0), TEXT_MUTED);
        });
        sized(ui, COLUMNS[3], |ui| {
            egui::containers::Sides::new().show(
                ui,
                |ui| {
                    text(ui, timestamp(tx.timestamp), body(12.0), TEXT_FAINT);
                },
                |ui| {
                    chip(
                        ui,
                        &confirmations(tx, tip),
                        TEXT_FAINT,
                        Color32::TRANSPARENT,
                        LINE,
                    );
                },
            );
        });
    });
}

fn sized(ui: &mut Ui, width: f32, contents: impl FnOnce(&mut Ui)) {
    ui.allocate_ui_with_layout(
        Vec2::new(width, ui.available_height()),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            ui.set_width(width);
            contents(ui);
        },
    );
}

// --------------------------------------------------------------- settings ---

pub fn settings(app: &mut App, ui: &mut Ui) {
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = GAP;
        let side_width = 268.0;
        let main_width = (ui.available_width() - side_width - GAP).max(380.0);

        column(ui, main_width, |ui| {
            ui.spacing_mut().item_spacing.y = GAP;
            security_section(app, ui);
            network_section(app, ui);
        });
        column(ui, side_width, |ui| wallet_data_section(app, ui));
    });
}

fn security_section(app: &mut App, ui: &mut Ui) {
    card(ui, 20.0, |ui| {
        section_header(ui, Icon::Shield, "Security");
        ui.add_space(4.0);

        setting_row(
            ui,
            "Change passphrase",
            "Re-encrypts the keystore with Argon2id (128 MiB, 4 passes).",
            |ui| {
                if Button::new("Change", ButtonKind::Ghost)
                    .small()
                    .show(ui)
                    .clicked()
                {
                    app.modal = Some(Modal::ChangePassphrase);
                }
            },
        );
        divider(ui);

        if biometric::supported() {
            let label = format!("Unlock with {}", biometric::label());
            setting_row(
                ui,
                &label,
                "Stores the passphrase in the system credential store.",
                |ui| {
                    let mut enabled = app.biometric_enabled;
                    if toggle(ui, &mut enabled).clicked() {
                        app.biometric_enabled = enabled;
                        app.worker.send(Cmd::SetBiometric {
                            enabled,
                            passphrase: String::new(),
                        });
                    }
                },
            );
            divider(ui);
        }

        setting_row(
            ui,
            "Reveal private key",
            "Shows the raw secret key, a .dat export and the recovery phrase.",
            |ui| {
                if Button::new("Reveal", ButtonKind::Ghost)
                    .icon(Icon::Key)
                    .small()
                    .show(ui)
                    .clicked()
                {
                    app.modal = Some(Modal::RevealSecret);
                }
            },
        );
    });
}

fn network_section(app: &mut App, ui: &mut Ui) {
    card(ui, 20.0, |ui| {
        section_header(ui, Icon::Peers, "Network");
        ui.add_space(4.0);

        setting_row(
            ui,
            "Minimum broadcast peers",
            "A transaction only counts as sent once this many peers accept it.",
            |ui| {
                let mut value = app.settings.min_broadcast_peers;
                stepper(ui, &mut value, 1, MAX_MIN_BROADCAST_PEERS);
                if value != app.settings.min_broadcast_peers {
                    app.settings.min_broadcast_peers = value;
                    app.persist_settings();
                }
            },
        );
        divider(ui);

        setting_row(
            ui,
            "Local node",
            "Tried first for balances and broadcasts.",
            |ui| {
                let response = Field::new(&mut app.forms.local_node)
                    .monospace()
                    .width(190.0)
                    .show(ui);
                if response.lost_focus() {
                    app.settings.local_node = app.forms.local_node.clone();
                    app.persist_settings();
                }
            },
        );
        divider(ui);

        ui.add_space(14.0);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 8.0;
            text(ui, "Seed nodes", medium(13.0), TEXT);
            text(
                ui,
                "One host:port per line. Leave empty to use the addresses built into this \
                 release.",
                body(12.0),
                TEXT_MUTED,
            );
            let response = ui.add(
                egui::TextEdit::multiline(&mut app.forms.bootstrap_peers)
                    .font(mono(13.0))
                    .text_color(TEXT)
                    .hint_text(
                        egui::RichText::new("seed.example.org:6000")
                            .font(mono(13.0))
                            .color(TEXT_FAINT),
                    )
                    .desired_rows(3)
                    .desired_width(ui.available_width()),
            );
            if response.lost_focus() {
                app.settings.bootstrap_peers = app
                    .forms
                    .bootstrap_peers
                    .lines()
                    .map(|line| line.trim().to_owned())
                    .filter(|line| !line.is_empty())
                    .collect();
                app.persist_settings();
                app.notify(ToastKind::Info, "Seed nodes updated.");
            }
        });
        ui.add_space(4.0);
    });
}

fn wallet_data_section(app: &mut App, ui: &mut Ui) {
    card(ui, 20.0, |ui| {
        section_header(ui, Icon::File, "Wallet data");
        ui.add_space(4.0);

        stacked_row(
            ui,
            "Data directory",
            &crate::storage::data_dir().display().to_string(),
            |ui| {
                if Button::new("Copy path", ButtonKind::Ghost)
                    .small()
                    .show(ui)
                    .clicked()
                {
                    ui.ctx()
                        .copy_text(crate::storage::data_dir().display().to_string());
                    app.notify(ToastKind::Success, "Path copied.");
                }
            },
        );
        divider(ui);

        stacked_row(
            ui,
            "Keystore",
            "Encrypted with your passphrase. Copy it to move this wallet to another machine.",
            |ui| {
                if Button::new("Export keystore", ButtonKind::Ghost)
                    .icon(Icon::File)
                    .small()
                    .show(ui)
                    .clicked()
                {
                    export_keystore(app);
                }
            },
        );
        divider(ui);

        stacked_row(
            ui,
            "Delete this wallet",
            "Removes the keystore and the credential-store entry from this machine. \
             Irreversible without your recovery phrase.",
            |ui| {
                if Button::new("Delete wallet", ButtonKind::Danger)
                    .icon(Icon::Trash)
                    .small()
                    .show(ui)
                    .clicked()
                {
                    app.modal = Some(Modal::ConfirmDelete);
                }
            },
        );
    });
}

fn export_keystore(app: &mut App) {
    let source = crate::storage::encrypted_wallet_path();
    if !source.exists() {
        app.notify(ToastKind::Error, "There is no keystore file to export yet.");
        return;
    }
    let Some(target) = rfd::FileDialog::new()
        .set_title("Export the encrypted keystore")
        .set_file_name("lofswap-wallet.keystore.json")
        .save_file()
    else {
        return;
    };
    match std::fs::copy(&source, &target) {
        Ok(_) => app.notify(
            ToastKind::Success,
            format!("Keystore written to {}", target.display()),
        ),
        Err(err) => app.notify(ToastKind::Error, format!("Export failed: {err}")),
    }
}

fn setting_row(ui: &mut Ui, title: &str, description: &str, control: impl FnOnce(&mut Ui)) {
    ui.add_space(14.0);
    // Give the copy a fixed share of the row so it wraps instead of running
    // under whatever control sits on the right.
    let text_width = (ui.available_width() * 0.62).max(160.0);
    egui::containers::Sides::new().spacing(20.0).show(
        ui,
        |ui| {
            column(ui, text_width, |ui| {
                ui.spacing_mut().item_spacing.y = 3.0;
                text(ui, title, medium(13.0), TEXT);
                ui.scope(|ui| {
                    ui.style_mut().visuals.override_text_color = Some(TEXT_MUTED);
                    ui.label(egui::RichText::new(description).font(body(12.0)));
                });
            });
        },
        control,
    );
    ui.add_space(14.0);
}

fn stacked_row(ui: &mut Ui, title: &str, description: &str, control: impl FnOnce(&mut Ui)) {
    ui.add_space(14.0);
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 10.0;
        text(ui, title, medium(13.0), TEXT);
        paragraph(ui, description);
        control(ui);
    });
    ui.add_space(14.0);
}

// ------------------------------------------------------------------ bits ----

fn paragraph(ui: &mut Ui, value: &str) {
    ui.scope(|ui| {
        ui.style_mut().visuals.override_text_color = Some(TEXT_MUTED);
        ui.label(egui::RichText::new(value).font(body(12.0)));
    });
}

fn empty_state(ui: &mut Ui, message: &str) {
    ui.add_space(GAP_LG);
    ui.vertical_centered(|ui| {
        text(ui, message, body(13.0), TEXT_FAINT);
    });
    ui.add_space(GAP_LG);
}

fn link(ui: &mut Ui, label: &str) -> egui::Response {
    // One allocated widget rather than a row, so it right-aligns as a unit.
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_owned(), body(13.0), ACCENT_LIT);
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(galley.size().x + 20.0, 20.0), Sense::click());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        painter.galley(
            egui::pos2(rect.left(), rect.center().y - galley.size().y / 2.0),
            galley,
            ACCENT_LIT,
        );
        icons::paint(
            painter,
            Icon::Chevron,
            Rect::from_center_size(
                egui::pos2(rect.right() - 7.0, rect.center().y),
                Vec2::splat(14.0),
            ),
            ACCENT_LIT,
            1.6,
        );
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn timestamp(unix: i64) -> String {
    match DateTime::from_timestamp(unix, 0) {
        Some(moment) => moment
            .with_timezone(&Local)
            .format("%b %-d, %H:%M")
            .to_string(),
        None => "—".to_owned(),
    }
}

fn ago(unix: i64) -> String {
    let seconds = (Utc::now().timestamp() - unix).max(0);
    match seconds {
        s if s < 60 => "just now".to_owned(),
        s if s < 3600 => format!("{} min ago", s / 60),
        s if s < 86_400 => format!("{} h ago", s / 3600),
        s => format!("{} d ago", s / 86_400),
    }
}
