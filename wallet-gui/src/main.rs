//! LofSwap Wallet — a native desktop wallet for the LofSwap chain.
//!
//! The window is drawn by egui: no browser engine, no bundled web assets, one
//! binary. Everything slow (peers, Argon2id, signing) happens on the worker
//! thread in [`worker`].

// A GUI application should not open a console window on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod biometric;
mod icons;
mod net;
mod screens;
mod storage;
mod theme;
mod wallet;
mod widgets;
mod worker;

pub const APP_TITLE: &str = "LofSwap Wallet";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const APP_ICON_PNG: &[u8] = include_bytes!("../../lofswap-logo.png");
/// The same mark at a size worth uploading to the GPU for in-app use.
pub const APP_MARK_PNG: &[u8] = include_bytes!("../assets/logo-256.png");

fn main() -> eframe::Result {
    storage::ensure_dirs();

    let mut viewport = egui::ViewportBuilder::default()
        .with_title(APP_TITLE)
        .with_app_id("lofswap-wallet")
        .with_inner_size(theme::WINDOW)
        .with_min_inner_size(theme::WINDOW_MIN);
    if let Ok(icon) = eframe::icon_data::from_png_bytes(APP_ICON_PNG) {
        viewport = viewport.with_icon(icon);
    }

    eframe::run_native(
        APP_TITLE,
        eframe::NativeOptions {
            viewport,
            ..Default::default()
        },
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}
