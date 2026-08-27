//! One function per artboard on the design canvas.

mod modals;
mod setup;
mod wallet;

pub use modals::{change_passphrase_modal, delete_modal, reveal_modal};
pub use setup::{create_wallet, import_dat, import_private_key, onboarding, recovery, unlock};
pub use wallet::{activity, dashboard, receive, send, settings};
