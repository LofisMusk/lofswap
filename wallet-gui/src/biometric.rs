//! Unlocking without retyping the passphrase.
//!
//! The passphrase goes into the OS credential store (Keychain, Secret Service,
//! Credential Manager). On macOS the read is additionally gated behind a Touch
//! ID prompt raised by a tiny Swift helper the wallet compiles on first use.

use std::fs;

use crate::storage;

const SERVICE: &str = "lofswap-wallet";
const ACCOUNT: &str = "default-wallet-passphrase";

#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::Command;

#[cfg(target_os = "macos")]
const HELPER_BIN: &str = "LofSwap Wallet TouchID";
#[cfg(target_os = "macos")]
const HELPER_SRC: &str = "lofswap-touchid-helper.swift";
#[cfg(target_os = "macos")]
const HELPER_ICON: &str = "lofswap-touchid-icon.png";
#[cfg(target_os = "macos")]
const HELPER_VERSION_FILE: &str = "lofswap-touchid-helper.version";
#[cfg(target_os = "macos")]
const HELPER_VERSION: &str = "4";
#[cfg(target_os = "macos")]
const HELPER_SWIFT: &str = r#"import LocalAuthentication
import Foundation
import Dispatch
import AppKit

let args = CommandLine.arguments
let reason = args.count > 1 ? args[1] : "Unlock LofSwap Wallet"
if args.count > 2 {
    let iconPath = args[2]
    if let icon = NSImage(contentsOfFile: iconPath) {
        NSApplication.shared.setApplicationIconImage(icon)
    }
}
ProcessInfo.processInfo.setValue("LofSwap Wallet", forKey: "processName")

let context = LAContext()
var error: NSError?
if !context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
    if let err = error {
        fputs("Touch ID unavailable: \(err.localizedDescription)\n", stderr)
    }
    exit(2)
}

let semaphore = DispatchSemaphore(value: 0)
var authenticated = false
context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { ok, err in
    authenticated = ok
    if !ok, let err = err {
        fputs("Touch ID failed: \(err.localizedDescription)\n", stderr)
    }
    semaphore.signal()
}
_ = semaphore.wait(timeout: .distantFuture)
exit(authenticated ? 0 : 3)
"#;

/// What the unlock button calls this on the current platform.
pub fn label() -> &'static str {
    if cfg!(target_os = "macos") {
        "Touch ID"
    } else {
        "the system keychain"
    }
}

/// True when this machine has a credential store the wallet can write to.
pub fn supported() -> bool {
    keyring::Entry::new(SERVICE, ACCOUNT).is_ok()
}

/// True when the user turned the feature on for this wallet.
pub fn enabled() -> bool {
    storage::biometric_marker_path().exists()
}

pub enum ReadError {
    /// Nothing stored — the user must unlock with the passphrase once.
    NoEntry,
    Failed(String),
}

/// Turn the feature on or off, storing or clearing the passphrase.
pub fn set_enabled(enable: bool, passphrase: &str) -> Result<(), String> {
    if enable {
        store(passphrase).map_err(|e| format!("could not enable {}: {e}", label()))?;
        fs::write(storage::biometric_marker_path(), b"enabled")
            .map_err(|e| format!("could not record the unlock preference: {e}"))?;
    } else {
        let _ = clear();
        let _ = fs::remove_file(storage::biometric_marker_path());
    }
    Ok(())
}

/// Prompt for biometrics (macOS) and return the stored passphrase.
pub fn unlock_passphrase() -> Result<String, ReadError> {
    #[cfg(target_os = "macos")]
    prompt_touch_id("Unlock LofSwap Wallet").map_err(ReadError::Failed)?;
    load()
}

pub fn store(passphrase: &str) -> Result<(), String> {
    let attempt = keyring::Entry::new(SERVICE, ACCOUNT)
        .map_err(|e| format!("credential store unavailable: {e}"))
        .and_then(|entry| {
            entry
                .set_password(passphrase)
                .map_err(|e| format!("credential store write failed: {e}"))
        });
    if attempt.is_ok() {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        macos_security_store(passphrase)
    }
    #[cfg(not(target_os = "macos"))]
    {
        attempt
    }
}

pub fn load() -> Result<String, ReadError> {
    let attempt = keyring::Entry::new(SERVICE, ACCOUNT)
        .map_err(|e| ReadError::Failed(format!("credential store unavailable: {e}")))
        .and_then(|entry| {
            entry.get_password().map_err(|e| match e {
                keyring::Error::NoEntry => ReadError::NoEntry,
                other => ReadError::Failed(format!("credential store read failed: {other}")),
            })
        });
    if attempt.is_ok() {
        return attempt;
    }
    #[cfg(target_os = "macos")]
    {
        macos_security_load()
    }
    #[cfg(not(target_os = "macos"))]
    {
        attempt
    }
}

pub fn clear() -> Result<(), String> {
    let attempt = keyring::Entry::new(SERVICE, ACCOUNT)
        .map_err(|e| format!("credential store unavailable: {e}"))
        .and_then(|entry| {
            entry
                .delete_credential()
                .map_err(|e| format!("credential store delete failed: {e}"))
        });
    if attempt.is_ok() {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        macos_security_clear()
    }
    #[cfg(not(target_os = "macos"))]
    {
        attempt
    }
}

// ------------------------------------------------------------------ macOS ---

#[cfg(target_os = "macos")]
fn macos_security_store(passphrase: &str) -> Result<(), String> {
    let output = Command::new("security")
        .args([
            "add-generic-password",
            "-U",
            "-a",
            ACCOUNT,
            "-s",
            SERVICE,
            "-w",
            passphrase,
        ])
        .output()
        .map_err(|e| format!("could not run the macOS security tool: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "keychain write failed: {}. Open Keychain Access and allow this app to store the item.",
            detail(&output)
        ))
    }
}

#[cfg(target_os = "macos")]
fn macos_security_load() -> Result<String, ReadError> {
    let output = Command::new("security")
        .args(["find-generic-password", "-w", "-a", ACCOUNT, "-s", SERVICE])
        .output()
        .map_err(|e| ReadError::Failed(format!("could not run the macOS security tool: {e}")))?;

    if output.status.success() {
        let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if value.is_empty() {
            Err(ReadError::NoEntry)
        } else {
            Ok(value)
        }
    } else if not_found(&output) {
        Err(ReadError::NoEntry)
    } else {
        Err(ReadError::Failed(format!(
            "keychain read failed: {}",
            detail(&output)
        )))
    }
}

#[cfg(target_os = "macos")]
fn macos_security_clear() -> Result<(), String> {
    let output = Command::new("security")
        .args(["delete-generic-password", "-a", ACCOUNT, "-s", SERVICE])
        .output()
        .map_err(|e| format!("could not run the macOS security tool: {e}"))?;
    if output.status.success() || not_found(&output) {
        Ok(())
    } else {
        Err(format!("keychain delete failed: {}", detail(&output)))
    }
}

#[cfg(target_os = "macos")]
fn not_found(output: &std::process::Output) -> bool {
    String::from_utf8_lossy(&output.stderr)
        .to_ascii_lowercase()
        .contains("could not be found")
}

#[cfg(target_os = "macos")]
fn detail(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if !stderr.is_empty() {
        return stderr;
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !stdout.is_empty() {
        return stdout;
    }
    format!("exit status {}", output.status)
}

#[cfg(target_os = "macos")]
fn prompt_touch_id(reason: &str) -> Result<(), String> {
    let helper = ensure_helper_binary()?;
    let icon = ensure_helper_icon()?;
    let output = Command::new(&helper)
        .arg(reason)
        .arg(icon)
        .output()
        .map_err(|e| format!("could not launch the Touch ID helper: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "Touch ID authentication failed: {}",
            detail(&output)
        ))
    }
}

#[cfg(target_os = "macos")]
fn ensure_helper_binary() -> Result<PathBuf, String> {
    storage::ensure_dirs();
    let binary = storage::cache_dir().join(HELPER_BIN);
    let source = storage::cache_dir().join(HELPER_SRC);
    let version = storage::cache_dir().join(HELPER_VERSION_FILE);

    let current = binary.is_file()
        && fs::read_to_string(&version)
            .map(|v| v.trim() == HELPER_VERSION)
            .unwrap_or(false);
    if current {
        return Ok(binary);
    }

    fs::write(&source, HELPER_SWIFT)
        .map_err(|e| format!("could not write the Touch ID helper source: {e}"))?;

    let build = |program: &str, args: &[&str]| {
        Command::new(program)
            .args(args)
            .arg("-O")
            .arg("-o")
            .arg(&binary)
            .arg(&source)
            .output()
    };

    let output = match build("swiftc", &[]) {
        Ok(output) => output,
        Err(direct) => build("xcrun", &["swiftc"]).map_err(|via_xcrun| {
            format!("could not build the Touch ID helper (swiftc: {direct}, xcrun: {via_xcrun})")
        })?,
    };
    if !output.status.success() {
        return Err(format!(
            "could not build the Touch ID helper: {}",
            detail(&output)
        ));
    }

    fs::write(version, HELPER_VERSION)
        .map_err(|e| format!("could not record the Touch ID helper version: {e}"))?;
    Ok(binary)
}

#[cfg(target_os = "macos")]
fn ensure_helper_icon() -> Result<PathBuf, String> {
    storage::ensure_dirs();
    let path = storage::cache_dir().join(HELPER_ICON);
    fs::write(&path, crate::APP_ICON_PNG)
        .map_err(|e| format!("could not write the Touch ID helper icon: {e}"))?;
    Ok(path)
}
