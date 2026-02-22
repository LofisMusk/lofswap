use std::borrow::Cow;
use std::env;
use std::error::Error;
use std::fs;
use std::io::{Cursor, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine;
use blockchain_core::{
    Block, CHAIN_ID, Transaction, TxKind, pubkey_to_address,
    wallet_keystore::{
        DEFAULT_DERIVATION_PATH, WalletSecretPayload, decrypt_secret_key,
        derive_secret_key_from_mnemonic, encrypt_secret_key, generate_mnemonic_12,
        load_keystore_file, payload_secret_key_bytes, save_keystore_file,
    },
};
use chrono::Utc;
use image::imageops::{FilterType, overlay, resize};
use image::{DynamicImage, ImageFormat, Rgba, RgbaImage};
use rand::seq::IndexedRandom;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use winit::application::ApplicationHandler;
use winit::dpi::LogicalSize;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, EventLoop};
use winit::window::{Icon, Window, WindowId};
use wry::http::{Method, Request, Response, StatusCode};
#[cfg(target_os = "macos")]
use wry::Rect;
use wry::{WebView, WebViewBuilder};

const APP_TITLE: &str = "LofSwap Wallet";
const DEFAULT_DEV_URL: &str = "http://127.0.0.1:5173";
const APP_PROTOCOL: &str = "lofswap";
const APP_ICON_PNG: &[u8] = include_bytes!("../../lofswap-logo.png");
const GUI_APP_DIST_DIR_ENV: &str = "GUI_APP_DIST_DIR";
const GUI_APP_DATA_DIR_ENV: &str = "GUI_APP_DATA_DIR";

const LEGACY_WALLET: &str = ".default_wallet";
const ENCRYPTED_WALLET: &str = ".default_wallet.keystore.json";
const WALLET_MNEMONIC_ENV: &str = "LOFSWAP_WALLET_MNEMONIC_PASSPHRASE";
const BIOMETRIC_MARKER_FILE: &str = ".default_wallet.biometric_enabled";
const BIOMETRIC_SERVICE: &str = "lofswap-wallet";
const BIOMETRIC_ACCOUNT: &str = "default-wallet-passphrase";
#[cfg(target_os = "macos")]
const TOUCH_ID_HELPER_BIN: &str = "LofSwap Wallet TouchID";
#[cfg(target_os = "macos")]
const TOUCH_ID_HELPER_SRC: &str = "lofswap-touchid-helper.swift";
#[cfg(target_os = "macos")]
const TOUCH_ID_HELPER_ICON: &str = "lofswap-touchid-icon.png";
#[cfg(target_os = "macos")]
const TOUCH_ID_HELPER_VERSION_FILE: &str = "lofswap-touchid-helper.version";
#[cfg(target_os = "macos")]
const TOUCH_ID_HELPER_VERSION: &str = "3";
#[cfg(target_os = "macos")]
const TOUCH_ID_HELPER_SWIFT: &str = r#"import LocalAuthentication
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

const WALLET_CACHE_DIR: &str = "wallet-cache";
const PEER_CACHE_FILE: &str = "peers_cache.json";
const GUI_SETTINGS_FILE: &str = "gui_settings.json";
const CONNECT_TIMEOUT: Duration = Duration::from_millis(250);
const OFFLINE_GRACE: Duration = Duration::from_secs(10);
const PEER_DISCOVERY_INTERVAL: Duration = Duration::from_secs(20);
const DEFAULT_MIN_BROADCAST_PEERS: usize = 2;
const DEFAULT_TX_FEE: u64 = 1;
const DEFAULT_TX_HISTORY_LIMIT: usize = 50;

static BOOTSTRAP_NODES: &[&str] = &["89.168.107.239:6000", "79.76.116.108:6000"];
static GUI_DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

type AnyError = Box<dyn Error + Send + Sync>;

fn main() {
    if let Err(err) = launch() {
        eprintln!("failed to start wallet-gui: {err}");
        std::process::exit(1);
    }
}

fn launch() -> Result<(), AnyError> {
    let frontend = resolve_frontend_source();

    let event_loop = EventLoop::new()?;
    let mut app = GuiApp::new(frontend);
    event_loop.run_app(&mut app)?;
    Ok(())
}

fn resolve_frontend_source() -> FrontendSource {
    if let Ok(dev_url) = env::var("GUI_APP_DEV_URL") {
        let trimmed = dev_url.trim();
        if !trimmed.is_empty() {
            return FrontendSource {
                app_url: trimmed.to_string(),
                dist_dir: None,
            };
        }
    }

    if let Ok(override_dist_dir) = env::var(GUI_APP_DIST_DIR_ENV) {
        let trimmed = override_dist_dir.trim();
        if !trimmed.is_empty() {
            let dist_dir = PathBuf::from(trimmed);
            if dist_dir.join("index.html").is_file() {
                return FrontendSource {
                    app_url: format!("{APP_PROTOCOL}://app/index.html"),
                    dist_dir: Some(dist_dir),
                };
            }
        }
    }

    if let Some(dist_dir) = bundled_frontend_dist_dir() {
        return FrontendSource {
            app_url: format!("{APP_PROTOCOL}://app/index.html"),
            dist_dir: Some(dist_dir),
        };
    }

    #[cfg(debug_assertions)]
    {
        let dist_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("frontend")
            .join("dist");
        if dist_dir.join("index.html").is_file() {
            return FrontendSource {
                app_url: format!("{APP_PROTOCOL}://app/index.html"),
                dist_dir: Some(dist_dir),
            };
        }
    }

    FrontendSource {
        app_url: DEFAULT_DEV_URL.to_string(),
        dist_dir: None,
    }
}

fn bundled_frontend_dist_dir() -> Option<PathBuf> {
    let exe = env::current_exe().ok()?;
    let resources = exe.parent()?.parent()?.join("Resources");
    let dist_dir = resources.join("frontend-dist");
    if dist_dir.join("index.html").is_file() {
        Some(dist_dir)
    } else {
        None
    }
}

fn gui_data_dir() -> &'static Path {
    GUI_DATA_DIR.get_or_init(compute_gui_data_dir).as_path()
}

fn compute_gui_data_dir() -> PathBuf {
    if let Ok(value) = env::var(GUI_APP_DATA_DIR_ENV) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("LofSwap Wallet");
        }
    }

    env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("wallet-gui-data")
}

fn data_path(file_name: &str) -> PathBuf {
    gui_data_dir().join(file_name)
}

fn cache_dir_path() -> PathBuf {
    gui_data_dir().join(WALLET_CACHE_DIR)
}

fn cache_file_path(file_name: &str) -> PathBuf {
    cache_dir_path().join(file_name)
}

fn encrypted_wallet_path() -> PathBuf {
    data_path(ENCRYPTED_WALLET)
}

fn legacy_wallet_path() -> PathBuf {
    data_path(LEGACY_WALLET)
}

fn biometric_marker_path() -> PathBuf {
    data_path(BIOMETRIC_MARKER_FILE)
}

#[cfg(target_os = "macos")]
fn touch_id_helper_bin_path() -> PathBuf {
    cache_file_path(TOUCH_ID_HELPER_BIN)
}

#[cfg(target_os = "macos")]
fn touch_id_helper_src_path() -> PathBuf {
    cache_file_path(TOUCH_ID_HELPER_SRC)
}

#[cfg(target_os = "macos")]
fn touch_id_helper_icon_path() -> PathBuf {
    cache_file_path(TOUCH_ID_HELPER_ICON)
}

#[cfg(target_os = "macos")]
fn touch_id_helper_version_path() -> PathBuf {
    cache_file_path(TOUCH_ID_HELPER_VERSION_FILE)
}

struct FrontendSource {
    app_url: String,
    dist_dir: Option<PathBuf>,
}

#[derive(Clone)]
struct BackendState {
    peer_store: PeerStore,
    user_settings: UserSettings,
    unlocked_wallet: Option<UnlockedWallet>,
    network_snapshot: NetworkSnapshot,
    last_biometric_error: Option<String>,
    session_biometric_passphrase: Option<String>,
}

#[derive(Clone, Default)]
struct NetworkSnapshot {
    peers_online: usize,
    balance: Option<u64>,
    transactions: Vec<TxView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct UserSettings {
    min_broadcast_peers: usize,
}

impl Default for UserSettings {
    fn default() -> Self {
        Self {
            min_broadcast_peers: DEFAULT_MIN_BROADCAST_PEERS,
        }
    }
}

impl UserSettings {
    fn normalize_min_peers(value: usize) -> usize {
        value.max(1)
    }

    fn load() -> Self {
        ensure_cache_dir();
        let settings_path = cache_file_path(GUI_SETTINGS_FILE);
        let from_disk = fs::read_to_string(settings_path)
            .ok()
            .and_then(|body| serde_json::from_str::<UserSettings>(&body).ok())
            .unwrap_or_default();
        Self {
            min_broadcast_peers: Self::normalize_min_peers(from_disk.min_broadcast_peers),
        }
    }

    fn save(&self) -> Result<(), String> {
        ensure_cache_dir();
        let body = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize settings: {e}"))?;
        let settings_path = cache_file_path(GUI_SETTINGS_FILE);
        fs::write(settings_path, body).map_err(|e| format!("failed to write settings: {e}"))
    }
}

#[derive(Clone)]
struct UnlockedWallet {
    secret_key: SecretKey,
    public_key: String,
    address: String,
}

impl UnlockedWallet {
    fn from_secret_key(secret_key: SecretKey) -> Self {
        let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret_key).to_string();
        let address = pubkey_to_address(&public_key);
        Self {
            secret_key,
            public_key,
            address,
        }
    }
}

struct GuiApp {
    frontend: FrontendSource,
    backend_state: Arc<Mutex<BackendState>>,
    webview: Option<WebView>,
    window: Option<Window>,
    macos_shell_configured: bool,
}

impl GuiApp {
    fn new(frontend: FrontendSource) -> Self {
        Self {
            frontend,
            backend_state: Arc::new(Mutex::new(BackendState {
                peer_store: PeerStore::load(),
                user_settings: UserSettings::load(),
                unlocked_wallet: None,
                network_snapshot: NetworkSnapshot::default(),
                last_biometric_error: None,
                session_biometric_passphrase: None,
            })),
            webview: None,
            window: None,
            macos_shell_configured: false,
        }
    }

    fn build_webview(&self, window: &Window) -> Result<WebView, wry::Error> {
        let api_state = Arc::clone(&self.backend_state);
        let dist_dir = self.frontend.dist_dir.clone().map(Arc::new);

        let builder = WebViewBuilder::new()
            .with_url(&self.frontend.app_url)
            .with_initialization_script("window.__LOFSWAP_API_BASE__ = 'lofswap://app/api';")
            .with_custom_protocol(APP_PROTOCOL.to_string(), move |_id, request| {
                handle_protocol_request(
                    &api_state,
                    dist_dir.as_deref().map(|path| path.as_path()),
                    request,
                )
            });

        #[cfg(target_os = "macos")]
        {
            // On macOS, using `build()` replaces NSWindow contentView. Winit expects its own
            // WinitView there and can crash on minimize/deactivate callbacks otherwise.
            return builder
                .with_bounds(webview_bounds_for_window(window))
                .build_as_child(window);
        }

        #[cfg(not(target_os = "macos"))]
        {
            builder.build(window)
        }
    }

    fn clear_window_state(&mut self) {
        // WebView must be dropped before Window on macOS to avoid platform crashes.
        self.webview = None;
        self.window = None;
    }

    fn sync_webview_bounds_to_window(&self) {
        #[cfg(target_os = "macos")]
        {
            if let (Some(webview), Some(window)) = (self.webview.as_ref(), self.window.as_ref()) {
                if let Err(err) = webview.set_bounds(webview_bounds_for_window(window)) {
                    eprintln!("failed to resize webview bounds: {err}");
                }
            }
        }
    }
}

impl ApplicationHandler for GuiApp {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }

        #[cfg(target_os = "macos")]
        {
            if !self.macos_shell_configured {
                configure_macos_app_shell();
                self.macos_shell_configured = true;
            }
        }

        let window_attributes = Window::default_attributes()
            .with_title(APP_TITLE)
            .with_inner_size(LogicalSize::new(1280.0, 820.0))
            .with_window_icon(load_app_icon());

        let window = match event_loop.create_window(window_attributes) {
            Ok(window) => window,
            Err(err) => {
                eprintln!("failed to create app window: {err}");
                event_loop.exit();
                return;
            }
        };

        let webview = match self.build_webview(&window) {
            Ok(webview) => webview,
            Err(err) => {
                eprintln!("failed to create webview: {err}");
                event_loop.exit();
                return;
            }
        };

        self.webview = Some(webview);
        self.window = Some(window);
    }

    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        event: WindowEvent,
    ) {
        match event {
            WindowEvent::CloseRequested => {
                event_loop.exit();
            }
            WindowEvent::Resized(_) | WindowEvent::ScaleFactorChanged { .. } => {
                self.sync_webview_bounds_to_window();
            }
            _ => {}
        }
    }

    fn exiting(&mut self, _event_loop: &ActiveEventLoop) {
        // Drop WebView/Window only when the app is really exiting.
        // This avoids lifecycle edge-cases on macOS minimize/restore.
        self.clear_window_state();
    }
}

fn load_app_icon() -> Option<Icon> {
    let icon = build_squircle_icon_image(512)?;
    let (width, height) = icon.dimensions();
    Icon::from_rgba(icon.into_raw(), width, height).ok()
}

#[cfg(target_os = "macos")]
fn webview_bounds_for_window(window: &Window) -> Rect {
    let logical = window
        .inner_size()
        .to_logical::<f64>(window.scale_factor());
    let width = logical.width.max(1.0).round() as i32;
    let height = logical.height.max(1.0).round() as i32;

    Rect {
        position: wry::dpi::LogicalPosition::new(0i32, 0i32).into(),
        size: wry::dpi::LogicalSize::new(width, height).into(),
    }
}

fn build_squircle_icon_png() -> Option<Vec<u8>> {
    let icon = build_squircle_icon_image(1024)?;
    let mut encoded = Vec::new();
    DynamicImage::ImageRgba8(icon)
        .write_to(&mut Cursor::new(&mut encoded), ImageFormat::Png)
        .ok()?;
    Some(encoded)
}

fn build_squircle_icon_image(size: u32) -> Option<RgbaImage> {
    if size < 32 {
        return None;
    }

    let source = image::load_from_memory(APP_ICON_PNG).ok()?.into_rgba8();
    // Bake in a black squircle/rounded-rect icon silhouette so the Dock/app icon
    // doesn't appear as a plain square when macOS uses the PNG directly.
    let mut canvas = RgbaImage::from_pixel(size, size, Rgba([0, 0, 0, 0]));
    let side = size as f32;
    let inset = (side * 0.028).max(2.0);
    let half_w = ((side - inset * 2.0) * 0.5).max(1.0);
    let half_h = half_w;
    let corner_radius = (side * 0.225).min(half_w).min(half_h);
    let center = side * 0.5;

    for y in 0..size {
        let py = y as f32 + 0.5;
        for x in 0..size {
            let px = x as f32 + 0.5;

            // Signed distance to a rounded rectangle, with a 1px AA edge.
            let qx = (px - center).abs() - (half_w - corner_radius);
            let qy = (py - center).abs() - (half_h - corner_radius);
            let outside = (qx.max(0.0).powi(2) + qy.max(0.0).powi(2)).sqrt();
            let inside = qx.max(qy).min(0.0);
            let sdf = outside + inside - corner_radius;
            let alpha = ((0.5 - sdf).clamp(0.0, 1.0) * 255.0).round() as u8;

            if alpha > 0 {
                canvas.put_pixel(x, y, Rgba([10, 10, 12, alpha]));
            }
        }
    }

    let logo_size = ((size as f32) * 0.94).round().clamp(32.0, size as f32) as u32;
    let logo = resize(&source, logo_size, logo_size, FilterType::Lanczos3);
    let offset = ((size - logo_size) / 2) as i64;
    overlay(&mut canvas, &logo, offset, offset);

    Some(canvas)
}

#[cfg(target_os = "macos")]
fn configure_macos_app_shell() {
    use cocoa::appkit::{
        NSApp, NSApplication, NSApplicationActivationPolicyRegular, NSEventModifierFlags, NSMenu,
    };
    use cocoa::base::{YES, nil, selector};

    unsafe {
        let app = NSApp();
        if app == nil {
            return;
        }

        app.setActivationPolicy_(NSApplicationActivationPolicyRegular);

        let menubar = NSMenu::new(nil);
        app.setMainMenu_(menubar);

        let app_menu = NSMenu::new(nil);
        add_menu_to_bar(menubar, app_menu);
        add_menu_item(
            app_menu,
            &format!("About {}", APP_TITLE),
            selector("orderFrontStandardAboutPanel:"),
            "",
            NSEventModifierFlags::empty(),
        );
        add_separator(app_menu);
        add_menu_item(
            app_menu,
            &format!("Hide {}", APP_TITLE),
            selector("hide:"),
            "h",
            NSEventModifierFlags::NSCommandKeyMask,
        );
        add_menu_item(
            app_menu,
            "Hide Others",
            selector("hideOtherApplications:"),
            "h",
            NSEventModifierFlags::NSCommandKeyMask | NSEventModifierFlags::NSAlternateKeyMask,
        );
        add_menu_item(
            app_menu,
            "Show All",
            selector("unhideAllApplications:"),
            "",
            NSEventModifierFlags::empty(),
        );
        add_separator(app_menu);
        add_menu_item(
            app_menu,
            &format!("Quit {}", APP_TITLE),
            selector("terminate:"),
            "q",
            NSEventModifierFlags::NSCommandKeyMask,
        );

        let file_menu = NSMenu::alloc(nil).initWithTitle_(nsstring("File"));
        add_menu_to_bar(menubar, file_menu);
        add_menu_item(
            file_menu,
            "Close Window",
            selector("performClose:"),
            "w",
            NSEventModifierFlags::NSCommandKeyMask,
        );

        let edit_menu = NSMenu::alloc(nil).initWithTitle_(nsstring("Edit"));
        add_menu_to_bar(menubar, edit_menu);
        add_menu_item(
            edit_menu,
            "Undo",
            selector("undo:"),
            "z",
            NSEventModifierFlags::NSCommandKeyMask,
        );
        add_menu_item(
            edit_menu,
            "Redo",
            selector("redo:"),
            "z",
            NSEventModifierFlags::NSCommandKeyMask | NSEventModifierFlags::NSShiftKeyMask,
        );
        add_separator(edit_menu);
        add_menu_item(
            edit_menu,
            "Cut",
            selector("cut:"),
            "x",
            NSEventModifierFlags::NSCommandKeyMask,
        );
        add_menu_item(
            edit_menu,
            "Copy",
            selector("copy:"),
            "c",
            NSEventModifierFlags::NSCommandKeyMask,
        );
        add_menu_item(
            edit_menu,
            "Paste",
            selector("paste:"),
            "v",
            NSEventModifierFlags::NSCommandKeyMask,
        );
        add_menu_item(
            edit_menu,
            "Select All",
            selector("selectAll:"),
            "a",
            NSEventModifierFlags::NSCommandKeyMask,
        );

        let view_menu = NSMenu::alloc(nil).initWithTitle_(nsstring("View"));
        add_menu_to_bar(menubar, view_menu);
        add_menu_item(
            view_menu,
            "Enter Full Screen",
            selector("toggleFullScreen:"),
            "f",
            NSEventModifierFlags::NSCommandKeyMask | NSEventModifierFlags::NSControlKeyMask,
        );

        let window_menu = NSMenu::alloc(nil).initWithTitle_(nsstring("Window"));
        add_menu_to_bar(menubar, window_menu);
        add_menu_item(
            window_menu,
            "Minimize",
            selector("performMiniaturize:"),
            "m",
            NSEventModifierFlags::NSCommandKeyMask,
        );
        add_menu_item(
            window_menu,
            "Zoom",
            selector("zoom:"),
            "",
            NSEventModifierFlags::empty(),
        );
        add_separator(window_menu);
        add_menu_item(
            window_menu,
            "Bring All to Front",
            selector("arrangeInFront:"),
            "",
            NSEventModifierFlags::empty(),
        );
        app.setWindowsMenu_(window_menu);

        let help_menu = NSMenu::alloc(nil).initWithTitle_(nsstring("Help"));
        add_menu_to_bar(menubar, help_menu);
        add_menu_item(
            help_menu,
            &format!("{} Help", APP_TITLE),
            selector("showHelp:"),
            "?",
            NSEventModifierFlags::NSCommandKeyMask,
        );

        app.activateIgnoringOtherApps_(YES);
    }
}

#[cfg(target_os = "macos")]
fn nsstring(value: &str) -> cocoa::base::id {
    use cocoa::base::nil;
    use cocoa::foundation::NSString;

    unsafe { NSString::alloc(nil).init_str(value) }
}

#[cfg(target_os = "macos")]
unsafe fn add_menu_to_bar(menubar: cocoa::base::id, submenu: cocoa::base::id) {
    use cocoa::appkit::{NSMenu, NSMenuItem};
    use cocoa::base::nil;

    unsafe {
        let item = NSMenuItem::new(nil);
        menubar.addItem_(item);
        item.setSubmenu_(submenu);
    }
}

#[cfg(target_os = "macos")]
unsafe fn add_menu_item(
    menu: cocoa::base::id,
    title: &str,
    action: cocoa::base::SEL,
    key_equivalent: &str,
    modifier_mask: cocoa::appkit::NSEventModifierFlags,
) {
    use cocoa::appkit::{NSMenu, NSMenuItem};
    use cocoa::base::nil;

    unsafe {
        let item = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
            nsstring(title),
            action,
            nsstring(key_equivalent),
        );
        item.setKeyEquivalentModifierMask_(modifier_mask);
        menu.addItem_(item);
    }
}

#[cfg(target_os = "macos")]
unsafe fn add_separator(menu: cocoa::base::id) {
    use cocoa::appkit::{NSMenu, NSMenuItem};
    use cocoa::base::nil;

    unsafe {
        menu.addItem_(NSMenuItem::separatorItem(nil));
    }
}

fn handle_protocol_request(
    backend_state: &Arc<Mutex<BackendState>>,
    dist_dir: Option<&Path>,
    request: Request<Vec<u8>>,
) -> Response<Cow<'static, [u8]>> {
    let path = request.uri().path();

    if path.starts_with("/api") {
        return handle_api_request(backend_state, request);
    }

    if let Some(dist_dir) = dist_dir {
        return serve_asset_request(dist_dir, request);
    }

    plain_response(
        StatusCode::NOT_FOUND,
        "text/plain; charset=utf-8",
        b"not found",
    )
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

type ApiResult<T> = Result<T, ApiError>;

fn handle_api_request(
    backend_state: &Arc<Mutex<BackendState>>,
    request: Request<Vec<u8>>,
) -> Response<Cow<'static, [u8]>> {
    if request.method() == Method::OPTIONS {
        return cors_response(StatusCode::NO_CONTENT, b"");
    }

    let method = request.method().clone();
    let path = request.uri().path().to_string();

    let mut state = match backend_state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let outcome: ApiResult<serde_json::Value> = (|| match (method, path.as_str()) {
        (Method::GET, "/api/state") => {
            let app_state = build_app_state(&mut state);
            serde_json::to_value(app_state)
                .map_err(|e| ApiError::internal(format!("failed to serialize app state: {e}")))
        }
        (Method::POST, "/api/state/refresh") => {
            refresh_network_snapshot(&mut state);
            let app_state = build_app_state(&mut state);
            serde_json::to_value(app_state).map_err(|e| {
                ApiError::internal(format!("failed to serialize refreshed app state: {e}"))
            })
        }
        (Method::POST, "/api/wallet/create") => {
            let req = parse_json_body::<CreateWalletRequest>(&request)?;
            let created = create_wallet(&mut state, req)?;
            serde_json::to_value(created).map_err(|e| {
                ApiError::internal(format!("failed to serialize wallet creation result: {e}"))
            })
        }
        (Method::POST, "/api/wallet/import-private-key") => {
            let req = parse_json_body::<ImportPrivateKeyRequest>(&request)?;
            let imported = import_private_key(&mut state, req)?;
            serde_json::to_value(imported).map_err(|e| {
                ApiError::internal(format!(
                    "failed to serialize private key import result: {e}"
                ))
            })
        }
        (Method::POST, "/api/wallet/import-dat") => {
            let req = parse_json_body::<ImportDatRequest>(&request)?;
            let imported = import_dat_wallet(&mut state, req)?;
            serde_json::to_value(imported).map_err(|e| {
                ApiError::internal(format!("failed to serialize dat import result: {e}"))
            })
        }
        (Method::POST, "/api/wallet/unlock") => {
            let req = parse_json_body::<UnlockRequest>(&request)?;
            let unlocked = unlock_wallet(&mut state, &req.passphrase)?;
            serde_json::to_value(unlocked)
                .map_err(|e| ApiError::internal(format!("failed to serialize unlock result: {e}")))
        }
        (Method::POST, "/api/wallet/unlock-biometric") => {
            let unlocked = unlock_wallet_with_biometric(&mut state)?;
            serde_json::to_value(unlocked).map_err(|e| {
                ApiError::internal(format!("failed to serialize biometric unlock result: {e}"))
            })
        }
        (Method::POST, "/api/wallet/lock") => {
            state.unlocked_wallet = None;
            Ok(serde_json::json!({ "locked": true }))
        }
        (Method::POST, "/api/wallet/change-passphrase") => {
            let req = parse_json_body::<ChangePassphraseRequest>(&request)?;
            let result = change_wallet_passphrase(&mut state, req)?;
            serde_json::to_value(result).map_err(|e| {
                ApiError::internal(format!("failed to serialize passphrase change result: {e}"))
            })
        }
        (Method::POST, "/api/wallet/reveal-private-key") => {
            let req = parse_json_body::<PrivateKeyAccessRequest>(&request)?;
            let result = access_private_key(req)?;
            serde_json::to_value(result).map_err(|e| {
                ApiError::internal(format!(
                    "failed to serialize private key reveal result: {e}"
                ))
            })
        }
        (Method::POST, "/api/wallet/export-private-key") => {
            let req = parse_json_body::<PrivateKeyAccessRequest>(&request)?;
            let result = access_private_key(req)?;
            serde_json::to_value(result).map_err(|e| {
                ApiError::internal(format!(
                    "failed to serialize private key export result: {e}"
                ))
            })
        }
        (Method::POST, "/api/wallet/delete-config") => {
            let result = delete_wallet_configuration(&mut state)?;
            serde_json::to_value(result).map_err(|e| {
                ApiError::internal(format!("failed to serialize wallet delete result: {e}"))
            })
        }
        (Method::POST, "/api/settings/update") => {
            let req = parse_json_body::<UpdateSettingsRequest>(&request)?;
            let result = update_user_settings(&mut state, req)?;
            serde_json::to_value(result).map_err(|e| {
                ApiError::internal(format!("failed to serialize settings update result: {e}"))
            })
        }
        (Method::POST, "/api/tx/send") => {
            let req = parse_json_body::<SendTxRequest>(&request)?;
            let result = send_transaction(&mut state, req)?;
            serde_json::to_value(result)
                .map_err(|e| ApiError::internal(format!("failed to serialize send result: {e}")))
        }
        _ => Err(ApiError {
            status: StatusCode::NOT_FOUND,
            message: "route not found".to_string(),
        }),
    })();

    match outcome {
        Ok(data) => json_response(
            StatusCode::OK,
            &serde_json::json!({ "ok": true, "data": data }),
        ),
        Err(err) => json_response(
            err.status,
            &serde_json::json!({ "ok": false, "error": err.message }),
        ),
    }
}

fn parse_json_body<T: DeserializeOwned>(request: &Request<Vec<u8>>) -> ApiResult<T> {
    serde_json::from_slice::<T>(request.body())
        .map_err(|e| ApiError::bad_request(format!("invalid request body: {e}")))
}

#[derive(Debug, Serialize)]
struct AppStateResponse {
    has_wallet_files: bool,
    wallet_unlocked: bool,
    wallet_address: Option<String>,
    wallet_public_key: Option<String>,
    min_broadcast_peers: usize,
    biometric_supported: bool,
    biometric_enabled: bool,
    biometric_label: String,
    biometric_error: Option<String>,
    peers_known: usize,
    peers_online: usize,
    balance: Option<u64>,
    transactions: Vec<TxView>,
}

#[derive(Debug, Serialize, Clone)]
struct TxView {
    txid: String,
    from: String,
    to: String,
    amount: u64,
    timestamp: i64,
    block_index: u64,
    confirmations: u64,
    direction: String,
    signature: String,
}

fn build_app_state(state: &mut BackendState) -> AppStateResponse {
    let has_wallet_files = wallet_files_exist();
    let known_peers = state.peer_store.as_slice().len();

    let (wallet_unlocked, wallet_address, wallet_public_key) = match &state.unlocked_wallet {
        Some(wallet) => (
            true,
            Some(wallet.address.clone()),
            Some(wallet.public_key.clone()),
        ),
        None => (false, None, None),
    };

    let (balance, transactions) = if wallet_unlocked {
        (
            state.network_snapshot.balance,
            state.network_snapshot.transactions.clone(),
        )
    } else {
        (None, Vec::new())
    };

    AppStateResponse {
        has_wallet_files,
        wallet_unlocked,
        wallet_address,
        wallet_public_key,
        min_broadcast_peers: state.user_settings.min_broadcast_peers,
        biometric_supported: biometric_supported(),
        biometric_enabled: biometric_marker_exists(),
        biometric_label: biometric_label().to_string(),
        biometric_error: state.last_biometric_error.clone(),
        peers_known: known_peers,
        peers_online: state.network_snapshot.peers_online,
        balance,
        transactions,
    }
}

fn refresh_network_snapshot(state: &mut BackendState) {
    let online_peers = state.peer_store.online_peers();
    let peers_online = online_peers.len();

    let (balance, transactions) = if let Some(wallet) = &state.unlocked_wallet {
        let balance = fetch_balance_from_peer_list(&online_peers, &wallet.address);
        let transactions = fetch_wallet_transactions_from_peer_list(&online_peers, &wallet.address)
            .unwrap_or_default()
            .into_iter()
            .take(DEFAULT_TX_HISTORY_LIMIT)
            .collect();
        (balance, transactions)
    } else {
        (None, Vec::new())
    };

    state.network_snapshot = NetworkSnapshot {
        peers_online,
        balance,
        transactions,
    };
}

#[derive(Debug, Deserialize)]
struct CreateWalletRequest {
    passphrase: String,
    #[serde(default)]
    use_biometric: bool,
    #[serde(default)]
    mnemonic_passphrase: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ImportPrivateKeyRequest {
    private_key_hex: String,
    passphrase: String,
    #[serde(default)]
    use_biometric: bool,
}

#[derive(Debug, Deserialize)]
struct ImportDatRequest {
    dat_base64: String,
    passphrase: String,
    #[serde(default)]
    use_biometric: bool,
}

#[derive(Debug, Deserialize)]
struct UnlockRequest {
    passphrase: String,
}

#[derive(Debug, Deserialize)]
struct ChangePassphraseRequest {
    current_passphrase: String,
    new_passphrase: String,
}

#[derive(Debug, Deserialize)]
struct PrivateKeyAccessRequest {
    passphrase: String,
}

#[derive(Debug, Deserialize)]
struct UpdateSettingsRequest {
    #[serde(default)]
    min_broadcast_peers: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct SendTxRequest {
    to: String,
    amount: u64,
    #[serde(default)]
    min_peers: Option<usize>,
}

#[derive(Debug, Serialize)]
struct WalletOperationResult {
    address: String,
    public_key: String,
    mnemonic: Option<String>,
    derivation_path: String,
    biometric_warning: Option<String>,
}

#[derive(Debug, Serialize)]
struct SendTxResult {
    txid: String,
    signature: String,
    sent_to: Vec<String>,
    required_peers: usize,
    sent_peers: usize,
}

#[derive(Debug, Serialize)]
struct PassphraseChangeResult {
    updated: bool,
    biometric_warning: Option<String>,
}

#[derive(Debug, Serialize)]
struct PrivateKeyAccessResult {
    private_key_hex: String,
    dat_base64: String,
}

#[derive(Debug, Serialize)]
struct WalletDeleteResult {
    deleted: bool,
}

#[derive(Debug, Serialize)]
struct SettingsUpdateResult {
    min_broadcast_peers: usize,
}

fn create_wallet(
    state: &mut BackendState,
    req: CreateWalletRequest,
) -> ApiResult<WalletOperationResult> {
    let passphrase = req.passphrase.trim();
    if passphrase.is_empty() {
        return Err(ApiError::bad_request("wallet passphrase is required"));
    }

    let mnemonic = generate_mnemonic_12()
        .map_err(|e| ApiError::internal(format!("failed to generate mnemonic: {e}")))?;

    let mnemonic_passphrase = req
        .mnemonic_passphrase
        .unwrap_or_else(default_mnemonic_passphrase);

    let derived =
        derive_secret_key_from_mnemonic(&mnemonic, &mnemonic_passphrase, DEFAULT_DERIVATION_PATH)
            .map_err(|e| ApiError::bad_request(format!("failed to derive wallet key: {e}")))?;

    let secret_key = SecretKey::from_byte_array(derived)
        .map_err(|_| ApiError::internal("derived secret key is invalid"))?;

    save_default_wallet_with_mnemonic(&secret_key, Some(&mnemonic), passphrase)
        .map_err(ApiError::internal)?;
    sync_biometric_preference(req.use_biometric, passphrase)?;

    let unlocked = UnlockedWallet::from_secret_key(secret_key);
    let result = WalletOperationResult {
        address: unlocked.address.clone(),
        public_key: unlocked.public_key.clone(),
        mnemonic: Some(mnemonic),
        derivation_path: DEFAULT_DERIVATION_PATH.to_string(),
        biometric_warning: None,
    };
    state.last_biometric_error = None;
    state.session_biometric_passphrase = Some(passphrase.to_string());
    state.unlocked_wallet = Some(unlocked);

    Ok(result)
}

fn import_private_key(
    state: &mut BackendState,
    req: ImportPrivateKeyRequest,
) -> ApiResult<WalletOperationResult> {
    let passphrase = req.passphrase.trim();
    if passphrase.is_empty() {
        return Err(ApiError::bad_request("wallet passphrase is required"));
    }

    let mut key_bytes = [0u8; 32];
    let decoded = hex::decode(req.private_key_hex.trim())
        .map_err(|_| ApiError::bad_request("invalid private key hex"))?;
    if decoded.len() != 32 {
        return Err(ApiError::bad_request("private key must be 32 bytes"));
    }
    key_bytes.copy_from_slice(&decoded);

    let secret_key = SecretKey::from_byte_array(key_bytes)
        .map_err(|_| ApiError::bad_request("invalid secp256k1 private key"))?;

    save_default_wallet_with_mnemonic(&secret_key, None, passphrase).map_err(ApiError::internal)?;
    sync_biometric_preference(req.use_biometric, passphrase)?;

    let unlocked = UnlockedWallet::from_secret_key(secret_key);
    let result = WalletOperationResult {
        address: unlocked.address.clone(),
        public_key: unlocked.public_key.clone(),
        mnemonic: None,
        derivation_path: DEFAULT_DERIVATION_PATH.to_string(),
        biometric_warning: None,
    };
    state.last_biometric_error = None;
    state.session_biometric_passphrase = Some(passphrase.to_string());
    state.unlocked_wallet = Some(unlocked);

    Ok(result)
}

fn import_dat_wallet(
    state: &mut BackendState,
    req: ImportDatRequest,
) -> ApiResult<WalletOperationResult> {
    let passphrase = req.passphrase.trim();
    if passphrase.is_empty() {
        return Err(ApiError::bad_request("wallet passphrase is required"));
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(req.dat_base64.trim())
        .map_err(|_| ApiError::bad_request("invalid .dat payload"))?;
    if decoded.len() != 32 {
        return Err(ApiError::bad_request(
            ".dat file must contain exactly 32 bytes",
        ));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&decoded);

    let secret_key = SecretKey::from_byte_array(key_bytes)
        .map_err(|_| ApiError::bad_request(".dat key is invalid for secp256k1"))?;

    save_default_wallet_with_mnemonic(&secret_key, None, passphrase).map_err(ApiError::internal)?;
    sync_biometric_preference(req.use_biometric, passphrase)?;

    let unlocked = UnlockedWallet::from_secret_key(secret_key);
    let result = WalletOperationResult {
        address: unlocked.address.clone(),
        public_key: unlocked.public_key.clone(),
        mnemonic: None,
        derivation_path: DEFAULT_DERIVATION_PATH.to_string(),
        biometric_warning: None,
    };
    state.last_biometric_error = None;
    state.session_biometric_passphrase = Some(passphrase.to_string());
    state.unlocked_wallet = Some(unlocked);

    Ok(result)
}

fn unlock_wallet(state: &mut BackendState, passphrase: &str) -> ApiResult<WalletOperationResult> {
    let passphrase = passphrase.trim();
    if passphrase.is_empty() {
        return Err(ApiError::bad_request("wallet passphrase is required"));
    }

    let secret_key = load_default_wallet(passphrase).map_err(ApiError::unauthorized)?;
    let unlocked = UnlockedWallet::from_secret_key(secret_key);

    // Self-heal missing secure-storage entries: if biometric was enabled before,
    // refresh the stored passphrase after a successful password unlock.
    let mut biometric_warning = None;
    if biometric_marker_exists() {
        if let Err(err) = store_biometric_passphrase(passphrase) {
            let warning = format!(
                "Touch ID credential refresh failed after password unlock: {}",
                err
            );
            eprintln!("warning: {}", warning);
            state.last_biometric_error = Some(warning.clone());
            biometric_warning = Some(warning);
        } else {
            state.last_biometric_error = None;
        }
    } else {
        state.last_biometric_error = None;
    }

    let result = WalletOperationResult {
        address: unlocked.address.clone(),
        public_key: unlocked.public_key.clone(),
        mnemonic: None,
        derivation_path: DEFAULT_DERIVATION_PATH.to_string(),
        biometric_warning,
    };
    state.session_biometric_passphrase = Some(passphrase.to_string());
    state.unlocked_wallet = Some(unlocked);

    Ok(result)
}

fn unlock_wallet_with_biometric(state: &mut BackendState) -> ApiResult<WalletOperationResult> {
    if !biometric_marker_exists() {
        return Err(ApiError::bad_request(
            "biometric unlock is not enabled for this wallet",
        ));
    }

    #[cfg(target_os = "macos")]
    {
        prompt_touch_id("Unlock LofSwap Wallet").map_err(ApiError::unauthorized)?;
    }

    let passphrase = match load_biometric_passphrase() {
        Ok(passphrase) => passphrase,
        Err(BiometricReadError::NoEntry) => {
            if let Some(session_passphrase) = state.session_biometric_passphrase.clone() {
                session_passphrase
            } else {
                return Err(ApiError::unauthorized(format!(
                    "{} is enabled, but no secure-storage entry was found. Unlock with password once, then try {} again.",
                    biometric_label(),
                    biometric_label()
                )));
            }
        }
        Err(BiometricReadError::Failed(err)) => {
            return Err(ApiError::unauthorized(err));
        }
    };
    unlock_wallet(state, &passphrase)
}

fn change_wallet_passphrase(
    state: &mut BackendState,
    req: ChangePassphraseRequest,
) -> ApiResult<PassphraseChangeResult> {
    let current = req.current_passphrase.trim();
    if current.is_empty() {
        return Err(ApiError::bad_request(
            "current wallet passphrase is required",
        ));
    }
    let new = req.new_passphrase.trim();
    if new.is_empty() {
        return Err(ApiError::bad_request("new wallet passphrase is required"));
    }

    let payload = load_default_wallet_payload(current).map_err(ApiError::unauthorized)?;
    save_wallet_from_payload(&payload, new).map_err(ApiError::internal)?;

    let secret_key =
        SecretKey::from_byte_array(payload_secret_key_bytes(&payload).map_err(|e| {
            ApiError::internal(format!("failed to parse wallet secret key bytes: {e}"))
        })?)
        .map_err(|_| ApiError::internal("wallet secret key is invalid for secp256k1"))?;
    state.unlocked_wallet = Some(UnlockedWallet::from_secret_key(secret_key));

    let mut biometric_warning = None;
    if biometric_marker_exists() {
        if let Err(err) = store_biometric_passphrase(new) {
            let warning = format!(
                "failed to refresh {} credential: {}",
                biometric_label(),
                err
            );
            state.last_biometric_error = Some(warning.clone());
            biometric_warning = Some(warning);
        } else {
            state.last_biometric_error = None;
        }
    } else {
        state.last_biometric_error = None;
    }

    state.session_biometric_passphrase = Some(new.to_string());

    Ok(PassphraseChangeResult {
        updated: true,
        biometric_warning,
    })
}

fn access_private_key(req: PrivateKeyAccessRequest) -> ApiResult<PrivateKeyAccessResult> {
    let passphrase = req.passphrase.trim();
    if passphrase.is_empty() {
        return Err(ApiError::bad_request("wallet passphrase is required"));
    }

    let payload = load_default_wallet_payload(passphrase).map_err(ApiError::unauthorized)?;
    let key_bytes = payload_secret_key_bytes(&payload)
        .map_err(|e| ApiError::internal(format!("failed to parse wallet secret key bytes: {e}")))?;

    Ok(PrivateKeyAccessResult {
        private_key_hex: hex::encode(key_bytes),
        dat_base64: base64::engine::general_purpose::STANDARD.encode(key_bytes),
    })
}

fn delete_wallet_configuration(state: &mut BackendState) -> ApiResult<WalletDeleteResult> {
    if let Err(err) = fs::remove_file(encrypted_wallet_path()) {
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(ApiError::internal(format!(
                "failed to delete encrypted wallet file: {err}"
            )));
        }
    }
    if let Err(err) = fs::remove_file(legacy_wallet_path()) {
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(ApiError::internal(format!(
                "failed to delete legacy wallet file: {err}"
            )));
        }
    }
    if let Err(err) = fs::remove_file(biometric_marker_path()) {
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(ApiError::internal(format!(
                "failed to delete biometric marker file: {err}"
            )));
        }
    }
    let _ = clear_biometric_passphrase();

    state.unlocked_wallet = None;
    state.network_snapshot = NetworkSnapshot::default();
    state.last_biometric_error = None;
    state.session_biometric_passphrase = None;

    Ok(WalletDeleteResult { deleted: true })
}

fn update_user_settings(
    state: &mut BackendState,
    req: UpdateSettingsRequest,
) -> ApiResult<SettingsUpdateResult> {
    let Some(min_peers) = req.min_broadcast_peers else {
        return Err(ApiError::bad_request(
            "min_broadcast_peers is required in settings update",
        ));
    };
    let normalized = UserSettings::normalize_min_peers(min_peers);
    state.user_settings.min_broadcast_peers = normalized;
    state
        .user_settings
        .save()
        .map_err(|e| ApiError::internal(format!("failed to persist settings: {e}")))?;

    Ok(SettingsUpdateResult {
        min_broadcast_peers: normalized,
    })
}

fn send_transaction(state: &mut BackendState, req: SendTxRequest) -> ApiResult<SendTxResult> {
    let wallet = state
        .unlocked_wallet
        .as_ref()
        .ok_or_else(|| ApiError::unauthorized("wallet must be unlocked"))?;

    let to = req.to.trim();
    if to.is_empty() {
        return Err(ApiError::bad_request("destination address is required"));
    }
    if req.amount == 0 {
        return Err(ApiError::bad_request("amount must be greater than zero"));
    }

    let min_peers = req
        .min_peers
        .unwrap_or(state.user_settings.min_broadcast_peers)
        .max(1);
    let tx = build_transfer_tx(&mut state.peer_store, &wallet.secret_key, to, req.amount);
    let payload = serde_json::to_vec(&tx)
        .map_err(|e| ApiError::internal(format!("failed to serialize transaction: {e}")))?;

    let summary = broadcast_to_peers(&mut state.peer_store, &payload, min_peers)
        .map_err(ApiError::bad_request)?;

    Ok(SendTxResult {
        txid: tx.txid,
        signature: tx.signature,
        sent_to: summary.sent_to,
        required_peers: summary.required_peers,
        sent_peers: summary.sent_peers,
    })
}

fn default_mnemonic_passphrase() -> String {
    env::var(WALLET_MNEMONIC_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
}

fn wallet_files_exist() -> bool {
    encrypted_wallet_path().exists() || legacy_wallet_path().exists()
}

fn save_default_wallet_with_mnemonic(
    secret_key: &SecretKey,
    mnemonic: Option<&str>,
    passphrase: &str,
) -> Result<(), String> {
    let bytes = secret_key.secret_bytes();
    let keystore = encrypt_secret_key(&bytes, mnemonic, Some(DEFAULT_DERIVATION_PATH), passphrase)?;
    save_keystore_file(&encrypted_wallet_path(), &keystore)?;
    let _ = fs::remove_file(legacy_wallet_path());
    Ok(())
}

fn migrate_legacy_wallet(passphrase: &str) -> Result<SecretKey, String> {
    let body = fs::read_to_string(legacy_wallet_path())
        .map_err(|e| format!("failed to read legacy wallet file: {e}"))?;
    let bytes = hex::decode(body.trim()).map_err(|_| "legacy wallet hex is invalid".to_string())?;
    if bytes.len() != 32 {
        return Err("legacy wallet key must be exactly 32 bytes".to_string());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    let secret_key = SecretKey::from_byte_array(key)
        .map_err(|_| "legacy wallet key is invalid for secp256k1".to_string())?;

    save_default_wallet_with_mnemonic(&secret_key, None, passphrase)?;
    Ok(secret_key)
}

fn load_default_wallet(passphrase: &str) -> Result<SecretKey, String> {
    if encrypted_wallet_path().exists() {
        let keystore = load_keystore_file(&encrypted_wallet_path())?;
        let payload = decrypt_secret_key(&keystore, passphrase)?;
        let key_bytes = payload_secret_key_bytes(&payload)?;
        return SecretKey::from_byte_array(key_bytes)
            .map_err(|_| "wallet secret key is invalid for secp256k1".to_string());
    }

    if legacy_wallet_path().exists() {
        return migrate_legacy_wallet(passphrase);
    }

    Err("no wallet files found".to_string())
}

fn load_default_wallet_payload(passphrase: &str) -> Result<WalletSecretPayload, String> {
    if encrypted_wallet_path().exists() {
        let keystore = load_keystore_file(&encrypted_wallet_path())?;
        return decrypt_secret_key(&keystore, passphrase);
    }

    if legacy_wallet_path().exists() {
        let _ = migrate_legacy_wallet(passphrase)?;
        let keystore = load_keystore_file(&encrypted_wallet_path())?;
        return decrypt_secret_key(&keystore, passphrase);
    }

    Err("no wallet files found".to_string())
}

fn save_wallet_from_payload(payload: &WalletSecretPayload, passphrase: &str) -> Result<(), String> {
    let key_bytes = payload_secret_key_bytes(payload)?;
    let derivation_path = if payload.derivation_path.trim().is_empty() {
        DEFAULT_DERIVATION_PATH
    } else {
        payload.derivation_path.as_str()
    };
    let keystore = encrypt_secret_key(
        &key_bytes,
        payload.mnemonic.as_deref(),
        Some(derivation_path),
        passphrase,
    )?;
    save_keystore_file(&encrypted_wallet_path(), &keystore)?;
    let _ = fs::remove_file(legacy_wallet_path());
    Ok(())
}

fn biometric_supported() -> bool {
    keyring::Entry::new(BIOMETRIC_SERVICE, BIOMETRIC_ACCOUNT).is_ok()
}

fn biometric_label() -> &'static str {
    if cfg!(target_os = "macos") {
        "Touch ID"
    } else {
        "Biometric Login"
    }
}

fn biometric_marker_exists() -> bool {
    biometric_marker_path().exists()
}

fn sync_biometric_preference(use_biometric: bool, passphrase: &str) -> ApiResult<()> {
    if use_biometric {
        store_biometric_passphrase(passphrase)
            .map_err(|e| ApiError::internal(format!("failed to enable biometric unlock: {}", e)))?;
        fs::write(biometric_marker_path(), b"enabled").map_err(|e| {
            ApiError::internal(format!("failed to persist biometric setting marker: {e}"))
        })?;
    } else {
        let _ = clear_biometric_passphrase();
        let _ = fs::remove_file(biometric_marker_path());
    }
    Ok(())
}

enum BiometricReadError {
    NoEntry,
    Failed(String),
}

fn store_biometric_passphrase(passphrase: &str) -> Result<(), String> {
    let keyring_attempt = keyring::Entry::new(BIOMETRIC_SERVICE, BIOMETRIC_ACCOUNT)
        .map_err(|e| format!("secure credential operation failed: {e}"))
        .and_then(|entry| {
            entry
                .set_password(passphrase)
                .map_err(|e| format!("secure credential operation failed: {e}"))
        });

    if keyring_attempt.is_ok() {
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        store_biometric_passphrase_macos_security(passphrase)
    }
    #[cfg(not(target_os = "macos"))]
    {
        keyring_attempt
    }
}

fn load_biometric_passphrase() -> Result<String, BiometricReadError> {
    let keyring_attempt = keyring::Entry::new(BIOMETRIC_SERVICE, BIOMETRIC_ACCOUNT)
        .map_err(|e| BiometricReadError::Failed(format!("secure credential operation failed: {e}")))
        .and_then(|entry| {
            entry.get_password().map_err(|e| match e {
                keyring::Error::NoEntry => BiometricReadError::NoEntry,
                other => BiometricReadError::Failed(format!(
                    "secure credential operation failed: {other}"
                )),
            })
        });

    if keyring_attempt.is_ok() {
        return keyring_attempt;
    }

    #[cfg(target_os = "macos")]
    {
        load_biometric_passphrase_macos_security()
    }
    #[cfg(not(target_os = "macos"))]
    {
        keyring_attempt
    }
}

fn clear_biometric_passphrase() -> Result<(), String> {
    let keyring_attempt = keyring::Entry::new(BIOMETRIC_SERVICE, BIOMETRIC_ACCOUNT)
        .map_err(|e| format!("secure credential operation failed: {e}"))
        .and_then(|entry| {
            entry
                .delete_credential()
                .map_err(|e| format!("secure credential operation failed: {e}"))
        });

    if keyring_attempt.is_ok() {
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        clear_biometric_passphrase_macos_security()
    }
    #[cfg(not(target_os = "macos"))]
    {
        keyring_attempt
    }
}

#[cfg(target_os = "macos")]
fn store_biometric_passphrase_macos_security(passphrase: &str) -> Result<(), String> {
    let output = Command::new("security")
        .args([
            "add-generic-password",
            "-U",
            "-a",
            BIOMETRIC_ACCOUNT,
            "-s",
            BIOMETRIC_SERVICE,
            "-w",
            passphrase,
        ])
        .output()
        .map_err(|e| format!("failed to execute macOS security tool: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            format!("exit status {}", output.status)
        };
        Err(format!(
            "macOS keychain write failed: {}. Open Keychain Access and allow this app/key to be stored.",
            detail
        ))
    }
}

#[cfg(target_os = "macos")]
fn load_biometric_passphrase_macos_security() -> Result<String, BiometricReadError> {
    let output = Command::new("security")
        .args([
            "find-generic-password",
            "-w",
            "-a",
            BIOMETRIC_ACCOUNT,
            "-s",
            BIOMETRIC_SERVICE,
        ])
        .output()
        .map_err(|e| {
            BiometricReadError::Failed(format!("failed to execute macOS security tool: {e}"))
        })?;

    if output.status.success() {
        let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if value.is_empty() {
            Err(BiometricReadError::NoEntry)
        } else {
            Ok(value)
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if stderr.contains("could not be found") || stderr.contains("item could not be found") {
            Err(BiometricReadError::NoEntry)
        } else {
            Err(BiometricReadError::Failed(format!(
                "macOS keychain read failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }
}

#[cfg(target_os = "macos")]
fn clear_biometric_passphrase_macos_security() -> Result<(), String> {
    let output = Command::new("security")
        .args([
            "delete-generic-password",
            "-a",
            BIOMETRIC_ACCOUNT,
            "-s",
            BIOMETRIC_SERVICE,
        ])
        .output()
        .map_err(|e| format!("failed to execute macOS security tool: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        // Deleting a non-existent credential is effectively already-cleared.
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if stderr.contains("could not be found") || stderr.contains("item could not be found") {
            Ok(())
        } else {
            Err(format!(
                "macOS keychain delete failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }
}

#[cfg(target_os = "macos")]
fn prompt_touch_id(reason: &str) -> Result<(), String> {
    let helper_binary = ensure_touch_id_helper_binary()?;
    let helper_icon = ensure_touch_id_helper_icon()?;
    let output = Command::new(&helper_binary)
        .arg(reason)
        .arg(helper_icon)
        .output()
        .map_err(|e| format!("failed to launch Touch ID helper binary: {e}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        format!("exit status {}", output.status)
    };
    Err(format!("Touch ID authentication failed: {detail}"))
}

#[cfg(target_os = "macos")]
fn ensure_touch_id_helper_binary() -> Result<PathBuf, String> {
    ensure_cache_dir();
    let helper_binary = touch_id_helper_bin_path();
    let helper_source = touch_id_helper_src_path();
    let helper_version = touch_id_helper_version_path();

    let needs_rebuild = !helper_binary.is_file()
        || fs::read_to_string(&helper_version)
            .map(|v| v.trim() != TOUCH_ID_HELPER_VERSION)
            .unwrap_or(true);

    if !needs_rebuild {
        return Ok(helper_binary);
    }

    fs::write(&helper_source, TOUCH_ID_HELPER_SWIFT)
        .map_err(|e| format!("failed to write Touch ID helper source: {e}"))?;

    let compile = Command::new("swiftc")
        .arg("-O")
        .arg("-o")
        .arg(&helper_binary)
        .arg(&helper_source)
        .output();

    let output = match compile {
        Ok(output) => output,
        Err(primary_err) => Command::new("xcrun")
            .arg("swiftc")
            .arg("-O")
            .arg("-o")
            .arg(&helper_binary)
            .arg(&helper_source)
            .output()
            .map_err(|fallback_err| {
                format!(
                    "failed to build Touch ID helper (swiftc: {}, xcrun swiftc: {})",
                    primary_err, fallback_err
                )
            })?,
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            format!("exit status {}", output.status)
        };
        return Err(format!("failed to build Touch ID helper binary: {detail}"));
    }

    fs::write(helper_version, TOUCH_ID_HELPER_VERSION)
        .map_err(|e| format!("failed to persist Touch ID helper version: {e}"))?;

    Ok(helper_binary)
}

#[cfg(target_os = "macos")]
fn ensure_touch_id_helper_icon() -> Result<PathBuf, String> {
    ensure_cache_dir();
    let icon_path = touch_id_helper_icon_path();
    let icon_png = build_squircle_icon_png()
        .ok_or_else(|| "failed to generate Touch ID helper icon".to_string())?;
    fs::write(&icon_path, &icon_png)
        .map_err(|e| format!("failed to write Touch ID helper icon: {e}"))?;
    Ok(icon_path)
}

fn ensure_cache_dir() {
    let _ = fs::create_dir_all(gui_data_dir());
    let _ = fs::create_dir_all(cache_dir_path());
}

fn peer_cache_path() -> PathBuf {
    cache_file_path(PEER_CACHE_FILE)
}

fn is_valid_peer(peer: &str) -> bool {
    peer.parse::<SocketAddr>().is_ok()
}

#[derive(Debug, Clone)]
struct PeerStore {
    peers: Vec<String>,
    offline_since: std::collections::HashMap<String, Instant>,
    last_discover_at: Option<Instant>,
}

impl PeerStore {
    fn load() -> Self {
        ensure_cache_dir();
        let mut peers: Vec<String> = BOOTSTRAP_NODES.iter().map(|p| (*p).to_string()).collect();

        let local_port = env::var("WALLET_LOCAL_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(6000);
        let local_env = env::var("WALLET_LOCAL_NODE").ok();
        let local_candidates = [
            local_env.unwrap_or_else(|| format!("127.0.0.1:{local_port}")),
            format!("localhost:{local_port}"),
        ];

        for peer in local_candidates {
            if is_valid_peer(&peer) && !peers.contains(&peer) {
                peers.push(peer);
            }
        }

        if let Ok(body) = fs::read_to_string(peer_cache_path()) {
            if let Ok(cached) = serde_json::from_str::<Vec<String>>(&body) {
                for peer in cached {
                    if is_valid_peer(&peer) && !peers.contains(&peer) {
                        peers.push(peer);
                    }
                }
            }
        }

        Self {
            peers,
            offline_since: std::collections::HashMap::new(),
            last_discover_at: None,
        }
    }

    fn save(&self) {
        ensure_cache_dir();
        let serialized = serde_json::to_string_pretty(&self.peers).unwrap_or_default();
        let _ = fs::write(peer_cache_path(), serialized);
    }

    fn as_slice(&self) -> &[String] {
        &self.peers
    }

    fn add_many(&mut self, peers: &[String]) {
        for peer in peers {
            if is_valid_peer(peer) && !self.peers.contains(peer) {
                self.peers.push(peer.clone());
            }
        }
    }

    fn discover(&mut self) {
        let candidates: Vec<String> = self
            .peers
            .iter()
            .cloned()
            .chain(BOOTSTRAP_NODES.iter().map(|peer| (*peer).to_string()))
            .collect();
        let mut seen = std::collections::HashSet::new();

        for peer in candidates {
            if !seen.insert(peer.clone()) {
                continue;
            }
            let Ok(sock) = peer.parse::<SocketAddr>() else {
                continue;
            };
            if let Ok(mut stream) = TcpStream::connect_timeout(&sock, CONNECT_TIMEOUT) {
                let _ = stream.set_read_timeout(Some(CONNECT_TIMEOUT));
                let _ = stream.set_write_timeout(Some(CONNECT_TIMEOUT));
                let _ = stream.write_all(b"/peers");
                let mut buf = Vec::new();
                if stream.read_to_end(&mut buf).is_ok() {
                    if let Ok(parsed) = serde_json::from_slice::<Vec<String>>(&buf) {
                        let filtered: Vec<String> = parsed
                            .into_iter()
                            .filter(|value| is_valid_peer(value))
                            .collect();
                        self.add_many(&filtered);
                    }
                }
            }
        }
    }

    fn refresh_online(&mut self) -> Vec<String> {
        let mut online = Vec::new();
        let mut to_remove = Vec::new();

        for peer in self.peers.clone() {
            if probe_peer(&peer) {
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
            self.peers.retain(|peer| !to_remove.contains(peer));
            for peer in to_remove {
                self.offline_since.remove(&peer);
            }
        }

        online
    }

    fn online_peers(&mut self) -> Vec<String> {
        let now = Instant::now();
        let should_discover = self
            .last_discover_at
            .map(|last| now.duration_since(last) >= PEER_DISCOVERY_INTERVAL)
            .unwrap_or(true);
        if should_discover {
            self.discover();
            self.last_discover_at = Some(now);
        }
        let deduped = self.refresh_online();
        self.save();
        deduped
    }
}

fn probe_peer(peer: &str) -> bool {
    let Ok(sock) = peer.parse::<SocketAddr>() else {
        return false;
    };
    TcpStream::connect_timeout(&sock, CONNECT_TIMEOUT).is_ok()
}

fn fetch_balance_from_peer_list(peers: &[String], address: &str) -> Option<u64> {
    let query = format!("/balance/{address}");
    for peer in peers {
        let Ok(sock) = peer.parse::<SocketAddr>() else {
            continue;
        };
        if let Ok(mut stream) = TcpStream::connect_timeout(&sock, CONNECT_TIMEOUT) {
            let _ = stream.set_read_timeout(Some(CONNECT_TIMEOUT));
            let _ = stream.set_write_timeout(Some(CONNECT_TIMEOUT));
            if stream.write_all(query.as_bytes()).is_ok() {
                let mut buf = String::new();
                if stream.read_to_string(&mut buf).is_ok() {
                    if let Ok(balance) = buf.trim().parse::<u64>() {
                        return Some(balance);
                    }
                }
            }
        }
    }
    None
}

fn fetch_chain_from_peer_list(peers: &[String]) -> Option<Vec<Block>> {
    for peer in peers {
        let Ok(sock) = peer.parse::<SocketAddr>() else {
            continue;
        };
        if let Ok(mut stream) = TcpStream::connect_timeout(&sock, CONNECT_TIMEOUT) {
            let _ = stream.set_read_timeout(Some(CONNECT_TIMEOUT));
            let _ = stream.set_write_timeout(Some(CONNECT_TIMEOUT));
            if stream.write_all(b"/chain").is_ok() {
                let mut buf = Vec::new();
                if stream.read_to_end(&mut buf).is_ok() {
                    if let Ok(chain) = serde_json::from_slice::<Vec<Block>>(&buf) {
                        return Some(chain);
                    }
                }
            }
        }
    }
    None
}

fn normalize_tx_addr(value: &str) -> String {
    if value.is_empty() {
        String::new()
    } else if value.starts_with("LFS") {
        value.to_string()
    } else {
        pubkey_to_address(value)
    }
}

fn fetch_wallet_transactions_from_peer_list(
    peers: &[String],
    address: &str,
) -> Option<Vec<TxView>> {
    let chain = fetch_chain_from_peer_list(peers)?;
    let normalized_target = normalize_tx_addr(address);
    let chain_height = chain.len() as u64;

    let mut txs = Vec::new();
    for block in &chain {
        for tx in &block.transactions {
            let from = normalize_tx_addr(&tx.from);
            let to = normalize_tx_addr(&tx.to);
            if from != normalized_target && to != normalized_target {
                continue;
            }

            let direction = if from == normalized_target {
                "sent"
            } else {
                "received"
            };
            let confirmations = chain_height.saturating_sub(block.index);
            txs.push(TxView {
                txid: tx.txid.clone(),
                from: tx.from.clone(),
                to: tx.to.clone(),
                amount: tx.amount,
                timestamp: tx.timestamp,
                block_index: block.index,
                confirmations,
                direction: direction.to_string(),
                signature: tx.signature.clone(),
            });
        }
    }

    txs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    Some(txs)
}

fn fetch_next_nonce_from_peers(store: &mut PeerStore, from_addr: &str) -> Option<u64> {
    let query = format!("/nonce/{from_addr}");
    let mut best = None;

    for peer in store.as_slice() {
        let Ok(sock) = peer.parse::<SocketAddr>() else {
            continue;
        };

        if let Ok(mut stream) = TcpStream::connect_timeout(&sock, CONNECT_TIMEOUT) {
            let _ = stream.set_read_timeout(Some(CONNECT_TIMEOUT));
            let _ = stream.set_write_timeout(Some(CONNECT_TIMEOUT));
            if stream.write_all(query.as_bytes()).is_ok() {
                let mut buf = String::new();
                if stream.read_to_string(&mut buf).is_ok() {
                    if let Ok(nonce) = buf.trim().parse::<u64>() {
                        best = Some(best.map_or(nonce, |current: u64| current.max(nonce)));
                    }
                }
            }
        }
    }

    best
}

fn build_transfer_tx(
    store: &mut PeerStore,
    secret_key: &SecretKey,
    to: &str,
    amount: u64,
) -> Transaction {
    let secp = Secp256k1::new();
    let pubkey = PublicKey::from_secret_key(&secp, secret_key);
    let from_address = pubkey_to_address(&pubkey.to_string());
    let timestamp = Utc::now().timestamp();
    let nonce = fetch_next_nonce_from_peers(store, &from_address).unwrap_or(0);

    let preimage = format!(
        "{}|{}|{:?}|{}|{}|{}|{}|{}|{}",
        3,
        CHAIN_ID,
        TxKind::Transfer,
        pubkey,
        to,
        amount,
        DEFAULT_TX_FEE,
        timestamp,
        nonce
    );
    let hash = Sha256::digest(preimage.as_bytes());
    let sig = secp.sign_ecdsa(Message::from_digest(hash.into()), secret_key);

    let mut tx = Transaction {
        version: 3,
        chain_id: CHAIN_ID.to_string(),
        kind: TxKind::Transfer,
        timestamp,
        from: from_address,
        to: to.to_string(),
        amount,
        fee: DEFAULT_TX_FEE,
        signature: hex::encode(sig.serialize_compact()),
        pubkey: pubkey.to_string(),
        nonce,
        txid: String::new(),
    };
    tx.txid = tx.compute_txid();
    tx
}

#[derive(Debug, Default)]
struct BroadcastSummary {
    sent_to: Vec<String>,
    required_peers: usize,
    sent_peers: usize,
}

fn is_already_known_reject(reason: &str) -> bool {
    let normalized = reason.to_ascii_lowercase();
    normalized.contains("transaction already exists")
        || normalized.contains("duplicate transaction")
}

fn send_tx_and_get_reply(peer: &str, payload: &[u8]) -> std::io::Result<Option<String>> {
    let sock: SocketAddr = peer
        .parse()
        .map_err(|_| std::io::Error::other("bad peer socket address"))?;

    let mut stream = TcpStream::connect_timeout(&sock, CONNECT_TIMEOUT)?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1200)));
    let _ = stream.set_write_timeout(Some(CONNECT_TIMEOUT));
    stream.write_all(payload)?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    if buf.is_empty() {
        Ok(None)
    } else {
        Ok(Some(String::from_utf8_lossy(&buf).trim().to_string()))
    }
}

fn broadcast_to_peers(
    store: &mut PeerStore,
    payload: &[u8],
    min_peers: usize,
) -> Result<BroadcastSummary, String> {
    let required = sanitize_broadcast_peer_target(min_peers);
    let peers = store.online_peers();

    if peers.len() < required {
        return Err(format!(
            "not enough reachable peers (have {}, need {})",
            peers.len(),
            required
        ));
    }

    let mut rng = rand::rng();
    let selected: Vec<String> = peers.choose_multiple(&mut rng, required).cloned().collect();

    let mut summary = BroadcastSummary {
        required_peers: required,
        ..BroadcastSummary::default()
    };

    for peer in &selected {
        match send_tx_and_get_reply(peer, payload) {
            Ok(Some(reply)) => {
                if let Some(reason) = reply.strip_prefix("reject: ") {
                    if is_already_known_reject(reason) {
                        summary.sent_to.push(peer.clone());
                    } else {
                        return Err(format!("peer {peer} rejected transaction: {reason}"));
                    }
                } else {
                    summary.sent_to.push(peer.clone());
                }
            }
            Ok(None) => summary.sent_to.push(peer.clone()),
            Err(_) => {}
        }
    }

    summary.sent_peers = summary.sent_to.len();
    if summary.sent_peers < required {
        return Err(format!(
            "transaction sent to {}/{} required peers",
            summary.sent_peers, required
        ));
    }

    Ok(summary)
}

fn sanitize_broadcast_peer_target(value: usize) -> usize {
    value.max(1)
}

fn serve_asset_request(dist_dir: &Path, request: Request<Vec<u8>>) -> Response<Cow<'static, [u8]>> {
    let request_path = request.uri().path();
    let file_path = resolve_asset_path(dist_dir, request_path);

    if file_path.is_file() {
        match fs::read(&file_path) {
            Ok(bytes) => {
                let mime = mime_guess::from_path(&file_path)
                    .first_or_octet_stream()
                    .essence_str()
                    .to_string();
                return plain_response(StatusCode::OK, &mime, &bytes);
            }
            Err(err) => {
                return plain_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "text/plain; charset=utf-8",
                    format!("failed to read asset: {err}").as_bytes(),
                );
            }
        }
    }

    plain_response(
        StatusCode::NOT_FOUND,
        "text/plain; charset=utf-8",
        b"not found",
    )
}

fn resolve_asset_path(dist_dir: &Path, request_path: &str) -> PathBuf {
    let mut normalized = PathBuf::new();
    let trimmed = request_path.trim_start_matches('/');

    for component in Path::new(trimmed).components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                return dist_dir.join("index.html");
            }
        }
    }

    if normalized.as_os_str().is_empty() {
        return dist_dir.join("index.html");
    }

    let candidate = dist_dir.join(&normalized);
    if candidate.is_file() {
        return candidate;
    }

    if candidate.extension().is_none() {
        return dist_dir.join("index.html");
    }

    candidate
}

fn response_builder(status: StatusCode, content_type: &str) -> http::response::Builder {
    Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        .header("Access-Control-Allow-Headers", "Content-Type")
}

fn plain_response(
    status: StatusCode,
    content_type: &str,
    body: &[u8],
) -> Response<Cow<'static, [u8]>> {
    response_builder(status, content_type)
        .body(Cow::Owned(body.to_vec()))
        .expect("plain response construction must succeed")
}

fn cors_response(status: StatusCode, body: &[u8]) -> Response<Cow<'static, [u8]>> {
    response_builder(status, "text/plain; charset=utf-8")
        .body(Cow::Owned(body.to_vec()))
        .expect("cors response construction must succeed")
}

fn json_response(status: StatusCode, body: &serde_json::Value) -> Response<Cow<'static, [u8]>> {
    let payload = serde_json::to_vec(body)
        .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"serialization error\"}".to_vec());
    response_builder(status, "application/json; charset=utf-8")
        .body(Cow::Owned(payload))
        .expect("json response construction must succeed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_broadcast_peer_target_never_returns_zero() {
        assert_eq!(sanitize_broadcast_peer_target(0), 1);
        assert_eq!(sanitize_broadcast_peer_target(1), 1);
        assert_eq!(sanitize_broadcast_peer_target(2), 2);
    }

    #[test]
    fn resolve_asset_path_blocks_parent_directory_escape() {
        let dist = PathBuf::from("/tmp/lofswap-test-dist");
        let resolved = resolve_asset_path(&dist, "/../secrets.txt");
        assert_eq!(resolved, dist.join("index.html"));
    }
}
