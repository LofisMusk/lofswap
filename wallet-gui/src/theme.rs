//! Design tokens for the wallet, mirroring `wallet-gui/design/Tokens.dc.html`.
//!
//! Everything the UI paints comes from here: the palette is the brand's
//! (crimson from the logo, monochrome tiers and Space Grotesk from the
//! website), and the metrics are the ones the design canvas was drawn on.

use std::sync::Arc;

use egui::{
    Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Margin, Stroke, Style,
    TextStyle, Visuals,
};

// ------------------------------------------------------------------ colors --

pub const BG: Color32 = Color32::from_rgb(0x00, 0x00, 0x00);
pub const SURFACE: Color32 = Color32::from_rgb(0x0d, 0x0d, 0x0d);
pub const SURFACE_HI: Color32 = Color32::from_rgb(0x14, 0x14, 0x14);
pub const LINE: Color32 = Color32::from_rgb(0x24, 0x24, 0x24);
pub const LINE_STRONG: Color32 = Color32::from_rgb(0x33, 0x33, 0x33);

pub const TEXT: Color32 = Color32::from_rgb(0xe6, 0xe6, 0xe6);
pub const TEXT_DIM: Color32 = Color32::from_rgb(0xb2, 0xb2, 0xb2);
pub const TEXT_MUTED: Color32 = Color32::from_rgb(0x8c, 0x8c, 0x8c);
pub const TEXT_FAINT: Color32 = Color32::from_rgb(0x6b, 0x6b, 0x6b);

pub const ACCENT: Color32 = Color32::from_rgb(0x7a, 0x00, 0x33);
pub const ACCENT_HOVER: Color32 = Color32::from_rgb(0x94, 0x25, 0x45);
pub const ACCENT_LIT: Color32 = Color32::from_rgb(0xd8, 0x64, 0x7e);
pub const ACCENT_BG: Color32 = Color32::from_rgb(0x1a, 0x07, 0x10);

pub const POSITIVE: Color32 = Color32::from_rgb(0x47, 0xbe, 0x8b);
pub const WARNING: Color32 = Color32::from_rgb(0xe5, 0xac, 0x4c);
pub const DANGER: Color32 = Color32::from_rgb(0xe4, 0x5d, 0x53);
pub const DANGER_LINE: Color32 = Color32::from_rgb(0x4a, 0x1f, 0x1c);

pub const ON_ACCENT: Color32 = Color32::WHITE;

// ----------------------------------------------------------------- metrics --

pub const WINDOW: [f32; 2] = [1100.0, 740.0];
pub const WINDOW_MIN: [f32; 2] = [940.0, 640.0];
pub const RAIL_WIDTH: f32 = 232.0;
pub const TOP_BAR_HEIGHT: f32 = 74.0;
pub const CONTENT_PAD: f32 = 28.0;

pub const RADIUS_CARD: u8 = 12;
pub const RADIUS_CONTROL: u8 = 8;
pub const RADIUS_CHIP: u8 = 6;

pub const INPUT_HEIGHT: f32 = 44.0;
pub const BUTTON_HEIGHT: f32 = 38.0;
pub const CHIP_HEIGHT: f32 = 26.0;
pub const NAV_HEIGHT: f32 = 40.0;

pub const GAP_XS: f32 = 6.0;
pub const GAP_SM: f32 = 10.0;
pub const GAP: f32 = 16.0;
pub const GAP_LG: f32 = 22.0;
pub const CARD_PAD: f32 = 22.0;

// ---------------------------------------------------------------- typefaces --

const SG_REGULAR: &[u8] = include_bytes!("../assets/fonts/SpaceGrotesk-Regular.ttf");
const SG_MEDIUM: &[u8] = include_bytes!("../assets/fonts/SpaceGrotesk-Medium.ttf");
const SG_SEMIBOLD: &[u8] = include_bytes!("../assets/fonts/SpaceGrotesk-SemiBold.ttf");
const JB_REGULAR: &[u8] = include_bytes!("../assets/fonts/JetBrainsMono-Regular.ttf");
const JB_MEDIUM: &[u8] = include_bytes!("../assets/fonts/JetBrainsMono-Medium.ttf");

/// Space Grotesk 500, for control labels and emphasised rows.
pub fn medium(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("medium".into()))
}

/// Space Grotesk 600, for headings and figures.
pub fn semibold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("semibold".into()))
}

/// Space Grotesk 400.
pub fn body(size: f32) -> FontId {
    FontId::new(size, FontFamily::Proportional)
}

/// JetBrains Mono 400, for addresses, hashes and heights.
pub fn mono(size: f32) -> FontId {
    FontId::new(size, FontFamily::Monospace)
}

/// JetBrains Mono 500, for amounts.
pub fn mono_medium(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("mono_medium".into()))
}

fn font_definitions() -> FontDefinitions {
    let mut fonts = FontDefinitions::empty();

    for (name, bytes) in [
        ("sg", SG_REGULAR),
        ("sg-medium", SG_MEDIUM),
        ("sg-semibold", SG_SEMIBOLD),
        ("jb", JB_REGULAR),
        ("jb-medium", JB_MEDIUM),
    ] {
        fonts
            .font_data
            .insert(name.to_owned(), Arc::new(FontData::from_static(bytes)));
    }

    // Each weight is its own family; the regular cut is the fallback in every
    // one of them so a glyph missing from a weight still renders.
    fonts
        .families
        .insert(FontFamily::Proportional, vec!["sg".into()]);
    fonts
        .families
        .insert(FontFamily::Monospace, vec!["jb".into()]);
    fonts.families.insert(
        FontFamily::Name("medium".into()),
        vec!["sg-medium".into(), "sg".into()],
    );
    fonts.families.insert(
        FontFamily::Name("semibold".into()),
        vec!["sg-semibold".into(), "sg".into()],
    );
    fonts.families.insert(
        FontFamily::Name("mono_medium".into()),
        vec!["jb-medium".into(), "jb".into()],
    );

    fonts
}

// -------------------------------------------------------------------- apply --

pub fn install(ctx: &egui::Context) {
    ctx.set_fonts(font_definitions());

    let mut style = Style::default();
    let mut visuals = Visuals::dark();

    visuals.override_text_color = Some(TEXT);
    visuals.panel_fill = BG;
    visuals.window_fill = SURFACE;
    visuals.extreme_bg_color = SURFACE_HI;
    visuals.faint_bg_color = SURFACE_HI;
    visuals.window_stroke = Stroke::new(1.0, LINE);
    visuals.selection.bg_fill = ACCENT;
    visuals.selection.stroke = Stroke::new(1.0, ON_ACCENT);
    visuals.text_cursor.stroke = Stroke::new(1.5, ACCENT_LIT);
    visuals.window_corner_radius = CornerRadius::same(RADIUS_CARD);
    visuals.menu_corner_radius = CornerRadius::same(RADIUS_CONTROL);
    visuals.popup_shadow = egui::epaint::Shadow::NONE;
    visuals.window_shadow = egui::epaint::Shadow::NONE;

    for widget in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        widget.corner_radius = CornerRadius::same(RADIUS_CONTROL);
        widget.bg_fill = SURFACE_HI;
        widget.weak_bg_fill = SURFACE_HI;
        widget.bg_stroke = Stroke::new(1.0, LINE_STRONG);
        widget.fg_stroke = Stroke::new(1.0, TEXT);
        widget.expansion = 0.0;
    }
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, LINE);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, TEXT_FAINT);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, ACCENT_LIT);

    style.visuals = visuals;
    style.spacing.item_spacing = egui::vec2(GAP_SM, GAP_SM);
    style.spacing.button_padding = egui::vec2(14.0, 8.0);
    style.spacing.window_margin = Margin::same(CARD_PAD as i8);
    style.spacing.interact_size = egui::vec2(40.0, BUTTON_HEIGHT);
    style.spacing.scroll.bar_width = 8.0;
    style.spacing.scroll.floating = false;

    style.text_styles = [
        (TextStyle::Heading, semibold(19.0)),
        (TextStyle::Body, body(14.0)),
        (TextStyle::Monospace, mono(13.0)),
        (TextStyle::Button, medium(14.0)),
        (TextStyle::Small, body(12.0)),
    ]
    .into();

    ctx.set_theme(egui::ThemePreference::Dark);
    ctx.all_styles_mut(move |target| *target = style.clone());
}
