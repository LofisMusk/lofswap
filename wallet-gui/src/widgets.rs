//! The small vocabulary of controls the design canvas is built from.

use egui::{
    Align, Color32, CornerRadius, FontId, Rect, Response, RichText, Sense, Shape, Stroke,
    StrokeKind, TextEdit, Ui, Vec2, text::LayoutJob,
};

use crate::icons::{self, Icon};
use crate::theme::*;

// ------------------------------------------------------------------- text ---

pub fn text(ui: &mut Ui, value: impl Into<String>, font: FontId, color: Color32) -> Response {
    ui.label(RichText::new(value).font(font).color(color))
}

/// Uppercase 11px label with the 0.09em tracking the design uses.
pub fn caps(ui: &mut Ui, value: &str) -> Response {
    caps_colored(ui, value, TEXT_MUTED)
}

pub fn caps_colored(ui: &mut Ui, value: &str, color: Color32) -> Response {
    let mut job = LayoutJob::default();
    job.append(
        &value.to_uppercase(),
        0.0,
        egui::TextFormat {
            font_id: medium(11.0),
            extra_letter_spacing: 1.0,
            color,
            ..Default::default()
        },
    );
    ui.label(job)
}

/// Shorten an address for places where the full string does not fit.
pub fn short_address(address: &str) -> String {
    if address.len() <= 20 {
        return address.to_owned();
    }
    format!("{}…{}", &address[..10], &address[address.len() - 6..])
}

/// Group digits so balances read as figures rather than numbers.
pub fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

// ----------------------------------------------------------------- buttons --

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ButtonKind {
    Primary,
    Secondary,
    Ghost,
    Danger,
}

impl ButtonKind {
    fn colors(self, hovered: bool, enabled: bool) -> (Color32, Color32, Color32) {
        // (fill, border, foreground)
        let (fill, border, fg) = match self {
            Self::Primary => (
                if hovered { ACCENT_HOVER } else { ACCENT },
                if hovered { ACCENT_HOVER } else { ACCENT },
                ON_ACCENT,
            ),
            Self::Secondary => (if hovered { LINE } else { SURFACE_HI }, LINE_STRONG, TEXT),
            Self::Ghost => (
                if hovered {
                    SURFACE_HI
                } else {
                    Color32::TRANSPARENT
                },
                LINE,
                TEXT_DIM,
            ),
            Self::Danger => (
                if hovered {
                    Color32::from_rgb(0x2a, 0x12, 0x10)
                } else {
                    Color32::TRANSPARENT
                },
                DANGER_LINE,
                DANGER,
            ),
        };
        if enabled {
            (fill, border, fg)
        } else {
            (Color32::TRANSPARENT, LINE, TEXT_FAINT)
        }
    }
}

pub struct Button<'a> {
    label: &'a str,
    kind: ButtonKind,
    icon: Option<Icon>,
    width: Option<f32>,
    height: f32,
    font_size: f32,
    enabled: bool,
}

impl<'a> Button<'a> {
    pub fn new(label: &'a str, kind: ButtonKind) -> Self {
        Self {
            label,
            kind,
            icon: None,
            width: None,
            height: BUTTON_HEIGHT,
            font_size: 14.0,
            enabled: true,
        }
    }

    pub fn icon(mut self, icon: Icon) -> Self {
        self.icon = Some(icon);
        self
    }

    pub fn width(mut self, width: f32) -> Self {
        self.width = Some(width);
        self
    }

    pub fn small(mut self) -> Self {
        self.height = 34.0;
        self.font_size = 13.0;
        self
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn show(self, ui: &mut Ui) -> Response {
        let font = medium(self.font_size);
        let galley =
            ui.painter()
                .layout_no_wrap(self.label.to_owned(), font.clone(), Color32::WHITE);
        let icon_size = self.font_size + 2.0;
        let icon_space = if self.icon.is_some() {
            icon_size + 8.0
        } else {
            0.0
        };
        let width = self.width.unwrap_or(galley.size().x + icon_space + 36.0);

        let sense = if self.enabled {
            Sense::click()
        } else {
            Sense::hover()
        };
        let (rect, response) = ui.allocate_exact_size(Vec2::new(width, self.height), sense);
        if !ui.is_rect_visible(rect) {
            return response;
        }

        let hovered = self.enabled && response.hovered();
        let (fill, border, fg) = self.kind.colors(hovered, self.enabled);
        let painter = ui.painter();
        painter.rect(
            rect,
            CornerRadius::same(RADIUS_CONTROL),
            fill,
            Stroke::new(1.0, border),
            StrokeKind::Inside,
        );

        let content_width = galley.size().x + icon_space;
        let mut cursor = rect.center().x - content_width / 2.0;
        if let Some(icon) = self.icon {
            let icon_rect = Rect::from_min_size(
                egui::pos2(cursor, rect.center().y - icon_size / 2.0),
                Vec2::splat(icon_size),
            );
            icons::paint(painter, icon, icon_rect, fg, 1.6);
            cursor += icon_size + 8.0;
        }
        painter.galley(
            egui::pos2(cursor, rect.center().y - galley.size().y / 2.0),
            galley,
            fg,
        );

        if self.enabled {
            response.on_hover_cursor(egui::CursorIcon::PointingHand)
        } else {
            response
        }
    }
}

/// A square icon-only button, used in the top bar.
pub fn icon_button(ui: &mut Ui, icon: Icon, size: f32) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(size), Sense::click());
    if ui.is_rect_visible(rect) {
        let fill = if response.hovered() {
            SURFACE_HI
        } else {
            SURFACE
        };
        let painter = ui.painter();
        painter.rect(
            rect,
            CornerRadius::same(RADIUS_CONTROL),
            fill,
            Stroke::new(1.0, LINE),
            StrokeKind::Inside,
        );
        let color = if response.hovered() { TEXT } else { TEXT_MUTED };
        icons::paint(painter, icon, rect.shrink(size * 0.28), color, 1.6);
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

// ------------------------------------------------------------------ fields --

pub struct Field<'a> {
    value: &'a mut String,
    hint: &'a str,
    password: bool,
    monospace: bool,
    suffix: Option<&'a str>,
    leading: Option<Icon>,
    width: Option<f32>,
    height: f32,
}

impl<'a> Field<'a> {
    pub fn new(value: &'a mut String) -> Self {
        Self {
            value,
            hint: "",
            password: false,
            monospace: false,
            suffix: None,
            leading: None,
            width: None,
            height: INPUT_HEIGHT,
        }
    }

    pub fn hint(mut self, hint: &'a str) -> Self {
        self.hint = hint;
        self
    }

    pub fn password(mut self) -> Self {
        self.password = true;
        self
    }

    pub fn monospace(mut self) -> Self {
        self.monospace = true;
        self
    }

    pub fn suffix(mut self, suffix: &'a str) -> Self {
        self.suffix = Some(suffix);
        self
    }

    pub fn width(mut self, width: f32) -> Self {
        self.width = Some(width);
        self
    }

    /// An icon drawn inside the field, before the text.
    pub fn leading(mut self, icon: Icon) -> Self {
        self.leading = Some(icon);
        self
    }

    /// A shorter field, for toolbars.
    pub fn compact(mut self) -> Self {
        self.height = 34.0;
        self
    }

    pub fn show(self, ui: &mut Ui) -> Response {
        let width = self.width.unwrap_or_else(|| ui.available_width());
        let (rect, _) = ui.allocate_exact_size(Vec2::new(width, self.height), Sense::hover());

        // Reserve the frame so it can be painted behind the text once the
        // focus state is known.
        let frame_index = ui.painter().add(Shape::Noop);

        let suffix_width = match self.suffix {
            Some(suffix) => {
                ui.painter()
                    .layout_no_wrap(suffix.to_owned(), medium(13.0), TEXT_MUTED)
                    .size()
                    .x
                    + 12.0
            }
            None => 0.0,
        };

        let leading_width = if self.leading.is_some() { 25.0 } else { 0.0 };
        let inner = Rect::from_min_max(
            egui::pos2(rect.left() + 14.0 + leading_width, rect.top()),
            egui::pos2(rect.right() - 14.0 - suffix_width, rect.bottom()),
        );
        let font = if self.monospace {
            mono(14.0)
        } else {
            body(14.0)
        };
        let response = ui.put(
            inner,
            TextEdit::singleline(self.value)
                .frame(egui::Frame::NONE)
                .password(self.password)
                .hint_text(
                    RichText::new(self.hint)
                        .font(font.clone())
                        .color(TEXT_FAINT),
                )
                .font(font)
                .text_color(TEXT)
                .vertical_align(Align::Center)
                .margin(egui::Margin::ZERO)
                .desired_width(inner.width()),
        );

        let border = if response.has_focus() {
            ACCENT_LIT
        } else if response.hovered() {
            TEXT_FAINT
        } else {
            LINE_STRONG
        };
        ui.painter().set(
            frame_index,
            Shape::Vec(vec![
                Shape::rect_filled(rect, CornerRadius::same(RADIUS_CONTROL), SURFACE_HI),
                Shape::rect_stroke(
                    rect,
                    CornerRadius::same(RADIUS_CONTROL),
                    Stroke::new(1.0, border),
                    StrokeKind::Inside,
                ),
            ]),
        );

        if let Some(icon) = self.leading {
            icons::paint(
                ui.painter(),
                icon,
                Rect::from_center_size(
                    egui::pos2(rect.left() + 22.0, rect.center().y),
                    Vec2::splat(15.0),
                ),
                TEXT_FAINT,
                1.6,
            );
        }

        if let Some(suffix) = self.suffix {
            ui.painter().text(
                egui::pos2(rect.right() - 14.0, rect.center().y),
                egui::Align2::RIGHT_CENTER,
                suffix,
                medium(13.0),
                TEXT_MUTED,
            );
        }

        response
    }
}

/// A labelled field: the caps label above, the input below.
pub fn labelled_field(ui: &mut Ui, label: &str, field: Field<'_>) -> Response {
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 8.0;
        caps(ui, label);
        field.show(ui)
    })
    .inner
}

// ------------------------------------------------------------------- cards --

pub fn card_frame(pad: f32) -> egui::Frame {
    egui::Frame::NONE
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, LINE))
        .corner_radius(CornerRadius::same(RADIUS_CARD))
        .inner_margin(egui::Margin::same(pad as i8))
}

pub fn card<R>(ui: &mut Ui, pad: f32, contents: impl FnOnce(&mut Ui) -> R) -> R {
    // A card is always a column, even when it sits in a horizontal row.
    card_frame(pad)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.vertical(contents).inner
        })
        .inner
}

// ------------------------------------------------------------------- chips --

pub fn chip(ui: &mut Ui, label: &str, color: Color32, fill: Color32, border: Color32) -> Response {
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_owned(), medium(12.0), color);
    let (rect, response) = ui.allocate_exact_size(
        Vec2::new(galley.size().x + 20.0, CHIP_HEIGHT),
        Sense::click(),
    );
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        painter.rect(
            rect,
            CornerRadius::same(RADIUS_CHIP),
            fill,
            Stroke::new(1.0, border),
            StrokeKind::Inside,
        );
        painter.galley(rect.center() - galley.size() / 2.0, galley, color);
    }
    response
}

pub fn status_dot(ui: &mut Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
    ui.painter().circle_filled(rect.center(), 3.5, color);
}

// ----------------------------------------------------------------- toggles --

pub fn toggle(ui: &mut Ui, on: &mut bool) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::new(42.0, 24.0), Sense::click());
    if response.clicked() {
        *on = !*on;
    }
    if ui.is_rect_visible(rect) {
        let fill = if *on { ACCENT } else { LINE_STRONG };
        let painter = ui.painter();
        painter.rect_filled(rect, CornerRadius::same(12), fill);
        let knob_x = if *on {
            rect.right() - 12.0
        } else {
            rect.left() + 12.0
        };
        painter.circle_filled(egui::pos2(knob_x, rect.center().y), 9.0, Color32::WHITE);
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// The −/n/+ control used for the minimum-peer setting.
pub fn stepper(ui: &mut Ui, value: &mut usize, min: usize, max: usize) {
    // Forced left-to-right so −/n/+ keep their order on the right-hand side of
    // a `Sides` row.
    ui.with_layout(egui::Layout::left_to_right(Align::Center), |ui| {
        ui.spacing_mut().item_spacing.x = 2.0;
        let segment = |ui: &mut Ui, icon: Option<Icon>, label: Option<String>, w: f32| {
            let (rect, response) = ui.allocate_exact_size(Vec2::new(w, 30.0), Sense::click());
            if ui.is_rect_visible(rect) {
                let hovered = icon.is_some() && response.hovered();
                let painter = ui.painter();
                painter.rect(
                    rect,
                    CornerRadius::same(7),
                    if hovered { LINE } else { SURFACE_HI },
                    Stroke::new(1.0, LINE_STRONG),
                    StrokeKind::Inside,
                );
                if let Some(icon) = icon {
                    icons::paint(painter, icon, rect.shrink(9.0), TEXT_DIM, 1.6);
                }
                if let Some(label) = label {
                    painter.text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        label,
                        mono(14.0),
                        TEXT,
                    );
                }
            }
            response
        };

        if segment(ui, Some(Icon::Minus), None, 30.0).clicked() {
            *value = value.saturating_sub(1).max(min);
        }
        segment(ui, None, Some(value.to_string()), 40.0);
        if segment(ui, Some(Icon::Plus), None, 30.0).clicked() {
            *value = (*value + 1).min(max);
        }
    });
}

// --------------------------------------------------------------- structure --

/// A fixed-width column of stacked widgets, laid out top-down whatever the
/// surrounding layout direction is.
pub fn column<R>(ui: &mut Ui, width: f32, contents: impl FnOnce(&mut Ui) -> R) -> R {
    ui.allocate_ui_with_layout(
        Vec2::new(width, ui.available_height()),
        egui::Layout::top_down(Align::Min),
        |ui| {
            ui.set_width(width);
            contents(ui)
        },
    )
    .inner
}

/// A full-width horizontal hairline.
pub fn divider(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 1.0), Sense::hover());
    ui.painter().rect_filled(rect, CornerRadius::ZERO, LINE);
}

/// Card header: an icon and a title.
pub fn section_header(ui: &mut Ui, icon: Icon, title: &str) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 9.0;
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(17.0), Sense::hover());
        icons::paint(ui.painter(), icon, rect, TEXT_DIM, 1.6);
        text(ui, title, semibold(15.0), TEXT);
    });
}
