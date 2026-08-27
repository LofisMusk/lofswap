//! Stroke icons painted directly with egui's `Painter`.
//!
//! The design canvas draws them as 24×24 SVGs with a 1.6px stroke and round
//! caps; these are the same shapes expressed as line segments, circles and
//! arcs so the app needs no SVG rasteriser.

use egui::{Color32, Painter, Pos2, Rect, Shape, Stroke, StrokeKind, Vec2, epaint::PathStroke};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Icon {
    Grid,
    ArrowUp,
    ArrowDown,
    Activity,
    Sliders,
    Lock,
    Copy,
    Check,
    Chevron,
    Key,
    File,
    Plus,
    Minus,
    Alert,
    Search,
    Peers,
    Shield,
    Trash,
    Eye,
    Refresh,
    Back,
}

enum Part {
    /// Open polyline through points on the 24×24 grid.
    Line(&'static [(f32, f32)]),
    /// Closed polygon.
    Closed(&'static [(f32, f32)]),
    Circle {
        c: (f32, f32),
        r: f32,
    },
    /// Rounded rectangle, corner radius in grid units.
    RRect {
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        r: f32,
    },
    /// Arc swept counter-clockwise from `from` to `to`, in degrees, 0° = east.
    Arc {
        c: (f32, f32),
        r: f32,
        from: f32,
        to: f32,
    },
}

// A compact shape table reads better than rustfmt's expansion of it.
#[rustfmt::skip]
fn parts(icon: Icon) -> &'static [Part] {
    use Part::*;
    match icon {
        Icon::Grid => &[
            RRect { x: 3.0, y: 3.0, w: 7.0, h: 7.0, r: 1.5 },
            RRect { x: 14.0, y: 3.0, w: 7.0, h: 7.0, r: 1.5 },
            RRect { x: 3.0, y: 14.0, w: 7.0, h: 7.0, r: 1.5 },
            RRect { x: 14.0, y: 14.0, w: 7.0, h: 7.0, r: 1.5 },
        ],
        Icon::ArrowUp => &[
            Line(&[(12.0, 19.0), (12.0, 5.0)]),
            Line(&[(5.5, 11.5), (12.0, 5.0), (18.5, 11.5)]),
        ],
        Icon::ArrowDown => &[
            Line(&[(12.0, 5.0), (12.0, 19.0)]),
            Line(&[(18.5, 12.5), (12.0, 19.0), (5.5, 12.5)]),
        ],
        Icon::Activity => &[Line(&[
            (3.0, 12.0),
            (7.0, 12.0),
            (9.5, 6.0),
            (13.5, 18.0),
            (16.0, 12.0),
            (21.0, 12.0),
        ])],
        Icon::Sliders => &[
            Line(&[(4.0, 7.5), (9.0, 7.5)]),
            Line(&[(13.0, 7.5), (20.0, 7.5)]),
            Line(&[(4.0, 16.5), (11.0, 16.5)]),
            Line(&[(15.0, 16.5), (20.0, 16.5)]),
            Circle { c: (11.0, 7.5), r: 2.0 },
            Circle { c: (13.0, 16.5), r: 2.0 },
        ],
        Icon::Lock => &[
            RRect { x: 4.5, y: 10.0, w: 15.0, h: 10.0, r: 2.2 },
            Arc { c: (12.0, 10.0), r: 3.8, from: 0.0, to: 180.0 },
        ],
        Icon::Copy => &[
            RRect { x: 8.5, y: 8.5, w: 11.0, h: 11.0, r: 2.0 },
            Line(&[(15.5, 5.5), (4.5, 5.5), (4.5, 16.5)]),
        ],
        Icon::Check => &[Line(&[(4.5, 12.5), (9.5, 17.5), (19.5, 6.5)])],
        Icon::Chevron => &[Line(&[(9.5, 5.5), (16.0, 12.0), (9.5, 18.5)])],
        Icon::Back => &[Line(&[(14.5, 5.5), (8.0, 12.0), (14.5, 18.5)])],
        Icon::Key => &[
            Circle { c: (8.0, 12.0), r: 3.5 },
            Line(&[(11.5, 12.0), (21.0, 12.0)]),
            Line(&[(17.5, 12.0), (17.5, 15.5)]),
            Line(&[(20.0, 12.0), (20.0, 14.5)]),
        ],
        Icon::File => &[
            Line(&[
                (13.5, 3.5),
                (5.0, 3.5),
                (5.0, 20.5),
                (19.0, 20.5),
                (19.0, 9.0),
                (13.5, 3.5),
            ]),
            Line(&[(13.5, 3.5), (13.5, 9.0), (19.0, 9.0)]),
        ],
        Icon::Plus => &[
            Line(&[(12.0, 5.5), (12.0, 18.5)]),
            Line(&[(5.5, 12.0), (18.5, 12.0)]),
        ],
        Icon::Minus => &[Line(&[(5.5, 12.0), (18.5, 12.0)])],
        Icon::Alert => &[
            Closed(&[(12.0, 4.5), (21.0, 19.5), (3.0, 19.5)]),
            Line(&[(12.0, 10.0), (12.0, 14.2)]),
            Line(&[(12.0, 17.1), (12.0, 17.4)]),
        ],
        Icon::Search => &[
            Circle { c: (11.0, 11.0), r: 6.0 },
            Line(&[(15.5, 15.5), (20.0, 20.0)]),
        ],
        Icon::Peers => &[
            Circle { c: (6.5, 12.0), r: 2.5 },
            Circle { c: (17.5, 6.5), r: 2.5 },
            Circle { c: (17.5, 17.5), r: 2.5 },
            Line(&[(8.7, 10.8), (15.3, 7.7)]),
            Line(&[(8.7, 13.2), (15.3, 16.3)]),
        ],
        Icon::Shield => &[Closed(&[
            (12.0, 3.5),
            (19.0, 6.2),
            (19.0, 11.8),
            (12.0, 20.5),
            (5.0, 11.8),
            (5.0, 6.2),
        ])],
        Icon::Trash => &[
            Line(&[(4.5, 7.0), (19.5, 7.0)]),
            Line(&[(9.5, 7.0), (9.5, 4.0), (14.5, 4.0), (14.5, 7.0)]),
            Line(&[(6.8, 7.0), (7.7, 20.5), (16.3, 20.5), (17.2, 7.0)]),
        ],
        Icon::Eye => &[
            Line(&[
                (2.5, 12.0),
                (6.0, 7.2),
                (12.0, 6.0),
                (18.0, 7.2),
                (21.5, 12.0),
                (18.0, 16.8),
                (12.0, 18.0),
                (6.0, 16.8),
                (2.5, 12.0),
            ]),
            Circle { c: (12.0, 12.0), r: 2.6 },
        ],
        Icon::Refresh => &[
            Arc { c: (12.0, 12.0), r: 8.0, from: 300.0, to: 0.0 },
            Line(&[(20.0, 4.0), (20.0, 8.5), (15.5, 8.5)]),
        ],
    }
}

fn map(rect: Rect, p: (f32, f32)) -> Pos2 {
    let s = rect.width().min(rect.height()) / 24.0;
    rect.min + Vec2::new(p.0 * s, p.1 * s)
}

/// Paint `icon` inside `rect` (square; the smaller side wins).
pub fn paint(painter: &Painter, icon: Icon, rect: Rect, color: Color32, width: f32) {
    let scale = rect.width().min(rect.height()) / 24.0;
    let stroke = Stroke::new(width, color);

    for part in parts(icon) {
        match part {
            Part::Line(points) => {
                let pts: Vec<Pos2> = points.iter().map(|p| map(rect, *p)).collect();
                painter.add(Shape::line(pts, PathStroke::from(stroke)));
            }
            Part::Closed(points) => {
                let pts: Vec<Pos2> = points.iter().map(|p| map(rect, *p)).collect();
                painter.add(Shape::closed_line(pts, PathStroke::from(stroke)));
            }
            Part::Circle { c, r } => {
                painter.circle_stroke(map(rect, *c), r * scale, stroke);
            }
            Part::RRect { x, y, w, h, r } => {
                let min = map(rect, (*x, *y));
                let size = Vec2::new(w * scale, h * scale);
                painter.rect_stroke(
                    Rect::from_min_size(min, size),
                    egui::CornerRadius::same((r * scale).round().max(1.0) as u8),
                    stroke,
                    StrokeKind::Middle,
                );
            }
            Part::Arc { c, r, from, to } => {
                let centre = map(rect, *c);
                let radius = r * scale;
                let sweep = to - from;
                let steps = ((sweep.abs() / 12.0).ceil() as usize).max(3);
                let pts: Vec<Pos2> = (0..=steps)
                    .map(|i| {
                        let deg = from + sweep * (i as f32 / steps as f32);
                        let rad = deg.to_radians();
                        // Screen y grows downwards, so the angle is negated.
                        centre + Vec2::new(rad.cos() * radius, -rad.sin() * radius)
                    })
                    .collect();
                painter.add(Shape::line(pts, PathStroke::from(stroke)));
            }
        }
    }
}
