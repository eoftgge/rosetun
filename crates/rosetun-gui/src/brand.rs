use eframe::egui::{self, Pos2, Rect, Shape, Stroke};

use crate::theme;

const PETAL: [(f32, f32); 4] = [(0.0, -20.0), (12.0, 0.0), (0.0, 22.0), (-12.0, 0.0)];
const SPIRAL: [(f32, f32); 9] = [
    (24.0, 31.0),
    (18.0, 27.0),
    (18.0, 21.0),
    (24.0, 17.0),
    (30.0, 21.0),
    (30.0, 25.0),
    (26.0, 28.0),
    (22.0, 25.0),
    (23.0, 22.0),
];

pub(crate) struct Petal {
    x: f32,
    y: f32,
    rotation: f32,
    scale: f32,
    alpha: f32,
    outline: bool,
}

const PETALS: [Petal; 13] = [
    Petal {
        x: 196.0,
        y: 18.0,
        rotation: 24.0,
        scale: 1.25,
        alpha: 0.10,
        outline: false,
    },
    Petal {
        x: 252.0,
        y: 56.0,
        rotation: -38.0,
        scale: 0.9,
        alpha: 0.07,
        outline: false,
    },
    Petal {
        x: 424.0,
        y: 46.0,
        rotation: -14.0,
        scale: 1.35,
        alpha: 0.08,
        outline: false,
    },
    Petal {
        x: 508.0,
        y: 20.0,
        rotation: 128.0,
        scale: 0.85,
        alpha: 0.06,
        outline: false,
    },
    Petal {
        x: 676.0,
        y: 14.0,
        rotation: -62.0,
        scale: 1.15,
        alpha: 0.09,
        outline: false,
    },
    Petal {
        x: 764.0,
        y: 52.0,
        rotation: 96.0,
        scale: 0.95,
        alpha: 0.06,
        outline: false,
    },
    Petal {
        x: 934.0,
        y: 58.0,
        rotation: 58.0,
        scale: 0.9,
        alpha: 0.08,
        outline: false,
    },
    Petal {
        x: 1016.0,
        y: 16.0,
        rotation: 150.0,
        scale: 1.05,
        alpha: 0.06,
        outline: false,
    },
    Petal {
        x: 1104.0,
        y: 54.0,
        rotation: -46.0,
        scale: 1.2,
        alpha: 0.07,
        outline: false,
    },
    Petal {
        x: 334.0,
        y: 12.0,
        rotation: 72.0,
        scale: 1.1,
        alpha: 0.16,
        outline: true,
    },
    Petal {
        x: 592.0,
        y: 60.0,
        rotation: 40.0,
        scale: 1.0,
        alpha: 0.14,
        outline: true,
    },
    Petal {
        x: 850.0,
        y: 18.0,
        rotation: -24.0,
        scale: 1.3,
        alpha: 0.13,
        outline: true,
    },
    Petal {
        x: 1168.0,
        y: 24.0,
        rotation: 34.0,
        scale: 0.9,
        alpha: 0.15,
        outline: true,
    },
];

pub(crate) fn petal_points(petal: &Petal, origin: Pos2, x_scale: f32) -> [Pos2; 4] {
    let (sin, cos) = petal.rotation.to_radians().sin_cos();
    PETAL.map(|(x, y)| {
        let x = x * petal.scale;
        let y = y * petal.scale;
        egui::pos2(
            origin.x + petal.x * x_scale + x * cos - y * sin,
            origin.y + petal.y + x * sin + y * cos,
        )
    })
}

pub(crate) fn paint_petals(painter: &egui::Painter, rect: Rect, bloom: f32, intro: f32) {
    let painter = painter.with_clip_rect(rect);
    let origin = rect.left_top() + egui::vec2(0.0, -20.0 * (1.0 - intro));
    for petal in &PETALS {
        let points = petal_points(petal, origin, rect.width() / 1200.0).to_vec();
        let alpha = petal_alpha(petal.alpha, bloom, intro);
        if petal.outline {
            painter.add(Shape::closed_line(
                points,
                Stroke::new(1.0, theme::ROSE_LIGHT.gamma_multiply(alpha)),
            ));
        } else {
            painter.add(Shape::convex_polygon(
                points,
                theme::ROSE.gamma_multiply(alpha),
                Stroke::NONE,
            ));
        }
    }
}

pub(crate) fn emblem_petal(index: usize) -> [Pos2; 4] {
    let (sin, cos) = (index as f32 * 72.0).to_radians().sin_cos();
    [(24.0, 3.0), (34.0, 15.0), (24.0, 24.0), (14.0, 15.0)].map(|(x, y)| {
        let x = x - 24.0;
        let y = y - 24.0;
        egui::pos2(24.0 + x * cos - y * sin, 24.0 + x * sin + y * cos)
    })
}

pub(crate) fn paint_emblem(painter: &egui::Painter, rect: Rect, bloom: f32) {
    let scale = rect.width() / 48.0;
    let place = |point: Pos2| rect.min + egui::vec2(point.x * scale, point.y * scale);
    for index in 0..5 {
        painter.add(Shape::convex_polygon(
            emblem_petal(index).map(place).to_vec(),
            theme::ROSE.gamma_multiply(0.18 + 0.14 * bloom),
            Stroke::new(1.4 * scale, theme::ROSE.gamma_multiply(0.6 + 0.3 * bloom)),
        ));
    }
    painter.add(Shape::line(
        SPIRAL.map(|(x, y)| place(egui::pos2(x, y))).to_vec(),
        Stroke::new(1.6 * scale, theme::ROSE_LIGHT),
    ));
}

fn inside_petal(point: Pos2, petal: &[Pos2; 4]) -> bool {
    let mut positive = false;
    let mut negative = false;
    for edge in 0..4 {
        let a = petal[edge];
        let b = petal[(edge + 1) % 4];
        let cross = (b.x - a.x) * (point.y - a.y) - (b.y - a.y) * (point.x - a.x);
        positive |= cross > 0.0;
        negative |= cross < 0.0;
        if positive && negative {
            return false;
        }
    }
    true
}

fn on_spiral(point: Pos2) -> bool {
    SPIRAL.windows(2).any(|segment| {
        let (ax, ay) = segment[0];
        let (bx, by) = segment[1];
        let dx = bx - ax;
        let dy = by - ay;
        let position =
            (((point.x - ax) * dx + (point.y - ay) * dy) / (dx * dx + dy * dy)).clamp(0.0, 1.0);
        let distance_x = point.x - ax - position * dx;
        let distance_y = point.y - ay - position * dy;
        distance_x * distance_x + distance_y * distance_y <= 1.2 * 1.2
    })
}

/// Straight-alpha RGBA of the emblem, `size`×`size`: the five petals filled with
/// `petals` and, when given, the spiral drawn over them in `spiral`.
pub(crate) fn emblem_rgba(
    size: u32,
    petals: egui::Color32,
    spiral: Option<egui::Color32>,
) -> Vec<u8> {
    let shapes: [[Pos2; 4]; 5] = std::array::from_fn(emblem_petal);
    let scale = 48.0 / size as f32;
    let mut rgba = Vec::with_capacity(size as usize * size as usize * 4);
    for y in 0..size {
        for x in 0..size {
            let mut covered = 0_u32;
            let (mut red, mut green, mut blue) = (0_u32, 0_u32, 0_u32);
            for j in 0..4 {
                for i in 0..4 {
                    let point = egui::pos2(
                        (x as f32 + (i as f32 + 0.5) / 4.0) * scale,
                        (y as f32 + (j as f32 + 0.5) / 4.0) * scale,
                    );
                    let color = if spiral.is_some() && on_spiral(point) {
                        spiral
                    } else if shapes.iter().any(|petal| inside_petal(point, petal)) {
                        Some(petals)
                    } else {
                        None
                    };
                    if let Some(color) = color {
                        covered += 1;
                        red += u32::from(color.r());
                        green += u32::from(color.g());
                        blue += u32::from(color.b());
                    }
                }
            }
            let divisor = covered.max(1);
            rgba.extend_from_slice(&[
                (red / divisor) as u8,
                (green / divisor) as u8,
                (blue / divisor) as u8,
                (covered * 255 / 16) as u8,
            ]);
        }
    }
    rgba
}

/// 0 when idle, 1 when connected; pulses between 0 and 0.35 while connecting.
pub(crate) fn bloom(settled: f32, transitional: bool, time: f64) -> f32 {
    if transitional {
        let pulse = 0.5 - 0.5 * (std::f64::consts::TAU * time / 1.6).cos();
        settled.max(0.35 * pulse as f32)
    } else {
        settled
    }
}

pub(crate) fn petal_alpha(base: f32, bloom: f32, intro: f32) -> f32 {
    (base * (1.0 + 0.8 * bloom) * intro).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn near(actual: f32, expected: f32) {
        assert!((actual - expected).abs() < 0.01, "{actual} != {expected}");
    }

    #[test]
    fn petal_transform_scales_and_rotates() {
        let petal = Petal {
            x: 100.0,
            y: 10.0,
            rotation: 90.0,
            scale: 1.0,
            alpha: 0.1,
            outline: false,
        };
        let origin = egui::pos2(0.0, 0.0);
        let point = petal_points(&petal, origin, 1.0)[0];
        near(point.x, 120.0);
        near(point.y, 10.0);
        near(
            petal_points(
                &Petal {
                    scale: 2.0,
                    ..petal
                },
                origin,
                1.0,
            )[0]
            .x,
            140.0,
        );
        near(petal_points(&petal, origin, 0.8)[1].x, 80.0);
    }

    #[test]
    fn emblem_rotates_around_center() {
        let point = emblem_petal(1)[0];
        near(point.x, 43.97);
        near(point.y, 17.51);
    }

    #[test]
    fn raster_emblem_has_opaque_petals_and_optional_spiral() {
        let petals = egui::Color32::from_rgb(12, 34, 56);
        let spiral = egui::Color32::from_rgb(200, 210, 220);
        let rgba = emblem_rgba(48, petals, Some(spiral));
        let pixel = |x: usize, y: usize| &rgba[(y * 48 + x) * 4..(y * 48 + x + 1) * 4];
        assert_eq!(rgba.len(), 48 * 48 * 4);
        assert_eq!(pixel(24, 10), &[12, 34, 56, 255]);
        assert_eq!(pixel(0, 0), &[0, 0, 0, 0]);
        assert_eq!(pixel(18, 24), &[200, 210, 220, 255]);
        assert_eq!(emblem_rgba(32, petals, None).len(), 32 * 32 * 4);
    }

    #[test]
    fn bloom_pulses_only_in_transition() {
        near(bloom(0.5, false, 0.8), 0.5);
        near(bloom(0.2, true, 0.0), 0.2);
        near(bloom(0.0, true, 0.8), 0.35);
    }

    #[test]
    fn petals_fade_in_and_brighten() {
        near(petal_alpha(0.1, 0.0, 1.0), 0.1);
        near(petal_alpha(0.1, 1.0, 1.0), 0.18);
        near(petal_alpha(0.1, 1.0, 0.0), 0.0);
    }
}
