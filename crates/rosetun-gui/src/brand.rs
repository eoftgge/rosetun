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
