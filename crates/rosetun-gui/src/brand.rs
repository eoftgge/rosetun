use eframe::egui::{self, Pos2, Rect, Shape, Stroke, Vec2};
use rosetun_config::AccentPreset;

use crate::rose_icon::{self, RoseIcon};
use crate::theme::{self, Palette};

const PETAL: [(f32, f32); 4] = [(0.0, -20.0), (12.0, 0.0), (0.0, 22.0), (-12.0, 0.0)];
/// Keeps the header petals behind the navigation instead of competing with it.
const HEADER_PETAL_FADE: f32 = 0.65;
/// Where a petal may wander: shift in points (x, y) and turn in degrees.
const DRIFT_LOW: [f32; 3] = [-5.0, -6.0, -8.0];
const DRIFT_HIGH: [f32; 3] = [7.0, 5.0, 10.0];

#[derive(Clone, Copy)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Speed {
    /// Connected: a new random aim every few seconds.
    Calm,
    /// Connecting: faster, under the bloom pulse.
    Quick,
}

impl Speed {
    fn knot_spacing(self) -> f64 {
        match self {
            Self::Calm => 2.6,
            Self::Quick => 0.8,
        }
    }
}

/// How far the header petals have drifted from their places.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Drift {
    pub(crate) time: f64,
    /// Picks the random paths; a new one each launch.
    pub(crate) seed: u64,
    /// 0 keeps every petal in place, 1 is the full drift.
    pub(crate) weight: f32,
    /// Blends the calm drift (0) into the quick one (1), so a change of
    /// speed moves the petals instead of jumping them to another phase.
    pub(crate) quick: f32,
}

impl Drift {
    fn offset(self, index: usize) -> (Vec2, f32) {
        if self.weight <= 0.0 {
            return (Vec2::ZERO, 0.0);
        }
        let (calm_shift, calm_turn) = drift(index, self.time, Speed::Calm, self.seed);
        let (quick_shift, quick_turn) = drift(index, self.time, Speed::Quick, self.seed);
        let shift = calm_shift + (quick_shift - calm_shift) * self.quick;
        let turn = calm_turn + (quick_turn - calm_turn) * self.quick;
        (shift * self.weight, turn * self.weight)
    }
}

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

pub(crate) fn paint_petals(
    painter: &egui::Painter,
    rect: Rect,
    bloom: f32,
    intro: f32,
    drift: Drift,
) {
    let painter = painter.with_clip_rect(rect);
    let origin = rect.left_top() + egui::vec2(0.0, -20.0 * (1.0 - intro));
    for (index, petal) in PETALS.iter().enumerate() {
        let (shift, turn) = drift.offset(index);
        let moved = Petal {
            rotation: petal.rotation + turn,
            ..*petal
        };
        let points = petal_points(&moved, origin + shift, rect.width() / 1200.0).to_vec();
        let alpha = petal_alpha(petal.alpha, bloom, intro) * HEADER_PETAL_FADE;
        if petal.outline {
            painter.add(Shape::closed_line(
                points,
                Stroke::new(1.0, theme::palette().accent_light.gamma_multiply(alpha)),
            ));
        } else {
            painter.add(Shape::convex_polygon(
                points,
                theme::palette().accent_base.gamma_multiply(alpha),
                Stroke::NONE,
            ));
        }
    }
}

fn emblem_pixel_size(side: f32, pixels_per_point: f32) -> u32 {
    (side * pixels_per_point).ceil() as u32
}

fn emblem_texture(
    ctx: &egui::Context,
    size: u32,
    accent: AccentPreset,
    rasterize: impl FnOnce(u32, &Palette) -> Vec<u8>,
) -> egui::TextureHandle {
    let id = egui::Id::new(("brand_emblem", size, accent));
    if let Some(texture) = ctx.data(|data| data.get_temp::<egui::TextureHandle>(id)) {
        return texture;
    }
    let pixels = rasterize(size, theme::palette_of(accent));
    let image = egui::ColorImage::from_rgba_unmultiplied([size as usize, size as usize], &pixels);
    let texture = ctx.load_texture(
        format!("brand_emblem_{size}_{accent:?}"),
        image,
        egui::TextureOptions::LINEAR,
    );
    ctx.data_mut(|data| data.insert_temp(id, texture.clone()));
    texture
}

/// The window's own icon (title bar, Alt+Tab, taskbar button) in `palette`.
pub(crate) fn window_icon(palette: &Palette) -> egui::IconData {
    egui::IconData {
        rgba: rose_icon::rose_icon_rgba(128, RoseIcon::App, palette),
        width: 128,
        height: 128,
    }
}

pub(crate) fn paint_emblem(painter: &egui::Painter, rect: Rect) {
    let ctx = painter.ctx();
    let size = emblem_pixel_size(rect.width(), ctx.pixels_per_point());
    let texture = emblem_texture(ctx, size, theme::accent(), |size, palette| {
        rose_icon::rose_icon_rgba(size, RoseIcon::Emblem, palette)
    });
    painter.image(
        texture.id(),
        rect,
        Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
        egui::Color32::WHITE,
    );
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

/// A petal's shift in points and turn in degrees at `time`: each of the
/// three wanders on its own random path inside the drift's bounds.
pub(crate) fn drift(index: usize, time: f64, speed: Speed, seed: u64) -> (Vec2, f32) {
    let at = |channel: usize| {
        let key = [seed, index as u64, channel as u64, speed as u64];
        let wander = smooth_noise(key, time / speed.knot_spacing());
        DRIFT_LOW[channel] + (DRIFT_HIGH[channel] - DRIFT_LOW[channel]) * wander
    };
    (egui::vec2(at(0), at(1)), at(2))
}

/// Smooth 1D value noise in `0..=1`: random knots at whole `position`s
/// joined by a Catmull-Rom curve, so a petal never stops at a knot or jerks.
fn smooth_noise(key: [u64; 4], position: f64) -> f32 {
    let knot = position.floor();
    let t = (position - knot) as f32;
    let knot = knot as i64;
    // Knots stay within 0.1..0.9 because the curve overshoots by at most an
    // eighth of their spread.
    let value = |offset: i64| 0.1 + 0.8 * unit_hash(key, knot.wrapping_add(offset));
    let [p0, p1, p2, p3] = [value(-1), value(0), value(1), value(2)];
    let curve = 0.5
        * (2.0 * p1
            + (p2 - p0) * t
            + (2.0 * p0 - 5.0 * p1 + 4.0 * p2 - p3) * t * t
            + (3.0 * p1 - p0 - 3.0 * p2 + p3) * t * t * t);
    curve.clamp(0.0, 1.0)
}

/// SplitMix64 over the key and knot, mapped to `0..1`.
fn unit_hash(key: [u64; 4], knot: i64) -> f32 {
    let mut hash = 0x9e37_79b9_7f4a_7c15_u64;
    for word in key.into_iter().chain([knot as u64]) {
        hash = (hash ^ word).wrapping_add(0x9e37_79b9_7f4a_7c15);
        hash = (hash ^ (hash >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        hash = (hash ^ (hash >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        hash ^= hash >> 31;
    }
    (hash >> 40) as f32 / (1u64 << 24) as f32
}

pub(crate) fn petal_alpha(base: f32, bloom: f32, intro: f32) -> f32 {
    (base * (1.0 + 1.2 * bloom) * intro).clamp(0.0, 1.0)
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
    fn emblem_uses_physical_pixels_and_reuses_its_texture() {
        let ctx = egui::Context::default();
        let rasterizations = std::cell::Cell::new(0);
        let make_texture = |size, accent| {
            emblem_texture(&ctx, size, accent, |size, palette| {
                rasterizations.set(rasterizations.get() + 1);
                rose_icon::rose_icon_rgba(size, RoseIcon::Emblem, palette)
            })
        };
        let size = emblem_pixel_size(40.0, 1.0);
        let first = make_texture(size, AccentPreset::Rose);
        assert_eq!(first.size(), [40, 40]);
        let repeated = make_texture(size, AccentPreset::Rose);
        assert_eq!(repeated.id(), first.id());
        assert_eq!(rasterizations.get(), 1);

        let scaled = make_texture(emblem_pixel_size(40.0, 1.5), AccentPreset::Rose);
        assert_eq!(scaled.size(), [60, 60]);
        assert_eq!(rasterizations.get(), 2);

        let teal = make_texture(size, AccentPreset::Teal);
        assert_ne!(teal.id(), first.id());
        assert_eq!(rasterizations.get(), 3);
        assert_eq!(make_texture(size, AccentPreset::Rose).id(), first.id());
        assert_eq!(rasterizations.get(), 3);
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
        near(petal_alpha(0.1, 1.0, 1.0), 0.22);
        near(petal_alpha(0.1, 0.5, 1.0), 0.16);
        near(petal_alpha(0.1, 1.0, 0.0), 0.0);
    }

    #[test]
    fn petals_stay_in_place_without_drift_weight() {
        for time in [0.0, 3.7, 120.25] {
            for quick in [0.0, 0.5, 1.0] {
                let drift = Drift {
                    time,
                    seed: 7,
                    weight: 0.0,
                    quick,
                };
                for index in 0..PETALS.len() {
                    assert_eq!(drift.offset(index), (Vec2::ZERO, 0.0));
                }
            }
        }
    }

    #[test]
    fn drift_stays_inside_its_bounds() {
        for seed in [0, 7, u64::MAX] {
            for speed in [Speed::Calm, Speed::Quick] {
                for index in 0..PETALS.len() {
                    for step in 0..400 {
                        let (shift, turn) = drift(index, f64::from(step) * 0.137, speed, seed);
                        assert!((-5.0..=7.0).contains(&shift.x), "{shift:?}");
                        assert!((-6.0..=5.0).contains(&shift.y), "{shift:?}");
                        assert!((-8.0..=10.0).contains(&turn), "{turn}");
                    }
                }
            }
        }
        let full = Drift {
            time: 4.2,
            seed: 7,
            weight: 1.0,
            quick: 0.0,
        };
        assert_eq!(full.offset(3), drift(3, 4.2, Speed::Calm, 7));
        let (half_shift, half_turn) = Drift {
            weight: 0.5,
            ..full
        }
        .offset(3);
        let (shift, turn) = drift(3, 4.2, Speed::Calm, 7);
        near(half_shift.x, shift.x / 2.0);
        near(half_turn, turn / 2.0);
    }

    #[test]
    fn neighbouring_petals_drift_out_of_step() {
        for speed in [Speed::Calm, Speed::Quick] {
            for time in [0.0, 2.5, 17.3] {
                for index in 0..PETALS.len() - 1 {
                    let (shift, turn) = drift(index, time, speed, 7);
                    let (next_shift, next_turn) = drift(index + 1, time, speed, 7);
                    assert!(
                        (shift - next_shift).length() > 0.01 || (turn - next_turn).abs() > 0.01,
                        "petals {index} and {} move together",
                        index + 1
                    );
                }
            }
        }
    }

    #[test]
    fn drift_moves_without_jumps() {
        for speed in [Speed::Calm, Speed::Quick] {
            for index in 0..PETALS.len() {
                let mut last = drift(index, 0.0, speed, 7);
                for step in 1..3000 {
                    let next = drift(index, f64::from(step) * 0.033, speed, 7);
                    assert!((next.0 - last.0).length() < 1.0, "{last:?} -> {next:?}");
                    assert!((next.1 - last.1).abs() < 1.5, "{last:?} -> {next:?}");
                    last = next;
                }
            }
        }
    }

    #[test]
    fn each_launch_wanders_its_own_way() {
        let path = |seed| {
            (0..20)
                .map(|step| drift(0, f64::from(step) * 1.3, Speed::Calm, seed))
                .collect::<Vec<_>>()
        };
        assert_eq!(path(7), path(7));
        assert_ne!(path(7), path(8));
    }
}
