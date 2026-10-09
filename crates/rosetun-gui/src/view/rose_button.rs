use std::{sync::OnceLock, time::Duration};

use eframe::egui::{
    self, Color32, FontFamily, FontId, Id, Pos2, Rect, Sense, Shape, Stroke, WidgetInfo, WidgetType,
};
use rosetun_config::ConnectionState;

use crate::theme;

const RING_RADIUS: f32 = 96.0;
const TRANSITION_SECONDS: f64 = 0.8;
const OUTER: usize = 0;
const MIDDLE: usize = 1;
const CORE: usize = 2;
const GLOW: usize = 3;
const STAMENS: usize = 4;
const CHROME: usize = 5;

#[derive(Clone, Copy)]
struct Timing {
    delay_ms: u64,
    duration_ms: u64,
}

impl Timing {
    const fn end_ms(self) -> u64 {
        self.delay_ms + self.duration_ms
    }

    fn progress(self, elapsed: f64) -> f32 {
        ((elapsed * 1000.0 - self.delay_ms as f64) / self.duration_ms as f64).clamp(0.0, 1.0) as f32
    }
}

const BLOOM_TIMING: [Timing; 6] = [
    Timing {
        delay_ms: 0,
        duration_ms: 700,
    },
    Timing {
        delay_ms: 130,
        duration_ms: 700,
    },
    Timing {
        delay_ms: 260,
        duration_ms: 700,
    },
    Timing {
        delay_ms: 300,
        duration_ms: 900,
    },
    Timing {
        delay_ms: 380,
        duration_ms: 600,
    },
    Timing {
        delay_ms: 0,
        duration_ms: 800,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RosePhase {
    Bud,
    Opening,
    Bloom,
    Blocked,
    Unavailable,
}

pub(crate) fn rose_phase(helper_available: bool, state: Option<&ConnectionState>) -> RosePhase {
    if !helper_available {
        return RosePhase::Unavailable;
    }
    match state {
        None | Some(ConnectionState::Disconnected | ConnectionState::Failed { .. }) => {
            RosePhase::Bud
        }
        Some(ConnectionState::Connecting | ConnectionState::Reconnecting) => RosePhase::Opening,
        Some(ConnectionState::Connected) => RosePhase::Bloom,
        Some(ConnectionState::FailedProtected { .. }) => RosePhase::Blocked,
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct PetalLayer {
    k: f32,
    rotation: f32,
    fill: Color32,
    stroke: Color32,
}

impl PetalLayer {
    const HIDDEN: Self = Self {
        k: 0.0,
        rotation: 0.0,
        fill: Color32::TRANSPARENT,
        stroke: Color32::TRANSPARENT,
    };
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct RoseParams {
    layers: [PetalLayer; 3],
    glow: f32,
    stamen_scale: f32,
    stamen_alpha: f32,
    disc_fill: Color32,
    disc_stroke: Color32,
    ring: Color32,
    label: Color32,
}

fn params(phase: RosePhase) -> RoseParams {
    let (layers, glow, stamen_scale, stamen_alpha, disc_fill, disc_stroke, ring, label) =
        match phase {
            RosePhase::Bud => (
                [
                    PetalLayer {
                        k: 1.35,
                        rotation: -24.0,
                        fill: theme::TEXT.gamma_multiply(0.20),
                        stroke: theme::TEXT,
                    },
                    PetalLayer::HIDDEN,
                    PetalLayer::HIDDEN,
                ],
                0.0,
                0.2,
                0.0,
                theme::ROSE,
                Color32::TRANSPARENT,
                theme::BORDER_STRONG,
                theme::TEXT,
            ),
            RosePhase::Opening => (
                [
                    PetalLayer {
                        k: 1.75,
                        rotation: -12.0,
                        fill: theme::ROSE_BRIGHT.gamma_multiply(0.30),
                        stroke: theme::ROSE_BRIGHT,
                    },
                    PetalLayer {
                        k: 0.90,
                        rotation: 16.0,
                        fill: theme::ROSE_BRIGHT.gamma_multiply(0.15),
                        stroke: theme::ROSE_BRIGHT.gamma_multiply(0.60),
                    },
                    PetalLayer::HIDDEN,
                ],
                0.0,
                0.2,
                0.0,
                theme::ROSE_BRIGHT.gamma_multiply(0.12),
                theme::ROSE_BRIGHT,
                theme::ROSE_BRIGHT.gamma_multiply(0.40),
                theme::ROSE_BRIGHT,
            ),
            RosePhase::Bloom => (
                [
                    PetalLayer {
                        k: 2.25,
                        rotation: 0.0,
                        fill: theme::ROSE_DARK.gamma_multiply(0.90),
                        stroke: theme::ROSE_LIGHT.gamma_multiply(0.55),
                    },
                    PetalLayer {
                        k: 1.60,
                        rotation: 36.0,
                        fill: theme::ROSE.gamma_multiply(0.92),
                        stroke: theme::ROSE_LIGHT.gamma_multiply(0.80),
                    },
                    PetalLayer {
                        k: 0.95,
                        rotation: 18.0,
                        fill: theme::ROSE_LIGHT.gamma_multiply(0.95),
                        stroke: theme::TEXT.gamma_multiply(0.55),
                    },
                ],
                1.0,
                1.0,
                1.0,
                theme::ROSE.gamma_multiply(0.10),
                theme::ROSE_LIGHT.gamma_multiply(0.90),
                theme::ROSE_LIGHT.gamma_multiply(0.35),
                theme::TEXT_MUTED,
            ),
            RosePhase::Unavailable => (
                [
                    PetalLayer {
                        k: 1.25,
                        rotation: 18.0,
                        fill: theme::DISABLED.gamma_multiply(0.12),
                        stroke: theme::DISABLED,
                    },
                    PetalLayer::HIDDEN,
                    PetalLayer::HIDDEN,
                ],
                0.0,
                0.2,
                0.0,
                theme::MODAL,
                theme::DISABLED,
                theme::BORDER_STRONG,
                theme::DISABLED,
            ),
            RosePhase::Blocked => (
                [
                    PetalLayer {
                        k: 1.35,
                        rotation: -24.0,
                        fill: theme::ERROR.gamma_multiply(0.18),
                        stroke: theme::ERROR,
                    },
                    PetalLayer::HIDDEN,
                    PetalLayer::HIDDEN,
                ],
                0.0,
                0.2,
                0.0,
                theme::MODAL,
                theme::ERROR,
                theme::ERROR.gamma_multiply(0.45),
                theme::ERROR,
            ),
        };
    RoseParams {
        layers,
        glow,
        stamen_scale,
        stamen_alpha,
        disc_fill,
        disc_stroke,
        ring,
        label,
    }
}

fn petal_outline() -> &'static [(f32, f32); 24] {
    static OUTLINE: OnceLock<[(f32, f32); 24]> = OnceLock::new();
    OUTLINE.get_or_init(|| {
        let cubic = |a: (f32, f32), b: (f32, f32), c: (f32, f32), d: (f32, f32), t: f32| {
            let u = 1.0 - t;
            (
                u.powi(3) * a.0
                    + 3.0 * u.powi(2) * t * b.0
                    + 3.0 * u * t.powi(2) * c.0
                    + t.powi(3) * d.0,
                u.powi(3) * a.1
                    + 3.0 * u.powi(2) * t * b.1
                    + 3.0 * u * t.powi(2) * c.1
                    + t.powi(3) * d.1,
            )
        };
        let mut points = [(0.0, 0.0); 24];
        for index in 0..12 {
            let t = index as f32 / 12.0;
            points[index] = cubic((0.0, 0.0), (-8.5, -5.0), (-10.0, -16.0), (0.0, -23.0), t);
            points[12 + index] = cubic((0.0, -23.0), (10.0, -16.0), (8.5, -5.0), (0.0, 0.0), t);
        }
        points
    })
}

fn petal_points(center: Pos2, angle: f32, k: f32) -> [Pos2; 24] {
    let (sin, cos) = angle.to_radians().sin_cos();
    petal_outline().map(|(x, y)| {
        let (x, y) = (x * k, y * k);
        egui::pos2(center.x + x * cos - y * sin, center.y + x * sin + y * cos)
    })
}

fn hits(center: Pos2, label: Rect, pointer: Pos2) -> bool {
    center.distance(pointer) <= RING_RADIUS || label.contains(pointer)
}

#[derive(Debug, Clone, Copy)]
struct RoseAnimation {
    from: RoseParams,
    to: RoseParams,
    started: f64,
    bloom: bool,
}

impl RoseAnimation {
    fn duration(&self) -> f64 {
        if self.bloom {
            BLOOM_TIMING
                .iter()
                .map(|timing| timing.end_ms())
                .max()
                .unwrap_or(0) as f64
                / 1000.0
        } else {
            TRANSITION_SECONDS
        }
    }

    fn displayed(&self, now: f64, reduce_motion: bool) -> RoseParams {
        let mut visible = self.visible(now, reduce_motion);
        if !reduce_motion && self.to == params(RosePhase::Opening) {
            visible.layers[OUTER].k += opening_pulse(now);
        }
        visible
    }

    fn visible(&self, now: f64, reduce_motion: bool) -> RoseParams {
        if reduce_motion || now - self.started >= self.duration() {
            return self.to;
        }
        let elapsed = (now - self.started).max(0.0);
        if !self.bloom {
            let t = (elapsed / TRANSITION_SECONDS) as f32;
            return lerp_params(&self.from, &self.to, ease_out_cubic(t), t);
        }
        let layers = std::array::from_fn(|index| {
            let t = BLOOM_TIMING[index].progress(elapsed);
            lerp_layer(
                self.from.layers[index],
                self.to.layers[index],
                ease_out_back(t),
                t,
            )
        });
        let glow = BLOOM_TIMING[GLOW].progress(elapsed);
        let stamens = BLOOM_TIMING[STAMENS].progress(elapsed);
        let chrome = ease_out_cubic(BLOOM_TIMING[CHROME].progress(elapsed));
        RoseParams {
            layers,
            glow: lerp(self.from.glow, self.to.glow, glow),
            stamen_scale: lerp(
                self.from.stamen_scale,
                self.to.stamen_scale,
                ease_out_back(stamens),
            ),
            stamen_alpha: lerp(self.from.stamen_alpha, self.to.stamen_alpha, stamens),
            disc_fill: color_lerp(self.from.disc_fill, self.to.disc_fill, chrome),
            disc_stroke: color_lerp(self.from.disc_stroke, self.to.disc_stroke, chrome),
            ring: color_lerp(self.from.ring, self.to.ring, chrome),
            label: color_lerp(self.from.label, self.to.label, chrome),
        }
    }
}

fn opening_pulse(now: f64) -> f32 {
    (0.08 * (0.5 - 0.5 * (std::f64::consts::TAU * now / 1.6).cos())) as f32
}

fn ease_out_cubic(t: f32) -> f32 {
    1.0 - (1.0 - t).powi(3)
}

fn ease_out_back(t: f32) -> f32 {
    let x = t - 1.0;
    1.0 + 2.2 * x.powi(3) + 1.2 * x.powi(2)
}

fn lerp(start: f32, end: f32, t: f32) -> f32 {
    start + (end - start) * t
}

fn color_lerp(start: Color32, end: Color32, t: f32) -> Color32 {
    start.lerp_to_gamma(end, t)
}

fn lerp_layer(from: PetalLayer, to: PetalLayer, numbers: f32, colors: f32) -> PetalLayer {
    PetalLayer {
        k: lerp(from.k, to.k, numbers),
        rotation: lerp(from.rotation, to.rotation, numbers),
        fill: color_lerp(from.fill, to.fill, colors),
        stroke: color_lerp(from.stroke, to.stroke, colors),
    }
}

fn lerp_params(from: &RoseParams, to: &RoseParams, numbers: f32, colors: f32) -> RoseParams {
    if numbers == 0.0 && colors == 0.0 {
        return *from;
    }
    if numbers == 1.0 && colors == 1.0 {
        return *to;
    }
    RoseParams {
        layers: std::array::from_fn(|index| {
            lerp_layer(from.layers[index], to.layers[index], numbers, colors)
        }),
        glow: lerp(from.glow, to.glow, numbers),
        stamen_scale: lerp(from.stamen_scale, to.stamen_scale, numbers),
        stamen_alpha: lerp(from.stamen_alpha, to.stamen_alpha, numbers),
        disc_fill: color_lerp(from.disc_fill, to.disc_fill, colors),
        disc_stroke: color_lerp(from.disc_stroke, to.disc_stroke, colors),
        ring: color_lerp(from.ring, to.ring, colors),
        label: color_lerp(from.label, to.label, colors),
    }
}

/// The connect button. Returns true when activated inside the ring or on the label.
pub(crate) fn rose_button(
    ui: &mut egui::Ui,
    phase: RosePhase,
    label: &str,
    enabled: bool,
    reduce_motion: bool,
) -> bool {
    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, response) = ui.allocate_exact_size(egui::vec2(240.0, 260.0), sense);
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Button, enabled, label));
    let center = egui::pos2(rect.center().x, rect.top() + 105.0);
    let label_center = egui::pos2(center.x, rect.top() + 218.0);
    let font_id = FontId::new(17.0, FontFamily::Name(theme::UI_SEMIBOLD.into()));
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_owned(), font_id, theme::TEXT);
    let label_rect = Rect::from_center_size(label_center, galley.size());
    let hovered = enabled
        && response.hovered()
        && response
            .hover_pos()
            .is_some_and(|pointer| hits(center, label_rect, pointer));
    let response = if hovered {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    };

    let ctx = ui.ctx();
    let now = ctx.input(|input| input.time);
    let target = params(phase);
    let id = Id::new("rose_button");
    let mut animation = ctx.data_mut(|data| {
        data.get_temp::<RoseAnimation>(id).unwrap_or(RoseAnimation {
            from: target,
            to: target,
            started: now,
            bloom: false,
        })
    });
    let current = animation.displayed(now, reduce_motion);
    if animation.to != target {
        animation = RoseAnimation {
            from: current,
            to: target,
            started: now,
            bloom: phase == RosePhase::Bloom,
        };
    }
    ctx.data_mut(|data| data.insert_temp(id, animation));
    let visible = animation.displayed(now, reduce_motion);
    if !reduce_motion
        && now - animation.started < animation.duration()
        && animation.from != animation.to
    {
        ctx.request_repaint();
    }
    if phase == RosePhase::Opening && !reduce_motion {
        ctx.request_repaint_after(Duration::from_millis(33));
    }

    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        painter.circle_stroke(
            center,
            RING_RADIUS,
            Stroke::new(
                1.0,
                if hovered {
                    theme::ROSE.gamma_multiply(0.6)
                } else {
                    visible.ring
                },
            ),
        );
        painter.circle(
            center,
            74.0,
            visible.disc_fill,
            Stroke::new(2.0, visible.disc_stroke),
        );
        if visible.glow > 0.0 {
            for (radius, alpha) in [(70.0, 0.06), (56.0, 0.08), (40.0, 0.10)] {
                painter.circle_filled(
                    center,
                    radius,
                    theme::ROSE.gamma_multiply(alpha * visible.glow),
                );
            }
        }
        for layer in [
            visible.layers[OUTER],
            visible.layers[MIDDLE],
            visible.layers[CORE],
        ] {
            if layer.k <= 0.0
                || (layer.fill == Color32::TRANSPARENT && layer.stroke == Color32::TRANSPARENT)
            {
                continue;
            }
            for index in 0..5 {
                painter.add(Shape::convex_polygon(
                    petal_points(center, 72.0 * index as f32 + layer.rotation, layer.k).to_vec(),
                    layer.fill,
                    Stroke::new(1.4, layer.stroke),
                ));
            }
        }
        if visible.stamen_alpha > 0.0 {
            let scale = visible.stamen_scale;
            let color = theme::TEXT.gamma_multiply(0.85 * visible.stamen_alpha);
            for index in 0..5 {
                let (sin, cos) = (72.0 * index as f32 + 18.0).to_radians().sin_cos();
                painter.circle_filled(
                    center + egui::vec2(5.0 * sin * scale, -5.0 * cos * scale),
                    1.8 * scale,
                    color,
                );
            }
            painter.circle_filled(
                center,
                2.6 * scale,
                theme::TEXT.gamma_multiply(0.90 * visible.stamen_alpha),
            );
        }
        painter.galley(label_rect.min, galley, visible.label);
    }

    enabled
        && response.clicked()
        && response
            .interact_pointer_pos()
            .is_none_or(|pointer| hits(center, label_rect, pointer))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn near(actual: f32, expected: f32) {
        assert!((actual - expected).abs() < 0.001, "{actual} != {expected}");
    }

    #[test]
    fn phases_match_connection_and_service_status() {
        let cases = [
            (ConnectionState::Disconnected, RosePhase::Bud),
            (
                ConnectionState::Failed {
                    failure_kind: None,
                    reason: String::new(),
                },
                RosePhase::Bud,
            ),
            (ConnectionState::Connecting, RosePhase::Opening),
            (ConnectionState::Reconnecting, RosePhase::Opening),
            (ConnectionState::Connected, RosePhase::Bloom),
            (
                ConnectionState::FailedProtected {
                    failure_kind: None,
                    reason: String::new(),
                },
                RosePhase::Blocked,
            ),
        ];
        for (state, phase) in &cases {
            assert_eq!(rose_phase(true, Some(state)), *phase);
            assert_eq!(rose_phase(false, Some(state)), RosePhase::Unavailable);
        }
        assert_eq!(rose_phase(false, None), RosePhase::Unavailable);
        assert_eq!(rose_phase(true, None), RosePhase::Bud);
    }

    fn visible_layers(phase: RosePhase) -> usize {
        params(phase)
            .layers
            .iter()
            .filter(|layer| layer.k > 0.0)
            .count()
    }

    fn transition(from: RosePhase, to: RosePhase) -> RoseAnimation {
        RoseAnimation {
            from: params(from),
            to: params(to),
            started: 0.0,
            bloom: to == RosePhase::Bloom,
        }
    }

    #[test]
    fn phase_parameters_match_the_layered_rose() {
        for phase in [RosePhase::Bud, RosePhase::Unavailable, RosePhase::Blocked] {
            assert_eq!(visible_layers(phase), 1);
            assert_eq!(params(phase).layers[MIDDLE], PetalLayer::HIDDEN);
            assert_eq!(params(phase).layers[CORE], PetalLayer::HIDDEN);
        }
        let bud = params(RosePhase::Bud);
        near(bud.layers[OUTER].k, 1.35);
        near(bud.layers[OUTER].rotation, -24.0);
        assert_eq!(bud.layers[OUTER].fill, theme::TEXT.gamma_multiply(0.20));
        assert_eq!(bud.layers[OUTER].stroke, theme::TEXT);
        assert_eq!(
            params(RosePhase::Blocked).layers[OUTER].stroke,
            theme::ERROR
        );
        assert_ne!(params(RosePhase::Blocked), bud);

        let opening = params(RosePhase::Opening);
        assert_eq!(visible_layers(RosePhase::Opening), 2);
        near(opening.layers[OUTER].k, 1.75);
        near(opening.layers[OUTER].rotation, -12.0);
        assert_eq!(
            opening.layers[OUTER].fill,
            theme::ROSE_BRIGHT.gamma_multiply(0.30)
        );
        assert_eq!(opening.layers[OUTER].stroke, theme::ROSE_BRIGHT);
        near(opening.layers[MIDDLE].k, 0.90);
        near(opening.layers[MIDDLE].rotation, 16.0);
        assert_eq!(
            opening.layers[MIDDLE].fill,
            theme::ROSE_BRIGHT.gamma_multiply(0.15)
        );
        assert_eq!(
            opening.layers[MIDDLE].stroke,
            theme::ROSE_BRIGHT.gamma_multiply(0.60)
        );

        let bloom = params(RosePhase::Bloom);
        assert_eq!(visible_layers(RosePhase::Bloom), 3);
        for (index, k, rotation, fill, stroke) in [
            (
                OUTER,
                2.25,
                0.0,
                theme::ROSE_DARK.gamma_multiply(0.90),
                theme::ROSE_LIGHT.gamma_multiply(0.55),
            ),
            (
                MIDDLE,
                1.60,
                36.0,
                theme::ROSE.gamma_multiply(0.92),
                theme::ROSE_LIGHT.gamma_multiply(0.80),
            ),
            (
                CORE,
                0.95,
                18.0,
                theme::ROSE_LIGHT.gamma_multiply(0.95),
                theme::TEXT.gamma_multiply(0.55),
            ),
        ] {
            near(bloom.layers[index].k, k);
            near(bloom.layers[index].rotation, rotation);
            assert_eq!(bloom.layers[index].fill, fill);
            assert_eq!(bloom.layers[index].stroke, stroke);
        }
        assert_eq!(bloom.ring, theme::ROSE_LIGHT.gamma_multiply(0.35));
        assert_eq!(bloom.disc_fill, theme::ROSE.gamma_multiply(0.10));
        assert_eq!(bloom.disc_stroke, theme::ROSE_LIGHT.gamma_multiply(0.90));
        assert_eq!(bloom.label, theme::TEXT_MUTED);
        near(bloom.glow, 1.0);
        near(bloom.stamen_scale, 1.0);
        near(bloom.stamen_alpha, 1.0);
    }

    #[test]
    fn easing_and_interpolation_reach_endpoints() {
        near(ease_out_cubic(0.0), 0.0);
        near(ease_out_cubic(1.0), 1.0);
        near(ease_out_cubic(0.5), 0.875);
        near(ease_out_back(0.0), 0.0);
        near(ease_out_back(1.0), 1.0);
        let peak = (0..=1000)
            .map(|index| ease_out_back(index as f32 / 1000.0))
            .fold(0.0_f32, f32::max);
        assert!(peak > 1.0 && peak < 1.15);
        let from = params(RosePhase::Bud);
        let to = params(RosePhase::Bloom);
        assert_eq!(lerp_params(&from, &to, 0.0, 0.0), from);
        assert_eq!(lerp_params(&from, &to, 1.0, 1.0), to);
    }

    #[test]
    fn petals_are_rounded_symmetric_and_convex() {
        let outline = petal_outline();
        assert_eq!(outline[0], (0.0, 0.0));
        assert_eq!(outline[12], (0.0, -23.0));
        for index in 1..12 {
            assert!(outline[index].1 > -23.0);
            near(outline[index].0, -outline[24 - index].0);
            near(outline[index].1, outline[24 - index].1);
        }
        for index in 0..outline.len() {
            let (a, b, c) = (
                outline[index],
                outline[(index + 1) % outline.len()],
                outline[(index + 2) % outline.len()],
            );
            let turn = (b.0 - a.0) * (c.1 - b.1) - (b.1 - a.1) * (c.0 - b.0);
            assert!(turn > 0.0, "concave turn at {index}: {turn}");
        }
    }

    #[test]
    fn petals_rotate_clockwise_around_the_center() {
        let center = egui::pos2(100.0, 100.0);
        let points = petal_points(center, 0.0, 2.0);
        near(points[0].x, center.x);
        near(points[0].y, center.y);
        near(points[12].x, center.x);
        near(points[12].y, center.y - 46.0);
        let tip = petal_points(center, 90.0, 2.0)[12];
        near(tip.x, center.x + 46.0);
        near(tip.y, center.y);
    }

    #[test]
    fn bloom_components_follow_one_staggered_schedule() {
        assert_eq!(
            BLOOM_TIMING.map(|timing| (timing.delay_ms, timing.duration_ms)),
            [
                (0, 700),
                (130, 700),
                (260, 700),
                (300, 900),
                (380, 600),
                (0, 800),
            ]
        );
        let animation = transition(RosePhase::Bud, RosePhase::Bloom);
        let start = animation.from;
        let at_100 = animation.visible(0.1, false);
        assert_ne!(at_100.layers[OUTER].k, start.layers[OUTER].k);
        assert_eq!(at_100.layers[MIDDLE], start.layers[MIDDLE]);
        assert_eq!(at_100.layers[CORE], start.layers[CORE]);
        assert_eq!(at_100.glow, 0.0);
        assert_eq!(at_100.stamen_alpha, 0.0);
        let at_1000 = animation.visible(1.0, false);
        assert_eq!(at_1000.layers, animation.to.layers);
        assert_eq!(at_1000.stamen_alpha, 1.0);
        assert_eq!(at_1000.ring, animation.to.ring);
        assert!(at_1000.glow < 1.0);
        near(animation.duration() as f32, 1.2);
        assert_eq!(animation.visible(1.2, false), animation.to);
    }

    #[test]
    fn bloom_overshoots_geometry_but_not_transparency() {
        let animation = transition(RosePhase::Bud, RosePhase::Bloom);
        let peak = animation.visible(0.55, false);
        assert!(peak.layers[OUTER].k > animation.to.layers[OUTER].k);
        for index in 0..=120 {
            let frame = animation.visible(index as f64 / 100.0, false);
            for layer in 0..3 {
                let fill_alpha = frame.layers[layer].fill.a();
                let stroke_alpha = frame.layers[layer].stroke.a();
                let initial = animation.from.layers[layer];
                let final_layer = animation.to.layers[layer];
                assert!(
                    (initial.fill.a().min(final_layer.fill.a())
                        ..=initial.fill.a().max(final_layer.fill.a()))
                        .contains(&fill_alpha)
                );
                assert!(
                    (initial.stroke.a().min(final_layer.stroke.a())
                        ..=initial.stroke.a().max(final_layer.stroke.a()))
                        .contains(&stroke_alpha)
                );
            }
            assert!((0.0..=1.0).contains(&frame.glow));
            assert!((0.0..=1.0).contains(&frame.stamen_alpha));
        }
    }

    #[test]
    fn leaving_bloom_never_overshoots() {
        let animation = transition(RosePhase::Bloom, RosePhase::Bud);
        for index in 0..=80 {
            let frame = animation.visible(index as f64 / 100.0, false);
            for layer in 0..3 {
                let start = animation.from.layers[layer].k;
                let end = animation.to.layers[layer].k;
                assert!((start.min(end)..=start.max(end)).contains(&frame.layers[layer].k));
            }
        }
    }

    #[test]
    fn reduced_motion_and_interruptions_use_visible_state() {
        let animation = transition(RosePhase::Bud, RosePhase::Bloom);
        assert_eq!(animation.visible(0.1, true), animation.to);
        let interrupted = RoseAnimation {
            from: animation.visible(0.5, false),
            to: params(RosePhase::Bud),
            started: 0.5,
            bloom: false,
        };
        assert_eq!(interrupted.visible(0.5, false), interrupted.from);
        assert_eq!(interrupted.visible(1.3, false), interrupted.to);

        let opening = transition(RosePhase::Bud, RosePhase::Opening);
        let pulsing = opening.displayed(0.8, false);
        near(pulsing.layers[OUTER].k, 1.83);
        let interrupted = RoseAnimation {
            from: pulsing,
            to: params(RosePhase::Bloom),
            started: 0.8,
            bloom: true,
        };
        assert_eq!(interrupted.displayed(0.8, false), pulsing);
        assert_eq!(opening.displayed(0.8, true), opening.to);
    }

    #[test]
    fn clicks_hit_the_ring_or_label_but_not_the_corners() {
        let center = egui::pos2(120.0, 105.0);
        let label = Rect::from_center_size(egui::pos2(120.0, 218.0), egui::vec2(140.0, 20.0));
        assert!(hits(center, label, center));
        assert!(hits(center, label, center + egui::vec2(95.0, 0.0)));
        assert!(!hits(center, label, center + egui::vec2(97.0, 0.0)));
        assert!(!hits(center, label, egui::pos2(0.0, 0.0)));
        assert!(hits(center, label, label.center()));
    }
}
