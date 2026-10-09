use std::time::Duration;

use eframe::egui::{
    self, Color32, FontFamily, FontId, Id, Pos2, Rect, Sense, Shape, Stroke, WidgetInfo, WidgetType,
};
use rosetun_config::ConnectionState;

use crate::theme;

const RING_RADIUS: f32 = 96.0;
const TRANSITION_SECONDS: f64 = 0.8;

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
struct RoseParams {
    k: f32,
    twist: f32,
    inner_k: f32,
    inner_twist: f32,
    inner_alpha: f32,
    outer_fill: Color32,
    inner_fill: Color32,
    petal_stroke: Color32,
    disc_fill: Color32,
    disc_stroke: Color32,
    ring: Color32,
    label: Color32,
}

fn params(phase: RosePhase) -> RoseParams {
    match phase {
        RosePhase::Bud => RoseParams {
            k: 1.35,
            twist: -24.0,
            inner_k: 0.0,
            inner_twist: 0.0,
            inner_alpha: 0.0,
            outer_fill: theme::TEXT.gamma_multiply(0.2),
            inner_fill: Color32::TRANSPARENT,
            petal_stroke: theme::TEXT,
            disc_fill: theme::ROSE,
            disc_stroke: Color32::TRANSPARENT,
            ring: theme::BORDER_STRONG,
            label: theme::TEXT,
        },
        RosePhase::Opening => RoseParams {
            k: 1.75,
            twist: -12.0,
            inner_k: 0.9,
            inner_twist: -20.0,
            inner_alpha: 0.6,
            outer_fill: theme::ROSE_BRIGHT.gamma_multiply(0.3),
            inner_fill: theme::ROSE_BRIGHT.gamma_multiply(0.25),
            petal_stroke: theme::ROSE_BRIGHT,
            disc_fill: theme::ROSE_BRIGHT.gamma_multiply(0.12),
            disc_stroke: theme::ROSE_BRIGHT,
            ring: theme::ROSE_BRIGHT.gamma_multiply(0.4),
            label: theme::ROSE_BRIGHT,
        },
        RosePhase::Bloom => RoseParams {
            k: 2.25,
            twist: 0.0,
            inner_k: 1.35,
            inner_twist: 0.0,
            inner_alpha: 1.0,
            outer_fill: theme::ROSE.gamma_multiply(0.45),
            inner_fill: theme::ROSE.gamma_multiply(0.75),
            petal_stroke: theme::ROSE_LIGHT,
            disc_fill: theme::CONNECTED.gamma_multiply(0.1),
            disc_stroke: theme::CONNECTED,
            ring: theme::CONNECTED.gamma_multiply(0.35),
            label: theme::TEXT_MUTED,
        },
        RosePhase::Unavailable => RoseParams {
            k: 1.25,
            twist: 18.0,
            inner_k: 0.0,
            inner_twist: 0.0,
            inner_alpha: 0.0,
            outer_fill: theme::DISABLED.gamma_multiply(0.12),
            inner_fill: Color32::TRANSPARENT,
            petal_stroke: theme::DISABLED,
            disc_fill: theme::MODAL,
            disc_stroke: theme::DISABLED,
            ring: theme::BORDER_STRONG,
            label: theme::DISABLED,
        },
        RosePhase::Blocked => RoseParams {
            k: 1.35,
            twist: -24.0,
            inner_k: 0.0,
            inner_twist: 0.0,
            inner_alpha: 0.0,
            outer_fill: theme::ERROR.gamma_multiply(0.18),
            inner_fill: Color32::TRANSPARENT,
            petal_stroke: theme::ERROR,
            disc_fill: theme::MODAL,
            disc_stroke: theme::ERROR,
            ring: theme::ERROR.gamma_multiply(0.45),
            label: theme::ERROR,
        },
    }
}

fn petal_points(center: Pos2, angle: f32, k: f32) -> [Pos2; 4] {
    let (sin, cos) = angle.to_radians().sin_cos();
    [(0.0, 0.0), (-5.5, -11.0), (0.0, -21.5), (5.5, -11.0)].map(|(x, y)| {
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
}

fn ease_out_cubic(t: f32) -> f32 {
    1.0 - (1.0 - t).powi(3)
}

fn lerp_params(from: &RoseParams, to: &RoseParams, numbers: f32, colors: f32) -> RoseParams {
    if numbers == 0.0 && colors == 0.0 {
        return *from;
    }
    if numbers == 1.0 && colors == 1.0 {
        return *to;
    }
    let number = |start, end| start + (end - start) * numbers;
    let color = |start: Color32, end: Color32| start.lerp_to_gamma(end, colors);
    RoseParams {
        k: number(from.k, to.k),
        twist: number(from.twist, to.twist),
        inner_k: number(from.inner_k, to.inner_k),
        inner_twist: number(from.inner_twist, to.inner_twist),
        inner_alpha: number(from.inner_alpha, to.inner_alpha),
        outer_fill: color(from.outer_fill, to.outer_fill),
        inner_fill: color(from.inner_fill, to.inner_fill),
        petal_stroke: color(from.petal_stroke, to.petal_stroke),
        disc_fill: color(from.disc_fill, to.disc_fill),
        disc_stroke: color(from.disc_stroke, to.disc_stroke),
        ring: color(from.ring, to.ring),
        label: color(from.label, to.label),
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
        })
    });
    let progress = if reduce_motion {
        1.0
    } else {
        ((now - animation.started) / TRANSITION_SECONDS).clamp(0.0, 1.0) as f32
    };
    let current = lerp_params(
        &animation.from,
        &animation.to,
        ease_out_cubic(progress),
        progress,
    );
    if animation.to != target {
        animation = RoseAnimation {
            from: current,
            to: target,
            started: now,
        };
    }
    ctx.data_mut(|data| data.insert_temp(id, animation));
    let progress = if reduce_motion {
        1.0
    } else {
        ((now - animation.started) / TRANSITION_SECONDS).clamp(0.0, 1.0) as f32
    };
    let mut visible = lerp_params(
        &animation.from,
        &animation.to,
        ease_out_cubic(progress),
        progress,
    );
    if progress < 1.0 {
        ctx.request_repaint();
    }
    if phase == RosePhase::Opening && !reduce_motion {
        let pulse = 0.5 - 0.5 * (std::f64::consts::TAU * now / 1.6).cos();
        visible.k += 0.08 * pulse as f32;
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
        for index in 0..5 {
            painter.add(Shape::convex_polygon(
                petal_points(center, 72.0 * index as f32 + visible.twist, visible.k).to_vec(),
                visible.outer_fill,
                Stroke::new(1.4, visible.petal_stroke),
            ));
        }
        if visible.inner_alpha > 0.0 {
            for index in 0..5 {
                painter.add(Shape::convex_polygon(
                    petal_points(
                        center,
                        72.0 * index as f32 + 36.0 + visible.inner_twist,
                        visible.inner_k,
                    )
                    .to_vec(),
                    visible.inner_fill.gamma_multiply(visible.inner_alpha),
                    Stroke::new(
                        1.4,
                        visible.petal_stroke.gamma_multiply(visible.inner_alpha),
                    ),
                ));
            }
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

    #[test]
    fn phase_parameters_distinguish_protection_from_disconnection() {
        assert_eq!(params(RosePhase::Bud).k, 1.35);
        assert_eq!(params(RosePhase::Bloom).twist, 0.0);
        assert_eq!(params(RosePhase::Blocked).petal_stroke, theme::ERROR);
        assert_ne!(params(RosePhase::Blocked), params(RosePhase::Bud));
    }

    #[test]
    fn easing_and_interpolation_reach_endpoints() {
        near(ease_out_cubic(0.0), 0.0);
        near(ease_out_cubic(1.0), 1.0);
        near(ease_out_cubic(0.5), 0.875);
        let from = params(RosePhase::Bud);
        let to = params(RosePhase::Bloom);
        assert_eq!(lerp_params(&from, &to, 0.0, 0.0), from);
        assert_eq!(lerp_params(&from, &to, 1.0, 1.0), to);
    }

    #[test]
    fn petals_rotate_clockwise_around_the_center() {
        let center = egui::pos2(100.0, 100.0);
        let points = petal_points(center, 0.0, 2.0);
        for (point, expected) in points.into_iter().zip([
            center,
            center + egui::vec2(-11.0, -22.0),
            center + egui::vec2(0.0, -43.0),
            center + egui::vec2(11.0, -22.0),
        ]) {
            near(point.x, expected.x);
            near(point.y, expected.y);
        }
        let tip = petal_points(center, 90.0, 2.0)[2];
        near(tip.x, center.x + 43.0);
        near(tip.y, center.y);
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
