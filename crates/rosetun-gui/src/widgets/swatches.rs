use eframe::egui::{self, Color32, Stroke};

use crate::theme;

const DIAMETER: f32 = 26.0;
const GAP: f32 = 10.0;

/// One choice of a colour group: the disc's fill and the ring around it.
pub(crate) struct Swatch<T> {
    pub(crate) value: T,
    pub(crate) label: String,
    pub(crate) fill: Color32,
    pub(crate) ring: Color32,
}

/// A radio group of colour discs. Tab reaches each disc, Space or Enter picks
/// it, and the left and right arrows pick the neighbour. Returns the option
/// picked when it differs from `selected`.
pub(crate) fn swatches<T: Copy + PartialEq>(
    ui: &mut egui::Ui,
    id_salt: impl std::hash::Hash + std::fmt::Debug,
    selected: T,
    options: &[Swatch<T>],
    enabled: bool,
) -> Option<T> {
    let enabled = enabled && ui.is_enabled();
    let id = ui.make_persistent_id(id_salt);
    let mut picked = None;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = GAP;
        for (index, swatch) in options.iter().enumerate() {
            let disc_id = id.with(index);
            let (rect, _) =
                ui.allocate_exact_size(egui::vec2(DIAMETER, DIAMETER), egui::Sense::hover());
            let response = ui.interact(
                rect,
                disc_id,
                if enabled {
                    egui::Sense::click()
                } else {
                    egui::Sense::hover()
                },
            );
            let active = swatch.value == selected;
            response.widget_info(|| {
                egui::WidgetInfo::selected(
                    egui::WidgetType::RadioButton,
                    enabled,
                    active,
                    &swatch.label,
                )
            });
            if enabled && response.clicked() && !active {
                picked = Some(swatch.value);
            }
            if enabled && response.has_focus() {
                ui.memory_mut(|memory| {
                    memory.set_focus_lock_filter(
                        disc_id,
                        egui::EventFilter {
                            horizontal_arrows: true,
                            ..Default::default()
                        },
                    );
                });
                let next = ui.input(|input| {
                    if input.key_pressed(egui::Key::ArrowRight) {
                        index.checked_add(1)
                    } else if input.key_pressed(egui::Key::ArrowLeft) {
                        index.checked_sub(1)
                    } else {
                        None
                    }
                });
                if let Some((next, neighbour)) =
                    next.and_then(|next| options.get(next).map(|swatch| (next, swatch)))
                {
                    ui.memory_mut(|memory| memory.request_focus(id.with(next)));
                    if neighbour.value != selected {
                        picked = Some(neighbour.value);
                    }
                }
            }
            paint(ui, rect, swatch, active, response.has_focus(), enabled);
            let response = response.on_hover_text(&swatch.label);
            if enabled {
                response.on_hover_cursor(egui::CursorIcon::PointingHand);
            }
        }
    });
    picked
}

fn paint<T>(
    ui: &egui::Ui,
    rect: egui::Rect,
    swatch: &Swatch<T>,
    active: bool,
    focused: bool,
    enabled: bool,
) {
    let fade = |color: Color32| {
        if enabled {
            color
        } else {
            color.gamma_multiply(0.5)
        }
    };
    let painter = ui.painter();
    let center = rect.center();
    let radius = DIAMETER / 2.0;
    painter.circle(
        center,
        radius - 1.0,
        fade(swatch.ring),
        Stroke::new(1.0, fade(theme::palette().border_strong)),
    );
    painter.circle_filled(center, radius - 6.0, fade(swatch.fill));
    if active {
        painter.circle_stroke(
            center,
            radius - 1.0,
            Stroke::new(2.0, fade(theme::palette().text)),
        );
    }
    if focused {
        painter.circle_stroke(
            center,
            radius + 2.0,
            Stroke::new(1.0, theme::palette().accent_light),
        );
    }
}
