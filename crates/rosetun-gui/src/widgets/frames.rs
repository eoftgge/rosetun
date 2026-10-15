use eframe::egui::{self, CornerRadius, Stroke};

use crate::theme::{BORDER, BORDER_STRONG, CARD, ERROR, MODAL, RADIUS};

pub(crate) fn card_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(egui::Margin::same(16))
}

pub(crate) fn modal_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(MODAL)
        .stroke(Stroke::new(1.0, BORDER_STRONG))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(egui::Margin::same(24))
}

pub(crate) fn dismissible_error(ui: &mut egui::Ui, message: &str) -> bool {
    dismissible_error_with_action(ui, message, None).0
}

pub(crate) fn dismissible_error_with_action(
    ui: &mut egui::Ui,
    message: &str,
    action: Option<(&str, bool)>,
) -> (bool, bool) {
    let mut clicked = false;
    let dismissed = card_frame()
        .show(ui, |ui| {
            egui::Sides::new()
                .shrink_left()
                .wrap()
                .spacing(16.0)
                .show(
                    ui,
                    |ui| {
                        ui.colored_label(ERROR, crate::constants::ERROR_MARK);
                        ui.vertical(|ui| {
                            ui.add(egui::Label::new(message).wrap());
                            if let Some((label, enabled)) = action {
                                clicked = ui
                                    .scope(|ui| {
                                        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
                                        crate::widgets::link(ui, label, enabled).clicked()
                                    })
                                    .inner;
                            }
                        });
                    },
                    |ui| ui.button(tr!("dismiss")).clicked(),
                )
                .1
        })
        .inner;
    (dismissed, clicked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_banner_keeps_action_on_one_line_in_compact_window() {
        let message = "Rules were not applied: the engine did not start. Try again; if it keeps happening, save a report under Settings › Service and log. Restored previous rules.";
        let action = "Restore my edits";
        for scale in [1.0, 1.25, 1.5] {
            let width = 960.0 / scale;
            let ctx = egui::Context::default();
            crate::theme::apply(&ctx);
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(width, 640.0 / scale),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        dismissible_error_with_action(ui, message, Some((action, true)));
                    });
                },
            );
            let text = |value: &str| {
                output.shapes.iter().find_map(|shape| match &shape.shape {
                    egui::Shape::Text(text) if text.galley.text() == value => Some(text),
                    _ => None,
                })
            };
            let message_shape = text(message).unwrap();
            let action_shape = text(action).unwrap();
            assert!(message_shape.galley.rows.len() <= 3, "{scale}");
            assert_eq!(action_shape.galley.rows.len(), 1, "{scale}");
            assert!(
                action_shape.pos.y >= message_shape.pos.y + message_shape.galley.size().y,
                "{scale}"
            );
            let banner = output
                .shapes
                .iter()
                .find_map(|shape| match &shape.shape {
                    egui::Shape::Rect(rect) if rect.fill == CARD => Some(rect.rect),
                    _ => None,
                })
                .unwrap();
            let line_height = message_shape.galley.rows[0].rect().height();
            assert!(
                banner.height() <= 3.0 * line_height + action_shape.galley.size().y + 48.0,
                "{scale}: {banner:?}"
            );
            assert!(action_shape.pos.x + action_shape.galley.size().x <= banner.right());
            output.textures_delta.clear();
        }
    }

    #[test]
    fn russian_error_banner_action_does_not_wrap() {
        let ctx = egui::Context::default();
        crate::theme::apply(&ctx);
        let action = "Вернуть мои правки";
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(640.0, 426.0),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    dismissible_error_with_action(
                        ui,
                        "Правила не применились: ядро не запустилось. Попробуйте ещё раз; если повторяется, соберите отчёт в Настройки › Служба и журнал. Вернули прежние.",
                        Some((action, true)),
                    );
                });
            },
        );
        let link = output
            .shapes
            .iter()
            .find_map(|shape| match &shape.shape {
                egui::Shape::Text(text) if text.galley.text() == action => Some(text),
                _ => None,
            })
            .unwrap();
        assert_eq!(link.galley.rows.len(), 1);
        output.textures_delta.clear();
    }
}
