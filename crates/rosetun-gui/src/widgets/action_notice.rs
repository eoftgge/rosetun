use eframe::egui::{self, RichText};

use super::{link, modal_frame};
use crate::theme;

pub(crate) struct NoticeAction<'a> {
    pub(crate) label: &'a str,
    pub(crate) hint: Option<&'a str>,
    pub(crate) enabled: bool,
}

/// A short notice at the bottom of the window with actions after it, as
/// "Rule deleted · Undo · Apply". Returns the index of the clicked action.
pub(crate) fn action_notice(
    ctx: &egui::Context,
    id: &str,
    text: &str,
    actions: &[NoticeAction<'_>],
) -> Option<usize> {
    egui::Area::new(egui::Id::unique(id))
        .anchor(
            egui::Align2::CENTER_BOTTOM,
            egui::vec2(0.0, -theme::space::XL),
        )
        .order(egui::Order::Foreground)
        .show(ctx, |ui| {
            modal_frame()
                .inner_margin(theme::margin::symmetric(theme::space::L, theme::space::M))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        let color = theme::palette().text;
                        ui.label(RichText::new(text).small().color(color));
                        let mut clicked = None;
                        for (index, action) in actions.iter().enumerate() {
                            ui.label(RichText::new(tr!("apply-separator")).small().color(color));
                            let response = link(ui, action.label, action.enabled);
                            let response = match action.hint {
                                Some(hint) => response.on_hover_text(hint),
                                None => response,
                            };
                            if response.clicked() {
                                clicked = Some(index);
                            }
                        }
                        clicked
                    })
                    .inner
                })
                .inner
        })
        .inner
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_ui::TestScreen;

    #[test]
    fn each_action_after_the_text_reports_its_own_click() {
        let mut screen = TestScreen::new(egui::vec2(800.0, 600.0));
        let mut clicked = Vec::new();
        let mut show = |ui: &mut egui::Ui| {
            let actions = [
                NoticeAction {
                    label: "Undo",
                    hint: None,
                    enabled: true,
                },
                NoticeAction {
                    label: "Apply",
                    hint: Some("Restarts the tunnel"),
                    enabled: true,
                },
            ];
            if let Some(index) = action_notice(ui.ctx(), "test_notice", "Rule deleted", &actions) {
                clicked.push(index);
            }
        };
        let shown = screen.settle(&mut show);
        let left = |label: &str| {
            shown
                .iter()
                .find(|(text, _)| text == label)
                .map_or_else(|| panic!("no {label:?} in {shown:?}"), |(_, rect)| rect.left())
        };
        assert!(left("Rule deleted") < left("Undo"));
        assert!(left("Undo") < left("Apply"));

        screen.click_text("Apply", &mut show);
        assert_eq!(clicked, [1]);
    }
}
