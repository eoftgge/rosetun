use eframe::egui;

const ITEM_RADIUS_PX: f32 = 6.0;

fn item_radius(pixels_per_point: f32) -> egui::CornerRadius {
    let points = (ITEM_RADIUS_PX / pixels_per_point).round().clamp(1.0, 6.0) as u8;
    egui::CornerRadius::same(points)
}

pub(crate) fn menu_popup(response: &egui::Response) -> egui::Popup<'_> {
    let radius = item_radius(response.ctx.pixels_per_point());
    egui::Popup::menu(response).style(move |style: &mut egui::Style| {
        egui::containers::menu::menu_style(style);
        style.spacing.button_padding.y = 4.0;
        let widgets = &mut style.visuals.widgets;
        widgets.inactive.corner_radius = radius;
        widgets.hovered.corner_radius = radius;
        widgets.active.corner_radius = radius;
        widgets.open.corner_radius = radius;
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_item_radius_tracks_physical_pixels() {
        assert_eq!(item_radius(1.0), egui::CornerRadius::same(6));
        assert_eq!(item_radius(1.25), egui::CornerRadius::same(5));
        assert_eq!(item_radius(1.5), egui::CornerRadius::same(4));
        assert_eq!(item_radius(2.0), egui::CornerRadius::same(3));
    }

    #[test]
    fn menu_popup_applies_compact_rectangular_item_style() {
        let ctx = egui::Context::default();
        crate::theme::apply(&ctx);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let trigger = ui.button("Menu");
                menu_popup(&trigger).open(true).show(|ui| {
                    assert_eq!(ui.spacing().button_padding.y, 4.0);
                    assert_eq!(
                        ui.visuals().widgets.hovered.corner_radius,
                        egui::CornerRadius::same(6)
                    );
                    let item = ui.button("Delete");
                    assert!(
                        item.rect.height() >= ui.text_style_height(&egui::TextStyle::Button) + 8.0
                    );
                });
            });
        });
        output.textures_delta.clear();
    }
}
