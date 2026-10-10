use super::*;

pub(super) fn set_controls(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let Some(set) = state.selected_rules() else {
        return;
    };
    let active = state.config.active_rule_set.as_ref() == Some(&set.id);
    ui.horizontal(|ui| {
        set_picker(ui, state, set, actions);
        let menu =
            icons::icon_button_sized(ui, Icon::More, true, 40.0).on_hover_text(tr!("more-actions"));
        widgets::menu_popup(&menu).show(|ui| {
            ui.set_min_width(180.0);
            if !active
                && widgets::menu_item(
                    ui,
                    widgets::MenuItem {
                        label: &tr!("make-active"),
                        enabled: state.can_edit_rules(),
                        selected: false,
                        danger: false,
                        note: None,
                    },
                )
                .clicked()
            {
                actions.push(Action::SelectRuleSet(Some(set.id.clone())));
                ui.close();
            }
            if widgets::menu_item(
                ui,
                widgets::MenuItem {
                    label: &tr!("new-set"),
                    enabled: state.can_edit_rules(),
                    selected: false,
                    danger: false,
                    note: None,
                },
            )
            .clicked()
            {
                actions.push(Action::OpenCreateSet);
                ui.close();
            }
            if widgets::menu_item(
                ui,
                widgets::MenuItem {
                    label: &tr!("rename"),
                    enabled: state.can_edit_rules(),
                    selected: false,
                    danger: false,
                    note: None,
                },
            )
            .clicked()
            {
                actions.push(Action::OpenRenameSet);
                ui.close();
            }
            ui.separator();
            if widgets::menu_item(
                ui,
                widgets::MenuItem {
                    label: &tr!("delete"),
                    enabled: state.can_edit_rules(),
                    selected: false,
                    danger: true,
                    note: None,
                },
            )
            .clicked()
            {
                actions.push(Action::RequestDeleteSet);
                ui.close();
            }
        });
    });
}

fn set_picker(ui: &mut egui::Ui, state: &State, set: &RuleSet, actions: &mut Vec<Action>) {
    let name = state.text(&set.name);
    let font = egui::FontId::new(
        egui::TextStyle::Body.resolve(ui.style()).size,
        egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
    );
    let name_width = ui
        .painter()
        .layout_no_wrap(name.clone(), font.clone(), theme::TEXT)
        .size()
        .x
        .min(260.0);
    let active = state.config.active_rule_set.as_ref() == Some(&set.id);
    let active_width = if active {
        ui.painter()
            .layout_no_wrap(
                tr!("active").to_owned(),
                egui::TextStyle::Small.resolve(ui.style()),
                theme::ROSE_LIGHT,
            )
            .size()
            .x
            + 12.0
    } else {
        0.0
    };
    let width = (12.0 + name_width + active_width + 36.0).max(220.0);
    let response = ui
        .scope_builder(egui::UiBuilder::new().sense(egui::Sense::click()), |ui| {
            ui.style_mut().interaction.selectable_labels = false;
            let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 40.0), egui::Sense::hover());
            let painter = ui.painter();
            painter.rect_filled(
                rect,
                theme::RADIUS,
                if ui.response().hovered() {
                    theme::BORDER
                } else {
                    theme::INPUT
                },
            );
            painter.rect_stroke(
                rect,
                theme::RADIUS,
                Stroke::new(1.0, theme::BORDER_STRONG),
                egui::StrokeKind::Inside,
            );
            let center_y = rect.center().y;
            let left = rect.left() + 12.0;
            let name_left = left;
            let galley = egui::WidgetText::from(RichText::new(name).font(font).color(theme::TEXT))
                .into_galley(
                    ui,
                    Some(egui::TextWrapMode::Truncate),
                    name_width,
                    egui::TextStyle::Body,
                );
            painter.galley(
                egui::pos2(name_left, center_y - galley.size().y / 2.0),
                galley,
                theme::TEXT,
            );
            let icon_right = 18.0;
            if active {
                painter.text(
                    egui::pos2(rect.right() - 10.0 - icon_right, center_y),
                    egui::Align2::RIGHT_CENTER,
                    tr!("active"),
                    egui::TextStyle::Small.resolve(ui.style()),
                    theme::ROSE_LIGHT,
                );
            }
            icons::paint(
                painter,
                egui::pos2(rect.right() - icon_right, center_y),
                Icon::Chevron { open: true },
                theme::TEXT_DIM,
            );
        })
        .response
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    widgets::menu_popup(&response).show(|ui| {
        ui.set_min_width(width);
        for item in &state.config.rule_sets {
            let selected = item.id == set.id;
            let is_active = state.config.active_rule_set.as_ref() == Some(&item.id);
            if widgets::menu_item(
                ui,
                widgets::MenuItem {
                    label: &state.text(&item.name),
                    enabled: true,
                    selected,
                    danger: false,
                    note: is_active.then_some(tr!("active")).as_deref(),
                },
            )
            .clicked()
            {
                actions.push(Action::ChooseRuleSet(item.id.clone()));
                ui.close();
            }
        }
    });
}
