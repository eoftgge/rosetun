use eframe::egui;

use crate::theme;

const FLAG_COLUMNS: usize = 16;
const FLAG_WIDTH: usize = 64;
const FLAG_HEIGHT: usize = 48;
/// Repeated edge pixels keep the feathered corners inside each flag's tile.
const FLAG_PADDING: usize = 3;
const TILE_WIDTH: usize = FLAG_WIDTH + 2 * FLAG_PADDING;
const TILE_HEIGHT: usize = FLAG_HEIGHT + 2 * FLAG_PADDING;
const FLAG_CODES: &[u8] = include_bytes!("../../assets/flags/codes.txt");
const FLAGS: &[u8] = include_bytes!("../../assets/flags/flags.png");

fn flag_index(code: &str) -> Option<usize> {
    let [first, second] = *code.as_bytes() else {
        return None;
    };
    let code = [first.to_ascii_uppercase(), second.to_ascii_uppercase()];
    FLAG_CODES
        .as_chunks::<3>()
        .0
        .binary_search_by(|entry| entry[..2].cmp(&code))
        .ok()
}

fn flag_atlas(ctx: &egui::Context) -> Option<egui::TextureHandle> {
    let id = egui::Id::unique("country_flag_atlas");
    if let Some(atlas) = ctx.data(|data| data.get_temp::<egui::TextureHandle>(id)) {
        return Some(atlas);
    }
    let image = image::load_from_memory_with_format(FLAGS, image::ImageFormat::Png)
        .ok()?
        .into_rgba8();
    let size = [image.width() as usize, image.height() as usize];
    let image = egui::ColorImage::from_rgba_unmultiplied(size, image.as_raw());
    let atlas = ctx.load_texture("country-flags", image, egui::TextureOptions::LINEAR);
    ctx.data_mut(|data| data.insert_temp(id, atlas.clone()));
    Some(atlas)
}

fn flag_uv(index: usize, atlas: egui::Vec2, badge: egui::Vec2) -> egui::Rect {
    let left = (index % FLAG_COLUMNS * TILE_WIDTH + FLAG_PADDING) as f32;
    let top = (index / FLAG_COLUMNS * TILE_HEIGHT + FLAG_PADDING) as f32;
    let artwork = egui::vec2(FLAG_WIDTH as f32, FLAG_HEIGHT as f32);
    // Fill the code badge's bounds without stretching the flag.
    let scale = (badge.x / artwork.x).max(badge.y / artwork.y);
    let visible = badge / scale;
    let center = egui::pos2(
        (left + artwork.x / 2.0) / atlas.x,
        (top + artwork.y / 2.0) / atlas.y,
    );
    egui::Rect::from_center_size(center, egui::vec2(visible.x / atlas.x, visible.y / atlas.y))
}

/// Flags and country codes occupy the same space so changing the setting keeps rows aligned.
pub(crate) fn country_badge(
    ui: &egui::Ui,
    rect: egui::Rect,
    code: &str,
    show_flag: bool,
    verified: bool,
) {
    if !ui.is_rect_visible(rect) {
        return;
    }
    let palette = theme::palette();
    let (border, text) = if verified {
        (palette.accent_dark, palette.accent_light)
    } else {
        (palette.border_strong, palette.text_muted)
    };
    let tile = |fill| {
        egui::epaint::RectShape::new(
            rect,
            theme::RADIUS_INNER,
            fill,
            egui::Stroke::new(theme::stroke::HAIRLINE, border),
            egui::StrokeKind::Inside,
        )
        .with_round_to_pixels(true)
    };
    let painter = ui.painter();
    if show_flag
        && let Some(index) = flag_index(code)
        && let Some(atlas) = flag_atlas(ui.ctx())
    {
        painter.add(
            tile(egui::Color32::WHITE)
                .with_texture(atlas.id(), flag_uv(index, atlas.size_vec2(), rect.size())),
        );
        return;
    }
    painter.add(tile(palette.border));
    painter.text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        code,
        theme::font::mono_small(),
        text,
    );
}

/// Text with room for a country marker in a button, list row or drop-down.
pub(crate) fn country_label<'a>(
    label: impl Into<egui::WidgetText>,
    code: Option<&'a str>,
    show_flag: bool,
    align_with_badges: bool,
) -> egui::Atoms<'a> {
    let mut label = egui::Atoms::new(label.into());
    let size = theme::country_badge::ROW_SIZE;
    if let Some(code) = code {
        label.push_left(egui::Atom::paint(size, move |ui, args| {
            country_badge(ui, args.rect, code, show_flag, false);
        }));
    } else if align_with_badges {
        label.push_left(egui::Atom {
            size: Some(size.into()),
            ..Default::default()
        });
    }
    label
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atlas_contains_every_country_code_and_only_one_tile_per_code() {
        let (codes, remainder) = FLAG_CODES.as_chunks::<3>();
        assert!(remainder.is_empty());
        assert!(codes.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(codes.iter().all(|code| code[2] == b'\n'));
        for code in rosetun_config::CountryCode::all() {
            assert!(flag_index(code.as_str()).is_some(), "{code:?}");
        }
        assert_eq!(flag_index("jp"), flag_index("JP"));
        let atlas = flag_atlas(&egui::Context::default()).unwrap();
        assert_eq!(
            atlas.size(),
            [
                FLAG_COLUMNS * TILE_WIDTH,
                codes.len().div_ceil(FLAG_COLUMNS) * TILE_HEIGHT
            ]
        );
    }

    #[test]
    fn badges_fit_at_both_sizes_and_fall_back_to_codes() {
        for scale in [1.0, 2.0] {
            let ctx = egui::Context::default();
            ctx.set_pixels_per_point(scale);
            theme::apply(&ctx);
            let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
                for (code, dimensions, show_flag) in [
                    ("DE", theme::country_badge::ROW_SIZE, true),
                    ("NP", theme::country_badge::SERVER_SIZE, true),
                    ("DE", theme::country_badge::ROW_SIZE, false),
                    ("NP", theme::country_badge::SERVER_SIZE, false),
                    ("ZZ", theme::country_badge::ROW_SIZE, true),
                ] {
                    let (rect, _) = ui.allocate_exact_size(dimensions.into(), egui::Sense::hover());
                    country_badge(ui, rect, code, show_flag, false);
                }
            });
            output.textures_delta.clear();
            let texts: Vec<_> = output
                .shapes
                .iter()
                .filter_map(|shape| match &shape.shape {
                    egui::Shape::Text(text) => Some(text),
                    _ => None,
                })
                .collect();
            assert_eq!(
                texts
                    .iter()
                    .map(|text| text.galley.text())
                    .collect::<Vec<_>>(),
                ["DE", "NP", "ZZ"]
            );
            let flags: Vec<_> = output
                .shapes
                .iter()
                .filter_map(|shape| match &shape.shape {
                    egui::Shape::Rect(flag) if flag.brush.is_some() => Some(flag),
                    _ => None,
                })
                .collect();
            assert_eq!(flags.len(), 2);
            let code_badges: Vec<_> = output
                .shapes
                .iter()
                .filter_map(|shape| match &shape.shape {
                    egui::Shape::Rect(badge)
                        if badge.brush.is_none()
                            && badge.stroke.color == theme::palette().border_strong =>
                    {
                        Some(badge)
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(code_badges.len(), 3);
            for (flag, code) in flags.iter().zip(code_badges) {
                assert_eq!(flag.rect.size(), code.rect.size());
                assert_eq!(flag.corner_radius, code.corner_radius);
                assert_eq!(flag.stroke, code.stroke);
                assert_eq!(flag.stroke_kind, code.stroke_kind);
                assert_eq!(flag.round_to_pixels, code.round_to_pixels);
                assert_ne!(code.fill, egui::Color32::TRANSPARENT);
            }
            assert_eq!(
                flags[0].brush.as_ref().unwrap().fill_texture_id,
                flags[1].brush.as_ref().unwrap().fill_texture_id,
            );
        }
    }
}
