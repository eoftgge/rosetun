use std::hash::{DefaultHasher, Hash, Hasher};

use eframe::egui::{self, emath::TSTransform};

use crate::motion;

use super::modal_frame;

/// How far new content travels up while it fades in.
const APPEAR_RISE: f32 = 6.0;
/// A dialog grows from this scale as it appears.
const MODAL_START_SCALE: f32 = 0.98;
/// `egui::Modal`'s own backdrop alpha.
const BACKDROP_ALPHA: f32 = 100.0;

#[derive(Clone, Copy)]
struct Appearance {
    key: u64,
    started: f64,
}

#[derive(Clone, Copy)]
struct ModalShown {
    frame: u64,
    started: f64,
}

/// How far a section opened by `open` is, eased; it follows clicks at once
/// and turns back from wherever it is.
pub(crate) fn reveal_progress(
    ctx: &egui::Context,
    id: egui::Id,
    open: bool,
    reduce_motion: bool,
) -> f32 {
    ctx.animate_bool_with_time_and_easing(
        id,
        open,
        motion::duration(motion::NORMAL, reduce_motion),
        motion::ease_out,
    )
}

/// Shows a section as tall as `progress` of its height, clipped below.
/// Nothing at zero.
pub(crate) fn reveal<R>(
    ui: &mut egui::Ui,
    id: egui::Id,
    progress: f32,
    add: impl FnOnce(&mut egui::Ui) -> R,
) -> Option<R> {
    if progress <= 0.0 {
        return None;
    }
    let height_id = id.with("reveal_height");
    // The clip has to be set before the content is laid out, so the height
    // comes from the last frame; the first one shows only a sliver.
    let full = ui
        .data(|data| data.get_temp::<f32>(height_id))
        .unwrap_or(10.0);
    let shown = motion::reveal_height(full, progress);
    let mut child = ui.new_child(
        egui::UiBuilder::new()
            .id_salt(height_id)
            .max_rect(ui.available_rect_before_wrap())
            .layout(*ui.layout()),
    );
    if progress < 1.0 {
        let mut clip = child.clip_rect();
        clip.max.y = clip.max.y.min(child.max_rect().top() + shown);
        child.set_clip_rect(clip);
    }
    let inner = add(&mut child);
    let mut rect = child.min_rect();
    ui.data_mut(|data| data.insert_temp(height_id, rect.height()));
    if progress < 1.0 {
        rect.max.y = rect.max.y.min(rect.top() + shown);
    }
    ui.advance_cursor_after_rect(rect);
    Some(inner)
}

/// How far content keyed by `key` has appeared: it starts over whenever the
/// key changes, as when another screen or tab is chosen.
pub(crate) fn appear_progress(
    ctx: &egui::Context,
    id: egui::Id,
    key: impl Hash,
    reduce_motion: bool,
) -> f32 {
    let key = {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    };
    let now = ctx.input(|input| input.time);
    let appearance = ctx.data_mut(|data| {
        let stored = data.get_temp::<Appearance>(id);
        let appearance = match stored {
            Some(stored) if stored.key == key => stored,
            // The first frame shows what was there already.
            None => Appearance {
                key,
                started: f64::NEG_INFINITY,
            },
            Some(_) => Appearance { key, started: now },
        };
        data.insert_temp(id, appearance);
        appearance
    });
    if reduce_motion {
        return 1.0;
    }
    let progress = motion::ease_out(((now - appearance.started) / f64::from(motion::FAST)) as f32);
    if progress < 1.0 {
        ctx.request_repaint();
    }
    progress
}

/// Fades content in and lifts it into place. Only the drawing moves, so
/// clicks, scrolling and focus work the same during the fade.
pub(crate) fn appear<R>(
    ui: &mut egui::Ui,
    progress: f32,
    add: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    let lift = TSTransform::from_translation(egui::vec2(0.0, APPEAR_RISE * (1.0 - progress)));
    ui.with_visual_transform(lift, |ui| {
        if progress < 1.0 {
            ui.multiply_opacity(progress);
        }
        add(ui)
    })
    .inner
}

/// Shows `modal` in the shared dialog frame, fading and growing it in as it
/// opens. It closes at once: the caller simply stops showing it.
pub(crate) fn show_modal<T>(
    ctx: &egui::Context,
    modal: egui::Modal,
    content: impl FnOnce(&mut egui::Ui) -> T,
) -> egui::ModalResponse<T> {
    let id = modal.area.layer().id.with("modal_shown");
    let frame = ctx.cumulative_frame_nr();
    let now = ctx.input(|input| input.time);
    let shown = ctx.data_mut(|data| {
        let shown = match data.get_temp::<ModalShown>(id) {
            Some(shown) if shown.frame + 1 >= frame => shown.started,
            _ => now,
        };
        data.insert_temp(
            id,
            ModalShown {
                frame,
                started: shown,
            },
        );
        shown
    });
    let progress = if motion::reduced() {
        1.0
    } else {
        motion::ease_out(((now - shown) / f64::from(motion::FAST)) as f32)
    };
    if progress < 1.0 {
        ctx.request_repaint();
    }
    modal
        .frame(egui::Frame::NONE)
        .backdrop_color(egui::Color32::from_black_alpha(
            (BACKDROP_ALPHA * progress).round() as u8,
        ))
        .show(ctx, |ui| {
            let layer = ui.layer_id();
            let start = ui.ctx().graphics(|graphics| {
                graphics
                    .get(layer)
                    .map_or(egui::layers::ShapeIdx(0), egui::layers::PaintList::next_idx)
            });
            let inner = ui.scope(|ui| {
                if progress < 1.0 {
                    ui.multiply_opacity(progress);
                }
                modal_frame().show(ui, content)
            });
            if progress < 1.0 {
                let center = inner.response.rect.center().to_vec2();
                let scale = MODAL_START_SCALE + (1.0 - MODAL_START_SCALE) * progress;
                let grow = TSTransform::from_translation(center)
                    * TSTransform::from_scaling(scale)
                    * TSTransform::from_translation(-center);
                ui.ctx().graphics_mut(|graphics| {
                    let list = graphics.entry(layer);
                    let end = list.next_idx();
                    list.transform_range(start, end, grow);
                });
            }
            inner.inner.inner
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs one frame at `time` seconds and returns what `read` saw.
    fn frame<T>(ctx: &egui::Context, time: f64, mut read: impl FnMut(&egui::Context) -> T) -> T {
        let mut value = None;
        let input = egui::RawInput {
            time: Some(time),
            ..Default::default()
        };
        let mut output = ctx.run_ui(input, |ui| value = Some(read(ui.ctx())));
        output.textures_delta.clear();
        value.expect("the frame ran")
    }

    #[test]
    fn new_content_fades_in_only_when_its_key_changes() {
        let ctx = egui::Context::default();
        let id = egui::Id::new("appear");
        assert_eq!(
            frame(&ctx, 0.0, |ctx| appear_progress(ctx, id, 1, false)),
            1.0
        );
        assert_eq!(
            frame(&ctx, 0.1, |ctx| appear_progress(ctx, id, 1, false)),
            1.0
        );
        assert_eq!(
            frame(&ctx, 0.2, |ctx| appear_progress(ctx, id, 2, false)),
            0.0
        );
        let halfway = frame(&ctx, 0.27, |ctx| appear_progress(ctx, id, 2, false));
        assert!(0.0 < halfway && halfway < 1.0, "{halfway}");
        assert_eq!(
            frame(&ctx, 0.4, |ctx| appear_progress(ctx, id, 2, false)),
            1.0
        );
    }

    #[test]
    fn reduced_motion_shows_new_content_and_sections_at_once() {
        let ctx = egui::Context::default();
        let id = egui::Id::new("instant");
        frame(&ctx, 0.0, |ctx| {
            appear_progress(ctx, id, 1, true);
            reveal_progress(ctx, id.with("open"), false, true)
        });
        let (shown, open) = frame(&ctx, 0.01, |ctx| {
            (
                appear_progress(ctx, id, 2, true),
                reveal_progress(ctx, id.with("open"), true, true),
            )
        });
        assert_eq!((shown, open), (1.0, 1.0));
    }

    #[test]
    fn a_section_opens_over_time_without_reduced_motion() {
        let ctx = egui::Context::default();
        let id = egui::Id::new("open");
        assert_eq!(
            frame(&ctx, 0.0, |ctx| reveal_progress(ctx, id, false, false)),
            0.0
        );
        let mut time = 0.0;
        let mut open = 0.0;
        while open < 1.0 && time < 1.0 {
            time += 1.0 / 60.0;
            open = frame(&ctx, time, |ctx| reveal_progress(ctx, id, true, false));
        }
        assert!(
            time > 0.15 && time < 0.3,
            "opened after {time} s instead of about {}",
            motion::NORMAL
        );
    }
}
