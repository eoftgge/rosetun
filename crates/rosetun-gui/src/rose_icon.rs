// Mirrors assets/icon/rosetun.svg through rose_shape.rs; change both together.
use eframe::egui::Color32;

use crate::{rose_shape::PETALS, theme};

const SAMPLES_PER_AXIS: usize = 4;
const DISTANCE_INFINITY: u32 = u32::MAX / 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoseIcon {
    /// Inside the window, on the app's own background.
    Emblem,
    /// Outside the window (taskbar, Explorer, installer), on a dark plate.
    App,
    /// The tray: a rose with a state-specific corner badge.
    // The tray exists only on Windows.
    #[cfg_attr(not(any(test, windows)), allow(dead_code))]
    Tray(TrayState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(not(any(test, windows)), allow(dead_code))]
pub(crate) enum TrayState {
    Connected,
    Disconnected,
    Connecting,
    Blocked,
    Failed,
    ServiceUnavailable,
}

type Pt = (f32, f32);

fn segment_distance_squared(point: Pt, a: Pt, b: Pt) -> f32 {
    let dx = b.0 - a.0;
    let dy = b.1 - a.1;
    let length_squared = dx * dx + dy * dy;
    let t = if length_squared > 0.0 {
        ((point.0 - a.0) * dx + (point.1 - a.1) * dy) / length_squared
    } else {
        0.0
    }
    .clamp(0.0, 1.0);
    let x = point.0 - a.0 - t * dx;
    let y = point.1 - a.1 - t * dy;
    x * x + y * y
}

fn badge_color(state: TrayState) -> Option<Color32> {
    match state {
        TrayState::Connected | TrayState::Disconnected => None,
        TrayState::Connecting => Some(theme::ROSE_BRIGHT),
        TrayState::Blocked | TrayState::Failed => Some(theme::ERROR),
        TrayState::ServiceUnavailable => Some(theme::DISABLED),
    }
}

/// The badge's place in a raster of one size, in design units.
#[derive(Debug, Clone, Copy)]
struct BadgeGrid {
    /// How far the badge moves from the 48 px design so that the edge of its
    /// disc lies on a pixel boundary; a disc between pixels blurs on all sides.
    shift: f32,
    /// One pixel.
    pixel: f32,
}

impl BadgeGrid {
    fn new(size: u32) -> Self {
        let pixel = 48.0 / size as f32;
        // The disc (x 23..47) is half the icon wide; keep it inside the icon.
        let left = (23.0 / pixel).round().min(size as f32 / 2.0);
        Self {
            shift: left * pixel - 23.0,
            pixel,
        }
    }
}

fn badge_mark(point: Pt, state: TrayState, pixel: f32) -> bool {
    let (x, y) = point;
    // Below about a pixel a stroke turns into a grey smear on the disc.
    let half = |width: f32| width.max(pixel);
    match state {
        TrayState::Connecting => {
            let dx = x - 35.0;
            let dy = y - 35.0;
            let angle =
                (dy.atan2(dx) + std::f32::consts::FRAC_PI_2).rem_euclid(std::f32::consts::TAU);
            ((dx * dx + dy * dy).sqrt() - 7.5).abs() <= half(1.7)
                && angle <= 3.0 * std::f32::consts::FRAC_PI_2
        }
        TrayState::Blocked => {
            (29.5..=40.5).contains(&x) && (34.0..=42.5).contains(&y)
                || segment_distance_squared(point, (31.8, 34.0), (31.8, 31.6)) <= half(1.3).powi(2)
                || segment_distance_squared(point, (38.2, 31.6), (38.2, 34.0)) <= half(1.3).powi(2)
                || (y <= 31.6 && ((x - 35.0).hypot(y - 31.6) - 3.2).abs() <= half(1.3))
        }
        TrayState::Failed => {
            let dot = 2.1_f32.max(pixel);
            // Thicker strokes would close the gap between the bar and the dot.
            let bottom = (41.0 - dot - pixel - half(1.9)).min(36.2);
            segment_distance_squared(point, (35.0, 28.5), (35.0, bottom)) <= half(1.9).powi(2)
                || (x - 35.0).hypot(y - 41.0) <= dot
        }
        TrayState::ServiceUnavailable => {
            segment_distance_squared(point, (30.8, 30.8), (39.2, 39.2)) <= half(1.8).powi(2)
                || segment_distance_squared(point, (39.2, 30.8), (30.8, 39.2)) <= half(1.8).powi(2)
        }
        TrayState::Connected | TrayState::Disconnected => false,
    }
}

fn sample_badge(point: Pt, state: TrayState, grid: BadgeGrid) -> Option<Option<Color32>> {
    let color = badge_color(state)?;
    let point = (point.0 - grid.shift, point.1 - grid.shift);
    let distance = (point.0 - 35.0).hypot(point.1 - 35.0);
    // The cutout must stay at least a pixel wide, or the badge merges with the petals.
    if distance > 12.0 + grid.pixel.max(2.5) {
        return None;
    }
    if distance > 12.0 {
        return Some(None);
    }
    Some(Some(if badge_mark(point, state, grid.pixel) {
        Color32::WHITE
    } else {
        color
    }))
}

fn sample(point: Pt, icon: RoseIcon, inside: bool, grid: BadgeGrid) -> Option<(Color32, u8)> {
    if let RoseIcon::Tray(state) = icon
        && let Some(badge) = sample_badge(point, state, grid)
    {
        return badge.map(|color| (color, 255));
    }
    let color = match icon {
        RoseIcon::Emblem | RoseIcon::App | RoseIcon::Tray(TrayState::Connected) => theme::ROSE,
        RoseIcon::Tray(_) => theme::DISCONNECTED,
    };
    let opacity = if matches!(icon, RoseIcon::Tray(TrayState::ServiceUnavailable)) {
        140
    } else {
        255
    };
    inside.then_some((color, opacity))
}

fn scanline(y: f32, intersections: &mut Vec<f32>) {
    intersections.clear();
    for vertices in PETALS {
        for index in 0..vertices.len() {
            let a = vertices[index];
            let b = vertices[(index + 1) % vertices.len()];
            // A half-open edge counts shared vertices once and skips horizontal edges.
            if (a.1 > y) != (b.1 > y) {
                intersections.push(a.0 + (y - a.1) * (b.0 - a.0) / (b.1 - a.1));
            }
        }
    }
    intersections.sort_unstable_by(f32::total_cmp);
}

/// Straight-alpha RGBA of the icon, `size`×`size`.
pub(crate) fn rose_icon_rgba(size: u32, icon: RoseIcon) -> Vec<u8> {
    let plate = (icon != RoseIcon::Emblem).then(|| back(size, icon));
    rasterize(size, icon, plate.as_deref())
}

/// Design-unit coordinate of sample `sub` inside pixel `pixel`.
fn sample_coordinate(pixel: usize, sub: usize, scale: f32) -> f32 {
    (pixel as f32 + (sub as f32 + 0.5) / SAMPLES_PER_AXIS as f32) * scale
}

/// Which samples the icon draws, petals and the tray badge alike, at the
/// positions `rasterize` uses.
fn drawn_mask(size: u32, icon: RoseIcon) -> Vec<bool> {
    let scale = 48.0 / size as f32;
    let side = size as usize * SAMPLES_PER_AXIS;
    let grid = BadgeGrid::new(size);
    let mut mask = vec![false; side * side];
    let mut intersections = Vec::new();
    for y in 0..side {
        let sample_y = sample_coordinate(y / SAMPLES_PER_AXIS, y % SAMPLES_PER_AXIS, scale);
        scanline(sample_y, &mut intersections);
        let mut crossing = 0;
        for x in 0..side {
            let sample_x = sample_coordinate(x / SAMPLES_PER_AXIS, x % SAMPLES_PER_AXIS, scale);
            while crossing < intersections.len() && intersections[crossing] <= sample_x {
                crossing += 1;
            }
            let drawn = sample((sample_x, sample_y), icon, crossing % 2 == 1, grid);
            mask[y * side + x] = drawn.is_some();
        }
    }
    mask
}

/// Squared Euclidean distance to the nearest `true` cell.
fn distance_transform(seeds: &[bool], side: usize) -> Vec<u32> {
    let mut rows = vec![DISTANCE_INFINITY; seeds.len()];
    let mut distances = vec![DISTANCE_INFINITY; seeds.len()];
    let mut input = vec![DISTANCE_INFINITY; side];
    let mut output = vec![DISTANCE_INFINITY; side];
    let mut sites = vec![0; side];
    let mut boundaries = vec![0.0; side + 1];
    let mut transform_line = |input: &[u32], output: &mut [u32]| {
        let mut count = 0;
        for q in 0..side {
            if input[q] == DISTANCE_INFINITY {
                continue;
            }
            if count == 0 {
                sites[0] = q;
                boundaries[0] = f64::NEG_INFINITY;
                boundaries[1] = f64::INFINITY;
                count = 1;
                continue;
            }
            let mut k = count - 1;
            let intersection = |q: usize, p: usize| {
                ((f64::from(input[q]) + (q * q) as f64) - (f64::from(input[p]) + (p * p) as f64))
                    / (2 * (q - p)) as f64
            };
            let mut boundary = intersection(q, sites[k]);
            while k > 0 && boundary <= boundaries[k] {
                k -= 1;
                boundary = intersection(q, sites[k]);
            }
            count = k + 1;
            sites[count] = q;
            boundaries[count] = boundary;
            boundaries[count + 1] = f64::INFINITY;
            count += 1;
        }
        if count == 0 {
            output.fill(DISTANCE_INFINITY);
            return;
        }
        let mut k = 0;
        for (q, distance) in output.iter_mut().enumerate() {
            while k + 1 < count && boundaries[k + 1] < q as f64 {
                k += 1;
            }
            let offset = q.abs_diff(sites[k]) as u32;
            *distance = input[sites[k]] + offset * offset;
        }
    };
    for (row, output_row) in seeds.chunks_exact(side).zip(rows.chunks_exact_mut(side)) {
        for (value, seed) in input.iter_mut().zip(row) {
            *value = if *seed { 0 } else { DISTANCE_INFINITY };
        }
        transform_line(&input, output_row);
    }
    for x in 0..side {
        for y in 0..side {
            input[y] = rows[y * side + x];
        }
        transform_line(&input, &mut output);
        for (y, distance) in output.iter().enumerate() {
            distances[y * side + x] = *distance;
        }
    }
    distances
}

/// Rose petals vanish on a background of a similar colour (a red Windows
/// accent on the taskbar), so every icon shown outside the window sits on a
/// dark plate: the silhouette of everything drawn (the tray badge too) with
/// the gaps between petals filled, plus a rim.
/// The gaps are channels open to the outside; a closing (grow, flood the
/// outside, grow it back) tells them from the outside itself.
fn back(size: u32, icon: RoseIcon) -> Vec<bool> {
    let sample_side = size as usize * SAMPLES_PER_AXIS;
    let radius = (size as usize / 16).max(1) * SAMPLES_PER_AXIS;
    let rim = (size as usize / 32).max(1) * SAMPLES_PER_AXIS;
    // A margin beyond the edges ensures the flood can reach every exterior cell.
    let pad = radius + rim + 1;
    let side = sample_side + 2 * pad;
    let mut solid = vec![false; side * side];
    let drawn = drawn_mask(size, icon);
    for (y, row) in drawn.chunks_exact(sample_side).enumerate() {
        let start = (y + pad) * side + pad;
        solid[start..start + sample_side].copy_from_slice(row);
    }

    let radius_squared = (radius * radius) as u32;
    let rim_squared = (rim * rim) as u32;
    let grown: Vec<bool> = distance_transform(&solid, side)
        .into_iter()
        .map(|distance| distance <= radius_squared)
        .collect();
    let mut outside = vec![false; side * side];
    let mut queue = vec![0];
    outside[0] = true;
    while let Some(index) = queue.pop() {
        let (x, y) = (index % side, index / side);
        for neighbor in [
            x.checked_sub(1).map(|_| index - 1),
            (x + 1 < side).then_some(index + 1),
            y.checked_sub(1).map(|_| index - side),
            (y + 1 < side).then_some(index + side),
        ]
        .into_iter()
        .flatten()
        {
            if !grown[neighbor] && !outside[neighbor] {
                outside[neighbor] = true;
                queue.push(neighbor);
            }
        }
    }
    let silhouette: Vec<bool> = distance_transform(&outside, side)
        .into_iter()
        .map(|distance| distance > radius_squared)
        .collect();
    let plate = distance_transform(&silhouette, side);
    let mut cropped = Vec::with_capacity(sample_side * sample_side);
    for row in plate.chunks_exact(side).skip(pad).take(sample_side) {
        cropped.extend(
            row[pad..pad + sample_side]
                .iter()
                .map(|distance| *distance <= rim_squared),
        );
    }
    cropped
}

fn rasterize(size: u32, icon: RoseIcon, plate: Option<&[bool]>) -> Vec<u8> {
    let scale = 48.0 / size as f32;
    let sample_side = size as usize * SAMPLES_PER_AXIS;
    let grid = BadgeGrid::new(size);
    let mut rgba = Vec::with_capacity(size as usize * size as usize * 4);
    let mut row = vec![[0_u32; 4]; size as usize];
    let mut intersections = Vec::new();
    for y in 0..size {
        row.fill([0; 4]);
        for j in 0..SAMPLES_PER_AXIS {
            let sample_y = sample_coordinate(y as usize, j, scale);
            scanline(sample_y, &mut intersections);
            let mut crossing = 0;
            for (x, pixel) in row.iter_mut().enumerate() {
                for i in 0..SAMPLES_PER_AXIS {
                    let sample_x = sample_coordinate(x, i, scale);
                    while crossing < intersections.len() && intersections[crossing] <= sample_x {
                        crossing += 1;
                    }
                    let foreground = sample((sample_x, sample_y), icon, crossing % 2 == 1, grid);
                    let backed = plate.is_some_and(|plate| {
                        plate[(y as usize * SAMPLES_PER_AXIS + j) * sample_side
                            + x * SAMPLES_PER_AXIS
                            + i]
                    });
                    if backed {
                        let background = theme::BG;
                        let opacity = foreground.map_or(0, |(_, opacity)| u32::from(opacity));
                        let color = foreground.map_or(background, |(color, _)| color);
                        for (total, (foreground, background)) in pixel[..3].iter_mut().zip(
                            [color.r(), color.g(), color.b()].into_iter().zip([
                                background.r(),
                                background.g(),
                                background.b(),
                            ]),
                        ) {
                            *total += u32::from(foreground) * opacity
                                + u32::from(background) * (255 - opacity);
                        }
                        pixel[3] += 255;
                    } else if let Some((color, opacity)) = foreground {
                        let opacity = u32::from(opacity);
                        pixel[0] += u32::from(color.r()) * opacity;
                        pixel[1] += u32::from(color.g()) * opacity;
                        pixel[2] += u32::from(color.b()) * opacity;
                        pixel[3] += opacity;
                    }
                }
            }
        }
        for &[red, green, blue, alpha] in &row {
            let divisor = alpha.max(1);
            rgba.extend_from_slice(&[
                (red / divisor) as u8,
                (green / divisor) as u8,
                (blue / divisor) as u8,
                (alpha / (SAMPLES_PER_AXIS * SAMPLES_PER_AXIS) as u32) as u8,
            ]);
        }
    }
    rgba
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRAY_STATES: [TrayState; 6] = [
        TrayState::Connected,
        TrayState::Disconnected,
        TrayState::Connecting,
        TrayState::Blocked,
        TrayState::Failed,
        TrayState::ServiceUnavailable,
    ];

    fn pixel(rgba: &[u8], size: usize, x: usize, y: usize) -> [u8; 4] {
        rgba[(y * size + x) * 4..(y * size + x + 1) * 4]
            .try_into()
            .unwrap()
    }

    #[test]
    fn emblem_has_solid_petals_and_transparent_gaps() {
        let rgba = rose_icon_rgba(48, RoseIcon::Emblem);
        // At y = 12.5, PETALS span x = 13.114..22.407, then 28.764..30.592.
        assert_eq!(pixel(&rgba, 48, 18, 12), theme::ROSE.to_array());
        for (x, y) in [(25, 12), (0, 0), (47, 47)] {
            assert_eq!(pixel(&rgba, 48, x, y), [0; 4], "({x}, {y})");
        }
        let filled = rgba.chunks_exact(4).filter(|pixel| pixel[3] != 0).count();
        let coverage = filled as f32 / (48 * 48) as f32;
        assert!((0.45..=0.75).contains(&coverage), "{coverage}");
        assert_eq!(rgba, rasterize(48, RoseIcon::Emblem, None), "no plate");
    }

    #[test]
    fn distance_transform_uses_squared_euclidean_distance() {
        let mut seeds = vec![false; 16];
        seeds[0] = true;
        assert_eq!(
            distance_transform(&seeds, 4),
            vec![0, 1, 4, 9, 1, 2, 5, 10, 4, 5, 8, 13, 9, 10, 13, 18]
        );
    }

    #[test]
    fn window_icon_rasterizes_within_two_seconds() {
        // `main` draws the window icon at 128 px on every start; the larger
        // sizes go only into the committed `.ico`, drawn ahead of time.
        let start = std::time::Instant::now();
        let rgba = rose_icon_rgba(128, RoseIcon::App);
        let elapsed = start.elapsed();
        assert_eq!(rgba.len(), 128 * 128 * 4);
        eprintln!("128 px rose rasterization: {elapsed:?}");
        assert!(elapsed < std::time::Duration::from_secs(2), "{elapsed:?}");
    }

    #[test]
    fn outside_icons_sit_on_an_antialiased_plate_that_fills_the_gaps() {
        let icons = TRAY_STATES.map(RoseIcon::Tray);
        for icon in icons.into_iter().chain([RoseIcon::App]) {
            for size in [16, 24, 32, 48, 256] {
                let plain = rasterize(size, icon, None);
                let backed = rose_icon_rgba(size, icon);
                for (before, after) in plain.chunks_exact(4).zip(backed.chunks_exact(4)) {
                    assert!(after[3] >= before[3], "{icon:?} {size} px");
                    if before[3] == 255 {
                        assert_eq!(before, after, "{icon:?} {size} px: plate over the rose");
                    } else if before != after {
                        assert!(after[3] > before[3], "{icon:?} {size} px");
                    }
                }
                let size = size as usize;
                assert_eq!(
                    pixel(&backed, size, 0, 0),
                    [0; 4],
                    "{icon:?} {size} px corner"
                );
            }
            let plain = rasterize(32, icon, None);
            let backed = rose_icon_rgba(32, icon);
            assert_eq!(
                pixel(&plain, 32, 14, 4),
                [0; 4],
                "{icon:?} gap before plate"
            );
            assert_eq!(
                pixel(&backed, 32, 14, 4),
                theme::BG.to_array(),
                "{icon:?} closed gap"
            );
        }
        let rgba = rose_icon_rgba(256, RoseIcon::App);
        assert!(rgba.chunks_exact(4).any(|pixel| {
            pixel[..3] == theme::BG.to_array()[..3] && (1..255).contains(&pixel[3])
        }));
    }

    #[test]
    fn tray_states_have_distinct_shapes_and_expected_petal_colors() {
        let states = TRAY_STATES;
        for size in [16, 32, 48] {
            let images = states.map(|state| rose_icon_rgba(size, RoseIcon::Tray(state)));
            assert_eq!(
                images
                    .iter()
                    .collect::<std::collections::HashSet<_>>()
                    .len(),
                6,
                "{size} px"
            );
        }
        let images = states.map(|state| rose_icon_rgba(48, RoseIcon::Tray(state)));
        for (state, rgba) in states.into_iter().zip(&images) {
            let petal = pixel(rgba, 48, 18, 12);
            assert_eq!(
                petal,
                match state {
                    TrayState::Connected => theme::ROSE.to_array(),
                    TrayState::ServiceUnavailable => [
                        ((u32::from(theme::DISCONNECTED.r()) * 140
                            + u32::from(theme::BG.r()) * 115)
                            / 255) as u8,
                        ((u32::from(theme::DISCONNECTED.g()) * 140
                            + u32::from(theme::BG.g()) * 115)
                            / 255) as u8,
                        ((u32::from(theme::DISCONNECTED.b()) * 140
                            + u32::from(theme::BG.b()) * 115)
                            / 255) as u8,
                        255,
                    ],
                    _ => theme::DISCONNECTED.to_array(),
                },
                "{state:?} petal"
            );
            if state != TrayState::Connected {
                assert!(
                    !rgba
                        .chunks_exact(4)
                        .any(|pixel| pixel == theme::ROSE.to_array())
                );
                assert!(
                    !rgba
                        .chunks_exact(4)
                        .any(|pixel| pixel == theme::ROSE_DARK.to_array())
                );
            }
        }
    }

    #[test]
    fn tray_badges_have_coloured_discs_white_marks_and_cutouts_on_the_plate() {
        for (state, color, mark) in [
            (TrayState::Connecting, theme::ROSE_BRIGHT, (35, 27)),
            (TrayState::Blocked, theme::ERROR, (35, 38)),
            (TrayState::Failed, theme::ERROR, (35, 32)),
            (TrayState::ServiceUnavailable, theme::DISABLED, (35, 35)),
        ] {
            let rgba = rose_icon_rgba(48, RoseIcon::Tray(state));
            assert_eq!(pixel(&rgba, 48, 35, 45), color.to_array(), "{state:?} disc");
            assert_eq!(
                pixel(&rgba, 48, mark.0, mark.1),
                Color32::WHITE.to_array(),
                "{state:?} mark"
            );
            assert_eq!(
                pixel(&rgba, 48, 34, 21),
                theme::BG.to_array(),
                "{state:?} cutout"
            );
        }
    }

    #[test]
    fn tray_badge_discs_lie_entirely_on_the_plate() {
        for size in [16, 20, 24, 32, 48] {
            let scale = 48.0 / size as f32;
            let side = size as usize * SAMPLES_PER_AXIS;
            let grid = BadgeGrid::new(size);
            for state in TRAY_STATES {
                let plate = back(size, RoseIcon::Tray(state));
                for (index, &backed) in plate.iter().enumerate() {
                    let (x, y) = (index % side, index / side);
                    let point = (
                        sample_coordinate(x / SAMPLES_PER_AXIS, x % SAMPLES_PER_AXIS, scale),
                        sample_coordinate(y / SAMPLES_PER_AXIS, y % SAMPLES_PER_AXIS, scale),
                    );
                    let on_disc = matches!(sample_badge(point, state, grid), Some(Some(_)));
                    assert!(backed || !on_disc, "{state:?} {size} px: {point:?}");
                }
            }
        }
    }

    #[test]
    fn tray_icons_at_taskbar_sizes_keep_the_badge_mark_and_the_outline() {
        for size in [16, 20, 24] {
            for state in TRAY_STATES {
                let rgba = rose_icon_rgba(size, RoseIcon::Tray(state));
                assert_eq!(
                    rgba.len(),
                    (size * size * 4) as usize,
                    "{state:?} {size} px"
                );
                let count = |wanted: &dyn Fn(&[u8]) -> bool| {
                    rgba.chunks_exact(4).filter(|pixel| wanted(pixel)).count()
                };
                assert!(
                    count(&|pixel| pixel == theme::BG.to_array()) >= 4,
                    "{state:?} {size} px outline"
                );
                let Some(color) = badge_color(state) else {
                    continue;
                };
                assert!(
                    count(&|pixel| pixel == color.to_array()) >= 8,
                    "{state:?} {size} px disc"
                );
                assert!(
                    count(&|pixel| pixel[3] == 255 && pixel[..3].iter().all(|&c| c >= 230)) >= 3,
                    "{state:?} {size} px mark"
                );
            }
        }
    }

    #[test]
    fn badge_disc_edge_lies_on_the_pixel_grid() {
        for size in 16..=64 {
            let grid = BadgeGrid::new(size);
            let left = (23.0 + grid.shift) / grid.pixel;
            assert!((left - left.round()).abs() < 1e-3, "{size} px: {left}");
            assert!(left + size as f32 / 2.0 <= size as f32 + 1e-3, "{size} px");
        }
        assert_eq!(BadgeGrid::new(48).shift, 0.0);
        // At 20 px the disc covers columns 10..20: column 9 has no disc colour.
        let rgba = rose_icon_rgba(20, RoseIcon::Tray(TrayState::Failed));
        assert_eq!(pixel(&rgba, 20, 15, 10)[..3], theme::ERROR.to_array()[..3]);
        assert_ne!(pixel(&rgba, 20, 9, 15), theme::ERROR.to_array());
        assert_eq!(pixel(&rgba, 20, 10, 15), theme::ERROR.to_array());
    }

    #[test]
    fn rgba_has_the_requested_size() {
        assert_eq!(rose_icon_rgba(32, RoseIcon::Emblem).len(), 32 * 32 * 4);
    }
}
