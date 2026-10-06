// Mirrors assets/icon/*.svg; change both together.
use eframe::egui::Color32;

use crate::theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoseIcon {
    /// 40 px and above: folds, centre disc and the full spiral.
    Large,
    /// 32 px and below: the same petals with a bolder, shorter spiral.
    // Used only by the test-only executable icon generator.
    #[allow(dead_code)]
    Small,
    /// The tray: petals in the state colour, no folds or disc, a light spiral.
    Tray(Color32),
}

type Pt = (f32, f32);

/// `M inner L side Q control tip L far Z`; the fold is the triangle inner, tip, far.
struct Petal {
    inner: Pt,
    side: Pt,
    control: Pt,
    tip: Pt,
    far: Pt,
}

const PETALS: [Petal; 5] = [
    Petal {
        inner: (21.75, 21.32),
        side: (16.73, 13.22),
        control: (17.82, 4.98),
        tip: (27.91, 1.84),
        far: (31.08, 14.94),
    },
    Petal {
        inner: (25.85, 21.03),
        side: (32.00, 13.76),
        control: (40.18, 12.24),
        tip: (46.28, 20.87),
        far: (34.81, 27.93),
    },
    Petal {
        inner: (27.40, 24.85),
        side: (36.22, 28.45),
        control: (40.18, 35.76),
        tip: (33.86, 44.22),
        far: (23.60, 35.49),
    },
    Petal {
        inner: (24.24, 27.49),
        side: (23.55, 36.99),
        control: (17.82, 43.02),
        tip: (7.81, 39.63),
        far: (12.95, 27.17),
    },
    Petal {
        inner: (20.75, 25.31),
        side: (11.50, 27.58),
        control: (4.00, 24.00),
        tip: (4.13, 13.44),
        far: (17.57, 14.47),
    },
];

const LARGE_SPIRAL: [Pt; 9] = [
    (24.0, 31.0),
    (18.0, 27.0),
    (18.0, 21.0),
    (24.0, 17.0),
    (30.0, 21.0),
    (30.0, 25.0),
    (26.0, 28.0),
    (22.0, 25.0),
    (23.0, 22.0),
];
const SMALL_SPIRAL: [Pt; 7] = [
    (24.0, 30.0),
    (18.5, 26.5),
    (18.5, 21.0),
    (24.0, 17.5),
    (29.5, 21.0),
    (29.5, 25.0),
    (25.0, 27.5),
];

fn face_points(petal: &Petal) -> [Pt; 19] {
    let mut points = [(0.0, 0.0); 19];
    points[0] = petal.inner;
    points[1] = petal.side;
    for step in 1..=16 {
        let t = step as f32 / 16.0;
        let u = 1.0 - t;
        points[step + 1] = (
            u * u * petal.side.0 + 2.0 * u * t * petal.control.0 + t * t * petal.tip.0,
            u * u * petal.side.1 + 2.0 * u * t * petal.control.1 + t * t * petal.tip.1,
        );
    }
    points[18] = petal.far;
    points
}

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

fn in_polygon(point: Pt, vertices: &[Pt]) -> bool {
    let mut inside = false;
    for index in 0..vertices.len() {
        let a = vertices[index];
        let b = vertices[(index + 1) % vertices.len()];
        if (a.1 > point.1) != (b.1 > point.1)
            && point.0 < a.0 + (point.1 - a.1) * (b.0 - a.0) / (b.1 - a.1)
        {
            inside = !inside;
        }
    }
    inside
}

fn in_path(point: Pt, vertices: &[Pt], half_stroke: f32) -> bool {
    in_polygon(point, vertices)
        || (0..vertices.len()).any(|index| {
            segment_distance_squared(
                point,
                vertices[index],
                vertices[(index + 1) % vertices.len()],
            ) <= half_stroke * half_stroke
        })
}

fn on_spiral(point: Pt, spiral: &[Pt], half_stroke: f32) -> bool {
    spiral.windows(2).any(|segment| {
        segment_distance_squared(point, segment[0], segment[1]) <= half_stroke * half_stroke
    })
}

fn sample(point: Pt, icon: RoseIcon, faces: &[[Pt; 19]; 5]) -> Option<Color32> {
    let (spiral, half_stroke, spiral_color): (&[Pt], _, _) = match icon {
        RoseIcon::Large => (&LARGE_SPIRAL, 0.9, theme::ROSE_LIGHT),
        RoseIcon::Small => (&SMALL_SPIRAL, 1.2, theme::ROSE_LIGHT),
        RoseIcon::Tray(_) => (&SMALL_SPIRAL, 1.3, theme::TEXT),
    };
    if on_spiral(point, spiral, half_stroke) {
        return Some(spiral_color);
    }
    let radius = match icon {
        RoseIcon::Large => Some(8.4),
        RoseIcon::Small => Some(8.0),
        RoseIcon::Tray(_) => None,
    };
    if radius.is_some_and(|radius| {
        let dx = point.0 - 24.0;
        let dy = point.1 - 24.0;
        dx * dx + dy * dy <= radius * radius
    }) {
        return Some(theme::ROSE);
    }
    for index in (0..PETALS.len()).rev() {
        let petal = &PETALS[index];
        if !matches!(icon, RoseIcon::Tray(_))
            && in_path(point, &[petal.inner, petal.tip, petal.far], 0.3)
        {
            return Some(theme::ROSE_DARK);
        }
        if in_path(point, &faces[index], 0.6) {
            return Some(match icon {
                RoseIcon::Tray(color) => color,
                _ => theme::ROSE,
            });
        }
    }
    None
}

/// Straight-alpha RGBA of the icon, `size`×`size`.
pub(crate) fn rose_icon_rgba(size: u32, icon: RoseIcon) -> Vec<u8> {
    let faces = PETALS.each_ref().map(face_points);
    let scale = 48.0 / size as f32;
    let mut rgba = Vec::with_capacity(size as usize * size as usize * 4);
    for y in 0..size {
        for x in 0..size {
            let mut covered = 0_u32;
            let (mut red, mut green, mut blue) = (0_u32, 0_u32, 0_u32);
            for j in 0..4 {
                for i in 0..4 {
                    let point = (
                        (x as f32 + (i as f32 + 0.5) / 4.0) * scale,
                        (y as f32 + (j as f32 + 0.5) / 4.0) * scale,
                    );
                    if let Some(color) = sample(point, icon, &faces) {
                        covered += 1;
                        red += u32::from(color.r());
                        green += u32::from(color.g());
                        blue += u32::from(color.b());
                    }
                }
            }
            let divisor = covered.max(1);
            rgba.extend_from_slice(&[
                (red / divisor) as u8,
                (green / divisor) as u8,
                (blue / divisor) as u8,
                (covered * 255 / 16) as u8,
            ]);
        }
    }
    rgba
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pixel(rgba: &[u8], size: usize, x: usize, y: usize) -> [u8; 4] {
        rgba[(y * size + x) * 4..(y * size + x + 1) * 4]
            .try_into()
            .unwrap()
    }

    #[test]
    fn large_has_petals_folds_disc_and_spiral() {
        let rgba = rose_icon_rgba(48, RoseIcon::Large);
        for (x, y) in [(0, 0), (47, 47)] {
            assert_eq!(pixel(&rgba, 48, x, y), [0; 4]);
        }
        for (x, y) in [(20, 12), (10, 20), (24, 24)] {
            assert_eq!(pixel(&rgba, 48, x, y), theme::ROSE.to_array(), "({x}, {y})");
        }
        for (x, y) in [(26, 12), (40, 22)] {
            assert_eq!(
                pixel(&rgba, 48, x, y),
                theme::ROSE_DARK.to_array(),
                "({x}, {y})"
            );
        }
    }

    #[test]
    fn small_has_bold_short_spiral() {
        let rgba = rose_icon_rgba(48, RoseIcon::Small);
        for (x, y) in [(18, 24), (24, 27)] {
            assert_eq!(
                pixel(&rgba, 48, x, y),
                theme::ROSE_LIGHT.to_array(),
                "({x}, {y})"
            );
        }
        assert_eq!(pixel(&rgba, 48, 23, 23), theme::ROSE.to_array());
        assert_eq!(pixel(&rgba, 48, 26, 12), theme::ROSE_DARK.to_array());
    }

    #[test]
    fn tray_recolors_petals_and_leaves_the_centre_open() {
        let color = Color32::from_rgb(40, 100, 160);
        let rgba = rose_icon_rgba(48, RoseIcon::Tray(color));
        for (x, y) in [(26, 12), (10, 20)] {
            assert_eq!(pixel(&rgba, 48, x, y), color.to_array(), "({x}, {y})");
        }
        assert_eq!(pixel(&rgba, 48, 18, 24), theme::TEXT.to_array());
        assert_eq!(pixel(&rgba, 48, 24, 24), [0; 4]);
    }

    #[test]
    fn rgba_has_the_requested_size() {
        assert_eq!(rose_icon_rgba(32, RoseIcon::Small).len(), 32 * 32 * 4);
    }
}
