//! Subscription links read from QR codes in an image file, on the clipboard or in a screen clip.
//!
//! A decoded link is a secret, as is the image holding it: nothing here logs, and errors carry
//! no text, path or detail of the image.

use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

use image::{GrayImage, ImageError, ImageReader, Limits};

/// Larger files are refused before they are read.
pub(crate) const MAX_FILE_BYTES: u64 = 20 * 1024 * 1024;
/// Either side; checked from the header, before decompression, against decompression bombs.
pub(crate) const MAX_SIDE: u32 = 8000;
/// Retries shrink an image until its longer side fits here, halving each time.
const RETRY_SIDES: [u32; 2] = [1600, 800];
const INVERTED_MAX_SIDE: u32 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QrError {
    Unreadable,
    NotImage,
    TooLarge,
    NotFound,
    NotSubscription,
    NoClipboardImage,
    Clipboard,
    ScreenClipUnavailable,
    ScreenClipTimedOut,
}

/// Distinct texts of the QR codes in `path` that `normalize` accepts as subscription links.
pub(crate) fn links_in_file(path: &Path) -> Result<Vec<String>, QrError> {
    let file = File::open(path).map_err(|_| QrError::Unreadable)?;
    let length = file.metadata().map_err(|_| QrError::Unreadable)?.len();
    if length > MAX_FILE_BYTES {
        return Err(QrError::TooLarge);
    }
    let mut bytes = Vec::new();
    // The file may grow between the length check and the read.
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| QrError::Unreadable)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(QrError::TooLarge);
    }
    links_in_bytes(&bytes)
}

/// As [`links_in_file`], for an encoded PNG, JPEG, BMP or WebP image.
pub(crate) fn links_in_bytes(bytes: &[u8]) -> Result<Vec<String>, QrError> {
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| QrError::NotImage)?;
    if reader.format().is_none() {
        return Err(QrError::NotImage);
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_SIDE);
    limits.max_image_height = Some(MAX_SIDE);
    reader.limits(limits);
    let image = reader.decode().map_err(|error| match error {
        ImageError::Limits(_) => QrError::TooLarge,
        _ => QrError::NotImage,
    })?;
    links_in_gray(&image.into_luma8())
}

/// As [`links_in_file`], for clipboard pixels: 8-bit RGBA rows, top to bottom.
pub(crate) fn links_in_rgba(
    width: usize,
    height: usize,
    rgba: &[u8],
) -> Result<Vec<String>, QrError> {
    if width == 0 || height == 0 {
        return Err(QrError::NotFound);
    }
    if width > MAX_SIDE as usize || height > MAX_SIDE as usize {
        return Err(QrError::TooLarge);
    }
    if rgba.len() != width * height * 4 {
        return Err(QrError::NotImage);
    }
    let luma = rgba
        .chunks_exact(4)
        .map(|pixel| {
            let [red, green, blue, alpha] = [pixel[0], pixel[1], pixel[2], pixel[3]].map(u32::from);
            let luma = (red * 299 + green * 587 + blue * 114) / 1000;
            // Over white, as the image looks on screen: a transparent background stays light.
            ((luma * alpha + 255 * (255 - alpha)) / 255) as u8
        })
        .collect();
    let image = GrayImage::from_raw(width as u32, height as u32, luma).ok_or(QrError::NotImage)?;
    links_in_gray(&image)
}

fn links_in_gray(image: &GrayImage) -> Result<Vec<String>, QrError> {
    let texts = decode(image);
    if texts.is_empty() {
        return Err(QrError::NotFound);
    }
    let mut links: Vec<String> = Vec::new();
    for text in texts {
        let text = text.trim();
        if rosetun_core::normalize_subscription_url(text).is_ok()
            && !links.iter().any(|link| link == text)
        {
            links.push(text.to_owned());
        }
    }
    if links.is_empty() {
        return Err(QrError::NotSubscription);
    }
    Ok(links)
}

/// Texts of every QR code found by the first attempt that yields any.
///
/// The image is tried as is first, so a small code on a 4K screenshot keeps its modules. Then,
/// for a large image, shrunk with a box filter: on a photo the code can fill the frame, rqrr's
/// geometry overflows on it (see [`decode_once`]), and averaging hides the sensor noise and JPEG
/// blocks the binarization trips over. Last, inverted, for a light code on a dark background;
/// not above [`INVERTED_MAX_SIDE`], where an inverted noisy photo turns into so many candidate
/// finder patterns that one attempt took 43 s in a release build.
fn decode(image: &GrayImage) -> Vec<String> {
    let mut shrunk: Vec<GrayImage> = Vec::new();
    for side in RETRY_SIDES {
        let current = shrunk.last().unwrap_or(image);
        if current.width().max(current.height()) <= side {
            continue;
        }
        let mut next = halve(current);
        while next.width().max(next.height()) > side {
            next = halve(&next);
        }
        shrunk.push(next);
    }
    for inverted in [false, true] {
        for scaled in std::iter::once(image).chain(&shrunk) {
            if inverted && scaled.width().max(scaled.height()) > INVERTED_MAX_SIDE {
                continue;
            }
            let texts = decode_once(scaled, inverted);
            if !texts.is_empty() {
                return texts;
            }
        }
    }
    Vec::new()
}

/// rqrr does its geometry in `i32` and overflows on a code a few thousand pixels wide: a panic
/// with overflow checks, a wrong point without. Either way that scale yields nothing, and the
/// smaller one gets its turn.
fn decode_once(image: &GrayImage, inverted: bool) -> Vec<String> {
    std::panic::catch_unwind(|| detect(image, inverted)).unwrap_or_default()
}

fn detect(image: &GrayImage, inverted: bool) -> Vec<String> {
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(
        image.width() as usize,
        image.height() as usize,
        |x, y| {
            let luma = image.get_pixel(x as u32, y as u32).0[0];
            if inverted { 255 - luma } else { luma }
        },
    );
    prepared
        .detect_grids()
        .into_iter()
        .filter_map(|grid| grid.decode().ok().map(|(_, text)| text))
        .collect()
}

fn halve(image: &GrayImage) -> GrayImage {
    let width = (image.width() / 2).max(1);
    let height = (image.height() / 2).max(1);
    GrayImage::from_fn(width, height, |x, y| {
        let mut sum = 0u32;
        for (dx, dy) in [(0, 0), (1, 0), (0, 1), (1, 1)] {
            let px = (x * 2 + dx).min(image.width() - 1);
            let py = (y * 2 + dy).min(image.height() - 1);
            sum += u32::from(image.get_pixel(px, py).0[0]);
        }
        image::Luma([(sum / 4) as u8])
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use image::{ImageFormat, Luma};

    const LINK: &str = "https://sub.example.com/private-token";
    const HAPP: &str = "happ://add/https://sub.example.com/happ-token";

    /// A QR code of `text`, `scale` pixels per module, with the standard four-module margin.
    pub(crate) fn code(text: &str, scale: u32) -> GrayImage {
        let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
        let modules = code.width() as u32;
        let colors = code.to_colors();
        let side = (modules + 8) * scale;
        GrayImage::from_fn(side, side, |x, y| {
            let (mx, my) = ((x / scale).wrapping_sub(4), (y / scale).wrapping_sub(4));
            let dark = mx < modules
                && my < modules
                && colors[(my * modules + mx) as usize] == qrcode::Color::Dark;
            Luma([if dark { 0 } else { 255 }])
        })
    }

    pub(crate) fn canvas(width: u32, height: u32, parts: &[(&GrayImage, u32, u32)]) -> GrayImage {
        let mut canvas = GrayImage::from_pixel(width, height, Luma([255]));
        for (part, left, top) in parts {
            image::imageops::replace(&mut canvas, *part, i64::from(*left), i64::from(*top));
        }
        canvas
    }

    pub(crate) fn png(image: &GrayImage) -> Vec<u8> {
        let mut bytes = Vec::new();
        image
            .write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .unwrap();
        bytes
    }

    fn rotated(image: &GrayImage, degrees: f32) -> GrayImage {
        let (sin, cos) = degrees.to_radians().sin_cos();
        let side = (image.width().max(image.height()) as f32 * 1.5) as u32;
        let center = side as f32 / 2.0;
        let (cx, cy) = (image.width() as f32 / 2.0, image.height() as f32 / 2.0);
        GrayImage::from_fn(side, side, |x, y| {
            let (dx, dy) = (x as f32 - center, y as f32 - center);
            let sx = cos * dx + sin * dy + cx;
            let sy = -sin * dx + cos * dy + cy;
            if sx >= 0.0 && sy >= 0.0 && (sx as u32) < image.width() && (sy as u32) < image.height()
            {
                *image.get_pixel(sx as u32, sy as u32)
            } else {
                Luma([255])
            }
        })
    }

    #[test]
    fn one_code_yields_its_link() {
        assert_eq!(
            links_in_bytes(&png(&code(LINK, 4))),
            Ok(vec![LINK.to_owned()])
        );
        assert_eq!(
            links_in_bytes(&png(&code(HAPP, 4))),
            Ok(vec![HAPP.to_owned()])
        );
    }

    #[test]
    fn a_link_without_a_scheme_is_kept_as_written() {
        let text = "sub.example.com/private-token";
        assert_eq!(
            links_in_bytes(&png(&code(text, 4))),
            Ok(vec![text.to_owned()])
        );
    }

    #[test]
    fn two_codes_yield_both_links_once_each() {
        let first = code(LINK, 4);
        let second = code(HAPP, 4);
        let image = canvas(
            first.width() * 3,
            first.height() * 2,
            &[
                (&first, 0, 0),
                (&second, first.width() * 2, 0),
                (&first, first.width(), first.height()),
            ],
        );
        let mut links = links_in_bytes(&png(&image)).unwrap();
        links.sort();
        assert_eq!(links, vec![HAPP.to_owned(), LINK.to_owned()]);
    }

    #[test]
    fn a_code_without_a_link_is_not_a_subscription() {
        assert_eq!(
            links_in_bytes(&png(&code("Meeting at noon", 4))),
            Err(QrError::NotSubscription)
        );
        let link = code(LINK, 4);
        let text = code("Meeting at noon", 4);
        let both = canvas(
            link.width() * 2,
            link.height(),
            &[(&link, 0, 0), (&text, link.width(), 0)],
        );
        assert_eq!(links_in_bytes(&png(&both)), Ok(vec![LINK.to_owned()]));
    }

    #[test]
    fn a_small_code_on_a_large_screenshot_is_found() {
        let small = code(LINK, 3);
        let image = canvas(3840, 2160, &[(&small, 3200, 1700)]);
        assert_eq!(links_in_bytes(&png(&image)), Ok(vec![LINK.to_owned()]));
    }

    #[test]
    fn a_code_filling_a_large_noisy_photo_is_found() {
        let big = code(LINK, 120);
        let mut seed = 0x2545_f491_u32;
        let noisy = GrayImage::from_fn(big.width(), big.height(), |x, y| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            let base = i32::from(big.get_pixel(x, y).0[0]).clamp(40, 215);
            Luma([(base + (seed % 161) as i32 - 80).clamp(0, 255) as u8])
        });
        assert_eq!(links_in_gray(&noisy), Ok(vec![LINK.to_owned()]));
    }

    #[test]
    fn a_rotated_code_is_found() {
        let image = rotated(&code(LINK, 6), 30.0);
        assert_eq!(links_in_gray(&image), Ok(vec![LINK.to_owned()]));
    }

    #[test]
    fn a_light_code_on_a_dark_background_is_found() {
        let mut image = code(LINK, 4);
        image::imageops::invert(&mut image);
        assert_eq!(links_in_gray(&image), Ok(vec![LINK.to_owned()]));
    }

    #[test]
    fn an_empty_image_has_no_code() {
        assert_eq!(
            links_in_bytes(&png(&canvas(64, 64, &[]))),
            Err(QrError::NotFound)
        );
        assert_eq!(links_in_rgba(0, 0, &[]), Err(QrError::NotFound));
    }

    #[test]
    fn a_broken_file_is_not_an_image() {
        assert_eq!(
            links_in_bytes(b"not an image at all"),
            Err(QrError::NotImage)
        );
        let mut truncated = png(&code(LINK, 4));
        truncated.truncate(truncated.len() / 2);
        assert_eq!(links_in_bytes(&truncated), Err(QrError::NotImage));
    }

    #[test]
    fn limits_refuse_large_images_and_files() {
        let wide = GrayImage::from_pixel(MAX_SIDE + 1, 1, Luma([255]));
        assert_eq!(links_in_bytes(&png(&wide)), Err(QrError::TooLarge));
        assert_eq!(
            links_in_rgba(
                MAX_SIDE as usize + 1,
                1,
                &vec![255; (MAX_SIDE as usize + 1) * 4]
            ),
            Err(QrError::TooLarge)
        );

        let path =
            std::env::temp_dir().join(format!("rosetun-qr-large-{}.png", std::process::id()));
        File::create(&path)
            .unwrap()
            .set_len(MAX_FILE_BYTES + 1)
            .unwrap();
        let result = links_in_file(&path);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(result, Err(QrError::TooLarge));
        assert_eq!(links_in_file(&path), Err(QrError::Unreadable));
    }

    #[test]
    fn clipboard_pixels_are_read_over_white() {
        let image = code(LINK, 4);
        let rgba: Vec<u8> = image
            .pixels()
            .flat_map(|pixel| {
                // Light modules transparent, as a copied PNG often has them.
                if pixel.0[0] == 0 {
                    [0, 0, 0, 255]
                } else {
                    [0, 0, 0, 0]
                }
            })
            .collect();
        assert_eq!(
            links_in_rgba(image.width() as usize, image.height() as usize, &rgba),
            Ok(vec![LINK.to_owned()])
        );
    }
}
