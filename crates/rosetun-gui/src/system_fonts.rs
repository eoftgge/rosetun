//! Fallback fonts from the system for scripts that Manrope and egui's fonts lack: names of
//! servers, subscriptions and lists in Chinese, Japanese, Korean, Thai, Indic scripts,
//! Arabic or Hebrew.
//!
//! Nothing is read at start. egui asks [`SystemFonts`] the first time a character has no
//! glyph in any configured font of a family, and appends the font found then to that family,
//! after Manrope and egui's fonts, so the look of Latin, Cyrillic and egui's symbols stays.
//! System font files are mapped into memory, not copied, and their paths are not logged.

use std::collections::HashMap;
#[cfg(not(windows))]
use std::collections::HashSet;
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use eframe::egui::{FallbackRequest, FontData, FontInsert, FontProvider};
use eframe::epaint::text::Blob;
use skrifa::MetadataProvider as _;

/// The largest font file read; the largest known one, Microsoft JhengHei, is about 21 MB.
const MAX_FONT_BYTES: u64 = 64 * 1024 * 1024;

const KANA: Script = Script {
    ranges: &[0x3040..=0x30FF, 0x31F0..=0x31FF, 0xFF65..=0xFF9F],
    windows: &[YU_GOTHIC_UI, MEIRYO_UI, YAHEI_UI],
    fontconfig_lang: Some("ja"),
};
const HANGUL: Script = Script {
    ranges: &[
        0x1100..=0x11FF,
        0x3130..=0x318F,
        0xA960..=0xA97F,
        0xAC00..=0xD7FF,
        0xFFA0..=0xFFDC,
    ],
    windows: &[MALGUN_GOTHIC],
    fontconfig_lang: Some("ko"),
};
/// Han ideographs with the CJK punctuation and full-width forms around them. One character is
/// shared by Chinese, Japanese and Korean fonts, so the order decides its shape: Simplified
/// Chinese first, as most names in Han alone are Chinese.
const HAN: Script = Script {
    ranges: &[
        0x2E80..=0x2FDF,
        0x3000..=0x303F,
        0x3190..=0x319F,
        0x31C0..=0x31EF,
        0x3200..=0x33FF,
        0x3400..=0x4DBF,
        0x4E00..=0x9FFF,
        0xF900..=0xFAFF,
        0xFE30..=0xFE4F,
        0xFF00..=0xFFEF,
        0x20000..=0x3FFFF,
    ],
    windows: &[
        YAHEI_UI,
        JHENGHEI_UI,
        YU_GOTHIC_UI,
        MEIRYO_UI,
        MALGUN_GOTHIC,
    ],
    fontconfig_lang: Some("zh-cn"),
};
/// Thai, Lao, Khmer and the other scripts of Leelawadee UI.
const SOUTHEAST_ASIAN: Script = Script {
    ranges: &[0x0E00..=0x0EFF, 0x1780..=0x17FF, 0x1980..=0x1AAF],
    windows: &[Face::new("LeelawUI.ttf", 0), Face::new("tahoma.ttf", 0)],
    fontconfig_lang: None,
};
/// Devanagari through Sinhala, all in Nirmala UI: a collection since Windows 11, a single file
/// on Windows 10.
const INDIC: Script = Script {
    ranges: &[0x0900..=0x0DFF, 0xA8E0..=0xA8FF],
    windows: &[Face::new("Nirmala.ttc", 0), Face::new("Nirmala.ttf", 0)],
    fontconfig_lang: None,
};
const SCRIPTS: [Script; 5] = [KANA, HANGUL, HAN, SOUTHEAST_ASIAN, INDIC];
/// Tried for every character after its script's fonts: Segoe UI has Arabic, Hebrew, Greek,
/// Armenian and Georgian, the others symbols, Ethiopic and Myanmar.
#[cfg_attr(
    not(any(windows, test)),
    expect(
        dead_code,
        reason = "the fonts folder is searched on Windows and in tests"
    )
)]
const GENERAL: &[Face] = &[
    Face::new("segoeui.ttf", 0),
    Face::new("seguisym.ttf", 0),
    Face::new("ebrima.ttf", 0),
    Face::new("mmrtext.ttf", 0),
];

const YAHEI_UI: Face = Face::new("msyh.ttc", 1);
const JHENGHEI_UI: Face = Face::new("msjh.ttc", 1);
/// Not installed on Windows 11 without the Japanese supplemental fonts.
const MEIRYO_UI: Face = Face::new("meiryo.ttc", 2);
const YU_GOTHIC_UI: Face = Face::new("YuGothM.ttc", 1);
const MALGUN_GOTHIC: Face = Face::new("malgun.ttf", 0);

/// A known Windows font: a file in the fonts folder and the face in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Face {
    file: &'static str,
    index: u32,
}

impl Face {
    const fn new(file: &'static str, index: u32) -> Self {
        Self { file, index }
    }
}

struct Script {
    ranges: &'static [RangeInclusive<u32>],
    #[cfg_attr(
        not(any(windows, test)),
        expect(
            dead_code,
            reason = "the fonts folder is searched on Windows and in tests"
        )
    )]
    windows: &'static [Face],
    /// The language that makes fontconfig pick the font where the character alone does not.
    #[cfg_attr(
        windows,
        expect(dead_code, reason = "fontconfig is asked only outside Windows")
    )]
    fontconfig_lang: Option<&'static str>,
}

/// A face of a font file on disk.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Location {
    path: PathBuf,
    index: u32,
}

enum Finder {
    /// Known fonts in a folder: the Windows fonts folder, or a test's folder.
    #[cfg(any(windows, test))]
    Folder(PathBuf),
    /// Whatever fontconfig picks for a language or a character.
    #[cfg(not(windows))]
    Fontconfig,
}

#[derive(Clone)]
struct LoadedFace {
    name: String,
    data: FontData,
}

impl LoadedFace {
    fn has(&self, c: char) -> bool {
        skrifa::FontRef::from_index(self.data.bytes(), self.data.index)
            .is_ok_and(|font| font.charmap().map(c).is_some())
    }
}

#[derive(Default)]
struct Loaded {
    /// Every face tried, `None` when it is missing, unreadable or not a font.
    faces: HashMap<Location, Option<LoadedFace>>,
    /// Faces in the order they were found.
    found: Vec<LoadedFace>,
    /// fontconfig's answer to each pattern asked.
    #[cfg(not(windows))]
    matched: HashMap<String, Option<Location>>,
    /// Characters fontconfig was asked about, so each is asked once.
    #[cfg(not(windows))]
    asked: HashSet<char>,
}

impl Loaded {
    fn face(&mut self, location: &Location) -> Option<LoadedFace> {
        if let Some(face) = self.faces.get(location) {
            return face.clone();
        }
        let face = read_face(location).map(|data| LoadedFace {
            name: format!("system-{}", self.found.len() + 1),
            data,
        });
        if let Some(face) = &face {
            self.found.push(face.clone());
            tracing::info!(fallback_fonts = self.found.len(), "found a fallback font");
        }
        self.faces.insert(location.clone(), face.clone());
        face
    }
}

/// The egui font provider that finds system fonts for characters the configured fonts lack.
pub(crate) struct SystemFonts {
    finder: Option<Finder>,
    loaded: Mutex<Loaded>,
}

impl SystemFonts {
    pub(crate) fn new() -> Self {
        #[cfg(windows)]
        let finder = rosetun_shell::fonts_dir().map(Finder::Folder);
        #[cfg(not(windows))]
        let finder = Some(Finder::Fontconfig);
        Self::with_finder(finder)
    }

    #[cfg(test)]
    fn in_folder(dir: &std::path::Path) -> Self {
        Self::with_finder(Some(Finder::Folder(dir.to_owned())))
    }

    fn with_finder(finder: Option<Finder>) -> Self {
        Self {
            finder,
            loaded: Mutex::new(Loaded::default()),
        }
    }

    fn find(&self, c: char) -> Option<LoadedFace> {
        let mut loaded = self.loaded.lock().unwrap_or_else(PoisonError::into_inner);
        match self.finder.as_ref()? {
            #[cfg(any(windows, test))]
            Finder::Folder(dir) => folder_locations(dir, c)
                .iter()
                .find_map(|location| loaded.face(location).filter(|face| face.has(c))),
            #[cfg(not(windows))]
            Finder::Fontconfig => fontconfig_face(&mut loaded, c),
        }
    }
}

impl FontProvider for SystemFonts {
    fn font_for(&self, request: &FallbackRequest<'_>) -> Option<FontInsert> {
        let c = request.cluster.chars().next()?;
        let face = self.find(c)?;
        Some(FontInsert {
            name: face.name,
            data: face.data,
            // egui appends the face to the family that asked.
            families: Vec::new(),
        })
    }
}

fn script_of(c: char) -> Option<&'static Script> {
    let code = u32::from(c);
    SCRIPTS
        .iter()
        .find(|script| script.ranges.iter().any(|range| range.contains(&code)))
}

/// The Windows fonts for `c` in the order they are tried: its script's, then the general ones.
#[cfg(any(windows, test))]
fn folder_locations(dir: &std::path::Path, c: char) -> Vec<Location> {
    let own = script_of(c).map_or(&[][..], |script| script.windows);
    let mut faces: Vec<Face> = Vec::new();
    for face in own.iter().chain(GENERAL) {
        if !faces.contains(face) {
            faces.push(*face);
        }
    }
    faces
        .into_iter()
        .map(|face| Location {
            path: dir.join(face.file),
            index: face.index,
        })
        .collect()
}

/// The language's own font first, then any font already found, then fontconfig's pick for the
/// character itself, asked once per character.
#[cfg(not(windows))]
fn fontconfig_face(loaded: &mut Loaded, c: char) -> Option<LoadedFace> {
    if let Some(lang) = script_of(c).and_then(|script| script.fontconfig_lang)
        && let Some(face) = fontconfig_pattern_face(loaded, &format!("sans-serif:lang={lang}"))
        && face.has(c)
    {
        return Some(face);
    }
    if let Some(face) = loaded.found.iter().find(|face| face.has(c)) {
        return Some(face.clone());
    }
    if !loaded.asked.insert(c) {
        return None;
    }
    fontconfig_pattern_face(loaded, &format!("sans-serif:charset={:x}", u32::from(c)))
        .filter(|face| face.has(c))
}

#[cfg(not(windows))]
fn fontconfig_pattern_face(loaded: &mut Loaded, pattern: &str) -> Option<LoadedFace> {
    let location = match loaded.matched.get(pattern) {
        Some(location) => location.clone(),
        None => {
            let location = fontconfig_match(pattern);
            loaded.matched.insert(pattern.to_owned(), location.clone());
            location
        }
    };
    loaded.face(&location?)
}

#[cfg(not(windows))]
fn fontconfig_match(pattern: &str) -> Option<Location> {
    let output = std::process::Command::new("fc-match")
        .arg("--format=%{index} %{file}")
        .arg(pattern)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_fontconfig_match(&output.stdout)
}

/// `fc-match --format='%{index} %{file}'` output: the face index, a space, the file.
#[cfg(not(windows))]
fn parse_fontconfig_match(output: &[u8]) -> Option<Location> {
    use std::os::unix::ffi::OsStrExt as _;

    let space = output.iter().position(|&byte| byte == b' ')?;
    let index = std::str::from_utf8(&output[..space]).ok()?.parse().ok()?;
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(&output[space + 1..]));
    path.is_absolute().then_some(Location { path, index })
}

fn read_face(location: &Location) -> Option<FontData> {
    let bytes = match font_bytes(&location.path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            tracing::debug!(kind = ?error.kind(), "could not read a fallback font");
            return None;
        }
    };
    let data = FontData::from_blob(bytes, location.index);
    if data.bytes().len() as u64 > MAX_FONT_BYTES {
        tracing::debug!("skipped a fallback font larger than the limit");
        return None;
    }
    if skrifa::FontRef::from_index(data.bytes(), data.index).is_err() {
        tracing::debug!("skipped a fallback font that could not be parsed");
        return None;
    }
    Some(data)
}

/// The file mapped into memory when only an administrator can change it, as system fonts,
/// else read into memory.
fn font_bytes(path: &std::path::Path) -> std::io::Result<Blob> {
    if let Some(mapped) = rosetun_shell::map_protected_file(path)? {
        return Ok(Arc::new(mapped));
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(
        &mut std::io::Read::take(std::fs::File::open(path)?, MAX_FONT_BYTES + 1),
        &mut bytes,
    )?;
    Ok(Arc::new(bytes))
}

#[cfg(test)]
mod tests;
