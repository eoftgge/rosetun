use std::io::Write;

use eframe::egui::{self, FontFamily, FontId};

use super::*;
use crate::theme;

const MANROPE: &[u8] = include_bytes!("../../assets/fonts/Manrope-Regular.ttf");
const CORMORANT: &[u8] = include_bytes!("../../assets/fonts/CormorantGaramond-SemiBold.ttf");
/// In Cormorant Garamond, but not in Manrope or egui's fonts.
const ONLY_IN_CORMORANT: char = '\u{1E0C}';

/// Held by every test that reads fonts: tracing caches whether anyone listens at a log line
/// when it first runs, and a run on another thread without a subscriber can hide the line
/// from the test that captures the log.
static READS_FONTS: Mutex<()> = Mutex::new(());

/// A folder of fake system fonts, removed when dropped.
struct FontsFolder(PathBuf);

impl FontsFolder {
    fn new(name: &str, files: &[(&str, &[u8])]) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "rosetun-system-fonts-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (file, bytes) in files {
            std::fs::write(dir.join(file), bytes).unwrap();
        }
        Self(dir)
    }
}

impl Drop for FontsFolder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn request(fonts: &SystemFonts, c: char) -> Option<FontInsert> {
    let cluster = c.to_string();
    fonts.font_for(&FallbackRequest {
        cluster: &cluster,
        family: &FontFamily::Proportional,
    })
}

fn files(dir: &std::path::Path, c: char) -> Vec<(String, u32)> {
    folder_locations(dir, c)
        .into_iter()
        .map(|location| {
            assert_eq!(location.path.parent(), Some(dir));
            let file = location.path.file_name().unwrap().to_string_lossy();
            (file.into_owned(), location.index)
        })
        .collect()
}

#[test]
fn each_script_tries_its_own_windows_fonts_before_the_general_ones() {
    let dir = std::path::Path::new("fonts");
    let general = [
        ("segoeui.ttf".to_owned(), 0),
        ("seguisym.ttf".to_owned(), 0),
        ("ebrima.ttf".to_owned(), 0),
        ("mmrtext.ttf".to_owned(), 0),
    ];
    let with_general = |own: &[(&str, u32)]| {
        own.iter()
            .map(|(file, index)| ((*file).to_owned(), *index))
            .chain(general.iter().cloned())
            .collect::<Vec<_>>()
    };
    for (c, own) in [
        (
            '东',
            &[
                ("msyh.ttc", 1),
                ("msjh.ttc", 1),
                ("YuGothM.ttc", 1),
                ("meiryo.ttc", 2),
                ("malgun.ttf", 0),
            ][..],
        ),
        (
            '・',
            &[("YuGothM.ttc", 1), ("meiryo.ttc", 2), ("msyh.ttc", 1)][..],
        ),
        ('テ', &[("YuGothM.ttc", 1), ("meiryo.ttc", 2), ("msyh.ttc", 1)][..]),
        ('서', &[("malgun.ttf", 0)][..]),
        ('ก', &[("LeelawUI.ttf", 0), ("tahoma.ttf", 0)][..]),
        ('द', &[("Nirmala.ttc", 0), ("Nirmala.ttf", 0)][..]),
        ('ه', &[][..]),
        ('Ε', &[][..]),
    ] {
        assert_eq!(files(dir, c), with_general(own), "{c}");
    }
}

#[test]
fn missing_and_broken_files_are_skipped() {
    let _serial = READS_FONTS.lock().unwrap_or_else(PoisonError::into_inner);
    let folder = FontsFolder::new(
        "skipped",
        &[("msyh.ttc", b"not a font"), ("segoeui.ttf", CORMORANT)],
    );
    let fonts = SystemFonts::in_folder(&folder.0);
    assert!(request(&fonts, '东').is_none());
    let found = request(&fonts, ONLY_IN_CORMORANT).unwrap();
    assert_eq!(found.name, "system-1");
    assert_eq!(found.data.bytes(), CORMORANT);
    assert_eq!(found.data.index, 0);
    assert!(request(&fonts, 'ה').is_none());
    let loaded = fonts.loaded.lock().unwrap();
    assert_eq!(loaded.found.len(), 1);
}

#[test]
fn a_font_in_two_scripts_is_read_once() {
    let _serial = READS_FONTS.lock().unwrap_or_else(PoisonError::into_inner);
    let folder = FontsFolder::new("shared", &[("segoeui.ttf", MANROPE)]);
    let fonts = SystemFonts::in_folder(&folder.0);
    for c in ['Ж', 'Ä', 'Ж'] {
        assert_eq!(request(&fonts, c).unwrap().name, "system-1");
    }
    assert_eq!(fonts.loaded.lock().unwrap().found.len(), 1);
}

#[test]
fn a_fallback_comes_after_manrope_and_egui_fonts_in_every_family() {
    let _serial = READS_FONTS.lock().unwrap_or_else(PoisonError::into_inner);
    let folder = FontsFolder::new("order", &[("segoeui.ttf", CORMORANT)]);
    let ctx = egui::Context::default();
    theme::apply(&ctx);
    ctx.add_font_provider(Arc::new(SystemFonts::in_folder(&folder.0)));
    let text = format!("A{ONLY_IN_CORMORANT}");
    let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
        ui.label(&text);
        ui.label(egui::RichText::new(&text).family(FontFamily::Name(theme::UI_SEMIBOLD.into())));
        ui.label(egui::RichText::new(&text).monospace());
    });
    output.textures_delta.clear();
    let primary = |family: &FontFamily| match family {
        FontFamily::Proportional => "manrope-regular",
        FontFamily::Monospace => "Hack",
        _ => "manrope-semibold",
    };
    ctx.fonts_mut(|fonts| {
        for family in [
            FontFamily::Proportional,
            FontFamily::Name(theme::UI_SEMIBOLD.into()),
            FontFamily::Monospace,
        ] {
            let font = FontId::new(14.0, family.clone());
            assert!(fonts.has_glyph(&font, ONLY_IN_CORMORANT), "{family:?}");
            let characters = fonts.characters(&family);
            assert_eq!(
                characters[&ONLY_IN_CORMORANT],
                ["system-1"],
                "{family:?}"
            );
            let latin = &characters[&'A'];
            assert_eq!(latin.first().map(String::as_str), Some(primary(&family)));
            assert_eq!(latin.last().map(String::as_str), Some("system-1"));
            assert!(latin.len() > 2, "egui's fonts sit between: {latin:?}");
        }
    });
}

#[test]
fn the_log_has_the_count_of_fallback_fonts_and_no_paths() {
    let _serial = READS_FONTS.lock().unwrap_or_else(PoisonError::into_inner);
    let folder = FontsFolder::new(
        "private-user",
        &[("msyh.ttc", b"not a font"), ("segoeui.ttf", CORMORANT)],
    );
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let fonts = SystemFonts::in_folder(&folder.0);
        assert!(request(&fonts, '东').is_none());
        assert!(request(&fonts, ONLY_IN_CORMORANT).is_some());
    });
    let log = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(log.contains("fallback_fonts=1"), "{log}");
    for private in ["private-user", "msyh", "segoeui", "rosetun-system-fonts"] {
        assert!(!log.contains(private), "{private} in {log}");
    }
    let temp = std::env::temp_dir();
    assert!(!log.contains(&*temp.to_string_lossy()), "{log}");
}

#[cfg(not(windows))]
#[test]
fn fontconfig_answers_are_parsed_into_a_face_of_a_file() {
    assert_eq!(
        parse_fontconfig_match(b"2 /usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
        Some(Location {
            path: PathBuf::from("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
            index: 2,
        })
    );
    assert_eq!(
        parse_fontconfig_match(b"0 /home/user name/.fonts/A B.ttf"),
        Some(Location {
            path: PathBuf::from("/home/user name/.fonts/A B.ttf"),
            index: 0,
        })
    );
    for broken in [&b""[..], b"0", b"x /a.ttf", b"0 relative.ttf", b"-1 /a.ttf"] {
        assert_eq!(parse_fontconfig_match(broken), None);
    }
}

/// The owner's manual check names on this machine's fonts: run with `--ignored` where the
/// usual fonts are installed (Windows, or Linux with the Noto fonts).
#[test]
#[ignore = "depends on the fonts installed on this machine"]
fn the_system_has_fonts_for_the_manual_check_names() {
    let ctx = egui::Context::default();
    theme::apply(&ctx);
    ctx.add_font_provider(Arc::new(SystemFonts::new()));
    let names = [
        "東京 · 日本",
        "서울",
        "กรุงเทพ",
        "दिल्ली",
        "Ελλάδα",
        "İstanbul",
        "تهران",
        "测试",
        "テスト",
    ];
    let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
        for name in names {
            ui.label(name);
        }
    });
    output.textures_delta.clear();
    ctx.fonts_mut(|fonts| {
        let font = FontId::proportional(14.0);
        for name in names {
            for c in name.chars().filter(|c| !c.is_whitespace()) {
                assert!(fonts.has_glyph(&font, c), "{c:?} in {name}");
            }
        }
    });
}
