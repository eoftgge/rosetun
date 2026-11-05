//! Starting the GUI at sign-in on Linux: an XDG autostart entry of the user.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const FILE_NAME: &str = "rosetun.desktop";
const GROUP: &str = "[Desktop Entry]";

/// What starts at sign-in: `exe` followed by `argument`. `description` has
/// no place in the entry; it names the Windows task.
#[derive(Debug, Clone, Copy)]
pub struct Autostart<'a> {
    pub exe: &'a Path,
    pub argument: &'a str,
    pub description: &'a str,
}

pub fn enable_autostart(autostart: &Autostart<'_>) -> io::Result<()> {
    write_entry(&entry_path()?, autostart)
}

pub fn disable_autostart() -> io::Result<()> {
    remove_entry(&entry_path()?)
}

/// Whether an enabled entry starts `exe`. An entry of a program that has
/// moved, or one switched off in the desktop's settings, does not count.
pub fn autostart_enabled(exe: &Path) -> io::Result<bool> {
    read_enabled(&entry_path()?, exe)
}

fn entry_path() -> io::Result<PathBuf> {
    entry_path_from(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
}

/// The base directory spec ignores a relative `XDG_CONFIG_HOME`.
fn entry_path_from(config: Option<OsString>, home: Option<OsString>) -> io::Result<PathBuf> {
    config
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            home.map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .map(|home| home.join(".config"))
        })
        .map(|config| config.join("autostart").join(FILE_NAME))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "neither XDG_CONFIG_HOME nor HOME names a folder",
            )
        })
}

fn write_entry(path: &Path, autostart: &Autostart<'_>) -> io::Result<()> {
    let content = entry_text(autostart)?;
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("the autostart entry has no folder"))?;
    fs::create_dir_all(dir)?;
    // Beside the entry, so the rename is atomic and a crash leaves the old
    // entry or the new one, never half of one.
    let temporary = dir.join(format!(".{FILE_NAME}.{}", std::process::id()));
    let written = (|| {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written
}

fn remove_entry(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

fn read_enabled(path: &Path, exe: &Path) -> io::Result<bool> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        // A file that is not UTF-8 is no entry of ours.
        Err(error) if error.kind() == io::ErrorKind::InvalidData => return Ok(false),
        Err(error) => return Err(error),
    };
    Ok(entry_starts(&text, exe))
}

fn entry_text(autostart: &Autostart<'_>) -> io::Result<String> {
    let exe = autostart.exe.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the program's path is not UTF-8",
        )
    })?;
    if [exe, autostart.argument]
        .iter()
        .any(|text| text.contains(['\n', '\r']))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a line break cannot be part of an autostart entry",
        ));
    }
    Ok(format!(
        "{GROUP}\nType=Application\nName=Rosetun\nExec={} {}\nX-GNOME-Autostart-enabled=true\n",
        exec_argument(exe),
        exec_argument(autostart.argument),
    ))
}

/// One argument of `Exec`: quoted when it holds a reserved character, then
/// escaped once more because the whole value is a desktop entry string.
fn exec_argument(argument: &str) -> String {
    let reserved =
        |character: char| character.is_whitespace() || "\"'\\><~|&;$*?#()`".contains(character);
    let quoted = if argument.chars().any(reserved) {
        let mut quoted = String::from("\"");
        for character in argument.chars() {
            if matches!(character, '"' | '`' | '$' | '\\') {
                quoted.push('\\');
            }
            quoted.push(character);
        }
        quoted.push('"');
        quoted
    } else {
        argument.to_owned()
    };
    quoted.replace('\\', "\\\\").replace('%', "%%")
}

fn entry_starts(text: &str, exe: &Path) -> bool {
    let mut in_group = false;
    let mut program = None;
    let mut enabled = true;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_group = line == GROUP;
            continue;
        }
        if !in_group {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "Exec" => program = exec_program(value.trim()),
            "Hidden" if value.trim() == "true" => enabled = false,
            "X-GNOME-Autostart-enabled" if value.trim() == "false" => enabled = false,
            _ => {}
        }
    }
    enabled && program.is_some_and(|program| Path::new(&program) == exe)
}

/// The first argument of an `Exec` value, with both layers of escaping undone.
fn exec_program(value: &str) -> Option<String> {
    let value = value.replace("\\\\", "\\").replace("%%", "%");
    let mut characters = value.chars();
    let mut program = String::new();
    match characters.next()? {
        '"' => loop {
            match characters.next()? {
                '"' => break,
                '\\' => program.push(characters.next()?),
                character => program.push(character),
            }
        },
        first => {
            program.push(first);
            program.extend(characters.take_while(|character| !character.is_whitespace()));
        }
    }
    Some(program)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// A temporary folder in the role of `XDG_CONFIG_HOME`.
    fn entry_in_new_config(test: &str) -> (PathBuf, PathBuf) {
        static DIRS: AtomicUsize = AtomicUsize::new(0);
        let config = std::env::temp_dir().join(format!(
            "rosetun-autostart-{test}-{}-{}",
            std::process::id(),
            DIRS.fetch_add(1, Ordering::Relaxed)
        ));
        let path = entry_path_from(Some(config.clone().into()), None).unwrap();
        (config, path)
    }

    fn start(exe: &str) -> Autostart<'_> {
        Autostart {
            exe: Path::new(exe),
            argument: "--hidden",
            description: "unused",
        }
    }

    #[test]
    fn the_entry_lives_under_the_config_home_or_else_in_home() {
        assert_eq!(
            entry_path_from(Some("/config".into()), Some("/home/user".into())).unwrap(),
            Path::new("/config/autostart/rosetun.desktop")
        );
        assert_eq!(
            entry_path_from(None, Some("/home/user".into())).unwrap(),
            Path::new("/home/user/.config/autostart/rosetun.desktop")
        );
        assert_eq!(
            entry_path_from(Some("relative".into()), Some("/home/user".into())).unwrap(),
            Path::new("/home/user/.config/autostart/rosetun.desktop")
        );
        assert!(entry_path_from(None, None).is_err());
    }

    #[test]
    fn enabling_writes_a_minimal_entry_and_disabling_removes_it() {
        let (config, path) = entry_in_new_config("cycle");
        let exe = "/usr/lib/rosetun/rosetun-gui";
        assert!(!read_enabled(&path, Path::new(exe)).unwrap());
        write_entry(&path, &start(exe)).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "[Desktop Entry]\nType=Application\nName=Rosetun\n\
             Exec=/usr/lib/rosetun/rosetun-gui --hidden\nX-GNOME-Autostart-enabled=true\n"
        );
        assert!(read_enabled(&path, Path::new(exe)).unwrap());
        assert_eq!(
            fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1,
            "no temporary file stays"
        );
        write_entry(&path, &start(exe)).unwrap();
        remove_entry(&path).unwrap();
        assert!(!read_enabled(&path, Path::new(exe)).unwrap());
        remove_entry(&path).unwrap();
        fs::remove_dir_all(config).unwrap();
    }

    #[test]
    fn an_entry_of_another_program_is_not_ours() {
        let (config, path) = entry_in_new_config("moved");
        write_entry(&path, &start("/opt/old/rosetun-gui")).unwrap();
        assert!(!read_enabled(&path, Path::new("/usr/lib/rosetun/rosetun-gui")).unwrap());
        fs::remove_dir_all(config).unwrap();
    }

    #[test]
    fn a_path_with_reserved_characters_reads_back_as_written() {
        for exe in [
            "/home/user/my apps/rosetun-gui",
            "/opt/a$b/rosetun-gui",
            "/opt/a\"b/rosetun-gui",
            "/opt/a\\b/rosetun-gui",
            "/opt/100%/rosetun-gui",
            "/opt/путь/rosetun-gui",
        ] {
            let text = entry_text(&start(exe)).unwrap();
            assert!(entry_starts(&text, Path::new(exe)), "{exe}: {text}");
        }
    }

    #[test]
    fn the_spec_escapes_are_applied_in_exec() {
        assert_eq!(exec_argument("--hidden"), "--hidden");
        assert_eq!(exec_argument("/my apps/x"), "\"/my apps/x\"");
        assert_eq!(exec_argument("/a$b"), "\"/a\\\\$b\"");
        assert_eq!(exec_argument("/100%"), "/100%%");
    }

    #[test]
    fn a_line_break_or_foreign_bytes_are_refused() {
        assert!(entry_text(&start("/opt/a\nb")).is_err());
        use std::os::unix::ffi::OsStrExt;
        let exe = Path::new(std::ffi::OsStr::from_bytes(b"/opt/\xff"));
        let autostart = Autostart {
            exe,
            argument: "--hidden",
            description: "",
        };
        assert_eq!(
            entry_text(&autostart).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn an_entry_switched_off_on_the_desktop_is_off() {
        let exe = Path::new("/opt/rosetun-gui");
        let entry = "[Desktop Entry]\nExec=/opt/rosetun-gui --hidden\n";
        assert!(entry_starts(entry, exe));
        assert!(!entry_starts(
            &format!("{entry}X-GNOME-Autostart-enabled=false\n"),
            exe
        ));
        assert!(!entry_starts(&format!("{entry}Hidden=true\n"), exe));
        assert!(entry_starts(
            "[Other]\nHidden=true\n[Desktop Entry]\nExec=/opt/rosetun-gui\n",
            exe
        ));
        assert!(!entry_starts("[Other]\nExec=/opt/rosetun-gui\n", exe));
        assert!(!entry_starts("[Desktop Entry]\nExec=\n", exe));
    }

    #[test]
    fn a_file_that_is_not_text_counts_as_no_entry() {
        let (config, path) = entry_in_new_config("binary");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, [0xff, 0xfe]).unwrap();
        assert!(!read_enabled(&path, Path::new("/opt/rosetun-gui")).unwrap());
        fs::remove_dir_all(config).unwrap();
    }
}
