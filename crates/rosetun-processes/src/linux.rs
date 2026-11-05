//! Running programs from `/proc`, and what the desktop knows about them from
//! its `.desktop` files. Command lines are never read: they can hold secrets.
//!
//! A program counts as running on the desktop ("windowed" on Windows) when
//! it is this user's and a menu entry starts it. Wayland tells no program
//! about another's windows, and asking KWin would tie this to one desktop,
//! so the menu entry stands in. It also holds for an application closed to
//! its tray, which is what a rule by program is wanted for; and it leaves
//! out services, which have no menu entry.

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::{ProcessListError, RunningProcess};

/// `kthreadd`: the parent of every kernel thread.
const KERNEL_THREADS_PARENT: u32 = 2;
const MAX_DESKTOP_FILE_BYTES: u64 = 64 * 1024;
/// Far more than a desktop has; bounds the work on a damaged folder.
const MAX_DESKTOP_FILES: usize = 8192;
const APPS_FOR: Duration = Duration::from_secs(30);
const MAX_FOLDER_DEPTH: usize = 3;
/// Their file name says nothing about the program they run, so neither an
/// entry that starts one nor a process of one matches by that name.
const LAUNCHERS: &[&str] = &[
    "bash", "dash", "env", "flatpak", "java", "node", "perl", "python", "python3", "ruby", "sh",
    "snap", "wine", "zsh",
];
/// Hicolor's usual sizes; scalable icons need a renderer Rosetun does not carry.
const ICON_SIZES: &[u32] = &[16, 22, 24, 32, 48, 64, 96, 128, 256, 512];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DesktopApp {
    name: String,
    /// `(locale, name)` from `Name[locale]`.
    local_names: Vec<(String, String)>,
    /// The program of `Exec`, or of `TryExec` without one; unless a launcher.
    program: Option<PathBuf>,
    window_class: Option<String>,
    icon: Option<String>,
}

pub(super) fn running_processes() -> Result<Vec<RunningProcess>, ProcessListError> {
    list_under(Path::new("/proc"), &desktop_apps(), own_uid())
}

pub(super) fn file_description(path: &Path, language: &str) -> Option<String> {
    let apps = desktop_apps();
    let app = app_of_program(&apps, path)?;
    Some(local_name(app, language).to_owned())
}

/// The PNG file of the program's icon in the desktop's icon folders. An
/// entry that has only a scalable icon gets none.
pub(super) fn icon_file(path: &Path, size_px: u32) -> Option<PathBuf> {
    let apps = desktop_apps();
    let icon = app_of_program(&apps, path)?.icon.as_deref()?;
    find_icon(icon, size_px, &icon_folders())
}

fn own_uid() -> u32 {
    fs::metadata("/proc/self").map_or(u32::MAX, |metadata| metadata.uid())
}

fn list_under(
    root: &Path,
    apps: &[DesktopApp],
    uid: u32,
) -> Result<Vec<RunningProcess>, ProcessListError> {
    let entries = fs::read_dir(root).map_err(ProcessListError::Snapshot)?;
    Ok(entries
        .flatten()
        .filter_map(|entry| {
            let pid = entry.file_name().to_str()?.parse::<u32>().ok()?;
            read_process(&entry.path(), pid, apps, uid)
        })
        .collect())
}

/// `None` for a kernel thread and for a process that has just ended.
fn read_process(folder: &Path, pid: u32, apps: &[DesktopApp], uid: u32) -> Option<RunningProcess> {
    let stat = fs::read(folder.join("stat")).ok()?;
    let stat = String::from_utf8_lossy(&stat);
    if pid == KERNEL_THREADS_PARENT || parent_of_stat(&stat) == Some(KERNEL_THREADS_PARENT) {
        return None;
    }
    let path = fs::read_link(folder.join("exe"))
        .ok()
        .filter(|path| path.is_absolute())
        .map(|path| without_deleted_mark(&path));
    let command = fs::read(folder.join("comm"))
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).trim_end().to_owned())
        .filter(|name| !name.is_empty())?;
    // sing-box matches a name against the executable's path, and `comm` is
    // cut at 15 bytes or renamed at will (Chromium's says `chrome`).
    let name = path.as_deref().and_then(Path::file_name).map_or_else(
        || command.clone(),
        |name| name.to_string_lossy().into_owned(),
    );
    let own = fs::metadata(folder).is_ok_and(|metadata| metadata.uid() == uid);
    let has_window = own && app_of_process(apps, path.as_deref(), &command).is_some();
    Some(RunningProcess {
        pid,
        name,
        path,
        has_window,
    })
}

/// The kernel adds ` (deleted)` to a file replaced since it started, as a
/// package upgrade does; a rule by path means the file at the plain path.
fn without_deleted_mark(path: &Path) -> PathBuf {
    let bytes = path.as_os_str().as_bytes();
    let bytes = bytes.strip_suffix(b" (deleted)").unwrap_or(bytes);
    PathBuf::from(OsStr::from_bytes(bytes))
}

/// The fourth field of `/proc/<pid>/stat`, read after the last `)` because
/// the command in parentheses can hold anything.
fn parent_of_stat(stat: &str) -> Option<u32> {
    let (_, rest) = stat.rsplit_once(')')?;
    rest.split_ascii_whitespace().nth(1)?.parse().ok()
}

fn app_of_process<'a>(
    apps: &'a [DesktopApp],
    path: Option<&Path>,
    command: &str,
) -> Option<&'a DesktopApp> {
    if let Some(path) = path
        && let Some(app) = app_of_program(apps, path)
    {
        return Some(app);
    }
    let file_name = path
        .and_then(Path::file_name)
        .and_then(OsStr::to_str)
        .filter(|name| !is_launcher(name));
    apps.iter().find(|app| {
        app.window_class.as_deref().is_some_and(|class| {
            class.eq_ignore_ascii_case(command)
                || file_name.is_some_and(|name| class.eq_ignore_ascii_case(name))
        })
    })
}

/// The entry that starts this file: by the very path, else by file name,
/// since a menu entry often names a wrapper in `/usr/bin` for a program in
/// `/usr/lib`.
fn app_of_program<'a>(apps: &'a [DesktopApp], path: &Path) -> Option<&'a DesktopApp> {
    let by_path = apps.iter().find(|app| {
        app.program
            .as_deref()
            .is_some_and(|program| program == path)
    });
    by_path.or_else(|| {
        let name = path.file_name()?;
        if is_launcher(&name.to_string_lossy()) {
            return None;
        }
        apps.iter().find(|app| {
            app.program
                .as_deref()
                .and_then(Path::file_name)
                .is_some_and(|program| program == name)
        })
    })
}

fn is_launcher(name: &str) -> bool {
    LAUNCHERS.contains(&name)
        || name
            .strip_prefix("python")
            .is_some_and(|version| version.starts_with(|c: char| c.is_ascii_digit()))
}

fn local_name<'a>(app: &'a DesktopApp, language: &str) -> &'a str {
    let matching = |wanted: &dyn Fn(&str) -> bool| {
        app.local_names
            .iter()
            .find(|(locale, _)| wanted(locale))
            .map(|(_, name)| name.as_str())
    };
    matching(&|locale| locale == language)
        .or_else(|| {
            matching(&|locale| {
                locale
                    .split(['_', '@', '.'])
                    .next()
                    .is_some_and(|part| part == language)
            })
        })
        .unwrap_or(&app.name)
}

/// The entries of the desktop, kept for a moment: a list of programs and
/// the names of a connection list ask for them many times in a row.
fn desktop_apps() -> Arc<Vec<DesktopApp>> {
    static APPS: Mutex<Option<(Instant, Arc<Vec<DesktopApp>>)>> = Mutex::new(None);
    let mut kept = APPS.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((read, apps)) = &*kept
        && read.elapsed() < APPS_FOR
    {
        return Arc::clone(apps);
    }
    let apps = Arc::new(read_apps(&data_folders()));
    *kept = Some((Instant::now(), Arc::clone(&apps)));
    apps
}

/// `XDG_DATA_HOME`, then `XDG_DATA_DIRS`, the order of precedence the spec gives.
fn data_folders() -> Vec<PathBuf> {
    data_folders_from(
        std::env::var_os("XDG_DATA_HOME"),
        std::env::var_os("XDG_DATA_DIRS"),
        std::env::var_os("HOME"),
    )
}

fn data_folders_from(
    home_data: Option<OsString>,
    data: Option<OsString>,
    home: Option<OsString>,
) -> Vec<PathBuf> {
    let home_data = home_data
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            home.map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .map(|home| home.join(".local/share"))
        });
    let data = data.filter(|value| !value.is_empty()).map_or_else(
        || {
            vec![
                PathBuf::from("/usr/local/share"),
                PathBuf::from("/usr/share"),
            ]
        },
        |value| {
            std::env::split_paths(&value)
                .filter(|path| path.is_absolute())
                .collect()
        },
    );
    home_data.into_iter().chain(data).collect()
}

fn icon_folders() -> Vec<PathBuf> {
    let mut folders: Vec<_> = data_folders()
        .into_iter()
        .map(|folder| folder.join("icons"))
        .collect();
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        folders.insert(0, home.join(".icons"));
    }
    folders.push(PathBuf::from("/usr/share/pixmaps"));
    folders
}

/// The entries under `folders`. An earlier folder's file hides a later one
/// of the same relative name, even when that makes the entry a hidden one.
fn read_apps(folders: &[PathBuf]) -> Vec<DesktopApp> {
    let mut seen = HashSet::new();
    let mut apps = Vec::new();
    for folder in folders {
        let root = folder.join("applications");
        let mut files = Vec::new();
        desktop_files(&root, 0, &mut files);
        for file in files {
            if seen.len() >= MAX_DESKTOP_FILES {
                return apps;
            }
            let relative = file.strip_prefix(&root).unwrap_or(&file).to_owned();
            if seen.insert(relative)
                && let Some(text) = read_small_text(&file)
                && let Some(app) = parse_desktop(&text)
            {
                apps.push(app);
            }
        }
    }
    apps
}

fn desktop_files(folder: &Path, depth: usize, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(folder) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "desktop")
        {
            files.push(path);
        } else if depth < MAX_FOLDER_DEPTH && entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            desktop_files(&path, depth + 1, files);
        }
    }
}

fn read_small_text(path: &Path) -> Option<String> {
    let mut text = String::new();
    fs::File::open(path)
        .ok()?
        .take(MAX_DESKTOP_FILE_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

/// `None` for anything but a visible application.
fn parse_desktop(text: &str) -> Option<DesktopApp> {
    let mut in_group = false;
    let mut app = DesktopApp::default();
    let (mut application, mut try_exec, mut exec) = (false, None, None);
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_group = line == "[Desktop Entry]";
            continue;
        }
        if !in_group || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        match key {
            "Type" => application = value == "Application",
            "Hidden" | "NoDisplay" if value == "true" => return None,
            "Name" => value.clone_into(&mut app.name),
            "Exec" => exec = exec_program(value),
            "TryExec" if !value.is_empty() => try_exec = Some(value.to_owned()),
            "StartupWMClass" if !value.is_empty() => app.window_class = Some(value.to_owned()),
            "Icon" if !value.is_empty() => app.icon = Some(value.to_owned()),
            _ => {
                if let Some(locale) = key
                    .strip_prefix("Name[")
                    .and_then(|rest| rest.strip_suffix(']'))
                {
                    app.local_names.push((locale.to_owned(), value.to_owned()));
                }
            }
        }
    }
    if !application || app.name.is_empty() {
        return None;
    }
    app.program = exec
        .or(try_exec)
        .filter(|program| !is_launcher(file_name_of(program)))
        .map(|program| resolve_program(&program));
    Some(app)
}

fn file_name_of(program: &str) -> &str {
    program.rsplit('/').next().unwrap_or(program)
}

/// The first real word of an `Exec` value, past `env` and its settings.
fn exec_program(value: &str) -> Option<String> {
    let value = value.replace("\\\\", "\\");
    let mut words = exec_words(&value).into_iter();
    let first = words.next()?;
    if file_name_of(&first) != "env" {
        return Some(first);
    }
    words.find(|word| !word.contains('=') && !word.starts_with('-'))
}

fn exec_words(value: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let (mut quoted, mut started) = (false, false);
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        match character {
            '"' => {
                quoted = !quoted;
                started = true;
            }
            '\\' if quoted => word.extend(characters.next()),
            character if character.is_whitespace() && !quoted => {
                if std::mem::take(&mut started) {
                    words.push(std::mem::take(&mut word));
                }
            }
            character => {
                word.push(character);
                started = true;
            }
        }
    }
    if started {
        words.push(word);
    }
    words
}

/// The file a program name stands for: found on `PATH` if bare, with links
/// followed (`/usr/bin/foo` is often one), or the name as it was.
fn resolve_program(program: &str) -> PathBuf {
    let path = Path::new(program);
    let found = if path.is_absolute() {
        Some(path.to_owned())
    } else {
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|folder| folder.join(program))
                .find(|candidate| candidate.is_file())
        })
    };
    found
        .and_then(|found| found.canonicalize().ok())
        .unwrap_or_else(|| path.to_owned())
}

/// The nearest size not below `size_px`, else the largest, as a PNG. An
/// earlier folder wins only among files of the same size.
fn find_icon(icon: &str, size_px: u32, folders: &[PathBuf]) -> Option<PathBuf> {
    let path = Path::new(icon);
    if path.is_absolute() {
        return is_png(path).then(|| path.to_owned());
    }
    if icon.contains('/') {
        return None;
    }
    let file = OsString::from_vec([icon.as_bytes(), b".png"].concat());
    let upward = ICON_SIZES.iter().copied().filter(|size| *size >= size_px);
    let downward = ICON_SIZES
        .iter()
        .rev()
        .copied()
        .filter(|size| *size < size_px);
    for size in upward.chain(downward) {
        let sized = format!("hicolor/{size}x{size}/apps");
        for folder in folders {
            let candidate = folder.join(&sized).join(&file);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    folders
        .iter()
        .map(|folder| folder.join(&file))
        .find(|candidate| candidate.is_file())
}

fn is_png(path: &Path) -> bool {
    path.extension().is_some_and(|extension| extension == "png") && path.is_file()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn temp_folder(test: &str) -> PathBuf {
        static FOLDERS: AtomicUsize = AtomicUsize::new(0);
        let folder = std::env::temp_dir().join(format!(
            "rosetun-processes-{test}-{}-{}",
            std::process::id(),
            FOLDERS.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&folder).unwrap();
        folder
    }

    /// A `/proc/<pid>` of files; `exe` as a link when the process has one to show.
    fn fake_process(root: &Path, pid: u32, parent: u32, comm: &str, exe: Option<&str>) {
        let folder = root.join(pid.to_string());
        fs::create_dir(&folder).unwrap();
        fs::write(
            folder.join("stat"),
            format!("{pid} ({comm}) S {parent} 1 1 0 -1 0"),
        )
        .unwrap();
        fs::write(folder.join("comm"), format!("{comm}\n")).unwrap();
        if let Some(exe) = exe {
            std::os::unix::fs::symlink(exe, folder.join("exe")).unwrap();
        }
    }

    fn app(name: &str, program: &str) -> DesktopApp {
        DesktopApp {
            name: name.to_owned(),
            program: Some(PathBuf::from(program)),
            ..DesktopApp::default()
        }
    }

    fn listed(root: &Path, apps: &[DesktopApp], uid: u32) -> Vec<RunningProcess> {
        let mut processes = list_under(root, apps, uid).unwrap();
        processes.sort_by_key(|process| process.pid);
        processes
    }

    #[test]
    fn a_process_shows_its_name_path_and_whether_a_menu_entry_starts_it() {
        let root = temp_folder("list");
        let uid = fs::metadata(&root).unwrap().uid();
        fake_process(
            &root,
            10,
            1,
            "firefox-esr",
            Some("/usr/lib/firefox/firefox-esr"),
        );
        fake_process(&root, 11, 1, "sshd", Some("/usr/sbin/sshd"));
        fake_process(&root, 12, 1, "secretd", None);
        fs::write(root.join("cpuinfo"), "not a process").unwrap();
        let apps = [app("Firefox", "/usr/lib/firefox/firefox-esr")];
        assert_eq!(
            listed(&root, &apps, uid),
            [
                RunningProcess {
                    pid: 10,
                    name: "firefox-esr".to_owned(),
                    path: Some(PathBuf::from("/usr/lib/firefox/firefox-esr")),
                    has_window: true,
                },
                RunningProcess {
                    pid: 11,
                    name: "sshd".to_owned(),
                    path: Some(PathBuf::from("/usr/sbin/sshd")),
                    has_window: false,
                },
                RunningProcess {
                    pid: 12,
                    name: "secretd".to_owned(),
                    path: None,
                    has_window: false,
                },
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn kernel_threads_are_not_programs() {
        let root = temp_folder("kernel");
        fake_process(&root, 2, 0, "kthreadd", None);
        fake_process(&root, 3, 2, "rcu_gp", None);
        fake_process(&root, 4, 1, "init", None);
        let names: Vec<_> = listed(&root, &[], 0)
            .into_iter()
            .map(|process| process.name)
            .collect();
        assert_eq!(names, ["init"]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn another_users_program_is_never_on_the_desktop() {
        let root = temp_folder("owner");
        let uid = fs::metadata(&root).unwrap().uid();
        fake_process(&root, 10, 1, "editor", Some("/usr/bin/editor"));
        let apps = [app("Editor", "/usr/bin/editor")];
        assert!(!listed(&root, &apps, uid.wrapping_add(1))[0].has_window);
        assert!(listed(&root, &apps, uid)[0].has_window);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_name_is_the_files_since_rules_match_it_against_the_path() {
        let root = temp_folder("name");
        // `comm` is cut at 15 bytes and can be anything.
        fake_process(
            &root,
            10,
            1,
            "org.kde.dolphin",
            Some("/usr/bin/org.kde.dolphin-bin"),
        );
        fake_process(&root, 11, 1, "chrome", Some("/usr/lib/chromium/chromium"));
        let names: Vec<_> = listed(&root, &[], 0)
            .into_iter()
            .map(|process| process.name)
            .collect();
        assert_eq!(names, ["org.kde.dolphin-bin", "chromium"]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_file_replaced_by_an_upgrade_keeps_its_plain_path() {
        let root = temp_folder("deleted");
        fake_process(&root, 10, 1, "app", Some("/usr/bin/app (deleted)"));
        let processes = listed(&root, &[], 0);
        assert_eq!(
            processes[0].path.as_deref(),
            Some(Path::new("/usr/bin/app"))
        );
        assert_eq!(processes[0].name, "app");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_missing_proc_is_an_error() {
        assert!(list_under(Path::new("/nonexistent/proc"), &[], 0).is_err());
    }

    #[test]
    fn the_parent_is_read_past_a_command_with_parentheses() {
        assert_eq!(parent_of_stat("7 (a) b) c) S 42 7 7"), Some(42));
        assert_eq!(parent_of_stat("7 (x) S 1 7 7"), Some(1));
        assert_eq!(parent_of_stat("garbage"), None);
    }

    #[test]
    fn a_wrapper_in_the_entry_finds_the_program_by_file_name() {
        let apps = [app("Chromium", "/usr/bin/chromium")];
        assert!(app_of_program(&apps, Path::new("/usr/lib/chromium/chromium")).is_some());
        assert!(app_of_program(&apps, Path::new("/usr/bin/other")).is_none());
    }

    #[test]
    fn an_interpreter_does_not_count_as_the_program_it_runs() {
        let mut python = app("Tool", "/usr/bin/python3");
        python.window_class = Some("tool".to_owned());
        let apps = [python];
        assert!(app_of_program(&apps, Path::new("/opt/python3")).is_none());
        assert!(app_of_program(&apps, Path::new("/usr/bin/python3.13")).is_none());
        assert!(
            app_of_process(&apps, Some(Path::new("/usr/bin/python3.13")), "tool").is_some(),
            "its window class still names it"
        );
        let entry = "[Desktop Entry]\nType=Application\nName=Tool\nExec=python3 /opt/tool.py\n";
        assert_eq!(parse_desktop(entry).unwrap().program, None);
    }

    #[test]
    fn a_window_class_names_a_program_with_another_file_name() {
        let mut telegram = app("Telegram", "/usr/bin/flatpak-run");
        telegram.window_class = Some("TelegramDesktop".to_owned());
        let apps = [telegram];
        assert!(app_of_process(&apps, None, "telegramdesktop").is_some());
        assert!(app_of_process(&apps, Some(Path::new("/app/bin/TelegramDesktop")), "x").is_some());
        assert!(app_of_process(&apps, None, "other").is_none());
    }

    #[test]
    fn an_entry_gives_its_fields() {
        let parsed = parse_desktop(
            "# comment\n[Desktop Entry]\nType=Application\nName=Files\nName[ru]=Файлы\n\
             Name[pt_BR]=Arquivos\nExec=/opt/files --new %U\nIcon=files\n\
             StartupWMClass=FilesApp\n[Desktop Action New]\nName=New\nExec=/opt/other\n",
        )
        .unwrap();
        assert_eq!(parsed.name, "Files");
        assert_eq!(parsed.program.as_deref(), Some(Path::new("/opt/files")));
        assert_eq!(parsed.icon.as_deref(), Some("files"));
        assert_eq!(parsed.window_class.as_deref(), Some("FilesApp"));
        assert_eq!(local_name(&parsed, "ru"), "Файлы");
        assert_eq!(local_name(&parsed, "pt"), "Arquivos");
        assert_eq!(local_name(&parsed, "de"), "Files");
    }

    #[test]
    fn only_a_visible_application_counts() {
        let entry = "[Desktop Entry]\nType=Application\nName=A\nExec=/opt/a\n";
        assert!(parse_desktop(entry).is_some());
        assert!(parse_desktop(&format!("{entry}NoDisplay=true\n")).is_none());
        assert!(parse_desktop(&format!("{entry}Hidden=true\n")).is_none());
        assert!(parse_desktop("[Desktop Entry]\nType=Link\nName=A\nExec=/opt/a\n").is_none());
        assert!(parse_desktop("[Desktop Entry]\nType=Application\nExec=/opt/a\n").is_none());
        assert!(parse_desktop("[Other]\nType=Application\nName=A\n").is_none());
    }

    #[test]
    fn exec_is_read_past_quotes_and_env() {
        for (value, expected) in [
            ("/opt/app %u", "/opt/app"),
            ("\"/opt/my app\" --flag", "/opt/my app"),
            ("env FOO=1 BAR=2 /opt/app %F", "/opt/app"),
            ("/usr/bin/env -i FOO=1 app", "app"),
            (r#""/opt/a\\$b" x"#, "/opt/a$b"),
        ] {
            assert_eq!(exec_program(value).as_deref(), Some(expected), "{value}");
        }
        assert_eq!(exec_program(""), None);
        assert_eq!(exec_program("env FOO=1"), None);
    }

    #[test]
    fn an_earlier_data_folder_hides_a_later_entry() {
        let (first, second) = (temp_folder("first"), temp_folder("second"));
        for folder in [&first, &second] {
            fs::create_dir_all(folder.join("applications/sub")).unwrap();
        }
        let entry =
            |name: &str| format!("[Desktop Entry]\nType=Application\nName={name}\nExec=/opt/x\n");
        fs::write(first.join("applications/same.desktop"), entry("First")).unwrap();
        fs::write(second.join("applications/same.desktop"), entry("Second")).unwrap();
        fs::write(
            second.join("applications/sub/other.desktop"),
            entry("Other"),
        )
        .unwrap();
        fs::write(
            first.join("applications/gone.desktop"),
            "[Desktop Entry]\nHidden=true\n",
        )
        .unwrap();
        fs::write(second.join("applications/gone.desktop"), entry("Gone")).unwrap();
        fs::write(second.join("applications/notes.txt"), entry("Notes")).unwrap();
        let mut names: Vec<_> = read_apps(&[first.clone(), second.clone()])
            .into_iter()
            .map(|app| app.name)
            .collect();
        names.sort();
        assert_eq!(names, ["First", "Other"]);
        fs::remove_dir_all(first).unwrap();
        fs::remove_dir_all(second).unwrap();
    }

    #[test]
    fn data_folders_follow_the_base_directory_spec() {
        let folders = |home_data: Option<&str>, data: Option<&str>, home: Option<&str>| {
            data_folders_from(
                home_data.map(Into::into),
                data.map(Into::into),
                home.map(Into::into),
            )
        };
        let paths = |list: &[&str]| list.iter().map(PathBuf::from).collect::<Vec<_>>();
        assert_eq!(
            folders(None, None, Some("/home/user")),
            paths(&["/home/user/.local/share", "/usr/local/share", "/usr/share"])
        );
        assert_eq!(
            folders(Some("/data"), Some("/a:relative:/b"), Some("/home/user")),
            paths(&["/data", "/a", "/b"])
        );
        assert_eq!(
            folders(None, Some(""), None),
            paths(&["/usr/local/share", "/usr/share"])
        );
    }

    #[test]
    fn the_nearest_png_is_found_and_a_scalable_icon_is_not() {
        let folder = temp_folder("icons");
        let sized = |size: u32| {
            let path = folder.join(format!("hicolor/{size}x{size}/apps"));
            fs::create_dir_all(&path).unwrap();
            path.join("app.png")
        };
        fs::write(sized(32), "").unwrap();
        fs::write(sized(128), "").unwrap();
        let folders = [folder.clone()];
        assert_eq!(find_icon("app", 24, &folders), Some(sized(32)));
        assert_eq!(find_icon("app", 48, &folders), Some(sized(128)));
        assert_eq!(
            find_icon("app", 512, &folders),
            Some(sized(128)),
            "the largest"
        );
        assert_eq!(find_icon("none", 32, &folders), None);
        assert_eq!(find_icon("../app", 32, &folders), None);

        fs::write(folder.join("flat.png"), "").unwrap();
        assert_eq!(
            find_icon("flat", 32, &folders),
            Some(folder.join("flat.png"))
        );
        let absolute = folder.join("flat.png");
        assert_eq!(
            find_icon(absolute.to_str().unwrap(), 32, &[]),
            Some(absolute)
        );
        fs::write(folder.join("vector.svg"), "").unwrap();
        assert_eq!(
            find_icon(folder.join("vector.svg").to_str().unwrap(), 32, &[]),
            None
        );
        fs::remove_dir_all(folder).unwrap();
    }

    #[test]
    fn this_process_is_listed_with_its_own_file() {
        let processes = running_processes().unwrap();
        let own = processes
            .iter()
            .find(|process| process.pid == std::process::id())
            .expect("this process is in the list");
        assert_eq!(
            own.path.as_deref(),
            Some(std::env::current_exe().unwrap().as_path())
        );
    }
}
