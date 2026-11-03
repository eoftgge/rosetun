//! Starting the GUI at sign-in.
//!
//! A Task Scheduler task with a logon trigger for the user, not the HKCU
//! Run value: Explorer starts Run entries one after another, late and at a
//! lowered priority, while a logon task starts at sign-in on its own. The
//! user registers the task for themselves; no service is involved. Earlier
//! versions wrote the Run value, which is moved to the task once.

mod scheduler;
mod task;

use std::io;
#[cfg(test)]
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
};
use windows_sys::Win32::System::Registry::{
    HKEY_CURRENT_USER, RRF_RT_REG_BINARY, RRF_RT_REG_SZ, RegDeleteKeyValueW, RegGetValueW,
};
#[cfg(test)]
use windows_sys::Win32::System::Registry::{REG_SZ, RegSetKeyValueW};

use self::scheduler::Scheduler;
use self::task::TaskDefinition;

const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const APPROVED_KEY: &str =
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run";
const VALUE_NAME: &str = "Rosetun";
const MAX_VALUE_BYTES: u32 = 64 * 1024;

/// What starts at sign-in: `exe` followed by `argument`, and the task's
/// description in the interface language.
#[derive(Debug, Clone, Copy)]
pub struct Autostart<'a> {
    pub exe: &'a Path,
    pub argument: &'a str,
    pub description: &'a str,
}

/// A registered task as far as autostart cares.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TaskState {
    /// False when the user disabled the task in Task Scheduler.
    enabled: bool,
    command: Option<String>,
}

/// Where autostart can live: the user's task and the old Run value.
trait Places {
    fn task(&self) -> io::Result<Option<TaskState>>;
    fn register_task(&self, xml: &str) -> io::Result<()>;
    fn delete_task(&self) -> io::Result<()>;
    /// The Run value exists and Task Manager has not disabled it.
    fn run_enabled(&self) -> io::Result<bool>;
    /// Deletes the Run value and Task Manager's mark for it.
    fn delete_run(&self) -> io::Result<()>;
}

struct System {
    scheduler: Scheduler,
    user_sid: String,
}

impl System {
    fn open() -> io::Result<Self> {
        Ok(Self {
            scheduler: Scheduler::connect(scheduler::FOLDER)?,
            user_sid: crate::link_pipe::current_user_sid()?,
        })
    }

    /// One task per user, so users of one computer do not replace each other's.
    fn task_name(&self) -> String {
        format!("Autostart-{}", self.user_sid)
    }
}

impl Places for System {
    fn task(&self) -> io::Result<Option<TaskState>> {
        self.scheduler.state(&self.task_name())
    }

    fn register_task(&self, xml: &str) -> io::Result<()> {
        self.scheduler.register(&self.task_name(), xml)
    }

    fn delete_task(&self) -> io::Result<()> {
        self.scheduler.delete(&self.task_name())
    }

    fn run_enabled(&self) -> io::Result<bool> {
        autostart_enabled_at(RUN_KEY, APPROVED_KEY, VALUE_NAME)
    }

    fn delete_run(&self) -> io::Result<()> {
        delete_value(RUN_KEY, VALUE_NAME)?;
        delete_value(APPROVED_KEY, VALUE_NAME)
    }
}

/// Registers (or replaces) the user's sign-in task, then removes the Run
/// value. When the task cannot be registered, the Run value stays as it is.
pub fn enable_autostart(autostart: &Autostart<'_>) -> io::Result<()> {
    let system = System::open()?;
    let definition = definition(autostart, &system.user_sid);
    enable(&system, &definition)
}

/// Removes the sign-in task and the Run value.
pub fn disable_autostart() -> io::Result<()> {
    disable(&System::open()?)
}

/// The task exists, is enabled and starts `exe`; or the Run value of an
/// earlier version is still there and enabled.
pub fn autostart_enabled(exe: &Path) -> io::Result<bool> {
    enabled(&System::open()?, exe)
}

/// Moves an enabled Run value of an earlier version to the task. `true`
/// when something was moved; the Run value stays when the task fails.
pub fn move_autostart_to_task(autostart: &Autostart<'_>) -> io::Result<bool> {
    let system = System::open()?;
    let definition = definition(autostart, &system.user_sid);
    move_to_task(&system, &definition)
}

fn definition<'a>(autostart: &Autostart<'a>, user_sid: &'a str) -> TaskDefinition<'a> {
    TaskDefinition {
        user_sid,
        exe: autostart.exe,
        argument: autostart.argument,
        description: autostart.description,
    }
}

fn enable(places: &impl Places, definition: &TaskDefinition<'_>) -> io::Result<()> {
    places.register_task(&definition.xml())?;
    places.delete_run()
}

fn disable(places: &impl Places) -> io::Result<()> {
    let task = places.delete_task();
    let run = places.delete_run();
    task.and(run)
}

fn enabled(places: &impl Places, exe: &Path) -> io::Result<bool> {
    let task_runs_exe = places.task()?.is_some_and(|state| {
        state.enabled
            && state
                .command
                .as_deref()
                .is_some_and(|command| task::runs(command, exe))
    });
    Ok(task_runs_exe || places.run_enabled()?)
}

fn move_to_task(places: &impl Places, definition: &TaskDefinition<'_>) -> io::Result<bool> {
    if !places.run_enabled()? {
        return Ok(false);
    }
    enable(places, definition)?;
    Ok(true)
}

fn autostart_enabled_at(run: &str, approved: &str, name: &str) -> io::Result<bool> {
    if read_value(run, name, RRF_RT_REG_SZ)?.is_none() {
        return Ok(false);
    }
    match read_value(approved, name, RRF_RT_REG_BINARY)? {
        None => Ok(true),
        Some(bytes) => bytes
            .first()
            .map(|byte| byte & 1 == 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty startup approval")),
    }
}

#[cfg(test)]
fn command_line(exe: &Path, argument: &str) -> Vec<u16> {
    let mut command = vec![u16::from(b'"')];
    command.extend(exe.as_os_str().encode_wide());
    command.extend([u16::from(b'"'), u16::from(b' ')]);
    command.extend(argument.encode_utf16());
    command.push(0);
    command
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn missing(status: u32) -> bool {
    status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND
}

#[cfg(test)]
fn write_value(subkey: &str, name: &str, kind: u32, data: &[u8]) -> io::Result<()> {
    let subkey = wide(subkey);
    let name = wide(name);
    // SAFETY: HKCU is a predefined borrowed handle. Both UTF-16 names and the
    // initialized data buffer remain valid for this synchronous Windows ABI call.
    let status = unsafe {
        RegSetKeyValueW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            name.as_ptr(),
            kind,
            data.as_ptr().cast(),
            data.len() as u32,
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

fn delete_value(subkey: &str, name: &str) -> io::Result<()> {
    let subkey = wide(subkey);
    let name = wide(name);
    // SAFETY: HKCU is borrowed; the NUL-terminated names live through the ABI call.
    let status = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, subkey.as_ptr(), name.as_ptr()) };
    if status == ERROR_SUCCESS || missing(status) {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

fn read_value(subkey: &str, name: &str, flags: u32) -> io::Result<Option<Vec<u8>>> {
    let subkey = wide(subkey);
    let name = wide(name);
    for _ in 0..4 {
        let mut size = 0;
        // SAFETY: HKCU is borrowed; both names and the writable byte count live
        // through the call. A null data pointer requests the required size.
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                name.as_ptr(),
                flags,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if missing(status) {
            return Ok(None);
        }
        if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if size > MAX_VALUE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "registry value too large",
            ));
        }
        if size == 0 {
            return Ok(Some(Vec::new()));
        }
        let mut bytes = vec![0u8; size as usize];
        let mut returned_size = size;
        // SAFETY: The vector is an initialized writable buffer of `size` bytes;
        // its pointer and byte count, HKCU and both names remain valid for this
        // synchronous ABI call. The returned size is checked before use.
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                name.as_ptr(),
                flags,
                std::ptr::null_mut(),
                bytes.as_mut_ptr().cast(),
                &mut returned_size,
            )
        };
        if missing(status) {
            return Ok(None);
        }
        if status == ERROR_MORE_DATA {
            continue;
        }
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if returned_size > size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid registry value size",
            ));
        }
        bytes.truncate(returned_size as usize);
        return Ok(Some(bytes));
    }
    Err(io::Error::other("registry value changed during read"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Registry::{REG_BINARY, RegDeleteKeyW};

    struct TestKey {
        root: String,
    }

    impl Drop for TestKey {
        fn drop(&mut self) {
            for key in [
                format!("{}\\Approved", self.root),
                format!("{}\\Run", self.root),
                self.root.clone(),
            ] {
                let key = wide(&key);
                // SAFETY: HKCU is borrowed and the key name is NUL-terminated and
                // lives through the call. Test keys contain no child keys.
                unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, key.as_ptr()) };
            }
        }
    }

    use std::cell::RefCell;

    const SID: &str = "S-1-5-21-1-2-3-1001";
    const EXE: &str = r"C:\Program Files\Rosetun\rosetun-gui.exe";

    /// Task and Run value in memory; `refuse_task` fails registration.
    #[derive(Default)]
    struct FakePlaces {
        task: RefCell<Option<TaskState>>,
        run: RefCell<bool>,
        refuse_task: bool,
        calls: RefCell<Vec<&'static str>>,
    }

    impl Places for FakePlaces {
        fn task(&self) -> io::Result<Option<TaskState>> {
            Ok(self.task.borrow().clone())
        }

        fn register_task(&self, xml: &str) -> io::Result<()> {
            self.calls.borrow_mut().push("register");
            if self.refuse_task {
                return Err(io::Error::from_raw_os_error(5));
            }
            *self.task.borrow_mut() = Some(TaskState {
                enabled: true,
                command: task::command_of(xml),
            });
            Ok(())
        }

        fn delete_task(&self) -> io::Result<()> {
            self.calls.borrow_mut().push("delete task");
            *self.task.borrow_mut() = None;
            Ok(())
        }

        fn run_enabled(&self) -> io::Result<bool> {
            Ok(*self.run.borrow())
        }

        fn delete_run(&self) -> io::Result<()> {
            self.calls.borrow_mut().push("delete run");
            *self.run.borrow_mut() = false;
            Ok(())
        }
    }

    fn gui(exe: &str) -> TaskDefinition<'_> {
        TaskDefinition {
            user_sid: SID,
            exe: Path::new(exe),
            argument: "--hidden",
            description: "Starts Rosetun at sign-in",
        }
    }

    #[test]
    fn enabling_registers_the_task_before_removing_the_run_value() {
        let places = FakePlaces {
            run: RefCell::new(true),
            ..FakePlaces::default()
        };
        enable(&places, &gui(EXE)).unwrap();
        assert_eq!(*places.calls.borrow(), ["register", "delete run"]);
        assert!(!*places.run.borrow());
        assert!(enabled(&places, Path::new(EXE)).unwrap());
    }

    #[test]
    fn a_task_that_cannot_be_registered_leaves_the_run_value() {
        let places = FakePlaces {
            run: RefCell::new(true),
            refuse_task: true,
            ..FakePlaces::default()
        };
        assert_eq!(
            enable(&places, &gui(EXE)).unwrap_err().raw_os_error(),
            Some(5)
        );
        assert!(*places.run.borrow());
        assert_eq!(move_to_task(&places, &gui(EXE)).ok(), None);
        assert!(*places.run.borrow());
        assert!(enabled(&places, Path::new(EXE)).unwrap());
    }

    #[test]
    fn an_enabled_run_value_moves_to_the_task_once() {
        let places = FakePlaces {
            run: RefCell::new(true),
            ..FakePlaces::default()
        };
        assert!(move_to_task(&places, &gui(EXE)).unwrap());
        assert!(!*places.run.borrow());
        assert!(enabled(&places, Path::new(EXE)).unwrap());
        assert!(!move_to_task(&places, &gui(EXE)).unwrap());
        assert_eq!(*places.calls.borrow(), ["register", "delete run"]);
    }

    #[test]
    fn without_an_enabled_run_value_nothing_moves() {
        let places = FakePlaces::default();
        assert!(!move_to_task(&places, &gui(EXE)).unwrap());
        assert!(places.calls.borrow().is_empty());
        assert!(!enabled(&places, Path::new(EXE)).unwrap());
    }

    #[test]
    fn disabling_removes_both_the_task_and_the_run_value() {
        let places = FakePlaces {
            run: RefCell::new(true),
            ..FakePlaces::default()
        };
        enable(&places, &gui(EXE)).unwrap();
        *places.run.borrow_mut() = true;
        disable(&places).unwrap();
        assert!(places.task.borrow().is_none());
        assert!(!*places.run.borrow());
        assert!(!enabled(&places, Path::new(EXE)).unwrap());
    }

    #[test]
    fn a_task_disabled_by_the_user_or_for_another_path_is_off() {
        let places = FakePlaces::default();
        enable(&places, &gui(r"D:\Old\rosetun-gui.exe")).unwrap();
        assert!(!enabled(&places, Path::new(EXE)).unwrap());
        enable(&places, &gui(EXE)).unwrap();
        assert!(enabled(&places, Path::new(EXE)).unwrap());
        places.task.borrow_mut().as_mut().unwrap().enabled = false;
        assert!(!enabled(&places, Path::new(EXE)).unwrap());
        enable(&places, &gui(EXE)).unwrap();
        assert!(enabled(&places, Path::new(EXE)).unwrap());
    }

    /// Registers, reads and deletes a real task in a test folder of the
    /// current user's Task Scheduler. Run with `--ignored` on Windows.
    #[test]
    #[ignore = "changes the real Task Scheduler"]
    fn a_real_sign_in_task_lifecycle() {
        const TEST_FOLDER: &str = "RosetunTest";
        let scheduler = Scheduler::connect(TEST_FOLDER).unwrap();
        let sid = crate::link_pipe::current_user_sid().unwrap();
        let name = format!("Autostart-{sid}-{}", std::process::id());
        let exe = std::env::current_exe().unwrap();
        let definition = TaskDefinition {
            user_sid: &sid,
            exe: &exe,
            argument: "--hidden",
            description: "Rosetun test task",
        };
        let result = std::panic::catch_unwind(|| {
            assert_eq!(scheduler.state(&name).unwrap(), None);
            scheduler.register(&name, &definition.xml()).unwrap();
            scheduler.register(&name, &definition.xml()).unwrap();
            let state = scheduler.state(&name).unwrap().unwrap();
            assert!(state.enabled);
            assert!(task::runs(state.command.as_deref().unwrap(), &exe));
        });
        scheduler.delete(&name).unwrap();
        assert_eq!(scheduler.state(&name).unwrap(), None);
        scheduler.delete(&name).unwrap();
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    #[test]
    fn command_line_quotes_executable_and_ends_with_nul() {
        let command = command_line(
            Path::new(r"C:\Program Files\Rosetun\rosetun-gui.exe"),
            "--hidden",
        );
        let expected: Vec<u16> = "\"C:\\Program Files\\Rosetun\\rosetun-gui.exe\" --hidden\0"
            .encode_utf16()
            .collect();
        assert_eq!(command, expected);
    }

    #[test]
    fn registry_value_lifecycle_and_approval() {
        let key = TestKey {
            root: format!("Software\\Rosetun-test-{}", std::process::id()),
        };
        let run = format!("{}\\Run", key.root);
        let approved = format!("{}\\Approved", key.root);
        let command: Vec<u8> = command_line(Path::new(r"C:\Rosetun\rosetun-gui.exe"), "--hidden")
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert!(!autostart_enabled_at(&run, &approved, VALUE_NAME).unwrap());
        write_value(&run, VALUE_NAME, REG_SZ, &command).unwrap();
        assert_eq!(
            read_value(&run, VALUE_NAME, RRF_RT_REG_SZ).unwrap(),
            Some(command)
        );
        assert!(autostart_enabled_at(&run, &approved, VALUE_NAME).unwrap());

        write_value(&approved, VALUE_NAME, REG_BINARY, &[0x03, 0]).unwrap();
        assert!(!autostart_enabled_at(&run, &approved, VALUE_NAME).unwrap());
        write_value(&approved, VALUE_NAME, REG_BINARY, &[0x04, 0]).unwrap();
        assert!(autostart_enabled_at(&run, &approved, VALUE_NAME).unwrap());
        delete_value(&approved, VALUE_NAME).unwrap();
        assert!(autostart_enabled_at(&run, &approved, VALUE_NAME).unwrap());

        delete_value(&run, VALUE_NAME).unwrap();
        delete_value(&run, VALUE_NAME).unwrap();
        assert_eq!(read_value(&run, VALUE_NAME, RRF_RT_REG_SZ).unwrap(), None);
        assert!(!autostart_enabled_at(&run, &approved, VALUE_NAME).unwrap());
    }
}
