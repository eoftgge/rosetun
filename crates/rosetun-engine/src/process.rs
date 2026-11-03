//! Engine processes on Linux: each starts in a process group of its own and
//! is tied to the helper's life.
//!
//! `PR_SET_PDEATHSIG` fires when the *thread* that forked the child ends,
//! not the process. The helper starts engines from client threads that end
//! with their connection, so every engine is forked by one launcher thread
//! that lives as long as the process; the engine then gets SIGTERM only
//! when the helper itself dies.
//!
//! Under the systemd unit every engine also starts in the `engines` cgroup
//! leaf, which the kill switch permits: the child moves itself there before
//! `exec`, so no socket of the engine is ever made outside it.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::sync::mpsc::{self, Sender};
use std::sync::{Mutex, PoisonError};
use std::thread;

type Job = (Command, Sender<io::Result<Child>>);

/// Never dropped, so the launcher's loop never ends.
static LAUNCHER: Mutex<Option<Sender<Job>>> = Mutex::new(None);

static PLACEMENT: Mutex<Placement> = Mutex::new(Placement::Inherit);

/// Which cgroup engines start in.
#[derive(Debug)]
pub enum Placement {
    /// The helper's own, outside the systemd unit, where there is no kill
    /// switch to tell engines apart.
    Inherit,
    /// The leaf whose `cgroup.procs` this is, opened for writing. Writing
    /// `0` there moves the writing process.
    Leaf(File),
    /// Under the unit the leaf could not be made: engines do not start at
    /// all rather than in the helper's cgroup.
    Refused(String),
}

/// Sets where every later engine starts. The helper calls it once, before
/// the first engine.
pub fn place_engines(placement: Placement) {
    *PLACEMENT.lock().unwrap_or_else(PoisonError::into_inner) = placement;
}

fn launcher() -> io::Result<Sender<Job>> {
    let mut launcher = LAUNCHER.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(sender) = launcher.as_ref() {
        return Ok(sender.clone());
    }
    let (sender, jobs) = mpsc::channel::<Job>();
    thread::Builder::new()
        .name("engine-launcher".to_owned())
        .spawn(move || {
            for (mut command, reply) in jobs {
                let placement = PLACEMENT.lock().unwrap_or_else(PoisonError::into_inner);
                let _ = reply.send(launch(&mut command, &placement));
            }
        })?;
    *launcher = Some(sender.clone());
    Ok(sender)
}

fn launch(command: &mut Command, placement: &Placement) -> io::Result<Child> {
    let helper = std::process::id();
    let leaf = match placement {
        Placement::Inherit => None,
        Placement::Leaf(procs) => Some(procs.as_raw_fd()),
        Placement::Refused(reason) => {
            return Err(io::Error::other(format!(
                "engines cannot start in their own cgroup: {reason}"
            )));
        }
    };
    command.process_group(0);
    // SAFETY: The hook runs in the forked child before exec and calls only
    // async-signal-safe functions (prctl, getppid, write, _exit) on plain
    // values; it allocates nothing and touches no lock. `helper` was read
    // before fork; `leaf` is a descriptor the caller keeps open (the
    // placement lock is held across the spawn), inherited by the child
    // and closed at exec.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGTERM as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            // The helper may have died between fork and prctl: then no
            // signal will ever come, so do not start at all.
            if u32::try_from(libc::getppid()).ok() != Some(helper) {
                libc::_exit(1);
            }
            // "0" moves the writing process, so the engine is in its leaf
            // before exec and every socket it makes belongs to the leaf.
            if let Some(leaf) = leaf
                && libc::write(leaf, b"0".as_ptr().cast(), 1) != 1
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn()
}

/// Starts `command` in a process group of its own, with SIGTERM delivered to
/// it when the helper dies. The standard library clears the signal mask in
/// the child, so the engine does not inherit the helper's blocked signals.
pub fn spawn(command: Command) -> io::Result<Child> {
    let (reply, result) = mpsc::channel();
    launcher()?
        .send((command, reply))
        .map_err(|_| io::Error::other("engine launcher is gone"))?;
    result
        .recv()
        .map_err(|_| io::Error::other("engine launcher is gone"))?
}

/// Sends SIGTERM to the process group led by `child`. Only a child that
/// leads its own group (as `spawn` starts it) is interrupted; any other is
/// `ErrorKind::Unsupported`, because its group may hold the helper itself.
pub fn interrupt_group(child: &mut Child) -> io::Result<()> {
    let pid = libc::pid_t::try_from(child.id())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pid out of range"))?;
    // SAFETY: Plain value. The `&mut Child` is not reaped, so its pid cannot
    // have been reused by another process.
    let group = unsafe { libc::getpgid(pid) };
    if group < 0 {
        return Err(io::Error::last_os_error());
    }
    if group != pid {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the process does not lead a group of its own",
        ));
    }
    // SAFETY: Plain values. The group is the one the unreaped child leads,
    // so the signal reaches only processes the helper started.
    if unsafe { libc::kill(-pid, libc::SIGTERM) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::process::Stdio;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "rosetun-process-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A fake engine: records TERM in `term`, and starts a second shell in
    /// the same group that records TERM in `child-term`.
    fn fake_engine(dir: &Path) -> Command {
        let script = r#"
            trap 'echo term > "$1/term"; exit 0' TERM
            sh -c 'trap "echo term > \"$1/child-term\"; exit 0" TERM; echo $$ > "$1/child"; while :; do sleep 1; done' inner "$1" &
            echo $$ > "$1/ready"
            while :; do sleep 1; done
        "#;
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", script, "fake-engine"])
            .arg(dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    fn wait_for(path: &Path, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        while !path.exists() {
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(20));
        }
        true
    }

    fn wait_exit(child: &mut Child, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        loop {
            if child.try_wait().unwrap().is_some() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn pid_in(path: &Path) -> libc::pid_t {
        std::fs::read_to_string(path)
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    fn kill_group(pid: libc::pid_t) {
        // SAFETY: Plain values; the test's own fake engine group.
        unsafe { libc::kill(-pid, libc::SIGKILL) };
    }

    #[test]
    fn an_engine_writes_itself_into_its_leaf_before_it_runs() {
        let dir = TempDir::new();
        let procs = dir.0.join("cgroup.procs");
        let leaf = Placement::Leaf(File::create(&procs).unwrap());
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "cat \"$1\" > \"$1.seen\"", "fake-engine"])
            .arg(&procs)
            .stdin(Stdio::null());
        let mut child = launch(&mut command, &leaf).unwrap();
        assert!(child.wait().unwrap().success());
        // The child wrote before exec; the program it became saw the write.
        assert_eq!(std::fs::read_to_string(&procs).unwrap(), "0");
        assert_eq!(
            std::fs::read_to_string(dir.0.join("cgroup.procs.seen")).unwrap(),
            "0"
        );
    }

    #[test]
    fn without_its_leaf_an_engine_does_not_start() {
        let dir = TempDir::new();
        let refused = Placement::Refused("the unit's cgroup is not delegated".to_owned());
        let error = launch(&mut fake_engine(&dir.0), &refused).unwrap_err();
        assert!(error.to_string().contains("not delegated"), "{error}");
        assert!(!wait_for(&dir.0.join("ready"), Duration::from_millis(300)));
    }

    #[test]
    fn a_leaf_that_refuses_the_move_stops_the_engine_before_it_runs() {
        let dir = TempDir::new();
        let procs = dir.0.join("cgroup.procs");
        std::fs::write(&procs, "").unwrap();
        // Opened for reading only: the write in the child fails.
        let leaf = Placement::Leaf(File::open(&procs).unwrap());
        assert!(launch(&mut fake_engine(&dir.0), &leaf).is_err());
        assert!(!wait_for(&dir.0.join("ready"), Duration::from_millis(300)));
    }

    #[test]
    fn an_engine_leads_its_own_group_and_the_interrupt_reaches_all_of_it() {
        let dir = TempDir::new();
        let mut child = spawn(fake_engine(&dir.0)).unwrap();
        assert!(wait_for(&dir.0.join("child"), Duration::from_secs(5)));
        let pid = libc::pid_t::try_from(child.id()).unwrap();
        // SAFETY: Plain values; our own unreaped child and its group member.
        let (own, inner) = unsafe {
            (
                libc::getpgid(pid),
                libc::getpgid(pid_in(&dir.0.join("child"))),
            )
        };
        assert_eq!(own, pid);
        assert_eq!(inner, pid);

        interrupt_group(&mut child).unwrap();
        assert!(wait_exit(&mut child, Duration::from_secs(5)));
        assert!(wait_for(&dir.0.join("term"), Duration::from_secs(5)));
        assert!(wait_for(&dir.0.join("child-term"), Duration::from_secs(5)));
    }

    #[test]
    fn a_process_outside_its_own_group_is_not_interrupted() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let error = interrupt_group(&mut child).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn an_engine_outlives_the_thread_that_asked_for_it() {
        let dir = TempDir::new();
        let path = dir.0.clone();
        let mut child = thread::spawn(move || spawn(fake_engine(&path)).unwrap())
            .join()
            .unwrap();
        assert!(wait_for(&dir.0.join("ready"), Duration::from_secs(5)));
        thread::sleep(Duration::from_millis(300));
        assert!(child.try_wait().unwrap().is_none());
        assert!(!dir.0.join("term").exists());
        kill_group(libc::pid_t::try_from(child.id()).unwrap());
        child.wait().unwrap();
    }

    /// The parent stands in for the helper: it blocks SIGTERM as the helper
    /// does, starts the engine and dies. The engine must get SIGTERM.
    #[test]
    fn an_engine_gets_sigterm_when_the_helper_dies() {
        const PARENT: &str = "ROSETUN_TEST_ENGINE_PARENT";
        if let Some(dir) = std::env::var_os(PARENT) {
            let mut set = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
            // SAFETY: Initializes and fills a local set, then blocks it for
            // this thread only; the launcher thread inherits the mask.
            unsafe {
                libc::sigemptyset(set.as_mut_ptr());
                libc::sigaddset(set.as_mut_ptr(), libc::SIGTERM);
                libc::pthread_sigmask(libc::SIG_BLOCK, set.as_ptr(), std::ptr::null_mut());
            }
            let dir = PathBuf::from(dir);
            #[expect(
                clippy::zombie_processes,
                reason = "this process dies at once, as a killed helper would"
            )]
            let child = spawn(fake_engine(&dir)).unwrap();
            assert!(wait_for(&dir.join("ready"), Duration::from_secs(5)));
            std::fs::write(dir.join("engine"), child.id().to_string()).unwrap();
            // SAFETY: Ends this test process at once, as a killed helper would.
            unsafe { libc::_exit(0) };
        }

        let dir = TempDir::new();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "process::tests::an_engine_gets_sigterm_when_the_helper_dies",
            ])
            .env(PARENT, &dir.0)
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        let engine = pid_in(&dir.0.join("engine"));
        let delivered = wait_for(&dir.0.join("term"), Duration::from_secs(5));
        // The inner shell got no signal and still runs in the group.
        kill_group(engine);
        assert!(delivered, "the orphaned engine did not get SIGTERM");
    }
}
