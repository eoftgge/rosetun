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
//! `exec`, so no socket of the engine is ever made outside it. Without the
//! leaf engines start in the helper's own cgroup and there is no protection
//! to permit them.
//!
//! An engine parses what the network sends it, so it does not run as root: the
//! child takes the `rosetun-engine` account before `exec`, keeping only the
//! capabilities in `ENGINE_CAPABILITIES`, as ambient ones so they survive
//! `exec`. Anything that fails on the way stops the engine before it runs.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
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

static IDENTITY: Mutex<Identity> = Mutex::new(Identity::Inherit);

/// The account engines run as, from `packaging/linux/rosetun.sysusers`.
pub const ENGINE_ACCOUNT: &str = "rosetun-engine";

const CAP_NET_BIND_SERVICE: u32 = 10;
const CAP_NET_ADMIN: u32 = 12;
const CAP_NET_RAW: u32 = 13;

/// What sing-box and Xray need and nothing else. `CAP_NET_ADMIN`: the TUN device
/// (`TUNSETIFF`), `auto_route`'s routes and rules over netlink, the rp_filter of
/// the new interface, `SO_MARK`. `CAP_NET_RAW`: `SO_BINDTODEVICE` for
/// `auto_detect_interface` and Xray's `sockopt.interface` on kernels before 5.7.
/// `CAP_NET_BIND_SERVICE`: a local proxy on a port below 1024.
///
/// `CAP_SYS_PTRACE`, which sing-box would need to read another account's
/// `/proc/<pid>/exe` and `/proc/<pid>/fd` for rules by program, is left out on
/// purpose: it lets a process inject code into root's, which is what this account
/// is there to prevent. The backend therefore does not offer those rules on Linux.
const ENGINE_CAPABILITIES: [u32; 3] = [CAP_NET_BIND_SERVICE, CAP_NET_ADMIN, CAP_NET_RAW];

/// `_LINUX_CAPABILITY_VERSION_3`.
const CAPABILITY_VERSION: u32 = 0x2008_0522;

/// An account engines can run as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Account {
    pub uid: u32,
    pub gid: u32,
}

/// Whose rights engines run with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    /// The helper's own, outside the systemd unit, where nothing is protected
    /// and nothing is installed.
    Inherit,
    Account(Account),
    /// The service needs the account and it is not there: no engine starts,
    /// rather than one that runs as root.
    Missing,
}

/// What the child does to become `account`, in this order, which matters: the
/// groups and the group go while it can still change them, `PR_SET_KEEPCAPS` has
/// to precede `setresuid` or the capabilities go with it, and a capability can
/// only be made ambient once it is permitted and inheritable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    KeepCapabilities,
    SetGroups(u32),
    SetGid(u32),
    SetUid(u32),
    SetCapabilities(u64),
    RaiseAmbient(u32),
    NoNewPrivileges,
}

const DROP_STEPS: usize = 6 + ENGINE_CAPABILITIES.len();

fn capability_mask(capabilities: &[u32]) -> u64 {
    capabilities
        .iter()
        .fold(0, |mask, capability| mask | 1u64 << capability)
}

/// A plain value made before `fork`, so the child allocates nothing.
fn drop_steps(account: Account) -> [Step; DROP_STEPS] {
    let [first, second, third] = ENGINE_CAPABILITIES;
    [
        Step::KeepCapabilities,
        Step::SetGroups(account.gid),
        Step::SetGid(account.gid),
        Step::SetUid(account.uid),
        Step::SetCapabilities(capability_mask(&ENGINE_CAPABILITIES)),
        Step::RaiseAmbient(first),
        Step::RaiseAmbient(second),
        Step::RaiseAmbient(third),
        Step::NoNewPrivileges,
    ]
}

/// Runs in the forked child: raw system calls on plain values, which are
/// async-signal-safe and, the child having one thread, reach all of it.
///
/// # Safety
/// Only between `fork` and `exec`: it changes the credentials of the thread.
unsafe fn apply(step: Step) -> io::Result<()> {
    let zero = 0 as libc::c_ulong;
    // SAFETY: Every call takes plain values, or pointers to locals that outlive
    // it and have the layout the kernel documents (`setgroups`, `capset`).
    let result = unsafe {
        match step {
            Step::KeepCapabilities => libc::syscall(
                libc::SYS_prctl,
                libc::PR_SET_KEEPCAPS as libc::c_ulong,
                1 as libc::c_ulong,
                zero,
                zero,
                zero,
            ),
            Step::SetGroups(gid) => {
                let groups = [gid];
                libc::syscall(libc::SYS_setgroups, groups.len(), groups.as_ptr())
            }
            Step::SetGid(gid) => libc::syscall(libc::SYS_setresgid, gid, gid, gid),
            Step::SetUid(uid) => libc::syscall(libc::SYS_setresuid, uid, uid, uid),
            Step::SetCapabilities(mask) => {
                let header = CapabilityHeader {
                    version: CAPABILITY_VERSION,
                    pid: 0,
                };
                let low = mask as u32;
                let high = (mask >> 32) as u32;
                let data = [
                    CapabilityData {
                        effective: low,
                        permitted: low,
                        inheritable: low,
                    },
                    CapabilityData {
                        effective: high,
                        permitted: high,
                        inheritable: high,
                    },
                ];
                libc::syscall(libc::SYS_capset, &raw const header, data.as_ptr())
            }
            Step::RaiseAmbient(capability) => libc::syscall(
                libc::SYS_prctl,
                libc::PR_CAP_AMBIENT as libc::c_ulong,
                libc::PR_CAP_AMBIENT_RAISE as libc::c_ulong,
                capability as libc::c_ulong,
                zero,
                zero,
            ),
            Step::NoNewPrivileges => libc::syscall(
                libc::SYS_prctl,
                libc::PR_SET_NO_NEW_PRIVS as libc::c_ulong,
                1 as libc::c_ulong,
                zero,
                zero,
                zero,
            ),
        }
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `struct __user_cap_header_struct`.
#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: libc::c_int,
}

/// `struct __user_cap_data_struct`.
#[repr(C)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// The account engines run as, if the system has it.
pub fn engine_account() -> io::Result<Option<Account>> {
    let name = CString::new(ENGINE_ACCOUNT).map_err(io::Error::other)?;
    let mut entry = MaybeUninit::<libc::passwd>::uninit();
    let mut buffer = vec![0u8; 1024];
    loop {
        let mut found = std::ptr::null_mut();
        // SAFETY: getpwnam_r borrows the NUL-terminated name and the writable
        // buffers for this call only, and writes the entry into them.
        let result = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut found,
            )
        };
        if result == libc::ERANGE && buffer.len() < 1024 * 1024 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        if found.is_null() {
            return Ok(None);
        }
        // SAFETY: A non-null `found` means getpwnam_r initialized the entry.
        let entry = unsafe { entry.assume_init() };
        return Ok(Some(Account {
            uid: entry.pw_uid,
            gid: entry.pw_gid,
        }));
    }
}

/// Sets whose rights every later engine runs with. The helper calls it once,
/// before the first engine.
pub fn run_engines_as(identity: Identity) {
    *IDENTITY.lock().unwrap_or_else(PoisonError::into_inner) = identity;
}

/// The group that may read engines' files, when engines run as an account.
pub fn engine_group() -> Option<u32> {
    match *IDENTITY.lock().unwrap_or_else(PoisonError::into_inner) {
        Identity::Account(account) => Some(account.gid),
        Identity::Inherit | Identity::Missing => None,
    }
}

/// Which cgroup engines start in.
#[derive(Debug)]
pub enum Placement {
    /// The helper's own: outside the systemd unit, or under it when the
    /// leaves could not be made. The routing backend then installs no rules
    /// at all, so nothing in this cgroup is ever permitted.
    Inherit,
    /// The leaf whose `cgroup.procs` this is, opened for writing. Writing
    /// `0` there moves the writing process.
    Leaf(File),
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
                let identity = *IDENTITY.lock().unwrap_or_else(PoisonError::into_inner);
                let _ = reply.send(launch(&mut command, &placement, identity));
            }
        })?;
    *launcher = Some(sender.clone());
    Ok(sender)
}

fn launch(command: &mut Command, placement: &Placement, identity: Identity) -> io::Result<Child> {
    let steps = match identity {
        Identity::Inherit => None,
        Identity::Account(account) => Some(drop_steps(account)),
        Identity::Missing => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("the account {ENGINE_ACCOUNT} is missing, and engines do not run as root"),
            ));
        }
    };
    let helper = std::process::id();
    let leaf = match placement {
        Placement::Inherit => None,
        Placement::Leaf(procs) => Some(procs.as_raw_fd()),
    };
    command.process_group(0);
    // SAFETY: The hook runs in the forked child before exec and calls only
    // async-signal-safe functions (raw system calls, prctl, getppid, write,
    // _exit) on plain values; it allocates nothing and touches no lock. `helper`
    // and `steps` were made before fork; `leaf` is a descriptor the caller keeps
    // open (the placement lock is held across the spawn), inherited by the child
    // and closed at exec.
    unsafe {
        command.pre_exec(move || {
            // "0" moves the writing process, so the engine is in its leaf
            // before exec and every socket it makes belongs to the leaf. As
            // root: only root may write there.
            if let Some(leaf) = leaf
                && libc::write(leaf, b"0".as_ptr().cast(), 1) != 1
            {
                return Err(io::Error::last_os_error());
            }
            if let Some(steps) = steps {
                for step in steps {
                    apply(step)?;
                }
            }
            // After the change of account, which clears the signal.
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
        let mut child = launch(&mut command, &leaf, Identity::Inherit).unwrap();
        assert!(child.wait().unwrap().success());
        // The child wrote before exec; the program it became saw the write.
        assert_eq!(std::fs::read_to_string(&procs).unwrap(), "0");
        assert_eq!(
            std::fs::read_to_string(dir.0.join("cgroup.procs.seen")).unwrap(),
            "0"
        );
    }

    #[test]
    fn without_a_leaf_an_engine_starts_in_the_helpers_cgroup() {
        let dir = TempDir::new();
        let mut child = launch(
            &mut fake_engine(&dir.0),
            &Placement::Inherit,
            Identity::Inherit,
        )
        .unwrap();
        assert!(wait_for(&dir.0.join("ready"), Duration::from_secs(5)));
        let own = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let engine = std::fs::read_to_string(format!("/proc/{}/cgroup", child.id())).unwrap();
        assert_eq!(engine, own);
        kill_group(libc::pid_t::try_from(child.id()).unwrap());
        child.wait().unwrap();
    }

    #[test]
    fn a_leaf_that_refuses_the_move_stops_the_engine_before_it_runs() {
        let dir = TempDir::new();
        let procs = dir.0.join("cgroup.procs");
        std::fs::write(&procs, "").unwrap();
        // Opened for reading only: the write in the child fails.
        let leaf = Placement::Leaf(File::open(&procs).unwrap());
        assert!(launch(&mut fake_engine(&dir.0), &leaf, Identity::Inherit).is_err());
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

#[cfg(test)]
mod identity_tests {
    use super::*;

    const ACCOUNT: Account = Account {
        uid: 64000,
        gid: 64001,
    };

    fn position(steps: &[Step], wanted: impl Fn(&Step) -> bool) -> usize {
        steps.iter().position(wanted).expect("the step is there")
    }

    #[test]
    fn engines_keep_exactly_the_network_capabilities() {
        // Bits 10, 12 and 13, as CapEff and CapAmb print them in /proc/<pid>/status.
        assert_eq!(capability_mask(&ENGINE_CAPABILITIES), 0x3400);
        assert_eq!(
            drop_steps(ACCOUNT)[4],
            Step::SetCapabilities(0x3400),
            "permitted, effective and inheritable"
        );
    }

    #[test]
    fn the_account_is_taken_in_the_order_the_kernel_needs() {
        let steps = drop_steps(ACCOUNT);
        let keep = position(&steps, |step| matches!(step, Step::KeepCapabilities));
        let groups = position(&steps, |step| matches!(step, Step::SetGroups(_)));
        let gid = position(&steps, |step| matches!(step, Step::SetGid(_)));
        let uid = position(&steps, |step| matches!(step, Step::SetUid(_)));
        let capabilities = position(&steps, |step| matches!(step, Step::SetCapabilities(_)));
        let ambient = position(&steps, |step| matches!(step, Step::RaiseAmbient(_)));
        let no_new = position(&steps, |step| matches!(step, Step::NoNewPrivileges));
        assert!(keep < uid, "without it setresuid takes the capabilities");
        assert!(groups < uid && gid < uid, "setresuid gives up the right to");
        assert!(uid < capabilities, "setresuid clears the effective set");
        assert!(
            capabilities < ambient,
            "only a permitted and inheritable one"
        );
        assert!(ambient < no_new);
    }

    #[test]
    fn the_steps_name_the_account() {
        let steps = drop_steps(ACCOUNT);
        assert!(steps.contains(&Step::SetGroups(ACCOUNT.gid)));
        assert!(steps.contains(&Step::SetGid(ACCOUNT.gid)));
        assert!(steps.contains(&Step::SetUid(ACCOUNT.uid)));
    }

    #[test]
    fn every_capability_is_raised_as_ambient() {
        let steps = drop_steps(ACCOUNT);
        for capability in ENGINE_CAPABILITIES {
            assert!(steps.contains(&Step::RaiseAmbient(capability)));
        }
    }

    fn marker_command(marker: &std::path::Path) -> Command {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(format!(": >{}", marker.display()));
        command
    }

    fn marker(test: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("rosetun-identity-{test}-{}", std::process::id()))
    }

    #[test]
    fn a_missing_account_starts_no_engine() {
        let marker = marker("missing");
        let error = launch(
            &mut marker_command(&marker),
            &Placement::Inherit,
            Identity::Missing,
        )
        .expect_err("no engine as root");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!marker.exists());
    }

    #[test]
    fn an_account_that_cannot_be_taken_starts_no_engine() {
        // SAFETY: Plain call without arguments.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let marker = marker("refused");
        let error = launch(
            &mut marker_command(&marker),
            &Placement::Inherit,
            Identity::Account(ACCOUNT),
        )
        .expect_err("an ordinary account cannot change its uid");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!marker.exists());
    }

    #[test]
    fn without_an_account_an_engine_keeps_the_helpers() {
        let marker = marker("inherit");
        let mut child = launch(
            &mut marker_command(&marker),
            &Placement::Inherit,
            Identity::Inherit,
        )
        .unwrap();
        assert!(child.wait().unwrap().success());
        assert!(marker.exists());
        std::fs::remove_file(marker).unwrap();
    }

    #[test]
    fn only_an_account_opens_the_engines_files_to_a_group() {
        run_engines_as(Identity::Inherit);
        assert_eq!(engine_group(), None);
    }
}
