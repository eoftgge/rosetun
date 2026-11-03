//! Termination signals on Linux without an async runtime. `block` runs first
//! in `main`, before any thread exists, so every later thread inherits the
//! mask and only the waiter thread takes these signals with `sigwait`.
//! Engines do not inherit the mask: the standard library clears it in the
//! child before `exec`.

use std::io;
use std::mem::MaybeUninit;
use std::thread::{self, JoinHandle};

const SIGNALS: [libc::c_int; 3] = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP];

/// The set of blocked termination signals.
#[derive(Clone, Copy)]
pub(crate) struct Blocked(libc::sigset_t);

impl std::fmt::Debug for Blocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Blocked(SIGTERM, SIGINT, SIGHUP)")
    }
}

fn termination_set() -> io::Result<libc::sigset_t> {
    let mut set = MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: sigemptyset initializes the sigset_t behind the pointer, which
    // is valid and writable for the call.
    if unsafe { libc::sigemptyset(set.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: sigemptyset succeeded, so the set is initialized.
    let mut set = unsafe { set.assume_init() };
    for signal in SIGNALS {
        // SAFETY: The set is initialized and owned here; the signal numbers
        // are valid constants.
        if unsafe { libc::sigaddset(&mut set, signal) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(set)
}

/// Blocks the termination signals in the calling thread.
fn block_in_this_thread(set: &libc::sigset_t) -> io::Result<()> {
    // SAFETY: The set is initialized and borrowed for the call; the old mask
    // is not requested. Only the calling thread's mask changes.
    let result = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, set, std::ptr::null_mut()) };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }
    Ok(())
}

/// Blocks SIGTERM, SIGINT and SIGHUP. Must run before the process starts
/// any thread, or a thread without the mask could take a signal and end
/// the process without a teardown.
pub(crate) fn block() -> io::Result<Blocked> {
    let set = termination_set()?;
    block_in_this_thread(&set)?;
    Ok(Blocked(set))
}

fn signal_name(signal: libc::c_int) -> &'static str {
    match signal {
        libc::SIGTERM => "SIGTERM",
        libc::SIGINT => "SIGINT",
        libc::SIGHUP => "SIGHUP",
        _ => "unexpected signal",
    }
}

/// Starts the thread that waits for the blocked signals. `on_first` runs
/// once, for the first signal. Later signals are only logged: a second
/// SIGTERM or Ctrl+C never cuts the engines' teardown short, and the
/// process ends when that teardown does.
pub(crate) fn spawn_waiter(
    blocked: Blocked,
    on_first: impl FnOnce(&'static str) + Send + 'static,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("signal-waiter".to_owned())
        .spawn(move || {
            // Already inherited in the helper; blocking again keeps `sigwait`
            // defined when the waiter is started from a thread without the mask.
            if let Err(error) = block_in_this_thread(&blocked.0) {
                tracing::error!(%error, "cannot block termination signals");
                return;
            }
            let mut on_first = Some(on_first);
            loop {
                let mut signal: libc::c_int = 0;
                // SAFETY: The set is initialized and owned by this closure;
                // sigwait writes one c_int to the valid local `signal`.
                let result = unsafe { libc::sigwait(&blocked.0, &mut signal) };
                if result != 0 {
                    tracing::error!(
                        error = %io::Error::from_raw_os_error(result),
                        "waiting for termination signals failed"
                    );
                    return;
                }
                let name = signal_name(signal);
                match on_first.take() {
                    Some(on_first) => {
                        tracing::info!(signal = name, "stopping the helper");
                        on_first(name);
                    }
                    None => tracing::info!(signal = name, "the helper is already stopping"),
                }
            }
        })
}
