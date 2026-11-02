//! Taking the session lock: how long a client request waits for it, and who
//! holds it.

use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{MutexGuard, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

use rosetun_ipc::{ErrorCode, HelperError};

use super::{Helper, Session};

/// How long a client request waits for the session before it answers busy.
///
/// The supervisor takes the session every 500 ms and holds it for the few
/// milliseconds its operating-system queries take, so a request that arrives
/// in that window only has to wait a moment. Two seconds is longer than any
/// supervisor tick and still short of what a user takes for a hang. A real
/// long operation, a connect or an apply that restarts the engine, lasts
/// seconds and still ends in busy after the wait. Background threads never
/// wait: they give way to the client, not the other way round.
#[cfg(not(test))]
pub(super) const SESSION_WAIT: Duration = Duration::from_secs(2);
/// Short enough that the tests holding the session for good stay quick, long
/// enough that a hold of 100 ms ends well inside it.
#[cfg(test)]
pub(super) const SESSION_WAIT: Duration = Duration::from_millis(500);
/// The pause between two attempts to take a busy session.
pub(super) const SESSION_POLL: Duration = Duration::from_millis(10);

/// What holds the session right now, for the log line of a refused request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum SessionHolder {
    Nobody = 0,
    Supervisor,
    Connect,
    Apply,
    Disconnect,
    Probe,
    Lockdown,
    Teardown,
    /// A short read of the session's data.
    Query,
}

impl SessionHolder {
    const ALL: [Self; 9] = [
        Self::Nobody,
        Self::Supervisor,
        Self::Connect,
        Self::Apply,
        Self::Disconnect,
        Self::Probe,
        Self::Lockdown,
        Self::Teardown,
        Self::Query,
    ];

    fn from_raw(raw: u8) -> Self {
        Self::ALL
            .into_iter()
            .find(|holder| *holder as u8 == raw)
            .unwrap_or(Self::Nobody)
    }

    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Nobody => "nobody",
            Self::Supervisor => "supervisor",
            Self::Connect => "connect",
            Self::Apply => "apply",
            Self::Disconnect => "disconnect",
            Self::Probe => "probe",
            Self::Lockdown => "lockdown",
            Self::Teardown => "teardown",
            Self::Query => "query",
        }
    }
}

/// The session lock plus the mark of who took it. The mark is cleared when
/// the guard goes, whatever path leaves the scope.
pub(super) struct SessionGuard<'a> {
    guard: MutexGuard<'a, Session>,
    mark: &'a AtomicU8,
}

impl<'a> SessionGuard<'a> {
    pub(super) fn new(
        guard: MutexGuard<'a, Session>,
        mark: &'a AtomicU8,
        holder: SessionHolder,
    ) -> Self {
        mark.store(holder as u8, Ordering::Relaxed);
        Self { guard, mark }
    }
}

impl Deref for SessionGuard<'_> {
    type Target = Session;

    fn deref(&self) -> &Session {
        &self.guard
    }
}

impl DerefMut for SessionGuard<'_> {
    fn deref_mut(&mut self) -> &mut Session {
        &mut self.guard
    }
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        // The mutex is released after this, so the next holder marks itself
        // only once this store is done.
        self.mark
            .store(SessionHolder::Nobody as u8, Ordering::Relaxed);
    }
}

/// The result of taking a free session: the guard, and whether an earlier
/// panic poisoned the mutex.
pub(super) enum Acquired<'a> {
    Locked(SessionGuard<'a>),
    Poisoned(SessionGuard<'a>),
}

impl Helper {
    /// One attempt, no waiting: for the background threads, and the first
    /// step of a client request. `None` means somebody else holds the session.
    pub(super) fn try_session(&self, holder: SessionHolder) -> Option<Acquired<'_>> {
        match self.session.try_lock() {
            Ok(guard) => Some(Acquired::Locked(SessionGuard::new(
                guard,
                &self.session_holder,
                holder,
            ))),
            Err(TryLockError::Poisoned(error)) => Some(Acquired::Poisoned(SessionGuard::new(
                error.into_inner(),
                &self.session_holder,
                holder,
            ))),
            Err(TryLockError::WouldBlock) => None,
        }
    }

    /// Waits for the session for up to `wait`, trying again every few
    /// milliseconds. No other lock is held meanwhile.
    pub(super) fn acquire_session(
        &self,
        holder: SessionHolder,
        wait: Duration,
    ) -> Option<Acquired<'_>> {
        let deadline = Instant::now() + wait;
        loop {
            if let Some(acquired) = self.try_session(holder) {
                return Some(acquired);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            thread::sleep(SESSION_POLL.min(deadline - now));
        }
    }

    /// The session for a client request: waits up to [`SESSION_WAIT`], then
    /// answers busy.
    pub(super) fn session_for(
        &self,
        holder: SessionHolder,
    ) -> Result<SessionGuard<'_>, HelperError> {
        let session = match self.acquire_session(holder, SESSION_WAIT) {
            Some(Acquired::Locked(session)) => session,
            Some(Acquired::Poisoned(_)) => {
                return Err(HelperError::new(
                    ErrorCode::Internal,
                    "helper state poisoned by an earlier panic",
                ));
            }
            None => {
                return Err(self.session_busy(holder, "another tunnel operation is in progress"));
            }
        };
        if session.stopping {
            return Err(HelperError::new(
                ErrorCode::InvalidState,
                "helper is shutting down",
            ));
        }
        Ok(session)
    }

    #[cfg(test)]
    pub(super) fn session(&self) -> Result<SessionGuard<'_>, HelperError> {
        self.session_for(SessionHolder::Query)
    }

    /// The busy answer after the wait ran out, with a note in the log of who
    /// asked and who held the session.
    pub(super) fn session_busy(
        &self,
        requested: SessionHolder,
        message: &'static str,
    ) -> HelperError {
        tracing::debug!(
            requested = requested.name(),
            held_by = self.session_holder().name(),
            waited_ms = SESSION_WAIT.as_millis() as u64,
            "session busy"
        );
        HelperError::new(ErrorCode::Busy, message)
    }

    pub(super) fn session_holder(&self) -> SessionHolder {
        SessionHolder::from_raw(self.session_holder.load(Ordering::Relaxed))
    }
}
