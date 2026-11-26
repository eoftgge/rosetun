//! Multiplexed non-blocking TCP relay over [`polling::Poller`].
//!
//! Instead of keeping two OS threads and two 32 KiB stack/heap buffers alive
//! for every open TCP connection, established connections are handed off to a
//! small fixed pool of reactor threads (`epoll` on Linux, `kqueue` on macOS,
//! `wepoll`/AFD IOCP on Windows). Idle keep-alive connections hold zero
//! threads and return their 32 KiB direction buffers to the shard's pool.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, mpsc};
use std::thread;
use std::time::Duration;

use polling::{Events, Poller};

use crate::conntable::{Counters, Registration};
use crate::poller::PolledStream;

const BUFFER_BYTES: usize = 32 * 1024;
const POOL_BUFFERS_PER_SHARD: usize = 64;
const RELAY_SHARDS: usize = 2;
const IO_BUDGET: usize = 16;
const SAFETY_SWEEP: Duration = Duration::from_secs(1);

type RelayBuf = Box<[u8; BUFFER_BYTES]>;
type CloseGuard = Box<dyn Send>;

thread_local! {
    static HANDOFF_GUARD: RefCell<Option<CloseGuard>> = const { RefCell::new(None) };
}

/// Installs `guard` for the current worker thread so that if `f` reaches
/// [`relay`], ownership of `guard` transfers into the multiplexed relay session
/// and `f` returns immediately while the connection stays tracked until close.
/// If `f` exits before reaching [`relay`], `guard` is dropped on return.
pub(crate) fn with_handoff_guard<R>(guard: impl Send + 'static, f: impl FnOnce() -> R) -> R {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            let _ = HANDOFF_GUARD.with(|slot| slot.borrow_mut().take());
        }
    }
    HANDOFF_GUARD.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(guard));
    });
    let _reset = Reset;
    f()
}

/// Wakes every active relay shard immediately after [`Registration`] marks a
/// connection closed.
pub(crate) fn notify_cancellation() {
    if let Some(pool) = RELAY_POOL.get() {
        for shard in &pool.shards {
            let _ = shard.poller.notify();
        }
    }
}

/// Copies both directions between `client` and `upstream`, sending `preface`
/// to `upstream` first.
///
/// When called inside [`with_handoff_guard`], hands the sockets off to the
/// background reactor pool and returns immediately so the caller thread exits.
/// When called directly (e.g. in standalone unit tests), runs on the same
/// reactor pool and waits until the session finishes.
pub(crate) fn relay(
    client: TcpStream,
    upstream: TcpStream,
    registration: Registration,
    preface: Vec<u8>,
) {
    registration.attach(&client);
    registration.attach(&upstream);
    if registration.is_closed() {
        shutdown_both(&client, &upstream);
        return;
    }

    let handoff_guard = HANDOFF_GUARD.with(|slot| slot.borrow_mut().take());

    if let Some(guard) = handoff_guard {
        if !pool().submit(RelayTask {
            client,
            upstream,
            registration,
            preface,
            on_close: TaskCleanup::Guard(guard),
        }) {
            // Dropped `RelayTask` drops `registration` and `guard`; sockets close on drop.
        }
        return;
    }

    let (done_tx, done_rx) = mpsc::sync_channel::<()>(0);
    if pool().submit(RelayTask {
        client,
        upstream,
        registration,
        preface,
        on_close: TaskCleanup::Waiter(done_tx),
    }) {
        let _ = done_rx.recv();
    }
}

enum TaskCleanup {
    #[expect(
        dead_code,
        reason = "held strictly for its Drop side effects when the session ends"
    )]
    Guard(CloseGuard),
    Waiter(mpsc::SyncSender<()>),
}

impl Drop for TaskCleanup {
    fn drop(&mut self) {
        if let Self::Waiter(tx) = self {
            let _ = tx.send(());
        }
    }
}

struct RelayTask {
    client: TcpStream,
    upstream: TcpStream,
    registration: Registration,
    preface: Vec<u8>,
    on_close: TaskCleanup,
}

struct RelayShard {
    poller: Arc<Poller>,
    queue: Arc<Mutex<VecDeque<RelayTask>>>,
}

struct RelayPool {
    shards: Vec<RelayShard>,
    next: AtomicUsize,
}

static RELAY_POOL: OnceLock<RelayPool> = OnceLock::new();

fn pool() -> &'static RelayPool {
    RELAY_POOL.get_or_init(|| {
        let mut shards = Vec::with_capacity(RELAY_SHARDS);
        for idx in 0..RELAY_SHARDS {
            if let Ok(poller) = Poller::new() {
                let poller = Arc::new(poller);
                let queue = Arc::new(Mutex::new(VecDeque::new()));
                let worker_poller = Arc::clone(&poller);
                let worker_queue = Arc::clone(&queue);
                if thread::Builder::new()
                    .name(format!("dataplane-relay-{idx}"))
                    .stack_size(256 * 1024)
                    .spawn(move || run_shard(worker_poller, worker_queue))
                    .is_ok()
                {
                    shards.push(RelayShard { poller, queue });
                }
            }
        }
        RelayPool {
            shards,
            next: AtomicUsize::new(0),
        }
    })
}

impl RelayPool {
    fn submit(&self, task: RelayTask) -> bool {
        if self.shards.is_empty() {
            return false;
        }
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.shards.len();
        let shard = &self.shards[idx];
        shard
            .queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(task);
        let _ = shard.poller.notify();
        true
    }
}

#[derive(Default)]
struct BufPool {
    free: Vec<RelayBuf>,
}

impl BufPool {
    fn take(&mut self) -> RelayBuf {
        self.free
            .pop()
            .unwrap_or_else(|| Box::new([0u8; BUFFER_BYTES]))
    }

    fn put(&mut self, buf: RelayBuf) {
        if self.free.len() < POOL_BUFFERS_PER_SHARD {
            self.free.push(buf);
        }
    }
}

#[derive(Default)]
struct DirPipe {
    buf: Option<RelayBuf>,
    pos: usize,
    len: usize,
    read_eof: bool,
    write_shut: bool,
}

impl DirPipe {
    fn has_pending(&self) -> bool {
        self.buf.is_some()
    }

    fn is_done(&self) -> bool {
        self.write_shut && self.buf.is_none()
    }

    fn release_buf(&mut self, pool: &mut BufPool) {
        if let Some(buf) = self.buf.take() {
            pool.put(buf);
        }
        self.pos = 0;
        self.len = 0;
    }
}

struct Session {
    client: PolledStream,
    upstream: PolledStream,
    counters: Counters,
    _registration: Registration,
    preface: Vec<u8>,
    preface_pos: usize,
    c2u: DirPipe,
    u2c: DirPipe,
    _cleanup: TaskCleanup,
}

impl Session {
    fn abort(&mut self, pool: &mut BufPool) {
        shutdown_both(self.client.get(), self.upstream.get());
        self.c2u.release_buf(pool);
        self.u2c.release_buf(pool);
    }
}

struct Slab {
    entries: Vec<Option<Session>>,
    free: Vec<usize>,
}

impl Slab {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            free: Vec::new(),
        }
    }

    fn next_index(&self) -> usize {
        self.free.last().copied().unwrap_or(self.entries.len())
    }

    fn insert(&mut self, session: Session) -> usize {
        if let Some(idx) = self.free.pop() {
            self.entries[idx] = Some(session);
            idx
        } else {
            let idx = self.entries.len();
            self.entries.push(Some(session));
            idx
        }
    }

    fn remove(&mut self, idx: usize, pool: &mut BufPool) {
        if let Some(mut session) = self.entries.get_mut(idx).and_then(Option::take) {
            session.c2u.release_buf(pool);
            session.u2c.release_buf(pool);
            self.free.push(idx);
        }
    }

    fn active_count(&self) -> usize {
        self.entries.len() - self.free.len()
    }
}

fn run_shard(poller: Arc<Poller>, queue: Arc<Mutex<VecDeque<RelayTask>>>) {
    let mut events = Events::with_capacity(NonZeroUsize::new(256).unwrap());
    let mut slab = Slab::new();
    let mut buf_pool = BufPool::default();
    let mut scratch = Box::new([0u8; BUFFER_BYTES]);
    let mut ready_indices: Vec<usize> = Vec::with_capacity(256);

    loop {
        drain_new_tasks(&poller, &queue, &mut slab, &mut buf_pool, &mut scratch);

        let timeout = (slab.active_count() > 0).then_some(SAFETY_SWEEP);
        events.clear();
        if poller.wait(&mut events, timeout).is_err() {
            thread::sleep(Duration::from_millis(1));
            continue;
        }

        ready_indices.clear();
        for ev in events.iter() {
            let idx = ev.key / 2;
            if !ready_indices.contains(&idx) {
                ready_indices.push(idx);
            }
        }

        if ready_indices.is_empty() {
            // Wakeup from `notify()` or periodic cancellation sweep.
            for idx in 0..slab.entries.len() {
                let closed = slab
                    .entries
                    .get(idx)
                    .and_then(Option::as_ref)
                    .is_some_and(|s| s.counters.is_closed());
                if closed {
                    if let Some(Some(session)) = slab.entries.get_mut(idx) {
                        session.abort(&mut buf_pool);
                    }
                    slab.remove(idx, &mut buf_pool);
                }
            }
            continue;
        }

        for &idx in &ready_indices {
            let keep = match slab.entries.get_mut(idx).and_then(Option::as_mut) {
                Some(session) => drive_session(session, &mut buf_pool, &mut scratch),
                None => continue,
            };
            if !keep {
                slab.remove(idx, &mut buf_pool);
            }
        }

        // Also sweep any cancelled sessions that were woken via `notify_cancellation()`.
        for idx in 0..slab.entries.len() {
            let closed = slab
                .entries
                .get(idx)
                .and_then(Option::as_ref)
                .is_some_and(|s| s.counters.is_closed());
            if closed {
                if let Some(Some(session)) = slab.entries.get_mut(idx) {
                    session.abort(&mut buf_pool);
                }
                slab.remove(idx, &mut buf_pool);
            }
        }
    }
}

fn drain_new_tasks(
    poller: &Arc<Poller>,
    queue: &Mutex<VecDeque<RelayTask>>,
    slab: &mut Slab,
    buf_pool: &mut BufPool,
    scratch: &mut [u8; BUFFER_BYTES],
) {
    loop {
        let task = queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front();
        let Some(task) = task else {
            break;
        };
        if task.registration.is_closed() {
            shutdown_both(&task.client, &task.upstream);
            continue;
        }
        let slot = slab.next_index();
        let key_client = slot * 2;
        let key_up = slot * 2 + 1;
        let Ok(client) =
            PolledStream::new(Arc::clone(poller), task.client, key_client, true, false)
        else {
            shutdown_stream(&task.upstream);
            continue;
        };
        let has_preface = !task.preface.is_empty();
        let Ok(upstream) =
            PolledStream::new(Arc::clone(poller), task.upstream, key_up, true, has_preface)
        else {
            shutdown_stream(client.get());
            continue;
        };
        let counters = task.registration.counters();
        let mut session = Session {
            client,
            upstream,
            counters,
            _registration: task.registration,
            preface: task.preface,
            preface_pos: 0,
            c2u: DirPipe::default(),
            u2c: DirPipe::default(),
            _cleanup: task.on_close,
        };
        if drive_session(&mut session, buf_pool, scratch) {
            let inserted = slab.insert(session);
            debug_assert_eq!(inserted, slot);
        }
    }
}

fn drive_session(
    session: &mut Session,
    buf_pool: &mut BufPool,
    scratch: &mut [u8; BUFFER_BYTES],
) -> bool {
    if session.counters.is_closed() {
        session.abort(buf_pool);
        return false;
    }

    // Flush any remaining sniffed/HTTP preface bytes before reading from `client`.
    while session.preface_pos < session.preface.len() {
        match session
            .upstream
            .get()
            .write(&session.preface[session.preface_pos..])
        {
            Ok(0) => {
                session.abort(buf_pool);
                return false;
            }
            Ok(written) => {
                session.preface_pos += written;
                session.counters.add_up(written as u64);
                if session.preface_pos == session.preface.len() {
                    session.preface = Vec::new();
                    session.preface_pos = 0;
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => {
                session.abort(buf_pool);
                return false;
            }
        }
    }

    if session.preface_pos == session.preface.len()
        && !pump_direction(
            session.client.get(),
            session.upstream.get(),
            &mut session.c2u,
            buf_pool,
            scratch,
            |n| session.counters.add_up(n),
        )
    {
        session.abort(buf_pool);
        return false;
    }

    if !pump_direction(
        session.upstream.get(),
        session.client.get(),
        &mut session.u2c,
        buf_pool,
        scratch,
        |n| session.counters.add_down(n),
    ) {
        session.abort(buf_pool);
        return false;
    }

    if session.counters.is_closed() {
        session.abort(buf_pool);
        return false;
    }

    if session.preface.is_empty() && session.c2u.is_done() && session.u2c.is_done() {
        return false;
    }

    let client_read =
        session.preface.is_empty() && !session.c2u.read_eof && !session.c2u.has_pending();
    let client_write = session.u2c.has_pending();
    let up_read = !session.u2c.read_eof && !session.u2c.has_pending();
    let up_write = !session.preface.is_empty() || session.c2u.has_pending();

    if session.client.rearm(client_read, client_write).is_err()
        || session.upstream.rearm(up_read, up_write).is_err()
    {
        session.abort(buf_pool);
        return false;
    }

    true
}

fn pump_direction(
    mut from: &TcpStream,
    mut to: &TcpStream,
    pipe: &mut DirPipe,
    buf_pool: &mut BufPool,
    scratch: &mut [u8; BUFFER_BYTES],
    mut count: impl FnMut(u64),
) -> bool {
    for _ in 0..IO_BUDGET {
        if let Some(buf) = pipe.buf.as_ref() {
            match to.write(&buf[pipe.pos..pipe.len]) {
                Ok(0) => return false,
                Ok(written) => {
                    pipe.pos += written;
                    count(written as u64);
                    if pipe.pos < pipe.len {
                        continue;
                    }
                    pipe.release_buf(buf_pool);
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return true,
                Err(_) => return false,
            }
        }

        if pipe.read_eof {
            if !pipe.write_shut {
                let _ = to.shutdown(Shutdown::Write);
                pipe.write_shut = true;
            }
            return true;
        }

        match from.read(&mut scratch[..]) {
            Ok(0) => {
                pipe.read_eof = true;
                if !pipe.write_shut {
                    let _ = to.shutdown(Shutdown::Write);
                    pipe.write_shut = true;
                }
                return true;
            }
            Ok(read) => {
                let mut written_total = 0usize;
                while written_total < read {
                    match to.write(&scratch[written_total..read]) {
                        Ok(0) => return false,
                        Ok(written) => {
                            written_total += written;
                            count(written as u64);
                        }
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                            let mut held = buf_pool.take();
                            let remaining = read - written_total;
                            held[..remaining].copy_from_slice(&scratch[written_total..read]);
                            pipe.buf = Some(held);
                            pipe.pos = 0;
                            pipe.len = remaining;
                            return true;
                        }
                        Err(_) => return false,
                    }
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return true,
            Err(_) => return false,
        }
    }
    true
}

fn shutdown_stream(stream: &TcpStream) {
    let _ = stream.shutdown(Shutdown::Both);
}

fn shutdown_both(a: &TcpStream, b: &TcpStream) {
    let _ = a.shutdown(Shutdown::Both);
    let _ = b.shutdown(Shutdown::Both);
}
