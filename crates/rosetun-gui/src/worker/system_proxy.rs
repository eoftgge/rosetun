use std::sync::{Arc, Mutex, PoisonError};

use rosetun_core::Store;
use rosetun_shell::{DesktopProxy, ProxySet};

use super::{WorkerDispatcher, WorkerEvent, emit};

/// Next to the configuration.
const RECORD_FILE: &str = "desktop-proxy.json";

/// What the desktop's proxy settings should be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SystemProxyWish {
    /// Pointed at the local proxy on this port.
    Listen(u16),
    /// Back to the user's own.
    Clear,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SystemProxyOutcome {
    Done,
    /// This desktop has no settings Rosetun can change.
    Manual,
    Failed,
}

/// Gives the desktop's settings back when the GUI exits normally. A crash leaves
/// the record, and the next start restores from it.
#[derive(Debug)]
pub(crate) struct DesktopProxyKeeper(Mutex<DesktopProxy>);

impl DesktopProxyKeeper {
    pub(super) fn new(store: &Store) -> Arc<Self> {
        let record = store.path().with_file_name(RECORD_FILE);
        Arc::new(Self(Mutex::new(DesktopProxy::new(record))))
    }

    fn apply(&self, wish: SystemProxyWish) -> SystemProxyOutcome {
        let proxy = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let result = match wish {
            SystemProxyWish::Listen(port) => proxy.set(port).map(|set| match set {
                ProxySet::Applied => SystemProxyOutcome::Done,
                ProxySet::Manual => SystemProxyOutcome::Manual,
            }),
            SystemProxyWish::Clear => proxy.restore().map(|_| {
                if proxy.automatic() {
                    SystemProxyOutcome::Done
                } else {
                    SystemProxyOutcome::Manual
                }
            }),
        };
        result.unwrap_or_else(|error| {
            tracing::warn!(kind = ?error.kind(), "could not change the desktop's proxy");
            SystemProxyOutcome::Failed
        })
    }
}

impl Drop for DesktopProxyKeeper {
    fn drop(&mut self) {
        self.apply(SystemProxyWish::Clear);
    }
}

impl WorkerDispatcher {
    pub(crate) fn sync_system_proxy(&self, wish: SystemProxyWish) {
        let keeper = Arc::clone(&self.desktop_proxy);
        self.spawn_task("rosetun-system-proxy", move |publisher| {
            let outcome = keeper.apply(wish);
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::SystemProxy { wish, outcome },
            );
        });
    }

    pub(crate) fn read_lan_address(&self) {
        self.spawn_task("rosetun-lan-address", move |publisher| {
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::LanAddress(rosetun_core::lan_address()),
            );
        });
    }

    /// On the caller's thread: the GUI is about to exit, and a session ending
    /// may not leave it time for anything later.
    pub(crate) fn restore_system_proxy(&self) {
        self.desktop_proxy.apply(SystemProxyWish::Clear);
    }
}
