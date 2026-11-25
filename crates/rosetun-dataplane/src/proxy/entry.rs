//! Authenticated loopback SOCKS5 entry for delay probes and client
//! subscription fetches.
//!
//! Each account maps straight to one outbound (`proxy` or an `ExitId`),
//! bypassing user rules and sniffing, TCP only, and keeping its connections
//! out of the user's live connection table.

use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rosetun_config::ExitId;
use rosetun_engine::{DelayInbound, PROXY_TAG, SUBSCRIPTION_PROXY_USER};

use super::Verdict;
use super::router::Router;
use super::server::wake_listener;
use super::socks::{self, Access, Account};
use crate::conntable::ConnectionTable;

const MAX_ENTRY_CONNECTIONS: usize = 128;

/// Outbound selected by an internal entry account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryTarget {
    Proxy,
    Exit(ExitId),
}

/// One authenticated account on [`EntryServer`].
#[derive(Clone, PartialEq, Eq)]
pub struct EntryAccount {
    pub username: String,
    pub password: String,
    pub target: EntryTarget,
}

impl fmt::Debug for EntryAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryAccount")
            .field("target", &self.target)
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .finish()
    }
}

impl EntryAccount {
    /// Builds accounts from a [`DelayInbound`] and the session's `(exit_tag, exit_id)`
    /// pairs. Unknown tags are ignored so they never reach any outbound.
    pub fn from_delay_inbound(inbound: &DelayInbound, exits: &[(String, ExitId)]) -> Vec<Self> {
        let mut accounts = Vec::with_capacity(inbound.accounts.len());
        for account in &inbound.accounts {
            let target = if account.tag == PROXY_TAG || account.tag == SUBSCRIPTION_PROXY_USER {
                Some(EntryTarget::Proxy)
            } else {
                exits
                    .iter()
                    .find(|(tag, _)| *tag == account.tag)
                    .map(|(_, exit)| EntryTarget::Exit(exit.clone()))
            };
            if let Some(target) = target {
                accounts.push(Self {
                    username: account.tag.clone(),
                    password: account.password.clone(),
                    target,
                });
            }
        }
        accounts
    }
}

struct EntrySlotGuard {
    active: Arc<AtomicUsize>,
}

impl Drop for EntrySlotGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_entry_slot(active: &AtomicUsize, limit: usize) -> bool {
    let mut current = active.load(Ordering::Acquire);
    while current < limit {
        match active.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
    false
}

/// Running authenticated loopback SOCKS5 server for internal probes and
/// subscription traffic.
pub struct EntryServer {
    address: SocketAddr,
    table: ConnectionTable,
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl fmt::Debug for EntryServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryServer")
            .field("stopped", &self.shutdown.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl EntryServer {
    /// Binds `address` (typically loopback) and serves SOCKS5 with RFC 1929
    /// authentication for `accounts`.
    pub fn bind(
        router: Arc<Router>,
        address: SocketAddr,
        accounts: Vec<EntryAccount>,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(address)?;
        let local_addr = listener.local_addr()?;
        let table = ConnectionTable::with_limits(MAX_ENTRY_CONNECTIONS, 0);
        let shutdown = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));

        let access = Arc::new(Access::Accounts(
            accounts
                .into_iter()
                .map(|account| Account {
                    username: account.username,
                    password: account.password,
                    verdict: match account.target {
                        EntryTarget::Proxy => Verdict::Proxy,
                        EntryTarget::Exit(exit) => Verdict::Exit(exit),
                    },
                })
                .collect(),
        ));

        let worker_table = table.clone();
        let worker_shutdown = Arc::clone(&shutdown);
        let worker = thread::Builder::new()
            .name("dataplane-entry".to_owned())
            .spawn(move || {
                while !worker_shutdown.load(Ordering::Acquire) {
                    let Ok((stream, _)) = listener.accept() else {
                        if worker_shutdown.load(Ordering::Acquire) {
                            break;
                        }
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    };
                    if worker_shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    if !try_acquire_entry_slot(&active, MAX_ENTRY_CONNECTIONS) {
                        continue;
                    }
                    let guard = EntrySlotGuard {
                        active: Arc::clone(&active),
                    };
                    let router = Arc::clone(&router);
                    let access = Arc::clone(&access);
                    let table = worker_table.clone();
                    let shutdown = Arc::clone(&worker_shutdown);
                    let _ = thread::Builder::new()
                        .name("dataplane-entry-conn".to_owned())
                        .spawn(move || {
                            let _guard = guard;
                            stream.set_nodelay(true).ok();
                            let _ = socks::serve(&router, stream, &access, &table, &shutdown);
                        });
                }
            })?;

        Ok(Self {
            address: local_addr,
            table,
            shutdown,
            worker: Some(worker),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// Stops accepting connections, closes active internal flows, and joins
    /// the accept thread. Idempotent.
    pub fn shutdown(&mut self) {
        if self.shutdown.swap(true, Ordering::AcqRel) {
            return;
        }
        self.table.close_all();
        wake_listener(self.address);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for EntryServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_account_debug_hides_credentials() {
        let account = EntryAccount {
            username: "secret-user".into(),
            password: "secret-password".into(),
            target: EntryTarget::Proxy,
        };
        let text = format!("{account:?}");
        assert!(!text.contains("secret"));
    }

    #[test]
    fn from_delay_inbound_maps_proxy_subscription_and_known_exits() {
        let inbound = DelayInbound::local([
            PROXY_TAG.to_owned(),
            SUBSCRIPTION_PROXY_USER.to_owned(),
            "exit-0".to_owned(),
            "exit-99".to_owned(),
        ])
        .unwrap();
        let exits = vec![("exit-0".to_owned(), ExitId::new("de"))];
        let mapped = EntryAccount::from_delay_inbound(&inbound, &exits);
        assert_eq!(mapped.len(), 3);
        assert_eq!(mapped[0].target, EntryTarget::Proxy);
        assert_eq!(mapped[1].target, EntryTarget::Proxy);
        assert_eq!(mapped[2].target, EntryTarget::Exit(ExitId::new("de")));
    }
}
