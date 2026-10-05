---
apply: by file patterns
patterns: crates/rosetun-helper-privileged/**, crates/rosetun-ipc/**
---

# Rosetun — helper and IPC

*Rule mode: By file patterns — `crates/rosetun-helper-privileged/**`,
`crates/rosetun-ipc/**`.*

The privileged helper is the only owner of a session. It spawns the engine, owns
the engine process lifecycle and owns the kill-switch lifecycle. The client does
not start the engine, does not change routes and touches no privileged API, so a
client crash never releases protection.

## Invariants

**Two mutexes: fast `status`, slow `session`.** Lock order is session then
status, never the reverse. `try_lock` on session maps to a busy error rather
than blocking. A long connect must not stop another client from reading status.

**`status` poison recovers via `into_inner()`; `session` poison returns an
internal error.** Status is only data, and losing the ability to report state is
worse than serving it. Tunnel state after a panic may be genuinely inconsistent.

**`Connected` is not reported until phase-2 tunnel authorization succeeds and
one DNS query through the tunnel is answered.** Otherwise the client shows a
usable protected tunnel while the firewall still blocks its traffic, or while
the resolver is unreachable from the node's exit. The query goes to the TUN's
DNS address from `EngineBackend::tunnel_dns_server` (`state/dns.rs`); a failure
fails a fresh connect and leaves a protected reconnect in `FailedProtected`.

**A failed connect and a dead engine are opposite cases.** A failed fresh
connect tears everything down and reports `Failed`, because nothing was ever
protected. An engine that dies after `Connected` leaves the routing guard
standing and reports `FailedProtected`: the kill switch stays closed until an
explicit disconnect.

**A connect from `FailedProtected` is a protected reconnect and must never drop
protection.** It reuses the standing routing guard, stops only the engine on
failure and stays in `FailedProtected`. It cannot turn the kill switch off — the
user disconnects first. It cannot resolve a new server name either, because DNS
is blocked: the node must be an IP literal or the same name as the last
successful endpoint, whose cached address is reused.

**Session teardown is transactional.** Partial failures roll back in reverse
order, a repeated teardown is safe, and `Drop` does not repeat a destructive
action.

**The helper never touches the network or user configuration.** It receives a
complete `ConnectRequest` over IPC. Subscriptions, persistence and HTTP live in
the client. The one network operation it performs is resolving the node name
before the kill switch goes up.

**The protocol is versioned.** NDJSON frames with a version handshake. Adding a
`ConnectionState` variant is a breaking change and needs a version bump.

**`ConnectRequest`'s `Debug` stays redacted.** It carries node credentials, and
debug logging of requests is on in testing.

## Transport

**Do not use a loopback TCP transport on Windows instead of named pipes.** An
open localhost port on a privileged process is reachable by any local user.

The named pipe must not use the default DACL, which grants read to Everyone and
the anonymous account. The first instance carries
`FILE_FLAG_FIRST_PIPE_INSTANCE` so binding fails loudly instead of joining a
pipe someone else created, and `PIPE_REJECT_REMOTE_CLIENTS` keeps it local.

The pipe DACL grants write to authenticated users, so any request the helper
honours without authentication is reachable by any local account — including
`shutdown`. Weigh that before adding a request that changes system state.

## Engine supervision

A successful spawn is not readiness. Readiness is the engine's startup log line
followed by phase-2 validation of the adapter, bounded by a deadline, with a
liveness check on every iteration.

An engine's piped stdout and stderr must be drained, or the engine blocks on its
next log write once the pipe buffer fills.

The helper joins a process-lifetime job object with `KILL_ON_JOB_CLOSE` before
spawning anything, so the engine cannot outlive a crashed or killed helper.
Never close that handle from Rust: it would kill the helper itself.

## Shutdown

A shutdown request ends the server loop, runs session teardown and only then
lets the process exit. Never end the process from inside a request handler:
that skips every destructor, orphans the engine and drops the firewall while the
engine keeps running.

## Testing

Elevated behaviour is verified in the Hyper-V failure matrix (`tools/vm`, see
its README). Unit tests cannot show that a WFP filter is effective or that a
tunnel carries traffic.
