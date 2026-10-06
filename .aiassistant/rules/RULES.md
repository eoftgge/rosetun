---
apply: always
---

# Rosetun — always-on rules

*Rule mode: Always. Scoped detail lives in `ENGINE.md`, `HELPER.md` and
`WINDOWS.md`; `ROADMAP.md` and `OPEN-PROBLEMS.md` are attached with @ when they
matter.*

Cross-platform desktop VPN client. Unprivileged client, privileged helper,
sing-box as the engine; mihomo is the planned second engine, deferred. The
engine runs the tunnel; Rosetun runs the engine and protects against leaks.

## Working rules

- English everywhere: identifiers, comments, error messages, commit messages.
- Comments only where they explain a non-obvious *why*. The code is rewritten
  often; a comment restating the next line is noise.
- Conventional Commits: `feat(scope): ...`, `fix(scope): ...`,
  `refactor(scope): ...`.
- The local toolchain and **MSRV are Rust 1.96**. Never use anything
  stabilised after 1.96. Dependency updates must remain compatible with this
  minimum version.
- Edition 2024, resolver 3, workspace lints in the root manifest.
- `cargo fmt`, targeted crate tests while iterating, then
  `cargo check --workspace` and `cargo test --workspace` before calling a change
  done.
- No async runtime anywhere. Blocking I/O on worker threads is the chosen model.
- No pull requests. Changes are ported and tested by hand.
- Keep platform FFI narrowly scoped. Next to unsafe code, document ownership,
  lifetime, ABI and the security rationale.
- Before adding a dependency, check MSRV 1.96, licence, maintenance status,
  dependency tree size, and that it drags in no async runtime.

## Never

- Never enable a partially implemented kill-switch path.
- Never replace fail-closed behaviour with a permissive fallback to make
  connectivity work.
- Never expose Windows LUIDs or WFP types through engine-facing public traits.
- Never rely on an engine control API as the source of TUN interface identity.
- Never treat passing unit tests as evidence that a WFP filter is valid,
  correctly layered or effective. That needs elevated testing on real Windows.

## Ownership

The privileged helper is the only owner of a session. It spawns the engine, owns
the engine process lifecycle and owns the kill-switch lifecycle. The client does
not start the engine, does not change routes and touches no privileged API, so a
client crash never releases protection. The helper does not read user
configuration and does not fetch subscriptions — it receives a complete
`ConnectRequest` over IPC.

The engine owns the TUN and all ordinary routes. sing-box runs with
`auto_route`, and Rosetun never installs the same routes; the routing layer does
leak protection only. Two owners of the routing table fight.

## Invariants that outrank convenience

**Capabilities must not lie.** A backend declares what it can express,
`render()` returns the rules it cannot, and the helper rejects the connect
before spawn. A backend claiming a capability it does not implement turns the
guarantee into a trap — worse than having no check at all.

**The kill switch is two phases and must never be collapsed into one.** Outbound
protection is installed before the engine spawns; the tunnel interface is
authorized afterwards, because its identity does not exist until the engine
creates the adapter.

**Rules are independent entities.** A rule set holds no reference to a
subscription, and the two are stored separately. This is a product requirement:
a rule must survive switching or deleting a subscription.

## How to hand over code

I port every change by hand, so a snippet without a location is unusable.

Every code block says where it goes:

- The repo-relative file path, always.
- The enclosing item by name — `fn`, `impl`, `struct`, module. This survives
  edits; line numbers do not.
- One short anchor: the existing line immediately above the insertion point, or
  the exact line being replaced, quoted verbatim so I can search for it.
- Line numbers only as a hint next to the anchor, never as the only locator.
  Your view of the file may already be stale.

Shape it like this:

    crates/rosetun-routing/src/platform/windows/filters.rs
    in `impl Drop for AppIdBlob` (~line 60)
    replace:  FwpmFreeMemory0((&mut self.0).cast());
    with:     FwpmFreeMemory0((&raw mut self.0).cast());

For a replacement, show the old line and the new line rather than the whole
function. Reproduce a whole item only when most of it changes.

For a change spanning several files, group by file, and keep them in the order
the edits must be applied when one depends on another.

If you are not sure where something belongs, say so instead of guessing at a
location.

## Testing

Kill-switch, routing and engine changes are done only when the Hyper-V failure
matrix passes (`tools/vm/README.md`). Unit tests cannot show that a WFP filter
is effective or that a tunnel carries traffic.
