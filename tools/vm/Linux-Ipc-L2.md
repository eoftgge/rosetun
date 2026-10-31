# Linux L2 transport review fixture

This is a transport-only exercise for an isolated Debian 13 VM. It never starts
Rosetun's privileged helper, engines, VPN, firewall or network tests. Run the
privileged steps yourself. Do not run this on a machine with an active helper.

Prerequisites: Rust 1.96.0 and a C linker; an existing `rosetun` group; two
existing ordinary test accounts (`ipc_owner`, `ipc_other`) with distinct UIDs,
both allowed to connect through that group. Provision these deliberately before
the exercise; no script creates users, groups or installs packages. If checking
sudo/wheel membership, use an existing member without elevating its process.
Group membership never changes the authenticated UID or grants administrator
permissions. All accounts and paths below are synthetic fixtures.

Build as the ordinary owner from the repository:

```sh
cargo +1.96.0 build -q -p rosetun-ipc --example l2_transport_fixture --locked
cargo +1.96.0 test -q -p rosetun-ipc -p rosetun-helper-privileged --locked
fixture="$(realpath target/debug/examples/l2_transport_fixture)"
id ipc_owner
id ipc_other
getent group rosetun
```

Use an otherwise empty test VM: `/run/rosetun` must not already exist. Record
`test ! -e /run/rosetun && test ! -L /run/rosetun` before proceeding. If it does
exist, stop and inspect it; do not delete or repair an unknown service directory.
The fixture creates only `/run/rosetun` and its socket. It does not prepare
`/var/lib/rosetun`, start workers, or store any session or secret.

## Root and distinct account credentials

In terminal A, after the explicit empty-path check:

```sh
sudo "$fixture" serve 4
```

In terminal B, using the same absolute `fixture` path:

```sh
stat -c '%U:%G %a %F' /run/rosetun /run/rosetun/helper.sock
sudo -u ipc_owner "$fixture" client /run/rosetun/helper.sock
sudo -u ipc_owner "$fixture" spoof-hello
sudo -u ipc_other "$fixture" client /run/rosetun/helper.sock
sudo "$fixture" client /run/rosetun/helper.sock
```

Expect directory owner root with no group/other write (normally `root:root 755`)
and `root:rosetun 660` socket. Both requests by `ipc_owner` must report its actual
UID and `admin=false`, including the JSON claiming UID 0. `ipc_other` must report
its own different UID and `admin=false`. Root must report UID 0 and `admin=true`.
The fixture then exits and removes only its own socket. No credentials are added
to the production JSON protocol; the fixture's version text is test output.

Business authorization is checked by
`linux_uids_preserve_session_and_owner_only_read_policies` and
`linux_shutdown_rejects_an_authenticated_non_administrator` in helper unit tests.
These use fake callers and stub backends, not engines. Other UID must receive
AccessDenied for control and session reads. Root can use the existing admin
control policy and TemporaryRules/SessionExits, but cannot read another owner's
Connections/DiagnosticLog or close its individual connections. Disabled IPC
shutdown still rejects root. Status remains public. Transport credentials above
are a separate real-socket check and do not depend on fake callers.

## Untrusted user server and custom paths

As `ipc_owner`, in two terminals, use a fresh private temporary directory:

```sh
probe_dir="$(mktemp -d /tmp/rosetun-l2.XXXXXXXX)"
"$fixture" user-server "$probe_dir/helper.sock"
# While user-server waits, in the second terminal:
"$fixture" client "$probe_dir/helper.sock"
```

Expect a client permission error before Hello and `no request bytes received`
from the server. Client verification rejects writable/untrusted ancestors even
before connecting. Unit test
`peer_credentials_reject_an_ordinary_server_before_any_write` independently
exercises the UID rejection on a connected real socket pair.

Linux ignores `ROSETUN_HELPER_ENDPOINT`. Repeat a normal default endpoint test
with that variable pointing at the user socket: it must not redirect the default
endpoint. Explicit custom client paths still require root-owned non-writable
ancestors, a root:rosetun 0660 socket, and a UID 0 peer. Production listener bind
rejects every custom path; no environment variable can relocate root writes.

Clean only the socket and the exact `probe_dir` created for this exercise:
`test -S "$probe_dir/helper.sock" && rm -- "$probe_dir/helper.sock"`, then
`rmdir -- "$probe_dir"`. Do not use recursive cleanup or wildcard paths.

## Endpoint exclusivity, stale refusal and object substitution

1. Start `sudo "$fixture" serve 1` in terminal A. Record socket device/inode with
   `stat -c '%d:%i' /run/rosetun/helper.sock`.
2. Run `sudo "$fixture" serve 1` in terminal B. Expect an occupied-endpoint error.
   Device/inode must be unchanged. Connect once with `ipc_owner`; the original
   listener must still work and exit normally.
3. Start the fixture again. Record its PID from the owner terminal, confirm its
   command is this exact fixture, and send SIGKILL to that PID yourself. This
   deliberately leaves the test socket stale. Restart must refuse; a refused
   connection is not permission to delete the object.
4. With all fixture processes stopped, record and inspect the stale socket with
   `stat`. Remove only that known test socket with
   `sudo rm -- /run/rosetun/helper.sock`. No automatic stale recovery occurs.
5. In the now-empty fixture directory, create a regular file at `helper.sock`,
   record its hash and inode, and try `serve 1`. Expect refusal and unchanged
   contents/inode. Remove only that test file. Repeat with a symlink to a
   nonexistent test name; expect refusal and the symlink untouched.
6. Unit tests `drop_preserves_a_replacement_endpoint`,
   `drop_preserves_symlinks_and_other_sockets`, and
   `unsafe_directories_and_socket_modes_are_rejected_without_repair` exercise
   substitution and permissions in separate unprivileged temporary directories.
   `symlink_directories_are_not_followed` checks O_NOFOLLOW. They never operate
   on service directories. The original socket inode is pinned by O_PATH until
   Drop, preventing inode reuse from confusing the comparison.
7. To check missing-group deployment, use a separate clean VM without `rosetun`;
   `serve 1` must name the missing group and create no socket. Do not rename or
   remove the group from the primary VM just for this check.

Clean only after every fixture process has stopped. Verify that
`/run/rosetun/helper.sock` is absent and `/run/rosetun` contains no entries, then
`sudo rmdir -- /run/rosetun`. This directory was absent before the exercise.
Leave all pre-existing directories, accounts, groups and data untouched.

## Review limits

Production paths are `/run/rosetun` for IPC, `/run/rosetun/private` (0700) for
secret runtime configurations, and `/var/lib/rosetun` (0700) for persistent state.
The `lists`, `private/sing-box` and `private/xray` directories are root-owned
0700 and validated before warmup or workers. Existing unsafe objects are refused,
never chmod/chowned. Root is trusted; the client group cannot mutate the pinned
service directories. Procfs and Linux renameat2 with RENAME_NOREPLACE are required;
there is no permissive fallback. Windows paths and ACLs retain their existing
policy. Linux systemd, polkit, engine launch hardening, nftables and Lockdown are
separate work. Passing these tests makes no claim about network protection.

Record OS/toolchain, commit SHA, actual UIDs, stat results, exact failing command
and its error on any discrepancy. Do not include subscriptions, keys, production
requests or connection history.
