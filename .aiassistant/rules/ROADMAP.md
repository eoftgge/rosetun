# Rosetun — state, roadmap and UI

*Rule mode: Manually. Status verified against `origin/master` at `cfe9e83` and
the Hyper-V failure matrix (38/38); update it as stages land.*

## Current state

| Stage | Status |
|---|---|
| 1. Windows IPC | **done** — named pipes, restrictive DACL, `PIPE_REJECT_REMOTE_CLIENTS`, protocol version 2; the client connects at identification level and accepts only a pipe owned by SYSTEM or Administrators |
| 2. Engine ownership contract | **done** — engine-managed TUN; the routing plan has no route fields |
| 3. Capabilities and unsupported rules | **done for sing-box** — rejection before spawn, sniffing emitted so domain rules match, the Xray stub claims nothing. A wider taxonomy waits for mihomo |
| 4. Lifecycle and protected failure | **done except graceful stop** — `FailedProtected`, protected reconnect, shutdown through the server loop, output draining, DNS check before `Connected`. The engine is still stopped by a kill |
| 5. Windows WFP kill switch | **verified in the VM** — see below |
| 6. End-to-end sing-box | **passed in the VM** — real binary, real tunnel, CLI connect, disconnect and shutdown, process rules, `FailedProtected` |
| 7. mihomo backend | **deferred** — still planned, not now |
| 8. Configuration on disk | **done** — `%APPDATA%\Rosetun\config.json` (`ROSETUN_CONFIG` overrides), validated atomic save, `connect` from the config, `select`, `config` |
| 9. Subscriptions | **done** — parser crate `rosetun-subscription` (link lists, Xray and sing-box JSON, metadata, provider notices, stable node IDs); loading with HWID headers over `ureq` with the Windows trust store; `sub add/update/list/remove`, `nodes`; verified against a real Happ-oriented panel |
| Application layer (before 12) | **done** — `rosetun-core`: `Store` (every change reloads the file first), subscription add, update, update-all and remove, node selection, provider-text sanitising and subscription URL redaction, sensitive log targets. `HelperClient` and `ConnectRequest::from_config` live in `rosetun-ipc`. The CLI only parses arguments and prints |
| 10. Traffic statistics | **10a done** — the helper polls the sing-box Clash API on loopback with a per-session secret and publishes rates and totals in `Status.traffic`; the CLI prints them. 10b (GUI) next |
| 11, 13–14 | not started |
| 12. GUI | **in progress** — 12a (connection screen) and 12b (rules screen, add-rule dialog, running-process picker) done and checked by hand on Windows, including process and domain rules through a live tunnel. Layout polish done: rule table grid with the default rule as its last row, drag-only reordering of rules and subscriptions, painted icons and switches, protection card. 12c-1 (settings screen) and 12c-2 (tray, close to tray, single instance) done; the header from the mockup done (brand header and the window frame drawn in it on Windows); 12c-3 (autostart, start in the tray, close-to-tray setting, `Browse` for process rules) and 12c-4 (Manrope, emblem window and tray icons) and 12c-5 (Russian translation, errors included) done, so 12c is complete |

What the matrix (`tools/vm`, 38 checks, elevated, clean Windows 11 guest)
proves:

- traffic and DNS go through the TUN within 5 s of `Connected`;
- direct IPv4 and IPv6 are blocked while connected, after an engine crash and
  during a reconnect;
- an adapter going down and up under the kill switch gets its DHCP lease back,
  and the tunnel recovers;
- process rules work, and direct traffic from the engine passes the kill switch;
- disconnect and shutdown restore the network and remove the adapter;
- a killed helper fails open, as designed.

What it does not cover yet:

- `allow_lan`: there is no scenario for it.
- A move to a different network. The adapter toggle gets the same address back
  within a second, so existing connections survive it. Wi-Fi to another
  network and sleep and resume on real hardware are untested, and with them the
  DoH stall (see `OPEN-PROBLEMS.md`).
- Real hardware, a remote node, and a network with real IPv6.
- IPv6 through the tunnel is not offered: the TUN is IPv4-only, and sing-tun's
  strict route blocks IPv6 (see `ENGINE.md`).

## Roadmap

### Leftovers from stages 4–6

- Graceful engine stop with a kill fallback after a timeout. Low priority:
  sing-box removed its adapter after every forced kill in the matrix.
- First connect on a fresh system (see `OPEN-PROBLEMS.md`): cache the version
  check, revisit the timeouts. Best solved together with the installer.
- An `allow_lan` scenario in the matrix.

### Stage 7 — mihomo backend (deferred)

Still the planned second engine, but not now: the stages after it do not depend
on it and go first. Do not start it, and do not widen the capability taxonomy
for it, until it is picked up again. When it is, see `ENGINE.md` for what to pin
and verify.

It is also the only route to XHTTP nodes. sing-box has no XHTTP transport in
1.14.1, nor in 1.15.0-alpha.10; mihomo has a VLESS XHTTP client with its modes,
connection reuse and download settings. If providers move to XHTTP, pick this
stage up right after the GUI. That also means a `Transport::Xhttp` in the model,
parsed instead of skipped, with engine capabilities deciding which engine can
run a node.

### Stage 8 — configuration on disk

Lives in the client, not the helper. Platform config directory, read, validate,
atomic save via temp file plus rename, so a corrupt new write cannot destroy a
working configuration. Tests for round-trip, missing optionals, a future
version, dangling selection and rule set, invalid JSON, and a failed save
leaving the old file usable.

### Stage 9 — subscriptions

Two steps. 9a: a pure parser in its own crate, `rosetun-subscription`, not in the
config crate, so the helper does not link base64, URL and JSON-format parsing.
9b: loading in the client — HTTP, HWID headers, metadata, CLI commands. The new
node list replaces the old one only after a complete successful download, decode
and parse that yields at least one usable node.

Formats: base64 or plain link lists, Xray JSON and sing-box JSON; Clash YAML is
detected and refused for now. Links: `vless`, `vmess`, `trojan`, `ss`; anything
sing-box 1.14.1 cannot run (XHTTP, gRPC multi mode, VLESS encryption, other
flows, shadowsocks plugins) is skipped with a reason, never silently degraded.
Panels covered: Marzban, 3x-ui, Remnawave, Hiddify, Happ-oriented setups.
`happ://crypt` links are encrypted for the Happ app and are refused, not
decrypted.

HWID: the `x-hwid`, `x-device-os`, `x-ver-os`, `x-device-model` convention that
Remnawave and 3x-ui accept; the ID is a hash of `MachineGuid` with an app prefix,
never the raw value. Subscription URLs are secrets: only scheme and host appear
in output and logs. Server-supplied text is untrusted and is stripped of control
and bidi characters before it reaches a terminal.

Use libraries for HTTP, base64 and URL parsing — do not hand-write a parser for
network input.

### Stage 9 follow-ups

Small extensions found while checking the Remnawave generators.

- **WebSocket early data.** Read `?ed=N` from the WebSocket path (links, Xray
  JSON) and `max_early_data` (sing-box JSON) into the model; render sing-box
  `max_early_data` with `early_data_header_name: Sec-WebSocket-Protocol` and the
  path without `?ed=`. Today the path is kept as is: it works, because Xray
  matches the path without the query, but every connection costs one more round
  trip.
- **Hysteria2.** A new `Outbound` variant, parsed from `hysteria2://` and
  `hy2://` links and from JSON, rendered as the sing-box `hysteria2` outbound.
  Remnawave already serves it to sing-box clients; the kill switch covers its
  UDP through the engine permit. Check salamander obfuscation and port hopping
  (`server_ports`) against the pinned sing-box docs before claiming support in
  the capabilities.

### Stage 10 — traffic statistics

Local-only control API, a unique port or socket per engine session, readiness
check, polling. Statistics errors never move the engine to a failed state, and
traffic updates independently of state transitions.

- **10a, helper side: done** (`4280744`, `4055f57`, `cfe9e83`). The contract
  and its invariants are in `ENGINE.md`, "Traffic statistics".
- **10b, GUI:** rates and session totals on the connection screen, only while
  connected. The totals include direct-rule traffic, so the label must not say
  "through the proxy". The speed graph needs a history kept in the GUI, because
  the helper publishes only the latest sample.

### Stage 11 — events and rule updates

Add subscription to events only once status polling is a reliable fallback;
events are never the only source of state. Decide writer serialisation, event
ordering, backpressure, cleanup on disconnect, and the protocol version impact.
A slow subscriber must not hold the session mutex.

Rule updates: use a backend reload where it exists, otherwise a controlled
restart. Never drop protection during a reload; on failure stay protected or
return to the last working configuration.

### After stage 11 — temporary rules (idea)

A rule added "for this session": it takes effect immediately and is gone after
disconnect, never written to the configuration. An overlay above the active
rule set, matched first; rule sets stay independent of subscriptions. Needs the
live rule updates of stage 11, since the point is not reconnecting. To decide:
whether the lifetime ends at disconnect or at client exit — the helper can
outlive the client, so disconnect is the recommended boundary; how the UI marks
temporary rules.

### Stage 12 — GUI

A shell over an already-proven application layer. First scope: status, current
engine and node, traffic, connect, disconnect, subscription list, node
selection, rule-set selection, subscription update, errors, a protected-failure
indicator and an explicit action to drop protection. IPC, HTTP and config saves
run on worker threads. Check `eframe`/`egui` against the dependency checklist.

The GUI calls `rosetun-core` and `rosetun-ipc` the way the CLI does. Logic that
both clients need goes into the core, not into the GUI crate. The GUI never
writes the configuration itself: every change goes through a core function, so
a CLI running at the same time does not lose its changes. Server-supplied text
passes through `provider_text` or `terminal_text` before it is displayed, as in
the CLI.

Interface texts live in the language tables (`strings/en.rs`, `strings/ru.rs`),
never inline. They avoid the em dash: a period, comma or colon reads more
naturally in short UI text. `·` separates parts of a status line.

Steps:

- **12a — connection screen. Done.** `eframe` with `glow`; status polling and
  operations on worker threads; connect, disconnect, protected failure with an
  explicit turn-off; subscriptions, nodes, node selection; add, update and
  remove subscriptions; kill switch and rule-set selection. English UI, every
  string in one module. Without the helper the window shows `Status unknown`,
  never the last state: a dead helper has taken the engine and the kill switch
  with it.
- **12b — rules screen. Done.** Three steps: rule-set and rule operations plus input
  parsing in the core; the rules screen (sets, order, targets, enable, default
  target); the add-rule dialog with a running-process picker
  (`rosetun-processes`). Rule changes apply on the next connect until stage 11;
  no reconnect button, because a disconnect drops the kill switch.
- **12c — settings and shell. Done.** Five steps:
  1. **Done.** Settings screen: saved interface scale (an `interface` section in
     `AppConfig`, not in `Settings`, which goes to the helper), DNS-over-HTTPS
     resolver, engine log level, about (versions, open the config and log
     folders). `allow_lan` is deliberately not exposed: it changes the
     kill-switch filters and the matrix has no scenario for it yet.
  2. **Done.** Tray icon with connect and disconnect, close to tray, single
     instance (`rosetun-instance`: a named event that also wakes the first
     window). Windows only; elsewhere the close button still quits.
  - **Done.** Header from the mockup, inserted before step 3, in two parts:
    the brand header (emblem, Cormorant Garamond wordmark, tabs with icons and
    a sliding underline, background petals; the rose "blooms" while
    connecting and when connected, with no animation in idle), then the
    window frame drawn in the header on Windows (`CUSTOM_FRAME`: one constant
    brings the system frame back).
  3. In two parts. (a) **Done.** Autostart for the window (HKCU `Run` with `--hidden`,
     starts in the tray; respects the Task Manager startup switch) and a
     setting for whether the close button hides the window to the tray (on by
     default); `rosetun-instance` becomes `rosetun-shell`. (b) **Done.** A `Browse`
     file dialog for process rules (`rfd`, Windows only). The installer will
     have to remove the `Run` value on uninstall.
  4. **Done.** The UI font and the application icons. The UI font is Manrope
     (Archivo from the mockup has no Cyrillic); headings use its SemiBold, the
     wordmark stays Cormorant Garamond. The window, tray and `.exe` icons are the "Vortex" rose
     designed in Claude Design (`assets/icon/rosetun-{large,small,tray}.svg`),
     rasterised by `rose_icon.rs`, which mirrors those SVGs: change both
     together. The tray variant takes the state colour. The header keeps its
     own emblem (`paint_emblem`, `paint_petals`). `assets/rosetun.ico` is
     drawn by an ignored test (`cargo test -p rosetun-gui -- --ignored
     write_app_icon`, rerun after changing the icon); `build.rs` writes it into
     a `.res` itself, with no crate and no Windows SDK, and the MSVC linker
     embeds it. The installer uses the same file.
  5. Russian translation, in three parts. (a) **Done.** A language setting (System,
     English, Russian; the system language comes from Windows), string tables
     checked by the compiler (`strings::t()`), Russian plurals, and the GUI's
     own age, expiry and traffic texts (the CLI stays English). (b) **Done.**
     The GUI's own texts for core, IPC and system error variants (`errors.rs`,
     an `ErrorStrings` table with one-pass `{name}` templates), and a failed
     connect (`EngineFailed`, `RoutingFailed`, `UnsupportedRules`) shown only in
     the status card;
     also a computed rule type column width, a footer panel for Update all and
     plain punctuation in interface texts. (c) **Done.** Subscription URL,
     fetch and parse errors and the skipped-node reasons: the core returns
     `SubscriptionUrlError` and a typed `UpdateReport::skipped`, the GUI
     translates them with exhaustive matches (no `_` arm), and the English
     table is tested against the core's `Display`. Free text from the provider,
     the helper and sing-box stays as the detail after a translated headline;
     typed helper failure reasons would need an IPC change. Log level names stay
     English, as sing-box writes them.
- Traffic and the speed graph are stage 10b; the helper provides the numbers
  since 10a.

### After stage 12 — custom lists (GeoIP and GeoSite)

User-supplied domain and IP lists as a rule matcher, so that a single rule can
say "proxy everything on this list" — for example, only blocked sites through
the proxy and the rest direct.

- sing-box removed GeoIP and GeoSite databases in 1.12; the replacement is
  rule-set files, binary `.srs` or JSON source. Xray `geoip.dat` and
  `geosite.dat` are a different format that sing-box cannot read; converting
  them is a separate feature, not part of this one.
- Call them lists in the model (`RuleMatcher::List`, a separate collection in
  the configuration), not rule sets: `RuleSet` already means the user's set of
  rules. Lists stay independent of subscriptions, like rules.
- The client downloads remote lists, like subscriptions; the helper never
  touches the network. The client also reads local files and sends their
  content to the helper, which writes it into its own run directory and gives
  sing-box a local rule-set. The helper runs as SYSTEM and must not open a path
  the user chose: that would let a user make it read files the user cannot.
- Do not use sing-box remote rule-sets: they download at engine start, slow
  readiness and depend on the cache file.
- Engines declare list support in their capabilities; mihomo reads `.dat` and
  MMDB natively, sing-box only rule-sets.

### After stage 12 — Windows service and installer

Before anything is given to other people. Two steps:

1. **Done, checked by hand (the VM matrix is still to be rerun).** The helper
   runs as the Windows service `Rosetun` (`--service`): LocalSystem, automatic
   start, depends on `BFE`, restarts 5 s after a failure (twice, reset after a
   day, also for non-crash failures), 30 s preshutdown. Stop and preshutdown
   go through the same graceful path as the IPC `shutdown` request, which the
   service refuses (`InvalidState`): only an administrator stops the service.
   `--install-service` creates or updates and starts it, `--uninstall-service`
   stops and deletes it. Without arguments the helper runs in the console, as
   the VM rig and development use it.
   - Data live in `data` next to the helper (`ROSETUN_DATA_DIR` overrides),
     reset to a protected DACL for SYSTEM and Administrators at every start:
     `data\run` for the engines, `data\logs` for the service log. Never move
     them to a place a user can create first, such as `ProgramData`: sing-box
     runs as SYSTEM with the config from there.
   - The service log is `data\logs\helper.log`, rotated at 10 MiB and at every
     start into `helper.previous.log`; a file held open by another process is
     appended to rather than failing the service.
   - The helper runs the sing-box version check on a thread at start, so the
     Defender scan of a new binary does not land on the first connect.
2. **Done, checked on a laptop that never had Rosetun** (install, first
   connect in about 3 s, service restart after a kill, upgrade over a
   running copy, uninstall with the service running). The installer (Inno Setup 6.3+,
   `installer\rosetun.iss` and `installer\build.ps1`, which pins sing-box by
   version and SHA-256 and checks it against `SUPPORTED_SING_BOX_VERSION`): `C:\Program Files\Rosetun` with no folder choice,
   since the helper runs as SYSTEM from there; sing-box launched once at
   install; the service installed through the helper's flags; the GUI started
   without elevation; the GPL text of sing-box shipped beside it. Uninstall
   removes the service, `data` and the current user's autostart values and
   keeps `%APPDATA%\Rosetun`. The workspace version must stay numeric
   (`x.y.z`): the script passes it to `VersionInfoVersion`, which rejects a
   suffix such as `-beta`. The `AppId` GUID never changes.

Later, before a public release: code signing, third-party notices for the
Rust dependencies, and possibly a version resource so Task Manager shows
"Rosetun" rather than `rosetun-gui.exe`.

### Stage 13 — rule groups

Deferred. Proxy, Direct and Block express "Proxy = the currently selected node"
well enough. When groups arrive they become their own domain entity — a group
target, a separate collection in the config, nodes drawn from several
subscriptions — so that rules still never depend on a subscription.

### Stage 14 — Linux and macOS protection

After one fully proven Windows flow. Only the platform protection layer is
needed, not an independent default-routing implementation, since the engine owns
routes.

## Release gates

1. Windows IPC works, helper and CLI exchange frames. **passed**
2. No duplicated native routes, lifecycle covered by tests. **passed**
3. Kill switch verified on Windows: IPv4 and IPv6, protection holds after
   engine failure, disconnect restores the network. **passed in the VM**
4. Real connect through the CLI with native TUN, native routes, process rules,
   protected failure state and disconnect. **passed in the VM**
5. mihomo on the same lifecycle and protection contract. **deferred**; gate 6
   does not wait for it.
6. Persistence, subscriptions, traffic, events, GUI.
7. Installable on a clean Windows: helper as a service, installer, first connect
   succeeds without a retry. **passed on real hardware** (a laptop, first
   connect in about 3 s).

## UI (not implemented)

Dark rose theme, deliberately unlike the usual blue/green VPN clients. Mockups
live in `design/`.

- Background `#171014`, panel `#1B1418`, card `#1F1519`, modal `#211519`,
  input `#2B1D23`. Borders `#33232A` / `#3A2A31` / `#432D36`.
- Text `#F3ECEE` / `#D8CBD0` / `#B9A9AF` / `#937F88`, disabled `#5C4D54`.
- Brand rose `#C2374F`, with `#8C2338` / `#D9475F` / `#E86A80`.
- State colours are deliberately separate: connected `#E0705B` (warm, must not
  read as an error), disconnected `#8C8189`, error `#FF6A2A` (sharp, must not be
  confusable with the brand red).
- Fonts: Cormorant Garamond for the wordmark, Manrope for the UI.
- Rose motif: logo in a corner, petals semi-transparent in the header. Icons are
  sharp and geometric; widgets and buttons are rounded.
- Flat fills, simple transitions, no gradients or shadows — it has to be
  drawable in egui.
