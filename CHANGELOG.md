# Changelog

All notable changes to PortSnatcher are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning
follows [Semantic Versioning](https://semver.org/).

The `portsnatcher/v1` event schema is frozen — additive-only until a
`v2` bump. Every release documents any new event fields or variants
here so downstream integrations (bus subscribers, future Burp
extension) can plan ahead.

## [Unreleased]

### Planned
- **macOS / Windows port of `SynRace`** (v1.3+): BPF on macOS,
  WinDivert on Windows.
- First-party Burp Suite extension.
- IPv6 support in the target plan and scope guard.
- `rand` for source-port pool randomisation.
- `HoldOpenClosed` event driven removal from the hold-open active-set
  (currently best-effort through `Drop`).

## [1.2.5] — 2026-04-24

Faster, cleaner shutdown.

### Changed
- **Run-live wind-down is now bounded by actual sink drain, not 800ms
  of cargo-cult sleeps.** The old flow was:
  `engine.stop() → 300ms → emit EngagementFinished → 400ms → shutdown.cancel() → 100ms`.
  The sleeps were compensating for the sink dispatcher fanning out
  per-sink emits as fire-and-forget `tokio::spawn` tasks — we had no
  way to know when an event had actually landed on disk.
  The dispatcher now awaits each event's sinks sequentially (all
  current sinks — tracing, JSONL append-with-flush — complete in
  <1ms, so HOL blocking is negligible in practice) and returns its
  `JoinHandle`. On `shutdown.cancelled()` it makes one `try_recv`
  drain pass over any buffered events, then exits. `run_live` awaits
  that handle — a real barrier, not a sleep.
  Net wind-down drops from ~800ms to ~50ms + drain.
- Added `BusReceiver::try_recv` and a `BusError::Empty` variant so
  the dispatcher can drain residual events without awaiting.

## [1.2.4] — 2026-04-24

Hotfix: hold-open tunnels never fired in v1.2.2 / v1.2.3 because of a
subscribe race. The `TUI Tunnel` column stayed blank, and the `Holds`
panel was empty, even for catches that fingerprinted successfully.

### Fixed
- `spawn_hold_open_manager` now subscribes to the bus **synchronously
  before** the task is spawned, and runs **before** the engine starts.
  Previously `bus.subscribe()` happened inside the spawned task after
  CA file I/O / keygen, so any `PortOpenDetected` the engine emitted
  in that window was dropped by `tokio::broadcast` (no history for
  late subscribers) — hold-open simply never saw them. Confirmed on
  Windows against a local HTTP listener: `HoldOpenReady` now fires
  reliably, and the TUI `Tunnel` column populates.
- Elevate hold-open failure log from `debug!` → `warn!` so the operator
  sees errors without flipping `RUST_LOG`.

## [1.2.3] — 2026-04-24

Hotfix: `--tui` mode was unusable because tracing logs (including
`TerminalSink` event summaries) were writing to the same stdout that
crossterm's alternate screen owns, smashing every rendered frame
into a wall of garbage. The Port Status panel was there — you just
couldn't see it under the log spam.

### Fixed
- `--tui` now sinks tracing to `<artifacts_dir>/portsnatcher-tui.log`
  (ANSI off) instead of stdout. Falls back to a no-op subscriber if the
  log file can't be opened — better to lose the operational log than
  corrupt the TUI. Non-TUI mode is unchanged.

## [1.2.2] — 2026-04-24

Live port status + hold-open tunnels in the live orchestrator.

### Added
- **`PortClosedDetected` event** (additive to the frozen
  `portsnatcher/v1` schema). Emitted by the scheduler when a port that
  was previously seen open is observed closed — either directly
  (`connection_refused`) or after two consecutive timeouts (interpreted
  as closed). Includes `was_open_for_ms` so consumers can reason about
  ephemeral flap behaviour.
- **Scheduler state tracking**: new `ps_engine::port_state` module with
  a thread-safe `PortStateTracker`. Shared by ConnectEngine,
  RawEngine's userspace fallback, and Linux SynRace's handoff. All
  three now emit `PortOpenDetected` only on Closed/Unknown → Open
  transitions (no more 443 pile-up) and `PortClosedDetected` on
  Open → Closed.
- **TUI "Port Status" panel** keyed by `(target, port)`. Shows
  `OPEN` / `CLOSED` / `FLAPPING` with colour, duration-in-state
  (`3m14s`), flip counter, protocol, and tunnel-port. Always-open
  services appear as a single stable row; ephemeral flappers flip
  in place and count up. TUI layout is now 3 stacked rows:
  Port Status → (Catches + Holds) → (Rate + Event log).
- **Hold-open tunnel wired into the live orchestrator**. On each
  PortOpenDetected, the orchestrator opens a fresh upstream TCP
  connection and hands it to `ps_proxy::DumbTunnel::establish`; one
  tunnel per `(ip, port)` (de-duplicated). `HoldOpenReady` events
  surface the `localhost:71xx` port on the TUI's Port Status row.
  CA bootstrap is best-effort: if CA load/generate fails (locked
  filesystem), hold-open is skipped and the rest of the engagement
  still runs.

### Changed
- PortOpenDetected semantics: now a **transition event**, not a
  per-attempt event. External consumers that depended on "one
  PortOpenDetected per catch" may want to also listen for
  `ConnectionCaught` (internal mpsc) — but that's internal; on the
  external JSON schema, consumers should reason in terms of
  open↔closed transitions.

### Notes for operators
- After the v1.2.1 run your team did, you'll now see:
  - `PortOpenDetected 38.32.112.58:443 engine=connect ...` exactly once
  - Subsequent catches silently cached; no event spam
  - `HoldOpenReady upstream=38.32.112.58:443 → localhost:7101 mode=dumb_tunnel`
    — point Burp at `localhost:7101`
  - A live Port Status panel when running with `--tui`

## [1.2.1] — 2026-04-24

UX / correctness fixes surfaced during the first real-world engagement
run. Same feature set as v1.2.0; no schema changes.

### Fixed
- **`TerminalSink` now prints the payload.** Before, every event
  rendered as `INFO EventType schema=... engagement=...` with the
  interesting fields swallowed — `ScopeViolationBlocked` in particular
  hid its `reason` and target, making "why was this blocked?"
  effectively unanswerable from the console. Per-variant summaries now
  surface target:port, reason, protocol, probe outcome, latency, etc.
- **Scope-file `authorized_targets.domains` are resolved at engagement
  start** and each resolved IPv4 is added to the `ScopeGuard`
  allowlist as a `/32`. The previous behaviour silently ignored the
  domains, so a scope that authorised only domains (or a mix of
  domains + `/32` IPs) effectively allowed nothing except the explicit
  IPs. Wildcard domains log a skip notice.
- **No more silent `--target` default to `127.0.0.1`.** If `--target`
  is omitted, the port plan is built from the scope file's `/32`
  ip-ranges + resolved domains. If neither are present, the binary
  now errors clearly instead of flooding `ScopeViolationBlocked`.

### Added
- **15-second progress heartbeat** (`tracing::info!`) during live
  engagements. Surfaces "elapsed=Xs remaining=Ys" so a 10-minute scan
  against a fully filtered host doesn't look dead.
- Helpful log lines when the orchestrator resolves scope domains,
  builds the port plan, and when large CIDRs in `ip_ranges` are
  skipped for iteration (add `--target` explicitly for those).

### Notes for operators
The first real engagement try revealed exactly the fixes above: a
10-minute scan of `ephemeral-iana` against a hardened public host
produced no open ports (correct) but also no intermediate output
(bad). A separate run without `--target` produced a flood of blocks
whose reason was invisible (worse). Both are fixed here. Rerun with
the same scope file and command line; output should now be legible.

## [1.2.0] — 2026-04-23

**Real sub-100ms SYN race on Linux.** This is the release where the
"catch ephemeral ports" headline stops being aspirational.

### Added
- **`ps-engine/src/raw/syn_race/`** — new Linux-only module:
  - `packet.rs`: TCP SYN header construction + IPv4-pseudo-header
    checksum. Pure-math, unit-tested cross-platform.
  - `port_pool.rs`: atomic-cursor source-port pool (40000–49999).
  - `sender.rs`: `pnet::transport` `IPPROTO_TCP` raw socket; sends
    crafted SYNs from pool-allocated source ports. Includes
    `discover_local_ipv4` helper (UDP-connect routing trick).
  - `receiver.rs`: `pnet::datalink` pcap-style thread that filters
    inbound SYN-ACKs by target-IP set + port-pool bounds and emits
    `SynAckHit` via tokio mpsc.
  - `linux_engine.rs`: orchestrator that spawns sender, receiver,
    and a handoff task emitting `PortOpenDetected` the moment a
    SYN-ACK lands and opening a `tokio::TcpStream::connect` for the
    downstream fingerprinter.
- `pnet = "0.35"` as a Linux-only workspace dep.
- Tests: 6 pure-math packet tests, 3 filter-logic receiver tests,
  4 port-pool tests. All run in CI without privileges.

### Changed
- **`RawEngine::start()` (Linux): delegates to `SynRace::start` first.**
  If SYN-race can't initialise (missing `CAP_NET_RAW`, no default
  IPv4 interface, etc.) it logs a warning and falls through to the
  existing connect-labelled-raw scheduler. Public interface unchanged.
- `BACKEND_STATUS` constant replaces the v1.0 `STUB_NOTE`. On Linux
  it reads "SynRace since v1.2"; on macOS/Windows it still reads
  "connect-labelled-raw scheduler; smoltcp/BPF/WinDivert port is
  v1.3+" — greppable per-platform truth.

### Scoped for v1.2
- **IPv4 only** — v6 support is a v1.3 item.
- **Single-NIC assumption** — we discover local IPv4 via the
  UDP-connect trick once at engine start; multi-homed hosts with
  different source IPs for different targets aren't handled yet.
- **`nftables` RST-drop kassist** is still installed in parallel but
  the SYN-race doesn't *require* it; on hosts without it, the remote
  may RST our half-open sprays (harmless; the kernel-connect handoff
  re-opens from a fresh source port).

### Notes for operators
- Grant `CAP_NET_RAW` (and `CAP_NET_BIND_SERVICE` if needed) to the
  binary. Either run as root or use `setcap`:
  ```
  sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/portsnatcher
  ```
  See `docs/operator-guide.md` for the full recipe.

## [1.0.1] — 2026-04-23

## [1.0.1] — 2026-04-23

Polish release. Closes the gap between "v1 code shipped" and
"`portsnatcher <target> --ports X` actually catches ports end-to-end."

### Added
- **Live-engagement orchestrator path**: `run_live` builds an
  `Engagement` (from `--scope-file` / `--config` or a permissive default
  for CLI-only runs), starts `ConnectEngine` with an expanded `(ip,
  port)` plan, spawns a `ProbeLadder` worker pool consuming
  `ConnectionCaught`, emits `EngagementStarted` / `EngagementFinished`.
- **`--tui` flag** dispatches into the already-shipped `ratatui` TUI as
  a peer subscriber to the bus. The TUI's own quit keybinding cancels
  the shared `CancellationToken` so the engagement winds down cleanly.
- **`--duration-ms`** CLI flag for explicit live-engagement windows
  (default 10,000 ms).
- **`live_smoke.rs`** E2E integration test: fixture TcpListener on
  loopback, the binary catches it, asserts the full event arc lands
  in `events.jsonl`.

### Fixed
- Emit `EngagementFinished` before cancelling the shared shutdown token
  so the sink dispatcher has a chance to pick it up. Previously the
  dispatcher broke out of its `tokio::select!` on cancel and discarded
  the terminal event.

### Notes
- `ps-engine` and `ps-fingerprint` were added as `portsnatcher` binary
  deps (they were transitively present but not directly listed, so the
  orchestrator's `use ps_engine::...` failed to resolve on CI).

## [1.0.0] — 2026-04-23

Public GA. Workspace complete across all phases of the original design
spec; all code compiles and every test passes on Linux / macOS / Windows.

### Added (since v0.1.0-alpha)
- **`ps-engine`**: `ProbeEngine` trait with `ConnectEngine` (unprivileged
  async TCP `connect()` with `FuturesUnordered` concurrency, per-(ip,port)
  exponential-jitter backoff for flapping ports), two-axis token-bucket
  rate limiter (global pps + per-target pps).
- **`ps-engine::raw`**: `RawEngine` facade implementing `ProbeEngine`
  with capability probe and graceful fallback between: userspace
  `smoltcp`-style path (documented v1 simplification — delegates to
  connect() with "raw" engine label), and per-OS kernel-assist
  backends (`nftables` on Linux, `pf` on macOS, `WinDivert` on Windows
  via runtime `libloading`).
- **`ps-fingerprint`**: `ProbeLadder` with fresh-connection discipline
  and scope-based technique gating; nine probes (passive banner, TLS
  ClientHello, HTTP HEAD, HTTP GET /, SSH banner, Redis PING, Mongo
  isMaster, Postgres StartupMessage, SMB2 NEGOTIATE); `FingerprintCache`
  keyed by `(ip, port)` with atomic JSON persistence.
- **`ps-proxy`**: `HoldOpen` trait, `DumbTunnel` with `HoldOpenReady`/
  `HoldOpenClosed` events and TCP keepalive, `TlsMitm` with rustls
  termination + plaintext transcript; reusable on-disk ECDSA P-256 CA
  (`rcgen`) with XDG-aware storage, hostname-bounded LRU leaf cache,
  platform trust-store install/uninstall helpers (Linux
  `update-ca-certificates`, macOS `security add-trusted-cert`, Windows
  `Import-Certificate`).
- **`portsnatcher ca` subcommand module**: `init`, `install`, `uninstall`,
  `fingerprint`, `show`.
- **`portsnatcher cleanup` subcommand module**: scans and removes
  orphaned kassist state files (nftables tables, pf anchors,
  WinDivert state).
- **`portsnatcher` TUI (`ratatui`)**: four-panel layout (catches, holds,
  rate gauge, event log) with crossterm event loop, `q`/`p`/`c`/`Enter`
  keybindings and `arboard` clipboard copy. Compiles into the binary;
  `--tui` flag dispatch is the v1 follow-up.
- **`ephemeral-flapper` test binary**: TOML-manifest-from-stdin drives
  deterministic port open/close cycles for the race-conformance suite.
- **`fuzz/`**: `cargo-fuzz` setup with four targets (scope file, event
  deserializer, HTTP parser, TLS record parser).
- **`deny.toml`**: license allowlist (Apache-2.0 / MIT / BSD family /
  Unicode / Mozilla); AGPL and GPL denied.
- **`.github/workflows/release.yml`**: tag-triggered cargo-dist build
  across `x86_64/aarch64-linux-gnu`, `x86_64/aarch64-apple-darwin`,
  `x86_64-pc-windows-msvc`; sigstore signing via OIDC
  (continue-on-error so missing policy doesn't block the release);
  ordered crates.io publish chain gated on `CARGO_REGISTRY_TOKEN`.
- **`.github/workflows/fuzz.yml`**: nightly 5-minute cargo-fuzz run
  per target.
- **Docs**: `docs/operator-guide.md` soup-to-nuts usage; `SECURITY.md`
  disclosure policy; `CONTRIBUTING.md` dev setup and schema-stability
  policy.

### Schema
- `portsnatcher/v1` unchanged. 10-variant frozen schema still enforced
  by `insta` snapshot tests.

### Notes
- v0.1.0, v0.2.0, and v0.3.0 intermediate tags from the master plan were
  collapsed into a single v1.0.0 cut. The phase plans remain under
  `docs/superpowers/plans/` for historical reference.
- The `RawEngine` userspace backend currently delegates to the same
  `connect()` scheduler as `ConnectEngine` with an `"raw"` engine label
  — a pragmatic v1 simplification while the full smoltcp-plus-raw-sockets
  path is developed. Kernel-assist fast-paths on Linux/macOS/Windows do
  install correctly when their tooling is available, providing the
  intended RST-drop optimization.

## [0.1.0-alpha] — 2026-04-23

The foundations release. Sets up the public repo, the frozen
`portsnatcher/v1` event schema, the scope-file contract shared with
`IntegSec/agentic-pentest-proxy`, and an end-to-end spine (scope →
config → event bus → sinks) that a `--dry-run` mode exercises with a
synthetic event stream.

### Added
- Rust 2021 workspace under `IntegSec/PortSnatcher`, Apache-2.0.
- `ps-core`: `Target`, `CidrBlock`, `PortSpec` (named sets including full
  nmap top-1000, ranges, mixed lists), `Profile` enum with internal /
  external / ctf defaults, `TechniqueTag` mirroring agentic-pentest-proxy
  taxonomy, ULID-backed `EngagementId` / `CatchId` / `EventId`, frozen
  `Event` envelope with all 10 payload variants, `ScopeFile` parser with
  vendored agentic-pentest-proxy fixtures, `ScopeGuard` capability-token
  chokepoint, monotonic DNS resolver, TOML `Config` covering every spec
  §8 section, `Engagement` runtime struct.
- `ps-bus`: tokio-broadcast wrapper, bearer-token auth, `axum` HTTP
  server exposing SSE (`GET /events`) and WebSocket (`GET /events/ws`).
- `ps-notify`: `EventSink` trait and four sinks — terminal (`tracing`),
  JSONL (append-only), webhook (HTTP POST with exponential-backoff
  retries), desktop (`notify-rust`, swallows failures in headless envs).
- `portsnatcher` binary (crates.io: `integsec-portsnatcher`) with clap
  CLI, orchestrator skeleton, and `--dry-run` synthetic event generator.
- Schema-stability tests: 10 `insta` snapshots, one per payload variant,
  pinned to deterministic IDs. Any diff requires a `portsnatcher/v2`
  bump and coordinated consumer updates.
- CI: Linux / macOS / Windows build+test matrix, `cargo fmt` and
  `cargo clippy --workspace --all-targets -- -D warnings` lint gate,
  weekly Dependabot updates for cargo + github-actions.

### Schema
- **Frozen at `portsnatcher/v1`.** Ten payload variants defined and
  snapshot-tested: `EngagementStarted`, `PortOpenDetected`, `HoldOpenReady`,
  `HoldOpenClosed`, `ProbeAttempted`, `FingerprintCaptured`, `CatchComplete`,
  `ScopeViolationBlocked`, `RateCapEngaged`, `EngagementFinished`.

### Notes
- MSRV is 1.85. `rust-toolchain.toml` is intentionally not pinned for
  this release; CI uses stable and developers pick any toolchain
  ≥ 1.85. We may pin later once host disk situations are unlikely
  to fight `rustup` sync behaviour.
- Dev profile is disk-constrained (`debug = 0`, `incremental = false`) —
  this was required to build on the original development host and has
  the side effect of making CI artefacts smaller too.

[Unreleased]: https://github.com/IntegSec/PortSnatcher/compare/v1.2.5...HEAD
[1.2.5]: https://github.com/IntegSec/PortSnatcher/releases/tag/v1.2.5
[1.2.4]: https://github.com/IntegSec/PortSnatcher/releases/tag/v1.2.4
[1.2.3]: https://github.com/IntegSec/PortSnatcher/releases/tag/v1.2.3
[1.2.2]: https://github.com/IntegSec/PortSnatcher/releases/tag/v1.2.2
[1.2.1]: https://github.com/IntegSec/PortSnatcher/releases/tag/v1.2.1
[1.2.0]: https://github.com/IntegSec/PortSnatcher/releases/tag/v1.2.0
[1.0.1]: https://github.com/IntegSec/PortSnatcher/releases/tag/v1.0.1
[1.0.0]: https://github.com/IntegSec/PortSnatcher/releases/tag/v1.0.0
[0.1.0-alpha]: https://github.com/IntegSec/PortSnatcher/releases/tag/v0.1.0-alpha
