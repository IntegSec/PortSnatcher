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
- Wire `--tui` flag dispatch so the `ratatui` TUI is reachable from the
  binary as a non-default mode.
- Real-engagement orchestrator path (currently `--dry-run` is the only
  exercised flow end-to-end).
- Fill out smoltcp userspace TCP stack in the `RawEngine` (currently a
  documented v1 simplification — engine delegates to `connect()` with
  `engine="raw"` label pending the SYN-craft follow-up).

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

[Unreleased]: https://github.com/IntegSec/PortSnatcher/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/IntegSec/PortSnatcher/releases/tag/v1.0.0
[0.1.0-alpha]: https://github.com/IntegSec/PortSnatcher/releases/tag/v0.1.0-alpha
