# Changelog

All notable changes to PortSnatcher are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning
follows [Semantic Versioning](https://semver.org/).

The `portsnatcher/v1` event schema is frozen — additive-only until a
`v2` bump. Every release documents any new event fields or variants
here so downstream integrations (bus subscribers, future Burp
extension) can plan ahead.

## [Unreleased]

### Planned for v0.1.0
- `ConnectEngine`: first real port-catching engine (unprivileged).
- Probe ladder: passive banner, TLS ClientHello, HTTP HEAD/GET, SSH,
  Redis, Mongo, Postgres, SMB probes on fresh connections.
- Fingerprint cache keyed by `(target, port)`.

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

[Unreleased]: https://github.com/IntegSec/PortSnatcher/compare/v0.1.0-alpha...HEAD
[0.1.0-alpha]: https://github.com/IntegSec/PortSnatcher/releases/tag/v0.1.0-alpha
