# PortSnatcher v1 — Master Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement each phase plan task-by-task. This master is a roadmap and shared convention document; execute the phase plans below in order.

**Goal:** Ship PortSnatcher v1.0.0 as a public Apache-2.0 release: a continuous-race port-catcher with two engines (raw + connect), probe-ladder fingerprinting, hold-open proxy (dumb + optional TLS MITM), event bus, notification sinks, and a TUI — running with feature parity on Linux, macOS, and Windows.

**Architecture:** Rust workspace under `IntegSec/PortSnatcher`; async `tokio` runtime; all inter-component communication flows through a versioned event bus; `ScopeGuard` is a single capability-token chokepoint for every outbound packet. See [the design spec](../specs/2026-04-22-portsnatcher-design.md) for the full design rationale.

**Tech Stack:** Rust 2021, `tokio`, `axum`, `clap`, `tracing`, `serde` + `serde_json`, `rustls`, `rcgen`, `smoltcp`, `pnet`, `ratatui`, `thiserror`, `anyhow`, `ulid`, `proptest`, `insta`.

---

## Phase roadmap and release milestones

| Phase | Plan | Release | What ships |
|---|---|---|---|
| 1 | [Foundations](./2026-04-22-portsnatcher-phase1-foundations.md) | **v0.1.0-alpha** | Workspace, `ps-core` types, scope/config, event bus (SSE + WS), sinks, CLI with `--dry-run`. End-to-end spine of the tool, no scanning yet. |
| 2 | [Connect Engine + Fingerprinter](./2026-04-22-portsnatcher-phase2-connect-engine-fingerprinter.md) | **v0.1.0** | `ConnectEngine`, probe ladder, v1 probe registry (passive banner, TLS, HTTP, SSH, Redis, Mongo, Postgres, SMB), fingerprint cache. First real catches. |
| 3 | [Hold-Open Proxy](./2026-04-22-portsnatcher-phase3-hold-open-proxy.md) | **v0.2.0** | `DumbTunnel` with keepalive, `TlsMitm` with on-disk CA, `portsnatcher ca` subcommands. Pentester-in-the-loop handoff works. |
| 4 | [Raw Engine](./2026-04-22-portsnatcher-phase4-raw-engine.md) | **v0.3.0** | Userspace `smoltcp` default + per-OS kernel fast-paths (`nftables` / `pf` / `WinDivert`). Sub-100ms races. |
| 5 | [TUI + Race Harness + Release](./2026-04-22-portsnatcher-phase5-tui-race-release.md) | **v1.0.0** | `ratatui` TUI, `ephemeral-flapper` test binary with codified race-rate CI gates, fuzzing, signed cross-platform prebuilts, crates.io publish. |

Each release tag corresponds to a GitHub Release with prebuilt binaries from that phase forward. Phase plans are independent — an engineer can pick one up and execute it end-to-end without needing to interleave work from another phase.

---

## Workspace file structure (full)

This is the final layout v1 ships with. Each phase plan creates a subset.

```
PortSnatcher/
├── Cargo.toml                       # workspace manifest (phase 1)
├── Cargo.lock                       # committed; this is an app, not a library
├── LICENSE                          # Apache-2.0 (already committed)
├── NOTICE                           # (already committed)
├── README.md                        # (already committed; each phase updates status section)
├── CHANGELOG.md                     # keepachangelog format (phase 1 creates)
├── CONTRIBUTING.md                  # contribution & review process (phase 5)
├── SECURITY.md                      # vulnerability reporting (phase 5)
├── rust-toolchain.toml              # pin stable; MSRV policy (phase 1)
├── clippy.toml                      # lint configuration (phase 1)
├── rustfmt.toml                     # formatting configuration (phase 1)
├── deny.toml                        # cargo-deny license/advisory policy (phase 5)
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                   # build + test matrix (phase 1)
│   │   ├── lint.yml                 # fmt + clippy + deny (phase 1)
│   │   ├── fuzz.yml                 # nightly fuzz run (phase 5)
│   │   ├── race-harness.yml         # nightly soak tests (phase 5)
│   │   └── release.yml              # cargo-dist release (phase 5)
│   ├── ISSUE_TEMPLATE/              # (phase 5)
│   ├── PULL_REQUEST_TEMPLATE.md     # (phase 5)
│   └── dependabot.yml               # (phase 1)
├── docs/
│   ├── superpowers/
│   │   ├── specs/
│   │   │   └── 2026-04-22-portsnatcher-design.md   # the design spec
│   │   └── plans/                   # these plans
│   ├── integrations/
│   │   └── burp-extension.md        # v1.1 roadmap (already committed)
│   └── operator-guide.md            # how to actually use the tool (phase 5)
└── crates/
    ├── ps-core/                     # phase 1
    │   ├── Cargo.toml
    │   ├── src/
    │   │   ├── lib.rs
    │   │   ├── target.rs            # Target, CidrBlock
    │   │   ├── port.rs              # PortSpec, PortSet, named port groups
    │   │   ├── profile.rs           # Profile enum + profile defaults
    │   │   ├── technique.rs         # TechniqueTag
    │   │   ├── id.rs                # EngagementId, CatchId, EventId (ULID)
    │   │   ├── event.rs             # Event envelope + all payload variants
    │   │   ├── scope/
    │   │   │   ├── mod.rs
    │   │   │   ├── file.rs          # ScopeFile (agentic-pentest-proxy format)
    │   │   │   ├── guard.rs         # ScopeGuard + ScopeToken
    │   │   │   └── resolver.rs      # monotonic DNS resolution
    │   │   ├── config.rs            # TOML config loading
    │   │   ├── engagement.rs        # Engagement type (runtime config)
    │   │   └── errors.rs            # thiserror domain errors
    │   └── tests/
    │       ├── fixtures/
    │       │   ├── scope-manifest.json        # vendored from agentic-pentest-proxy
    │       │   ├── scope-test-integsec.json   # vendored
    │       │   └── scope-portsnatcher-ext.json
    │       ├── snapshots/           # insta snapshot files for event schema
    │       ├── scope_file.rs
    │       ├── scope_guard.rs
    │       └── event_schema.rs
    ├── ps-bus/                      # phase 1
    │   ├── Cargo.toml
    │   ├── src/
    │   │   ├── lib.rs
    │   │   ├── broadcast.rs         # tokio::broadcast wrapper
    │   │   ├── server.rs            # axum app with /events (SSE) + /events/ws (WS)
    │   │   ├── auth.rs              # bearer token
    │   │   └── subscriber.rs        # SubscriberHandle
    │   └── tests/
    │       ├── sse.rs
    │       ├── ws.rs
    │       └── auth.rs
    ├── ps-notify/                   # phase 1
    │   ├── Cargo.toml
    │   ├── src/
    │   │   ├── lib.rs
    │   │   ├── sink.rs              # EventSink trait
    │   │   ├── terminal.rs
    │   │   ├── jsonl.rs
    │   │   ├── webhook.rs
    │   │   └── desktop.rs
    │   └── tests/
    │       ├── jsonl.rs
    │       └── webhook.rs
    ├── ps-engine/                   # phase 2 (ConnectEngine), phase 4 (RawEngine)
    │   ├── Cargo.toml
    │   ├── src/
    │   │   ├── lib.rs
    │   │   ├── engine.rs            # ProbeEngine trait + EngineContext
    │   │   ├── rate.rs              # token-bucket rate limiter
    │   │   ├── connect/
    │   │   │   ├── mod.rs
    │   │   │   ├── worker.rs
    │   │   │   └── scheduler.rs
    │   │   └── raw/
    │   │       ├── mod.rs
    │   │       ├── userspace.rs     # smoltcp path
    │   │       └── kassist/
    │   │           ├── mod.rs
    │   │           ├── linux.rs     # nftables
    │   │           ├── macos.rs     # pf
    │   │           └── windows.rs   # WinDivert
    │   └── tests/
    │       ├── connect_engine.rs
    │       ├── raw_userspace.rs
    │       └── rate_limiter.rs
    ├── ps-fingerprint/              # phase 2
    │   ├── Cargo.toml
    │   ├── src/
    │   │   ├── lib.rs
    │   │   ├── ladder.rs            # ProbeLadder state machine
    │   │   ├── cache.rs             # FingerprintCache
    │   │   ├── report.rs            # FingerprintReport
    │   │   └── probes/
    │   │       ├── mod.rs
    │   │       ├── passive_banner.rs
    │   │       ├── tls_hello.rs
    │   │       ├── http.rs          # HEAD + GET
    │   │       ├── ssh.rs
    │   │       ├── redis.rs
    │   │       ├── mongo.rs
    │   │       ├── postgres.rs
    │   │       └── smb.rs
    │   └── tests/
    │       ├── fixtures/
    │       │   ├── servers.rs       # fixture servers for tests
    │       │   └── certs/
    │       ├── ladder.rs
    │       └── probes/
    │           └── …                # one test file per probe
    ├── ps-proxy/                    # phase 3
    │   ├── Cargo.toml
    │   ├── src/
    │   │   ├── lib.rs
    │   │   ├── hold_open.rs         # HoldOpen trait + HoldOpenMode
    │   │   ├── dumb_tunnel.rs
    │   │   ├── keepalive.rs
    │   │   ├── tls_mitm.rs
    │   │   └── ca/
    │   │       ├── mod.rs
    │   │       ├── storage.rs       # XDG-aware CA on-disk layout
    │   │       ├── generate.rs      # rcgen leaf signing
    │   │       └── trust.rs         # platform install/uninstall
    │   └── tests/
    │       ├── dumb_tunnel.rs
    │       ├── tls_mitm.rs
    │       └── ca.rs
    └── portsnatcher/                # binary crate — phases 1, 2, 3, 4, 5 add subcommands
        ├── Cargo.toml
        ├── src/
        │   ├── main.rs
        │   ├── cli.rs               # clap definitions
        │   ├── orchestrator.rs      # wires everything together
        │   ├── cmd/
        │   │   ├── mod.rs
        │   │   ├── run.rs           # the main watch loop
        │   │   ├── dry_run.rs       # phase 1
        │   │   ├── ca.rs            # phase 3
        │   │   └── cleanup.rs       # phase 4 (orphaned firewall rules)
        │   └── tui/
        │       ├── mod.rs           # phase 5
        │       ├── app.rs
        │       └── widgets.rs
        └── tests/
            └── e2e/
                ├── dry_run.rs       # phase 1
                ├── smoke.rs         # phase 2 forward
                └── ca_lifecycle.rs  # phase 3
```

**File-responsibility principle:** one responsibility per file. If a file approaches 300 lines, split it. Each file answers three questions without reading internals: what it does, how you use it, what it depends on.

---

## Shared conventions

These apply across every phase plan. Don't re-justify them per-task.

### Development rhythm

Every task follows this pattern:

1. **Read** the task to understand scope and acceptance criteria.
2. **Write the failing test first** (TDD). Run it; assert it fails for the right reason.
3. **Write the minimal implementation** to make the test pass. Resist adding features not covered by a test.
4. **Run the whole affected crate's test suite**, not just the one test. Regressions matter more than the new test.
5. **Commit** with a conventional-commits-style message.

Frequent, small commits. One logical unit per commit. If a task has multiple steps, commit after each step; don't batch.

### Conventional commit format

```
<type>(<scope>): <subject>

<body — the *why* in 1–3 sentences>

<footer — co-author tag if AI-assisted>
```

Types used: `feat`, `fix`, `test`, `docs`, `chore`, `refactor`, `perf`, `ci`, `build`. Scope is a crate name (`ps-core`, `ps-bus`, etc.) or `workspace` / `ci` / `docs`.

Example:
```
feat(ps-core): add ScopeGuard with capability-token enforcement

Packet-sending APIs in ps-engine will accept only a ScopeToken, which is
produced exclusively by ScopeGuard::allow(). This makes scope bypass
impossible from any caller — the chokepoint is structural, not discipline.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

Every commit authored through this plan should include the `Co-Authored-By` footer.

### Test layout conventions

- **Unit tests** live in `#[cfg(test)] mod tests { ... }` blocks inside the module they test. Fast, synchronous where possible, no network.
- **Integration tests** live in `crates/<crate>/tests/*.rs`. They exercise the crate's public API through `use <crate>::…`. Loopback-only; fixture servers bound to `127.0.0.1:0`.
- **Snapshot tests** use `insta`. The snapshots directory is `crates/<crate>/tests/snapshots/` and is **committed**. Snapshot updates are a deliberate, reviewable action (`cargo insta review`).
- **Property tests** use `proptest` for anything with combinatorial input (CIDR overlap, port spec parsing, etc.). Default case count 256.

### Error handling

- Library crates (`ps-*`): use `thiserror`-derived enums. Each crate has one `Error` enum in `errors.rs`, plus `pub type Result<T> = std::result::Result<T, Error>;` re-exported from `lib.rs`.
- Binary crate (`portsnatcher`): use `anyhow::Result` at the top level and convert lib errors with `?`. Never swallow errors; every error path ends in either a propagated `Err` or a `tracing::error!` with full context.
- Per-catch errors (a single probe timing out, a single hold-open RST'ing) are logged as events, not returned as errors — the engagement continues.

### Cross-platform code

- Code that differs per OS lives under `#[cfg(target_os = "…")]` modules, not behind runtime `if` checks.
- Every public API is available on every supported OS. If an OS lacks a capability (e.g. no `pf` on a particular system), the fallback implementation is wired in at compile time so the public API still works.
- CI matrix runs every test on `ubuntu-latest`, `macos-latest`, and `windows-latest` for every PR. Green CI on all three OSes is non-negotiable before merge.

### Dependencies — discipline

- Prefer standard `tokio` ecosystem crates over niche alternatives. Popularity is a proxy for security review and longevity.
- Pin exact versions in `Cargo.toml` for application dependencies; use ranges only where the ecosystem expects it (e.g. `serde = "1"`).
- `cargo-deny` enforces license policy (Apache-2.0 / MIT / BSD family only; `GPL` and `AGPL` blocked for v1) and advisory status. PRs that add a disallowed license fail CI.
- Every new top-level dependency in a PR warrants a one-line justification in the commit body.

### Commit cadence and branches

For v1 pre-release, the rhythm is:

- **Phase 1–4:** work lives on `main` directly. Commits are small enough and reviews fast enough that branch ceremony is overhead. CI runs per commit on `main`.
- **Phase 5:** switch to feature branches + PRs starting with the release plumbing, since that's where community contributors will land first.

After v1.0.0, every change goes through a PR. Before then, the low-ceremony approach respects that there's one author and many tasks.

### Rust toolchain

Pin `1.76.0` in `rust-toolchain.toml` for v1. Document MSRV policy in README: "PortSnatcher supports the latest stable Rust and the two minor releases prior."

---

## Execution order and cross-phase dependencies

The plans have ordered dependencies — don't skip ahead:

```
Phase 1 ──┬─▶ Phase 2 ──┬─▶ Phase 3 ──┬─▶ Phase 5
          │             │             │
          │             └─▶ Phase 4 ──┘
          │
          └─▶ (schema frozen here; every later phase inherits)
```

- **Phase 1** creates the workspace, freezes the event schema, and ships the event bus. Every later phase emits events that conform to this schema.
- **Phase 2** requires the event bus from Phase 1. Ships the first engine.
- **Phase 3** requires Phase 2 (hold-open needs caught connections to hold open). Independent of Phase 4.
- **Phase 4** requires Phase 2 (RawEngine emits the same events ConnectEngine does and reuses the probe ladder). Independent of Phase 3.
- **Phase 5** requires Phases 3 and 4 (TUI shows holds; race-harness tests both engines).

Phases 3 and 4 can be built in parallel in principle. For a single operator working sequentially, execute in numeric order.

---

## Acceptance criteria — v1.0.0 release gate

Before tagging v1.0.0, every one of these must hold:

- [ ] All phase plans' checklists are complete (inherit their acceptance criteria).
- [ ] Every event emitted by the binary validates against the frozen `portsnatcher/v1` schema.
- [ ] CI green on Linux / macOS / Windows, including race-harness conformance.
- [ ] `cargo install integsec-portsnatcher` from a clean machine succeeds on all three OSes.
- [ ] The operator guide (`docs/operator-guide.md`) walks through scope setup → run → catch → hold-open for a realistic scenario.
- [ ] `portsnatcher --version` prints v1.0.0.
- [ ] The README status section is updated from "design complete — implementation in progress" to "v1.0.0 shipped."
- [ ] Release artifacts are signed and published; GitHub Release notes reference the spec and each phase plan.
- [ ] CHANGELOG.md entry for v1.0.0 is complete.

---

## Self-review of this master

- **Spec coverage:** the five phase plans together cover every section of the spec. Burp extension (§2 deferred) is explicitly roadmapped in `docs/integrations/burp-extension.md`, not a v1 task. ✓
- **Placeholder scan:** the master is a roadmap, not a task list — no bite-sized tasks live here. Task-level placeholders are the phase plans' job. ✓
- **Internal consistency:** crate names, file paths, and release versions match across this doc and are referenced consistently by every phase plan. ✓
- **Dependencies between phases** are stated explicitly so no phase starts without its prerequisites. ✓

---

## Next step

Open the Phase 1 plan and start: [`./2026-04-22-portsnatcher-phase1-foundations.md`](./2026-04-22-portsnatcher-phase1-foundations.md).
