# PortSnatcher — Design Spec

- **Date:** 2026-04-22
- **Author:** IntegSec (mike.chamberland@integsec.com) with Claude
- **Status:** Approved (design), pending implementation plan
- **License of tool:** Apache-2.0

## 1. Purpose

PortSnatcher is a pentester-facing tool that **continuously monitors a set of TCP ports on a scoped set of targets and races to exploit the short window during which an ephemeral port is open.** When it catches a port open, it fingerprints the service, stands up a local hold-open tunnel so the pentester can attack through Burp/ncat/custom tooling before the port closes again, and pushes a real-time event to notification sinks so the pentester doesn't have to watch a terminal.

It is not another general-purpose port scanner. `nmap`, `masscan`, `zmap`, `unicornscan` already cover one-shot scanning. PortSnatcher's differentiator is the **continuous race + pentester-in-the-loop handoff** — winning access to services that open for milliseconds to seconds at a time (ephemeral listeners, cloud-metadata-style short-lived bindings, flapping services, reconnection-window races).

## 2. Scope of this spec

In scope for v1:
- Continuous TCP port monitoring with three targeting profiles (internal / external / CTF)
- Two probe engines (raw / connect) with full feature parity across Linux, macOS, and Windows
- Probe ladder fingerprinting with one-probe-per-connection discipline
- Hold-open proxy (dumb TCP tunnel default, opt-in TLS MITM for HTTPS catches)
- Event bus with stable schema (SSE + WebSocket)
- Notification sinks: terminal/TUI, JSONL artifacts, desktop toast, generic webhooks
- Scope file compatible with IntegSec's `agentic-pentest-proxy`
- Public release under Apache-2.0

Deferred to v1.1+:
- First-party Burp Suite extension (architected-for, not shipped in v1)
- Caido / ZAP integrations (same event bus consumer pattern)
- UDP support
- Web dashboard for the event bus

Explicitly out of scope:
- Exploitation payload delivery (PortSnatcher hands the pentester a live socket; exploitation is the pentester's job via their chosen tooling)
- Internet-wide scanning (the explicit-target rule in §7 prohibits this)

## 3. Architecture

Rust workspace under a single repository. Runtime is async on `tokio`.

```
portsnatcher/
├── Cargo.toml                 # workspace manifest
├── LICENSE                    # Apache-2.0
├── NOTICE
├── README.md
├── docs/
│   ├── superpowers/specs/     # this doc + future specs
│   └── integrations/
│       └── burp-extension.md  # v1.1 roadmap placeholder
└── crates/
    ├── portsnatcher           # `portsnatcher` CLI binary (thin — orchestration + TUI)
    ├── ps-core                # engagement model, scope enforcement, config, shared types
    ├── ps-engine              # `ProbeEngine` trait + 2 impls: raw / connect
    ├── ps-fingerprint         # banner/TLS/protocol probes (pluggable via `Fingerprinter` trait)
    ├── ps-proxy               # hold-open: dumb TCP tunnel + opt-in TLS MITM
    ├── ps-bus                 # internal tokio broadcast + external SSE/WebSocket server
    └── ps-notify              # desktop toast + webhook sinks (Slack/Discord/ntfy/custom)
```

### 3.1 Runtime shape

A single `Orchestrator` in the binary owns the event bus and, per engagement, spawns: one `ProbeEngine` task, a pool of `Fingerprinter` workers, a `ProxyManager`, a `Notifier`, and the TUI. **All inter-component communication is via the event bus** — no direct coupling between subsystems. This is the same seam the future Burp extension consumes externally.

### 3.2 Key trait contracts

```rust
#[async_trait]
pub trait ProbeEngine: Send + Sync {
    async fn start(&mut self, ctx: EngineContext) -> Result<EventStream>;
    fn capabilities(&self) -> EngineCapabilities;
}

pub trait Fingerprinter: Send + Sync {
    fn techniques(&self) -> &[TechniqueTag];   // for scope-based gating
    fn is_destructive(&self) -> bool;
    async fn probe(&self, ctx: ProbeContext) -> ProbeOutcome;
}

#[async_trait]
pub trait HoldOpen: Send + Sync {
    async fn establish(&self, target: Target, mode: HoldOpenMode) -> Result<LocalEndpoint>;
}

#[async_trait]
pub trait EventSink: Send + Sync {
    async fn emit(&self, event: &Event);
}

pub struct ScopeGuard { /* opaque */ }
impl ScopeGuard {
    pub fn allow(&self, target: &Target) -> Result<ScopeToken, ScopeViolation>;
}
```

`ScopeToken` is the capability proof required by all packet-sending APIs in `ps-engine` — they are private to the crate and accept only a `ScopeToken`, so there is no code path that sends a packet without consulting `ScopeGuard`.

## 4. Probe engines

Two user-visible engines. Selected by `--engine raw|connect` or auto-picked based on profile + privilege check. Both emit identical `PortOpenDetected` events — everything downstream is engine-agnostic.

### 4.1 `RawEngine` (primary)

Userspace TCP via `smoltcp` as the portable default. Crafts SYN, sniffs for SYN-ACK via pcap/WinDivert, completes the handshake in userspace, hands the established connection to the fingerprinter / hold-open.

Per-OS kernel-assist fast-paths used transparently when available (identical external behavior, different internals):
- **Linux:** `nftables` rule that drops outgoing RST for the engagement's 4-tuples. Kernel adopts the handshake. Rules are scoped to the engagement and cleaned up on exit via `Drop`.
- **macOS:** Equivalent `pf` rule.
- **Windows:** `WinDivert` filter that drops outgoing RST.

When the kernel-assist path isn't available (no privileges, unsupported kernel), falls back to the userspace `smoltcp` path silently. Never degrades feature set — only internal mechanism changes.

**Requires:** `CAP_NET_RAW` on Linux, `SeLockMemoryPrivilege` / admin on Windows, `ChmodBPF` or root on macOS.

### 4.2 `ConnectEngine` (unprivileged fallback)

Plain `tokio::net::TcpStream::connect` with tight timeouts, thousands of in-flight attempts via `FuturesUnordered`, `SO_REUSEPORT` where supported. Loses sub-100ms race windows that `RawEngine` catches, but wins many sub-second races and runs anywhere — containers, jumpboxes, locked-down corp laptops.

### 4.3 Engine capability matrix

| | `RawEngine` | `ConnectEngine` |
|---|---|---|
| Needs root/admin | Yes | No |
| Linux | Yes | Yes |
| macOS | Yes | Yes |
| Windows | Yes | Yes |
| Min detect latency (typical) | ~10ms | ~50–200ms |
| Stealthier (no completed handshake signal until we want one) | Yes | No |
| Unprivileged containers | No | Yes |

## 5. Fingerprinting — the probe ladder

Fingerprinting runs in parallel with hold-open establishment, on **fresh connections** (one probe per connection) wherever the port is re-catchable. This prevents a destructive probe from polluting subsequent probes' results. For ports that open exactly once, the ladder short-circuits on the first strong signal from the passive read, skipping destructive probes in favor of the hold-open handoff.

### 5.1 Ladder order

1. **Passive banner read** (default 500ms) — zero bytes sent. Disambiguates SSH, FTP, SMTP, Redis-with-AUTH, anything that talks first. Often ends the ladder immediately.
2. **TLS ClientHello** on a fresh connection — neutral probe. Non-TLS servers close cleanly; TLS servers respond with ServerHello and the ladder forks into HTTP-over-TLS probes.
3. **Protocol-specific probes**, one per fresh connection, ordered by **port-number prior** (e.g. 5432 → Postgres first, 6379 → Redis first), each gated on "previous probe did not yield a confident match" and on **authorized techniques** (§7.2). Probe tags determine which techniques apply.

### 5.2 Probe registry (v1)

| Probe | Technique tags | Destructive? |
|---|---|---|
| `passive_banner` | `recon` | No |
| `tls_hello` | `recon`, `ssl_tls` | No |
| `http_head` | `recon`, `web_app` | No |
| `http_get_root` | `web_app` | No |
| `redis_ping` | `api_testing` | No |
| `mongo_ismaster` | `api_testing` | No |
| `postgres_startup` | `api_testing` | No |
| `smb_negotiate` | `recon` | No |
| `ssh_banner` | `recon` | No |
| `malformed_os_fp` | `recon`, `destructive` | Yes |

Probes are gated by **authorized techniques** from the scope file. Probes tagged `destructive` are additionally gated by `excluded_techniques` not containing `destructive` — which defaults to excluded for all pentest profiles.

### 5.3 Fingerprint cache

Keyed by `(target, port)`. When the same port is caught repeatedly (common on flapping services), cached partial signals and confirmed protocol are reused — no re-running a ladder whose answer we already know. Cache persists to `artifacts/<engagement>/fingerprint-cache.json` for engagement-level resume.

## 6. Hold-open proxy

Activated in parallel with fingerprinting. Two modes:

### 6.1 `DumbTunnel` (default)

Local listener (port auto-assigned from `tunnel_port_range` in config, default `7100-7199`), bidirectional byte pipe to the held-open upstream socket. Pentester attaches any TCP-speaking tool (Burp with its own upstream TLS, ncat, custom exploit). Protocol-agnostic.

**Keepalive heartbeat:** a background task sends protocol-appropriate noops to keep the upstream from idle-closing:
- TCP layer: `SO_KEEPALIVE` with aggressive intervals
- If fingerprint says HTTP: periodic `OPTIONS /` with zero side-effects
- If fingerprint says TLS: heartbeat handshake probe
- Default: nothing (pure TCP passthrough)

### 6.2 `TlsMitm` (opt-in)

Auto-offered when `tls_hello` probe detects HTTPS. `rustls` server using an on-disk PortSnatcher CA; re-encrypts upstream; logs plaintext to `artifacts/<catch>/http/transcript`. Exposes the same local tunnel port but as an HTTPS-terminating endpoint.

**CA management:**
- Generated on first run of `portsnatcher ca init`, stored in `$XDG_CONFIG_HOME/portsnatcher/ca/` (`~/.config/portsnatcher/ca/` on Linux, `~/Library/Application Support/portsnatcher/ca/` on macOS, `%APPDATA%\portsnatcher\ca\` on Windows).
- Reused across runs (single CA per install).
- `portsnatcher ca install` runs the platform-specific trust-store install (requires elevation, prompts the operator, prints fingerprint).
- `portsnatcher ca uninstall` removes it.
- No ACME / Let's Encrypt — fundamentally incompatible with MITM.

### 6.3 Mode selection per catch

- If `tls_hello` confidence ≥ 0.8 AND config `holdopen.auto_mitm_on_https = true` → `TlsMitm`.
- Otherwise → `DumbTunnel`.
- CLI flag `--force-mitm` / `--force-dumb` overrides for a run.
- TUI lets the operator toggle per-catch before anyone attaches.

## 7. Safety and scope enforcement

### 7.1 Scope file format

**PortSnatcher consumes the exact same JSON format as IntegSec's `agentic-pentest-proxy`** with a minimal namespaced extension. A scope file valid for the proxy is valid for PortSnatcher.

```json
{
  "engagement_id": "ENG-2026-0142",
  "client": "Acme Corp",
  "operator": "mike.chamberland@integsec.com",
  "authorized_targets": {
    "ip_ranges": ["10.10.10.0/24", "203.0.113.0/28"],
    "domains": ["*.acme.com"],
    "urls": ["https://app.acme.com"],
    "cloud_accounts": ["aws:123456789012"]
  },
  "excluded_targets": ["203.0.113.5", "hr.acme.com"],
  "authorized_techniques": ["recon", "web_app", "api_testing", "ssl_tls"],
  "excluded_techniques": ["dos", "destructive", "social_engineering"],
  "engagement_window": {
    "start": "2026-03-26T08:00:00Z",
    "end": "2026-04-09T17:00:00Z"
  },
  "portsnatcher": {
    "port_policy": {
      "include": ["ephemeral-iana", "22", "80", "443"],
      "exclude": []
    }
  }
}
```

**Field interpretation:**

| Field | PortSnatcher behavior |
|---|---|
| `authorized_targets.ip_ranges` | Allowlisted CIDRs — direct match |
| `authorized_targets.domains` | Resolved at startup and refreshed every 60s; wildcards supported; monotonic scope growth (§7.2) |
| `authorized_targets.urls` | Hostname extracted and resolved like `domains`; URL port is informational-only unless operator opts in |
| `authorized_targets.cloud_accounts` | **Ignored** (PortSnatcher is network-layer); accepted for format compatibility; logged as "not enforced here" on startup |
| `excluded_targets` | Denylist; wins over allowlist |
| `authorized_techniques` | Drives probe-ladder gating (§5.2); probes whose tags are not covered are skipped with `ProbeAttempted { outcome: "skipped_by_scope" }` |
| `excluded_techniques` | Hard-block for probes with those tags |
| `engagement_window` | Refuses to run before `start`; auto-stops at `end` with `EngagementFinished { reason: "window_expired" }`; soft-warns at T-30min |
| `portsnatcher.port_policy` | Optional extension namespaced so the MCP proxy ignores it cleanly |

**Format detection:** loader accepts `.json` canonical and `.yaml` / `.yml` as a convenience (warning: "canonical format is JSON for cross-tool compatibility").

### 7.2 Monotonic domain resolution

Domains are re-resolved every 60 seconds. New IPs for an authorized domain are added to the effective allowlist. Old IPs that disappear from DNS **remain allowed** for the remainder of the engagement. This matches how a pentester thinks about scope ("those services, whatever IPs they're on today") and prevents silent scope loss mid-engagement. Every resolution is logged to `audit.log`; the audit trail shows scope evolution over time.

### 7.3 `ScopeGuard` — the chokepoint

One `ScopeGuard` instance per engagement. Every outbound packet in the codebase goes through `ScopeGuard::allow(&target)?` first. Enforcement mechanism: packet-sending functions in `ps-engine` are crate-private and accept only a `ScopeToken`, which is the opaque return value of `ScopeGuard::allow`. No code path can send a packet without consulting the guard.

Every `allow` call — accept or reject — is logged to `audit.log` with full context.

### 7.4 Rate limiting

- **Global pps cap** (token bucket in `ps-engine`). Defaults vary by profile (§8).
- **Per-target pps cap** (separate token bucket per target). Defaults vary by profile.
- Both emit `RateCapEngaged` events when throttling.
- Both bypassable with `--i-know-what-im-doing` (exact flag name). The flag's friction is the feature; its presence in audit logs surfaces in pentest reports.

### 7.5 Explicit-target rule

Rejects `0.0.0.0/0`, `::/0`, and any scope file that amounts to "all of the internet." Requires at least one concrete CIDR narrower than `/8`. Prevents accidental internet-wide scanning.

### 7.6 Loopback / link-local / multicast

Hard-denied by default. Overridable with `allow_loopback = true` / `allow_link_local = true` in config for lab use.

### 7.7 Profiles

`--profile` is sugar over coherent default bundles:

| | **internal** | **external** | **ctf** |
|---|---|---|---|
| Default engine | Raw | Raw | Raw |
| Global rate cap | 50,000 pps | 1,000 pps | 100,000 pps |
| Per-target cap | 2,000 pps | 200 pps | 10,000 pps |
| Probe ladder | full | minimal (banner + TLS only) | full + aggressive |
| Toast on catch | Yes | No | Yes |
| Artifact retention | full pcap | events + banners only | full pcap |
| Scope file required | Yes | Yes (extra-strictly) | No (CTF lab mode) |

Individual settings override the profile.

## 8. Configuration model

Three layers; later overrides earlier:

1. **Profile defaults**
2. **Config file** (TOML; conventional locations + `--config`)
3. **CLI flags**

Example config:

```toml
profile = "internal"
scope_file = "./scope.json"
output_dir = "./artifacts"

[engine]
kind = "raw"                 # "raw" | "connect"

[rate]
global_pps = 50000
per_target_pps = 2000

[fingerprint]
ladder_timeout_ms = 2000
protocols = ["http", "tls", "ssh", "redis", "postgres", "mongo", "smb"]

[bus]
listen = "127.0.0.1:7177"
auth_token_file = "~/.config/portsnatcher/bus-token"

[notify]
desktop = true
webhooks = ["https://ntfy.sh/integsec-alerts"]

[holdopen]
default_mode = "dumb_tunnel"
auto_mitm_on_https = true
tunnel_port_range = "7100-7199"
```

### 8.1 Port specifications

`include` and `exclude` accept any of:
- Named sets: `all`, `top-1000`, `ephemeral-iana` (49152–65535), `ephemeral-linux` (32768–60999), `ephemeral-windows` (49152–65535), `ephemeral-bsd` (49152–65535)
- Ranges: `1024-65535`
- Individual ports: `22`, `80`, `443`
- Lists (mixed): `["ephemeral-iana", "22", "80", "443"]`

### 8.2 CLI shortcuts

```
portsnatcher 10.20.5.17 --ports ephemeral-iana --profile internal
portsnatcher --config ./engagement.toml
portsnatcher 10.20.5.17 --ports 49152-65535 --dry-run
portsnatcher ca init
portsnatcher ca install
portsnatcher cleanup                # remove any orphaned firewall rules
```

## 9. Event bus and schema

### 9.1 Transport

- **Internal:** `tokio::sync::broadcast` channel. Every event is cloned to every subscriber.
- **External:** `axum` HTTP server exposing:
  - `GET /events` (Server-Sent Events, UTF-8 JSON lines)
  - `GET /events/ws` (WebSocket, JSON messages)
- Default bind: `127.0.0.1:7177`.
- Auth: `Authorization: Bearer <token>` where the token is written to `$XDG_CONFIG_HOME/portsnatcher/bus-token` on startup (re-generated per run unless pinned in config).

### 9.2 Schema contract (frozen at `portsnatcher/v1`)

Every event is a JSON object with this envelope:

```json
{
  "schema": "portsnatcher/v1",
  "event_id": "01HX2K7Z9P8R5M4N3A2B1C0D9E",
  "catch_id": "01HX2K7Y...",
  "engagement_id": "01HX2K00...",
  "timestamp": "2026-04-22T20:30:15.123456Z",
  "type": "PortOpenDetected",
  "payload": { /* type-specific */ }
}
```

IDs are **ULID** — lexicographically sortable, so directory listings and log files are already time-ordered.

### 9.3 Event type catalog (v1)

| `type` | Payload highlights |
|---|---|
| `EngagementStarted` | `engagement_id`, `profile`, `engine`, `targets`, `ports`, `rate_cap`, `dry_run` |
| `PortOpenDetected` | `target`, `port`, `detect_latency_ms`, `engine`, `syn_rtt_ms` |
| `HoldOpenReady` | `catch_id`, `local_port`, `upstream`, `mode`, `ca_fingerprint?` |
| `HoldOpenClosed` | `catch_id`, `reason`, `duration_ms` |
| `ProbeAttempted` | `catch_id`, `probe`, `outcome`, `bytes_captured` |
| `FingerprintCaptured` | `catch_id`, `protocol_guess`, `confidence`, `banner_excerpt`, `tls_info?`, `artifacts_path` |
| `CatchComplete` | `catch_id`, `total_duration_ms`, `probes_run`, `final_protocol`, `artifacts_path` |
| `ScopeViolationBlocked` | `attempted_target`, `attempted_port`, `reason` |
| `RateCapEngaged` | `current_pps`, `cap_pps`, `throttled_targets` |
| `EngagementFinished` | `engagement_id`, `catches_total`, `artifacts_root`, `reason` |

### 9.4 Schema stability rules

- **Additive only.** New fields and new event types are non-breaking. Removing or renaming requires `portsnatcher/v2`.
- **Unknown fields ignored** on the consumer side. Consumers are explicitly instructed to tolerate unknown fields.
- **Every event carries `catch_id` where applicable** so consumers can correlate without stateful joins.

This schema is the **load-bearing contract** for future integrations — the v1.1 Burp extension, Caido/ZAP plugins, and third-party team tools all consume this bus. It does not change without a `v2` bump.

## 10. Notification sinks

All sinks implement `EventSink`; none is privileged. Active sinks are config-driven.

- `TerminalSink` — structured log to stderr via `tracing`.
- `TuiSink` — live table in the `ratatui` TUI: catches, active holds, rate gauge, audit counter.
- `JsonlSink` — appends every event to `artifacts/<engagement>/events.jsonl`.
- `DesktopSink` — native OS toast via `notify-rust`.
- `WebhookSink` — generic HTTP POST with the event JSON as the body. Covers Slack, Discord, ntfy, PagerDuty-via-Events-API, and custom team endpoints.

## 11. Artifact layout

```
artifacts/<engagement_id>/
├── engagement.json        # engagement config snapshot
├── events.jsonl           # every event, one per line, append-only
├── audit.log              # every outbound-packet decision + scope-guard verdict
├── fingerprint-cache.json
└── catches/
    └── <catch_id>/
        ├── catch.json     # summary
        ├── banner.bin     # raw passive-read bytes
        ├── tls/
        │   ├── servercert.pem
        │   └── handshake.bin
        ├── http/
        │   └── head.response
        └── transcript.pcap  # optional, --pcap flag
```

`events.jsonl` and `audit.log` are the same format shipped to bus subscribers — re-playable, grep-able, diff-able.

## 12. Error handling philosophy

- **Pre-flight errors** (bad config, missing scope file, insufficient privileges, unreachable target): exit non-zero with a clear message. No partial runs.
- **Engagement-level errors** (pcap handle dies, bus listener can't bind, disk fills): stop cleanly, emit `EngagementFinished { reason: "error", detail: … }`, flush artifacts, exit non-zero. No silent continuation on foundational failures.
- **Per-catch errors** (probe timeout, hold-open RST, single connect failure): logged as events, engagement continues. These are expected on live networks.

Standard Rust hygiene: `anyhow::Result` in the binary, `thiserror`-derived domain errors in the libraries.

## 13. Dry-run mode

`--dry-run` simulates a full engagement without sending any packets. Emits the full event stream using a synthetic "would-probe" stream. Uses:

- Confirming scope file behavior before a real run
- Confirming rate limits
- Integration testing the bus/sink pipeline without a target

## 14. Testing strategy

### 14.1 Tier 1 — Unit (per crate, no network)

- `ScopeGuard` — all allow/deny combinations, wildcard domain merging, monotonic IP accumulation, time-window enforcement, technique gating. Property tests (`proptest`) for CIDR overlap correctness.
- Event serialization round-trips — `portsnatcher/v1` events written today deserialize unchanged forever. Snapshot tests with `insta`.
- Scope file parser — golden tests against the `agentic-pentest-proxy` example files checked into `tests/fixtures/` (copied, not symlinked, so we catch drift).
- Rate-limiter token-bucket math — burst, sustained, idle patterns.
- Probe-ladder state machine transitions.

### 14.2 Tier 2 — Integration (loopback, real sockets)

Fixture servers on `127.0.0.1:0`; kernel assigns ephemeral ports. Each test is a full slice through the real stack.

- `ConnectEngine` end-to-end — fixture opens/closes on schedule; assert `PortOpenDetected` within N ms.
- Fingerprinter — fixture servers impersonating HTTP / Redis / SSH / TLS / Postgres; assert ladder reaches correct protocol guess in expected order; assert destructive probes are not sent when excluded.
- Hold-open dumb tunnel — fixture upstream, attach through tunnel port, assert bidirectional flow, assert `HoldOpenClosed` on upstream close.
- Hold-open TLS MITM — fixture HTTPS server; assert plaintext capture; assert CA-signed leaf cert served.
- Event bus — SSE + WebSocket subscribers; assert ordering; assert auth-token enforcement.
- Audit log completeness — scripted scenario; assert exactly one audit entry per `ScopeGuard.allow()` call.

Runs on every PR across Linux / macOS / Windows via GitHub Actions matrix.

### 14.3 Tier 3 — Race-harness (the hard part)

- **`ephemeral-flapper`** — test-only binary that opens/closes ports on programmable schedules. Runs on loopback.
- **Race conformance suite** — each engine runs against `ephemeral-flapper`; assert catch rate ≥ codified thresholds:
  - `RawEngine`: ≥95% of ≥50ms windows, ≥70% of ≥20ms windows
  - `ConnectEngine`: ≥90% of ≥500ms windows, ≥50% of ≥100ms windows
- Thresholds are CI gates. If a refactor regresses catch rate, the test fails concretely.
- Two scales: tight (single target, CI-friendly) and soak (1000 targets for 10 minutes, nightly only).

### 14.4 Tier 4 — Cross-platform conformance

Tiers 2 and 3 run on all three OSes. Additional:

- Privilege-downgrade tests (Linux/macOS) — with/without `CAP_NET_RAW` / admin; assert `RawEngine` fails cleanly and `ConnectEngine` works.
- Firewall-rollback tests (Linux) — `SIGKILL` mid-engagement; assert nftables rules are still there; `portsnatcher cleanup` removes orphans.

### 14.5 Fuzzing

`cargo-fuzz` targets:
- Scope file parser (must not panic on any JSON)
- Event deserializer (malformed events from file replay must not crash)
- Banner parsers and protocol-probe response parsers

### 14.6 Test data

All fixtures live under `crates/*/tests/fixtures/`. No downloads at test time. CI is offline-capable.

### 14.7 Explicitly not tested

- Live internet targets — never, not even nightly. Tests are offline and deterministic or run against local fixture servers.
- Specific achieved `pps` numbers — runner-dependent, flaky. Rate *limits* are asserted; rate *achievements* are measured and reported but not asserted.

## 15. Release artifacts and naming

- **Public GitHub repo:** `IntegSec/PortSnatcher` (PascalCase matches IntegSec's brand; functionally equivalent to lowercase in every tool).
- **crates.io package:** `integsec-portsnatcher` (lowercase-kebab, IntegSec prefix for brand/family discovery).
- **Binary name:** `portsnatcher` (shell-friendly; set via `[[bin]] name = "portsnatcher"` in the binary crate's `Cargo.toml`).
- **Workspace crates:** `ps-core`, `ps-engine`, `ps-fingerprint`, `ps-proxy`, `ps-bus`, `ps-notify` (kebab-case Rust norm).
- **Prebuilt binaries** via GitHub Releases for `x86_64-linux`, `aarch64-linux`, `x86_64-darwin`, `aarch64-darwin`, `x86_64-windows`.
- **`cargo install integsec-portsnatcher`** from crates.io.
- **Signed releases** via sigstore / cosign (preferred) with GPG fallback.

## 16. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Abuse as an internet-wide scanner | Scope file required; explicit-target rule; `--i-know-what-im-doing` friction; audit log |
| OS-specific raw-socket failures | `ConnectEngine` fallback with full feature parity; capability probe on startup |
| Event-bus schema churn breaks integrations | Frozen `portsnatcher/v1`; additive-only rule; snapshot tests enforce it in CI |
| Destructive probes wedge fragile services | One-probe-per-connection; technique tagging; `destructive` excluded by default in every profile |
| Firewall rules leak after crash | RAII cleanup; `portsnatcher cleanup` command; CI test for SIGKILL scenario |
| Trust-store pollution from unmanaged CAs | CA install/uninstall commands; fingerprint always printed; CA lifetime is explicit |

## 17. Open questions for implementation-plan phase

- Exact `smoltcp` integration shape — whether to use its sync stack behind an adapter or adopt its `async` branch.
- WinDivert licensing implications for bundling vs. runtime-download.
- `pf` behavior on Apple Silicon macOS under SIP — confirm that the RawEngine's macOS kernel-assist path works unmodified on M-series hardware, or flag userspace-`smoltcp` as the macOS default.
- Whether `ratatui` TUI is in scope for v1 or deferred to v1.1 (a functional terminal log satisfies v1 acceptance; the TUI is polish).
- Release signing mechanism — sigstore/cosign (preferred) vs. GPG — depends on CI maturity at release time.

These are implementation decisions, not design decisions, and belong in the plan.

## 18. Explicit non-goals

- Cross-tool configuration unification beyond the scope file. Each tool has its own config.
- UDP. TCP only in v1.
- IPv6. Deferred to v1.1 (not blocked architecturally — `Target` is address-family-generic — but not validated in v1 testing).
- Payload delivery / exploitation. PortSnatcher hands the pentester a live socket; exploitation is the pentester's job.
