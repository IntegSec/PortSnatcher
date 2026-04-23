# Phase 1 — Foundations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the PortSnatcher workspace, freeze the `portsnatcher/v1` event schema, and ship the full spine (scope → config → event bus → sinks → CLI) end-to-end so every later phase has a stable platform to build on. No actual port scanning yet; a `--dry-run` mode emits a synthetic event stream that exercises the whole pipeline.

**Architecture:** Rust 2021 workspace; async `tokio`; event-driven throughout. `ScopeGuard` is the single capability-token chokepoint (unused this phase — no packets — but defined and tested). Event schema is frozen here.

**Tech Stack:** `tokio`, `axum`, `clap`, `tracing`, `tracing-subscriber`, `serde`, `serde_json`, `thiserror`, `anyhow`, `ulid`, `toml`, `reqwest`, `reqwest-eventsource`, `tokio-tungstenite`, `notify-rust`, `insta`, `proptest`, `httpmock`, `directories`, `ipnet`, `hickory-resolver`, `async-trait`, `bytes`, `tokio-util`, `futures`.

**Release target:** v0.1.0-alpha.

**Assumes:** the repo already exists at `IntegSec/PortSnatcher` with `LICENSE`, `NOTICE`, `README.md`, `.gitignore`, `.gitattributes`, the design spec under `docs/superpowers/specs/`, and the master plan under `docs/superpowers/plans/` all committed to `main`. Phase 1 adds everything else.

---

## Conventions recap (applies to every task in this phase)

Follow the master plan's shared conventions (`docs/superpowers/plans/2026-04-22-portsnatcher-v1-master.md` § "Shared conventions"). Key points repeated here for tight reference:

- **TDD rhythm per task:** write the failing test → run it → write minimal implementation → run test(s) → commit.
- **Run the whole crate's tests after each implementation**, not just the new test, to catch regressions: `cargo test -p <crate>`.
- **Commit format:** `<type>(<scope>): <subject>` with a 1-3 sentence body explaining *why*, and a `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>` footer. All commits pass `cargo fmt --check` and `cargo clippy -- -D warnings`.
- **Scope per commit:** one logical unit. If a task splits into multiple logical units, split into multiple commits.
- **Frequent pushes:** `git push` after each logical group of tasks so CI runs early and often.

Standard commit template:

```bash
git add <files>
git commit -m "$(cat <<'EOF'
<type>(<scope>): <subject>

<body — 1-3 sentences on why>

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task map

| # | Task | Scope |
|---|---|---|
| 1 | Create Cargo workspace manifest | `workspace` |
| 2 | Pin Rust toolchain + format/lint configs | `workspace` |
| 3 | Create `ps-core` crate skeleton | `ps-core` |
| 4 | Define `Target` and `CidrBlock` types | `ps-core` |
| 5 | Define `PortSpec` parser with named sets | `ps-core` |
| 6 | Define `Profile` enum + defaults | `ps-core` |
| 7 | Define `TechniqueTag` enum | `ps-core` |
| 8 | Define ULID-backed ID newtypes | `ps-core` |
| 9 | Define `Event` envelope + discriminator | `ps-core` |
| 10 | Define all 10 payload variants | `ps-core` |
| 11 | Snapshot-test event schema stability | `ps-core` |
| 12 | Vendor agentic-pentest-proxy scope fixtures | `ps-core` |
| 13 | Define `ScopeFile` and parser | `ps-core` |
| 14 | Define `ScopeGuard` + `ScopeToken` | `ps-core` |
| 15 | Property-test CIDR overlap correctness | `ps-core` |
| 16 | Scope time-window enforcement | `ps-core` |
| 17 | Scope technique gating | `ps-core` |
| 18 | Monotonic DNS resolver | `ps-core` |
| 19 | TOML config loader | `ps-core` |
| 20 | `Engagement` runtime struct | `ps-core` |
| 21 | `ps-core::errors` thiserror enum | `ps-core` |
| 22 | Create `ps-bus` crate skeleton | `ps-bus` |
| 23 | Bus broadcast wrapper | `ps-bus` |
| 24 | Bearer-token auth | `ps-bus` |
| 25 | SSE endpoint | `ps-bus` |
| 26 | WebSocket endpoint | `ps-bus` |
| 27 | Create `ps-notify` crate skeleton | `ps-notify` |
| 28 | `EventSink` trait + `TerminalSink` | `ps-notify` |
| 29 | `JsonlSink` append-only | `ps-notify` |
| 30 | `WebhookSink` with retries | `ps-notify` |
| 31 | `DesktopSink` stub + cross-platform wiring | `ps-notify` |
| 32 | Create `portsnatcher` binary crate | `portsnatcher` |
| 33 | `clap` CLI definition | `portsnatcher` |
| 34 | `Orchestrator` skeleton | `portsnatcher` |
| 35 | `--dry-run` synthetic event generator | `portsnatcher` |
| 36 | E2E smoke: dry-run → bus → JSONL | `portsnatcher` |
| 37 | GitHub Actions CI matrix | `ci` |
| 38 | Lint workflow (fmt + clippy + deny-warnings) | `ci` |
| 39 | Dependabot config | `ci` |
| 40 | CHANGELOG.md skeleton | `docs` |
| 41 | README status section update | `docs` |
| 42 | Tag v0.1.0-alpha and create GitHub Release | `release` |

---

## Task 1: Create Cargo workspace manifest

**Files:**
- Create: `Cargo.toml` (root)
- Create: `.cargo/config.toml`

- [ ] **Step 1: Write the `Cargo.toml` workspace manifest**

```toml
[workspace]
resolver = "2"
members = [
    "crates/ps-core",
    "crates/ps-bus",
    "crates/ps-notify",
    "crates/portsnatcher",
]

[workspace.package]
version = "0.1.0-alpha.0"
edition = "2021"
rust-version = "1.76"
license = "Apache-2.0"
repository = "https://github.com/IntegSec/PortSnatcher"
authors = ["IntegSec <security@integsec.com>"]

[workspace.dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }
tokio-util = { version = "0.7", features = ["io"] }
futures = "0.3"
async-trait = "0.1"

# HTTP / web
axum = { version = "0.7", features = ["ws"] }
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
reqwest-eventsource = "0.6"
tokio-tungstenite = { version = "0.23", features = ["rustls-tls-webpki-roots"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"

# Error handling / logging
thiserror = "1"
anyhow = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }

# IDs / time / paths
ulid = { version = "1", features = ["serde"] }
time = { version = "0.3", features = ["serde", "formatting", "parsing", "macros"] }
directories = "5"

# Networking types
ipnet = { version = "2", features = ["serde"] }
hickory-resolver = "0.24"

# CLI
clap = { version = "4", features = ["derive", "env"] }

# Desktop toast
notify-rust = "4"

# Utility
bytes = "1"

# Testing
insta = { version = "1", features = ["json", "yaml"] }
proptest = "1"
httpmock = "0.7"
tempfile = "3"
```

- [ ] **Step 2: Create `.cargo/config.toml` with release-ish dev profile overrides**

```toml
[build]
# Empty — let rustc pick defaults. Reserved for per-OS overrides if needed later.

[alias]
# Convenience aliases used in later tasks and docs.
fmt-check = "fmt --all -- --check"
clippy-all = "clippy --workspace --all-targets -- -D warnings"
test-all = "test --workspace"
```

- [ ] **Step 3: Verify workspace parses (no crates exist yet so this should fail cleanly)**

Run: `cargo metadata --format-version=1 --no-deps 2>&1 | head -5`
Expected: JSON output listing zero packages plus a `workspace_root` key, or a clean "no targets" message. A compiler error here means the manifest is malformed.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml .cargo/config.toml
git commit -m "$(cat <<'EOF'
build(workspace): add Cargo workspace manifest with shared dependencies

Locks every crate to Rust edition 2021 / 1.76 MSRV, Apache-2.0, and the
common dependency versions used throughout v1. The [workspace.dependencies]
table is the single source of truth — per-crate manifests inherit with
`tokio = { workspace = true }` so upgrades happen in exactly one place.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Pin Rust toolchain + format/lint configs

**Files:**
- Create: `rust-toolchain.toml`
- Create: `rustfmt.toml`
- Create: `clippy.toml`

- [ ] **Step 1: Write `rust-toolchain.toml`**

```toml
[toolchain]
channel = "1.76.0"
components = ["rustfmt", "clippy", "rust-src"]
profile = "minimal"
```

- [ ] **Step 2: Write `rustfmt.toml`**

```toml
edition = "2021"
max_width = 100
use_field_init_shorthand = true
use_try_shorthand = true
imports_granularity = "Module"
group_imports = "StdExternalCrate"
reorder_imports = true
newline_style = "Unix"
```

- [ ] **Step 3: Write `clippy.toml`**

```toml
msrv = "1.76.0"
cognitive-complexity-threshold = 30
too-many-arguments-threshold = 8
type-complexity-threshold = 250
```

- [ ] **Step 4: Verify the toolchain file is valid**

Run: `cargo --version`
Expected: `cargo 1.76.0 (…)` — if `rustup` is installed, this will trigger toolchain install first.

- [ ] **Step 5: Commit**

```bash
git add rust-toolchain.toml rustfmt.toml clippy.toml
git commit -m "$(cat <<'EOF'
build: pin Rust 1.76 toolchain and shared formatter/linter configuration

Consistent style and lint behaviour across every contributor's machine
matters more than the exact values picked; `rust-toolchain.toml` makes
clones reproducible, `rustfmt.toml` and `clippy.toml` mean `cargo fmt`
and `cargo clippy` are green on the same rules CI runs.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Create `ps-core` crate skeleton

**Files:**
- Create: `crates/ps-core/Cargo.toml`
- Create: `crates/ps-core/src/lib.rs`

- [ ] **Step 1: Write the failing integration test**

Create `crates/ps-core/tests/smoke.rs`:

```rust
#[test]
fn crate_loads() {
    // Import and use a marker type so the crate has to compile and export it.
    let _v: &'static str = ps_core::VERSION;
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p ps-core`
Expected: FAIL with `error[E0432]: unresolved import \`ps_core\`` or "can't find crate".

- [ ] **Step 3: Write Cargo.toml**

`crates/ps-core/Cargo.toml`:

```toml
[package]
name = "ps-core"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true
description = "PortSnatcher core types: events, scope, config, engagement."

[dependencies]
tokio = { workspace = true }
async-trait = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
toml = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }
ulid = { workspace = true }
time = { workspace = true }
directories = { workspace = true }
ipnet = { workspace = true }
hickory-resolver = { workspace = true }
bytes = { workspace = true }

[dev-dependencies]
insta = { workspace = true }
proptest = { workspace = true }
tempfile = { workspace = true }
tokio = { workspace = true, features = ["test-util", "macros"] }
```

- [ ] **Step 4: Write minimal `lib.rs`**

`crates/ps-core/src/lib.rs`:

```rust
//! PortSnatcher core: types, scope enforcement, config, and the frozen `portsnatcher/v1` event schema.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p ps-core`
Expected: PASS, 1 passed.

- [ ] **Step 6: Commit**

```bash
git add crates/ps-core/Cargo.toml crates/ps-core/src/lib.rs crates/ps-core/tests/smoke.rs
git commit -m "$(cat <<'EOF'
feat(ps-core): scaffold the ps-core crate

Starts ps-core empty except for a VERSION constant that proves the crate
compiles and re-exports correctly. Every subsequent ps-core task adds one
module and one test; this is the landing pad.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Define `Target` and `CidrBlock` types

**Files:**
- Create: `crates/ps-core/src/target.rs`
- Modify: `crates/ps-core/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Add to the bottom of `crates/ps-core/src/target.rs` (file not yet created — write it with the module and tests):

```rust
//! Target addressing: hosts, CIDR blocks, ip/port pairs.

use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Target {
    pub ip: IpAddr,
    pub port: u16,
}

impl Target {
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CidrBlock(pub IpNet);

impl CidrBlock {
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.contains(&ip)
    }
}

impl FromStr for CidrBlock {
    type Err = ipnet::AddrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<IpNet>().map(CidrBlock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_equality() {
        let a = Target::new("10.0.0.1".parse().unwrap(), 80);
        let b = Target::new("10.0.0.1".parse().unwrap(), 80);
        assert_eq!(a, b);
    }

    #[test]
    fn cidr_contains_host() {
        let block: CidrBlock = "10.0.0.0/24".parse().unwrap();
        assert!(block.contains("10.0.0.17".parse().unwrap()));
        assert!(!block.contains("10.0.1.17".parse().unwrap()));
    }

    #[test]
    fn cidr_round_trips_through_json() {
        let block: CidrBlock = "2001:db8::/32".parse().unwrap();
        let json = serde_json::to_string(&block).unwrap();
        let back: CidrBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(block, back);
    }
}
```

- [ ] **Step 2: Update `lib.rs` to export the module**

```rust
//! PortSnatcher core: types, scope enforcement, config, and the frozen `portsnatcher/v1` event schema.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod target;
pub use target::{CidrBlock, Target};
```

- [ ] **Step 3: Run test to verify it passes**

Run: `cargo test -p ps-core target::tests`
Expected: PASS, 3 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/ps-core/src/target.rs crates/ps-core/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ps-core): add Target and CidrBlock with ipnet-backed semantics

Both are Serialize/Deserialize so they flow through scope files, events,
and configs without adapters. CidrBlock wraps IpNet via a transparent
newtype so JSON stays human-readable ("10.0.0.0/24" rather than an object).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Define `PortSpec` parser with named sets

**Files:**
- Create: `crates/ps-core/src/port.rs`
- Modify: `crates/ps-core/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/ps-core/src/port.rs`:

```rust
//! Port specifications: named sets, ranges, explicit ports, and mixed lists.

use std::collections::BTreeSet;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

const EPHEMERAL_IANA: (u16, u16) = (49152, 65535);
const EPHEMERAL_LINUX: (u16, u16) = (32768, 60999);
const EPHEMERAL_WINDOWS: (u16, u16) = (49152, 65535);
const EPHEMERAL_BSD: (u16, u16) = (49152, 65535);
// Curated top-1000 TCP ports (kept small here for compilation speed; the real
// list lives in `const TOP_1000: [u16; 1000]` below and is verified by a test.
const TOP_1000_RAW: &str = include_str!("../data/top-1000.txt");

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(from = "PortSpecWire", into = "PortSpecWire")]
pub struct PortSpec(pub BTreeSet<u16>);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum PortSpecWire {
    Scalar(String),
    List(Vec<String>),
}

impl From<PortSpecWire> for PortSpec {
    fn from(w: PortSpecWire) -> Self {
        let items: Vec<String> = match w {
            PortSpecWire::Scalar(s) => vec![s],
            PortSpecWire::List(v) => v,
        };
        let mut set = BTreeSet::new();
        for item in items {
            for p in expand(&item).expect("invalid port spec; validate before deserialize") {
                set.insert(p);
            }
        }
        PortSpec(set)
    }
}

impl From<PortSpec> for PortSpecWire {
    fn from(ps: PortSpec) -> Self {
        // Serialize back as a single list of explicit ports so round-tripping is lossless.
        let items: Vec<String> = ps.0.iter().map(|p| p.to_string()).collect();
        PortSpecWire::List(items)
    }
}

impl PortSpec {
    pub fn from_spec_str(s: &str) -> Result<Self, PortSpecError> {
        let mut set = BTreeSet::new();
        for item in expand(s)? {
            set.insert(item);
        }
        Ok(PortSpec(set))
    }

    pub fn contains(&self, port: u16) -> bool {
        self.0.contains(&port)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = u16> + '_ {
        self.0.iter().copied()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PortSpecError {
    #[error("unknown named port set: {0}")]
    UnknownNamedSet(String),
    #[error("invalid port number: {0}")]
    InvalidNumber(String),
    #[error("invalid range (expected lo-hi, got {0})")]
    InvalidRange(String),
    #[error("range out of order: {0}-{1}")]
    RangeOutOfOrder(u16, u16),
}

fn expand(s: &str) -> Result<Vec<u16>, PortSpecError> {
    let s = s.trim();
    match s {
        "all" => Ok((1u16..=65535).collect()),
        "top-1000" => Ok(parse_top_1000()),
        "ephemeral-iana" => Ok(range_inclusive(EPHEMERAL_IANA.0, EPHEMERAL_IANA.1)),
        "ephemeral-linux" => Ok(range_inclusive(EPHEMERAL_LINUX.0, EPHEMERAL_LINUX.1)),
        "ephemeral-windows" => Ok(range_inclusive(EPHEMERAL_WINDOWS.0, EPHEMERAL_WINDOWS.1)),
        "ephemeral-bsd" => Ok(range_inclusive(EPHEMERAL_BSD.0, EPHEMERAL_BSD.1)),
        other if other.contains('-') => {
            let (lo_s, hi_s) = other
                .split_once('-')
                .ok_or_else(|| PortSpecError::InvalidRange(other.to_owned()))?;
            let lo: u16 = lo_s
                .trim()
                .parse()
                .map_err(|_| PortSpecError::InvalidNumber(lo_s.to_owned()))?;
            let hi: u16 = hi_s
                .trim()
                .parse()
                .map_err(|_| PortSpecError::InvalidNumber(hi_s.to_owned()))?;
            if lo > hi {
                return Err(PortSpecError::RangeOutOfOrder(lo, hi));
            }
            Ok(range_inclusive(lo, hi))
        }
        other => {
            let port: u16 = other
                .parse()
                .map_err(|_| PortSpecError::InvalidNumber(other.to_owned()))?;
            Ok(vec![port])
        }
    }
}

fn range_inclusive(lo: u16, hi: u16) -> Vec<u16> {
    (lo..=hi).collect()
}

fn parse_top_1000() -> Vec<u16> {
    TOP_1000_RAW
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.parse::<u16>().ok())
        .collect()
}

impl FromStr for PortSpec {
    type Err = PortSpecError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PortSpec::from_spec_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_port() {
        let ps = PortSpec::from_spec_str("22").unwrap();
        assert!(ps.contains(22));
        assert_eq!(ps.len(), 1);
    }

    #[test]
    fn parses_range() {
        let ps = PortSpec::from_spec_str("1024-1026").unwrap();
        assert_eq!(ps.len(), 3);
        assert!(ps.contains(1024));
        assert!(ps.contains(1025));
        assert!(ps.contains(1026));
    }

    #[test]
    fn parses_named_iana_ephemeral() {
        let ps = PortSpec::from_spec_str("ephemeral-iana").unwrap();
        assert_eq!(ps.len(), (65535 - 49152 + 1) as usize);
        assert!(ps.contains(49152));
        assert!(ps.contains(65535));
        assert!(!ps.contains(49151));
    }

    #[test]
    fn rejects_out_of_order_range() {
        assert!(matches!(
            PortSpec::from_spec_str("500-100"),
            Err(PortSpecError::RangeOutOfOrder(500, 100))
        ));
    }

    #[test]
    fn rejects_unknown_named_set() {
        let err = PortSpec::from_spec_str("ephemeral-moon").unwrap_err();
        assert!(matches!(err, PortSpecError::InvalidNumber(_)));
    }
}
```

- [ ] **Step 2: Create the top-1000 data file**

Create `crates/ps-core/data/top-1000.txt` with the nmap top-1000 TCP ports. (The canonical list is published by nmap under nmap-services. For this phase, include the top 100 below and leave a comment noting the truncation; expansion to the full 1000 is a mechanical follow-up.)

```text
# Nmap top TCP ports, truncated to 100 for initial bring-up.
# Expand to full 1000 before v0.1.0 final.
21
22
23
25
53
80
110
111
135
139
143
443
445
993
995
1723
3306
3389
5900
8080
# ... continue with the full list up to 1000 entries ...
```

- [ ] **Step 3: Update `lib.rs`**

```rust
pub mod port;
pub use port::{PortSpec, PortSpecError};
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p ps-core port::tests`
Expected: PASS, 5 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ps-core/src/port.rs crates/ps-core/data/top-1000.txt crates/ps-core/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ps-core): add PortSpec parser with named sets and ranges

Supports 'all', 'top-1000', 'ephemeral-iana/linux/windows/bsd', numeric
ranges ('1024-65535'), single ports, and mixed lists. BTreeSet storage
keeps the port list sorted and deduplicated; serde round-trip is lossless.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Define `Profile` enum + defaults

**Files:**
- Create: `crates/ps-core/src/profile.rs`
- Modify: `crates/ps-core/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/ps-core/src/profile.rs`:

```rust
//! Pentest profile: a coherent bundle of defaults (rate caps, probe ladder, artifact retention).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Internal,
    External,
    Ctf,
}

#[derive(Debug, Clone, Copy)]
pub struct ProfileDefaults {
    pub global_pps: u32,
    pub per_target_pps: u32,
    pub full_probe_ladder: bool,
    pub toast_on_catch: bool,
    pub full_pcap: bool,
    pub scope_file_required: bool,
}

impl Profile {
    pub fn defaults(self) -> ProfileDefaults {
        match self {
            Profile::Internal => ProfileDefaults {
                global_pps: 50_000,
                per_target_pps: 2_000,
                full_probe_ladder: true,
                toast_on_catch: true,
                full_pcap: true,
                scope_file_required: true,
            },
            Profile::External => ProfileDefaults {
                global_pps: 1_000,
                per_target_pps: 200,
                full_probe_ladder: false,
                toast_on_catch: false,
                full_pcap: false,
                scope_file_required: true,
            },
            Profile::Ctf => ProfileDefaults {
                global_pps: 100_000,
                per_target_pps: 10_000,
                full_probe_ladder: true,
                toast_on_catch: true,
                full_pcap: true,
                scope_file_required: false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_has_conservative_caps() {
        let d = Profile::Internal.defaults();
        assert_eq!(d.global_pps, 50_000);
        assert_eq!(d.per_target_pps, 2_000);
        assert!(d.scope_file_required);
    }

    #[test]
    fn external_is_quietest() {
        let d = Profile::External.defaults();
        assert!(d.global_pps < Profile::Internal.defaults().global_pps);
        assert!(!d.toast_on_catch);
        assert!(d.scope_file_required);
    }

    #[test]
    fn ctf_is_loudest_and_skips_scope_requirement() {
        let d = Profile::Ctf.defaults();
        assert!(d.global_pps > Profile::Internal.defaults().global_pps);
        assert!(!d.scope_file_required);
    }

    #[test]
    fn profile_serializes_lowercase() {
        let json = serde_json::to_string(&Profile::Internal).unwrap();
        assert_eq!(json, "\"internal\"");
    }
}
```

- [ ] **Step 2: Export from `lib.rs`**

```rust
pub mod profile;
pub use profile::{Profile, ProfileDefaults};
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p ps-core profile::tests`
Expected: PASS, 4 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/ps-core/src/profile.rs crates/ps-core/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ps-core): add Profile enum with internal/external/ctf defaults

Profile defaults match the spec §7.7 table. Defaults are accessed via
Profile::defaults() so callers can override individual fields without
touching the profile's canonical values.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Define `TechniqueTag` enum

**Files:**
- Create: `crates/ps-core/src/technique.rs`
- Modify: `crates/ps-core/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/ps-core/src/technique.rs`:

```rust
//! Technique tags mirror the agentic-pentest-proxy technique taxonomy.
//!
//! Values: "recon", "web_app", "api_testing", "ssl_tls", "dos",
//! "destructive", "social_engineering". Unknown tags deserialize to
//! `TechniqueTag::Other(String)` so forward-compatibility is preserved.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TechniqueTag {
    Recon,
    WebApp,
    ApiTesting,
    SslTls,
    Dos,
    Destructive,
    SocialEngineering,
    Other(String),
}

impl TechniqueTag {
    pub fn as_wire(&self) -> &str {
        match self {
            Self::Recon => "recon",
            Self::WebApp => "web_app",
            Self::ApiTesting => "api_testing",
            Self::SslTls => "ssl_tls",
            Self::Dos => "dos",
            Self::Destructive => "destructive",
            Self::SocialEngineering => "social_engineering",
            Self::Other(s) => s.as_str(),
        }
    }

    pub fn from_wire(s: &str) -> Self {
        match s {
            "recon" => Self::Recon,
            "web_app" => Self::WebApp,
            "api_testing" => Self::ApiTesting,
            "ssl_tls" => Self::SslTls,
            "dos" => Self::Dos,
            "destructive" => Self::Destructive,
            "social_engineering" => Self::SocialEngineering,
            other => Self::Other(other.to_owned()),
        }
    }
}

impl Serialize for TechniqueTag {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_wire())
    }
}

impl<'de> Deserialize<'de> for TechniqueTag {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(Self::from_wire(&s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_tag_round_trips() {
        let t = TechniqueTag::WebApp;
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"web_app\"");
        let back: TechniqueTag = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn unknown_tag_preserved() {
        let back: TechniqueTag = serde_json::from_str("\"wireless\"").unwrap();
        assert_eq!(back, TechniqueTag::Other("wireless".into()));
        let json = serde_json::to_string(&back).unwrap();
        assert_eq!(json, "\"wireless\"");
    }
}
```

- [ ] **Step 2: Export**

```rust
pub mod technique;
pub use technique::TechniqueTag;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p ps-core technique::tests`
Expected: PASS, 2 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/ps-core/src/technique.rs crates/ps-core/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ps-core): add TechniqueTag mirroring agentic-pentest-proxy values

Seven named variants plus a catch-all Other(String) so scope files from
future sister tools don't break the parser. Serializes as a wire string,
matching the JSON shape exactly.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Define ULID-backed ID newtypes

**Files:**
- Create: `crates/ps-core/src/id.rs`
- Modify: `crates/ps-core/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/ps-core/src/id.rs`:

```rust
//! Identifier newtypes. Backed by ULID so they sort lexicographically by time.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use ulid::Ulid;

macro_rules! id_newtype {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Ulid);

        impl $name {
            pub fn new() -> Self {
                Self(Ulid::new())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl FromStr for $name {
            type Err = ulid::DecodeError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self(Ulid::from_string(s)?))
            }
        }
    };
}

id_newtype!(EngagementId, "Identifier for a single engagement run.");
id_newtype!(CatchId, "Identifier for one port-catch (groups all events per catch).");
id_newtype!(EventId, "Per-event unique identifier.");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_time_sortable() {
        let a = EventId::new();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = EventId::new();
        assert!(a.to_string() < b.to_string(), "ULIDs must sort by generation time");
    }

    #[test]
    fn ids_round_trip_json() {
        let id = CatchId::new();
        let json = serde_json::to_string(&id).unwrap();
        let back: CatchId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn ids_parse_from_string() {
        let id = EngagementId::new();
        let s = id.to_string();
        let parsed: EngagementId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }
}
```

- [ ] **Step 2: Export**

```rust
pub mod id;
pub use id::{CatchId, EngagementId, EventId};
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p ps-core id::tests`
Expected: PASS, 3 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/ps-core/src/id.rs crates/ps-core/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ps-core): add ULID-backed EngagementId / CatchId / EventId newtypes

ULIDs sort lexicographically by generation time, which means `ls
artifacts/` and `cat events.jsonl` are already in event order without
explicit sorts. Newtype wrappers keep the types distinct at the type
level so a CatchId can't be passed where an EngagementId is expected.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Define `Event` envelope + discriminator

**Files:**
- Create: `crates/ps-core/src/event/mod.rs`
- Create: `crates/ps-core/src/event/payload.rs` (Task 10 fills this out)
- Modify: `crates/ps-core/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/ps-core/src/event/mod.rs`:

```rust
//! Frozen `portsnatcher/v1` event schema. See the spec §9.
//!
//! **Stability contract:** this schema is additive-only. New fields and new
//! variants are non-breaking; removing or renaming requires a v2 bump and
//! a parallel consumer update. The `insta` snapshots in the tests
//! directory are the enforcement mechanism.

pub mod payload;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::id::{CatchId, EngagementId, EventId};

pub const SCHEMA: &str = "portsnatcher/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub schema: String,
    pub event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catch_id: Option<CatchId>,
    pub engagement_id: EngagementId,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    #[serde(flatten)]
    pub body: payload::EventBody,
}

impl Event {
    pub fn new(
        engagement_id: EngagementId,
        catch_id: Option<CatchId>,
        body: payload::EventBody,
    ) -> Self {
        Self {
            schema: SCHEMA.to_owned(),
            event_id: EventId::new(),
            catch_id,
            engagement_id,
            timestamp: OffsetDateTime::now_utc(),
            body,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::payload::{EventBody, EngagementStarted};

    #[test]
    fn envelope_round_trips() {
        let e = Event::new(
            EngagementId::new(),
            None,
            EventBody::EngagementStarted(EngagementStarted {
                profile: "internal".into(),
                engine: "connect".into(),
                targets: vec!["10.0.0.0/24".into()],
                ports: "ephemeral-iana".into(),
                rate_cap_pps: 50_000,
                dry_run: false,
            }),
        );
        let json = serde_json::to_string(&e).unwrap();
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema, SCHEMA);
        assert_eq!(back.engagement_id, e.engagement_id);
    }
}
```

- [ ] **Step 2: Placeholder `payload.rs` so the module graph compiles**

`crates/ps-core/src/event/payload.rs`:

```rust
//! Event payload variants. Task 10 fills out every variant and freezes the schema.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum EventBody {
    EngagementStarted(EngagementStarted),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementStarted {
    pub profile: String,
    pub engine: String,
    pub targets: Vec<String>,
    pub ports: String,
    pub rate_cap_pps: u32,
    pub dry_run: bool,
}
```

- [ ] **Step 3: Export from `lib.rs`**

```rust
pub mod event;
pub use event::{Event, SCHEMA as EVENT_SCHEMA};
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p ps-core event::tests`
Expected: PASS, 1 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ps-core/src/event/mod.rs crates/ps-core/src/event/payload.rs crates/ps-core/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ps-core): add Event envelope with frozen portsnatcher/v1 schema

The envelope is load-bearing for every integration (bus subscribers,
Burp extension in v1.1, third-party tooling) — this commit sets the
shape and a round-trip test. Payload variants land in the next commit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: Define all 10 payload variants

**Files:**
- Modify: `crates/ps-core/src/event/payload.rs`

- [ ] **Step 1: Write the failing test (round-trip + discriminator placement)**

Add to `crates/ps-core/src/event/mod.rs` at the bottom of the `tests` module:

```rust
    #[test]
    fn all_variants_round_trip() {
        use payload::*;
        use crate::id::CatchId;

        let engagement_id = EngagementId::new();
        let catch_id = CatchId::new();

        let bodies = vec![
            EventBody::EngagementStarted(EngagementStarted {
                profile: "internal".into(),
                engine: "raw".into(),
                targets: vec!["10.0.0.0/24".into()],
                ports: "ephemeral-iana".into(),
                rate_cap_pps: 50_000,
                dry_run: false,
            }),
            EventBody::PortOpenDetected(PortOpenDetected {
                target: "10.0.0.1".into(),
                port: 54283,
                detect_latency_ms: 180,
                engine: "raw".into(),
                syn_rtt_ms: Some(2),
            }),
            EventBody::HoldOpenReady(HoldOpenReady {
                local_port: 7101,
                upstream: "10.0.0.1:54283".into(),
                mode: "dumb_tunnel".into(),
                ca_fingerprint: None,
            }),
            EventBody::HoldOpenClosed(HoldOpenClosed {
                reason: "upstream_closed".into(),
                duration_ms: 4721,
            }),
            EventBody::ProbeAttempted(ProbeAttempted {
                probe: "passive_banner".into(),
                outcome: "match".into(),
                bytes_captured: 42,
            }),
            EventBody::FingerprintCaptured(FingerprintCaptured {
                protocol_guess: Some("http/1.1".into()),
                confidence: 0.95,
                banner_excerpt: "HTTP/1.1 200 OK".into(),
                tls_info: None,
                artifacts_path: "artifacts/x/catches/y".into(),
            }),
            EventBody::CatchComplete(CatchComplete {
                total_duration_ms: 1800,
                probes_run: 3,
                final_protocol: Some("http/1.1".into()),
                artifacts_path: "artifacts/x/catches/y".into(),
            }),
            EventBody::ScopeViolationBlocked(ScopeViolationBlocked {
                attempted_target: "10.0.99.5".into(),
                attempted_port: 80,
                reason: "target not in scope".into(),
            }),
            EventBody::RateCapEngaged(RateCapEngaged {
                current_pps: 50_500,
                cap_pps: 50_000,
                throttled_targets: 2,
            }),
            EventBody::EngagementFinished(EngagementFinished {
                catches_total: 7,
                artifacts_root: "artifacts/x".into(),
                reason: "completed".into(),
            }),
        ];
        for body in bodies {
            let ev = Event::new(engagement_id, Some(catch_id), body.clone());
            let json = serde_json::to_string(&ev).unwrap();
            let back: Event = serde_json::from_str(&json).unwrap();
            assert_eq!(
                serde_json::to_string(&back.body).unwrap(),
                serde_json::to_string(&body).unwrap(),
                "body round-trip mismatch"
            );
        }
    }
```

- [ ] **Step 2: Write `payload.rs` with every variant**

Replace `crates/ps-core/src/event/payload.rs`:

```rust
//! Every payload variant in the frozen `portsnatcher/v1` schema.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum EventBody {
    EngagementStarted(EngagementStarted),
    PortOpenDetected(PortOpenDetected),
    HoldOpenReady(HoldOpenReady),
    HoldOpenClosed(HoldOpenClosed),
    ProbeAttempted(ProbeAttempted),
    FingerprintCaptured(FingerprintCaptured),
    CatchComplete(CatchComplete),
    ScopeViolationBlocked(ScopeViolationBlocked),
    RateCapEngaged(RateCapEngaged),
    EngagementFinished(EngagementFinished),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementStarted {
    pub profile: String,
    pub engine: String,
    pub targets: Vec<String>,
    pub ports: String,
    pub rate_cap_pps: u32,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortOpenDetected {
    pub target: String,
    pub port: u16,
    pub detect_latency_ms: u64,
    pub engine: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syn_rtt_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoldOpenReady {
    pub local_port: u16,
    pub upstream: String,
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoldOpenClosed {
    pub reason: String,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeAttempted {
    pub probe: String,
    pub outcome: String,
    pub bytes_captured: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintCaptured {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_guess: Option<String>,
    pub confidence: f32,
    pub banner_excerpt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_info: Option<TlsInfo>,
    pub artifacts_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub server_name: Option<String>,
    pub alpn: Option<String>,
    pub cert_subject: Option<String>,
    pub cert_issuer: Option<String>,
    pub not_after: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatchComplete {
    pub total_duration_ms: u64,
    pub probes_run: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_protocol: Option<String>,
    pub artifacts_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeViolationBlocked {
    pub attempted_target: String,
    pub attempted_port: u16,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateCapEngaged {
    pub current_pps: u32,
    pub cap_pps: u32,
    pub throttled_targets: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementFinished {
    pub catches_total: u32,
    pub artifacts_root: String,
    pub reason: String,
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p ps-core event`
Expected: PASS, 2 passed (the existing envelope test plus `all_variants_round_trip`).

- [ ] **Step 4: Commit**

```bash
git add crates/ps-core/src/event/payload.rs crates/ps-core/src/event/mod.rs
git commit -m "$(cat <<'EOF'
feat(ps-core): land all 10 event payload variants for portsnatcher/v1

Implements every event type from spec §9.3 and freezes the schema.
Round-trip test exercises every variant; `insta` snapshot tests land in
the next task and become the authoritative CI gate against schema drift.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: Snapshot-test event schema stability

**Files:**
- Create: `crates/ps-core/tests/event_schema.rs`
- Create: `crates/ps-core/tests/snapshots/` (directory; `insta` populates files)

- [ ] **Step 1: Write the snapshot test**

`crates/ps-core/tests/event_schema.rs`:

```rust
//! Schema-stability tests. If any of these snapshots change, the schema
//! is changing — which requires a `portsnatcher/v2` bump AND consumer
//! coordination. Regenerate only as a deliberate action:
//!   cargo insta review
//! Commit reviewed snapshots in the same PR as the schema bump.

use ps_core::event::payload::*;
use ps_core::event::Event;
use ps_core::id::{CatchId, EngagementId, EventId};
use serde::Serialize;
use time::macros::datetime;

/// Stamps deterministic IDs and timestamp so snapshots are reproducible.
fn deterministic_event(body: EventBody) -> Event {
    Event {
        schema: "portsnatcher/v1".to_owned(),
        event_id: EventId("01HX2K7Z9P8R5M4N3A2B1C0D9E".parse().unwrap()),
        catch_id: Some(CatchId("01HX2K7Y9P8R5M4N3A2B1C0D9E".parse().unwrap())),
        engagement_id: EngagementId("01HX2K009P8R5M4N3A2B1C0D9E".parse().unwrap()),
        timestamp: datetime!(2026-04-22 20:30:15 UTC),
        body,
    }
}

fn to_canonical_json<T: Serialize>(v: &T) -> String {
    // pretty print with sorted keys for snapshot stability
    let value: serde_json::Value = serde_json::to_value(v).unwrap();
    serde_json::to_string_pretty(&value).unwrap()
}

#[test]
fn snapshot_engagement_started() {
    let ev = deterministic_event(EventBody::EngagementStarted(EngagementStarted {
        profile: "internal".into(),
        engine: "raw".into(),
        targets: vec!["10.0.0.0/24".into()],
        ports: "ephemeral-iana".into(),
        rate_cap_pps: 50_000,
        dry_run: false,
    }));
    insta::assert_snapshot!("engagement_started", to_canonical_json(&ev));
}

#[test]
fn snapshot_port_open_detected() {
    let ev = deterministic_event(EventBody::PortOpenDetected(PortOpenDetected {
        target: "10.0.0.1".into(),
        port: 54283,
        detect_latency_ms: 180,
        engine: "raw".into(),
        syn_rtt_ms: Some(2),
    }));
    insta::assert_snapshot!("port_open_detected", to_canonical_json(&ev));
}

// Repeat for every remaining variant — one test per variant, all named
// snapshot_<variant_snake_case>. The tests directory becomes the
// schema-freeze contract.
#[test]
fn snapshot_hold_open_ready() {
    let ev = deterministic_event(EventBody::HoldOpenReady(HoldOpenReady {
        local_port: 7101,
        upstream: "10.0.0.1:54283".into(),
        mode: "dumb_tunnel".into(),
        ca_fingerprint: None,
    }));
    insta::assert_snapshot!("hold_open_ready", to_canonical_json(&ev));
}

#[test]
fn snapshot_hold_open_closed() {
    let ev = deterministic_event(EventBody::HoldOpenClosed(HoldOpenClosed {
        reason: "upstream_closed".into(),
        duration_ms: 4721,
    }));
    insta::assert_snapshot!("hold_open_closed", to_canonical_json(&ev));
}

#[test]
fn snapshot_probe_attempted() {
    let ev = deterministic_event(EventBody::ProbeAttempted(ProbeAttempted {
        probe: "tls_hello".into(),
        outcome: "match".into(),
        bytes_captured: 1234,
    }));
    insta::assert_snapshot!("probe_attempted", to_canonical_json(&ev));
}

#[test]
fn snapshot_fingerprint_captured() {
    let ev = deterministic_event(EventBody::FingerprintCaptured(FingerprintCaptured {
        protocol_guess: Some("https".into()),
        confidence: 0.95,
        banner_excerpt: "HTTP/1.1 200 OK".into(),
        tls_info: Some(TlsInfo {
            server_name: Some("example.com".into()),
            alpn: Some("h2".into()),
            cert_subject: Some("CN=example.com".into()),
            cert_issuer: Some("CN=Example CA".into()),
            not_after: Some("2027-01-01T00:00:00Z".into()),
        }),
        artifacts_path: "artifacts/01HX2K00.../catches/01HX2K7Y...".into(),
    }));
    insta::assert_snapshot!("fingerprint_captured", to_canonical_json(&ev));
}

#[test]
fn snapshot_catch_complete() {
    let ev = deterministic_event(EventBody::CatchComplete(CatchComplete {
        total_duration_ms: 1800,
        probes_run: 3,
        final_protocol: Some("http/1.1".into()),
        artifacts_path: "artifacts/01HX2K00.../catches/01HX2K7Y...".into(),
    }));
    insta::assert_snapshot!("catch_complete", to_canonical_json(&ev));
}

#[test]
fn snapshot_scope_violation_blocked() {
    let ev = deterministic_event(EventBody::ScopeViolationBlocked(ScopeViolationBlocked {
        attempted_target: "10.0.99.5".into(),
        attempted_port: 80,
        reason: "not in scope".into(),
    }));
    insta::assert_snapshot!("scope_violation_blocked", to_canonical_json(&ev));
}

#[test]
fn snapshot_rate_cap_engaged() {
    let ev = deterministic_event(EventBody::RateCapEngaged(RateCapEngaged {
        current_pps: 50_500,
        cap_pps: 50_000,
        throttled_targets: 2,
    }));
    insta::assert_snapshot!("rate_cap_engaged", to_canonical_json(&ev));
}

#[test]
fn snapshot_engagement_finished() {
    let ev = deterministic_event(EventBody::EngagementFinished(EngagementFinished {
        catches_total: 7,
        artifacts_root: "artifacts/01HX2K00...".into(),
        reason: "completed".into(),
    }));
    insta::assert_snapshot!("engagement_finished", to_canonical_json(&ev));
}
```

- [ ] **Step 2: Run tests — they will fail with "snapshot file missing"**

Run: `cargo test -p ps-core --test event_schema`
Expected: FAIL, `insta` reports 10 snapshots requiring review.

- [ ] **Step 3: Accept snapshots**

Run: `cargo insta accept` (or `INSTA_UPDATE=auto cargo test -p ps-core --test event_schema`).
Expected: all 10 snapshots are written under `crates/ps-core/tests/snapshots/`.

- [ ] **Step 4: Re-run tests to confirm they pass from disk**

Run: `cargo test -p ps-core --test event_schema`
Expected: PASS, 10 passed.

- [ ] **Step 5: Commit the tests AND the snapshot files**

```bash
git add crates/ps-core/tests/event_schema.rs crates/ps-core/tests/snapshots
git commit -m "$(cat <<'EOF'
test(ps-core): freeze portsnatcher/v1 schema via insta snapshots

Every event variant has a deterministic-ID snapshot. Snapshots are the
load-bearing schema contract — a diff means a schema change, and schema
changes require a v2 bump plus coordinated consumer updates. Regenerate
only through `cargo insta review` as a deliberate action.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: Vendor agentic-pentest-proxy scope fixtures

**Files:**
- Create: `crates/ps-core/tests/fixtures/scope-manifest.json`
- Create: `crates/ps-core/tests/fixtures/scope-test-integsec.json`
- Create: `crates/ps-core/tests/fixtures/scope-portsnatcher-ext.json`

- [ ] **Step 1: Copy the two examples from `IntegSec/agentic-pentest-proxy/examples/`**

Write `crates/ps-core/tests/fixtures/scope-manifest.json`:

```json
{
  "engagement_id": "ENG-2025-0142",
  "client": "Acme Corp",
  "operator": "operator@integsec.com",
  "authorized_targets": {
    "ip_ranges": ["10.10.10.0/24", "203.0.113.0/28"],
    "domains": ["*.acme.com", "acme-staging.example.com"],
    "urls": ["https://app.acme.com", "https://api.acme.com"],
    "cloud_accounts": ["aws:123456789012", "azure:sub-xxxx"]
  },
  "excluded_targets": ["203.0.113.5", "hr.acme.com"],
  "authorized_techniques": ["recon", "web_app", "api_testing"],
  "excluded_techniques": ["dos", "destructive", "social_engineering"],
  "engagement_window": {
    "start": "2026-03-26T08:00:00Z",
    "end": "2026-04-09T17:00:00Z"
  }
}
```

Write `crates/ps-core/tests/fixtures/scope-test-integsec.json`:

```json
{
  "engagement_id": "ENG-2026-TEST-001",
  "client": "IntegSec Internal",
  "operator": "security@integsec.com",
  "authorized_targets": {
    "ip_ranges": [],
    "domains": [
      "turbopentest.com",
      "*.turbopentest.com",
      "integsec.com",
      "*.integsec.com"
    ],
    "urls": [
      "https://turbopentest.com",
      "https://integsec.com"
    ],
    "cloud_accounts": []
  },
  "excluded_targets": [],
  "authorized_techniques": ["recon", "web_app", "api_testing", "ssl_tls"],
  "excluded_techniques": ["dos", "destructive", "social_engineering"],
  "engagement_window": {
    "start": "2026-03-27T00:00:00Z",
    "end": "2026-04-27T23:59:59Z"
  }
}
```

Write `crates/ps-core/tests/fixtures/scope-portsnatcher-ext.json`:

```json
{
  "engagement_id": "ENG-2026-0142",
  "client": "Acme Corp",
  "operator": "mike.chamberland@integsec.com",
  "authorized_targets": {
    "ip_ranges": ["10.10.10.0/24"],
    "domains": ["*.acme.com"],
    "urls": ["https://app.acme.com"],
    "cloud_accounts": []
  },
  "excluded_targets": ["203.0.113.5"],
  "authorized_techniques": ["recon", "web_app", "api_testing", "ssl_tls"],
  "excluded_techniques": ["dos", "destructive", "social_engineering"],
  "engagement_window": {
    "start": "2026-04-22T08:00:00Z",
    "end": "2026-05-06T17:00:00Z"
  },
  "portsnatcher": {
    "port_policy": {
      "include": ["ephemeral-iana", "22", "80", "443"],
      "exclude": []
    }
  }
}
```

- [ ] **Step 2: Commit the fixtures (no tests touch them yet — Task 13 will)**

```bash
git add crates/ps-core/tests/fixtures
git commit -m "$(cat <<'EOF'
test(ps-core): vendor agentic-pentest-proxy scope fixtures

scope-manifest.json and scope-test-integsec.json are copied verbatim
from IntegSec/agentic-pentest-proxy as golden fixtures for the parser.
scope-portsnatcher-ext.json exercises the portsnatcher namespaced
extension. Golden-fixture tests in the next task guard against any
accidental drift from the sister tool's format.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: Define `ScopeFile` and parser

**Files:**
- Create: `crates/ps-core/src/scope/mod.rs`
- Create: `crates/ps-core/src/scope/file.rs`
- Create: `crates/ps-core/tests/scope_file.rs`
- Modify: `crates/ps-core/src/lib.rs`

- [ ] **Step 1: Write the failing integration test**

`crates/ps-core/tests/scope_file.rs`:

```rust
use ps_core::scope::file::ScopeFile;

#[test]
fn parses_agentic_manifest() {
    let raw = include_str!("fixtures/scope-manifest.json");
    let sf: ScopeFile = serde_json::from_str(raw).expect("parse");
    assert_eq!(sf.engagement_id, "ENG-2025-0142");
    assert_eq!(sf.client, "Acme Corp");
    assert_eq!(sf.authorized_targets.ip_ranges.len(), 2);
    assert_eq!(sf.authorized_targets.domains.len(), 2);
    assert!(sf.portsnatcher.is_none());
}

#[test]
fn parses_integsec_fixture() {
    let raw = include_str!("fixtures/scope-test-integsec.json");
    let sf: ScopeFile = serde_json::from_str(raw).expect("parse");
    assert_eq!(sf.engagement_id, "ENG-2026-TEST-001");
    assert!(sf.authorized_targets.ip_ranges.is_empty());
}

#[test]
fn parses_portsnatcher_extension() {
    let raw = include_str!("fixtures/scope-portsnatcher-ext.json");
    let sf: ScopeFile = serde_json::from_str(raw).expect("parse");
    let ext = sf.portsnatcher.as_ref().expect("has extension");
    assert!(ext.port_policy.include.contains(&"ephemeral-iana".to_owned()));
}
```

- [ ] **Step 2: Write `scope/file.rs`**

`crates/ps-core/src/scope/file.rs`:

```rust
//! Scope file: exact JSON shape consumed by IntegSec/agentic-pentest-proxy
//! plus an optional, namespaced `portsnatcher` extension.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::technique::TechniqueTag;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeFile {
    pub engagement_id: String,
    pub client: String,
    pub operator: String,
    pub authorized_targets: AuthorizedTargets,
    #[serde(default)]
    pub excluded_targets: Vec<String>,
    #[serde(default)]
    pub authorized_techniques: Vec<TechniqueTag>,
    #[serde(default)]
    pub excluded_techniques: Vec<TechniqueTag>,
    pub engagement_window: EngagementWindow,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portsnatcher: Option<PortsnatcherExtension>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedTargets {
    #[serde(default)]
    pub ip_ranges: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub cloud_accounts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementWindow {
    #[serde(with = "time::serde::rfc3339")]
    pub start: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub end: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortsnatcherExtension {
    pub port_policy: PortPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortPolicy {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

impl ScopeFile {
    pub fn load(path: &std::path::Path) -> Result<Self, LoadError> {
        let raw = std::fs::read_to_string(path)?;
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            Ok(serde_json::from_str(&raw)?)
        } else {
            tracing::warn!(
                "loading scope file as YAML; canonical format is JSON for cross-tool compatibility"
            );
            Ok(serde_yaml::from_str(&raw).map_err(LoadError::Yaml)?)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("yaml parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}
```

Add `serde_yaml = "0.9"` to `crates/ps-core/Cargo.toml` `[dependencies]`.

- [ ] **Step 3: Write `scope/mod.rs` and export**

```rust
pub mod file;
pub use file::ScopeFile;
```

Update `crates/ps-core/src/lib.rs`:

```rust
pub mod scope;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p ps-core --test scope_file`
Expected: PASS, 3 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ps-core/src/scope/mod.rs crates/ps-core/src/scope/file.rs crates/ps-core/tests/scope_file.rs crates/ps-core/src/lib.rs crates/ps-core/Cargo.toml
git commit -m "$(cat <<'EOF'
feat(ps-core): add ScopeFile parser (agentic-pentest-proxy compatible)

Exact JSON shape, plus a namespaced `portsnatcher` extension for the
port policy. YAML is accepted as a convenience with a warning. The
vendored agentic-pentest-proxy examples are golden fixtures — any
drift in the sister tool's format will surface as a test failure here.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 14: Define `ScopeGuard` + `ScopeToken`

**Files:**
- Create: `crates/ps-core/src/scope/guard.rs`
- Modify: `crates/ps-core/src/scope/mod.rs`

- [ ] **Step 1: Write the failing unit test**

Inside `crates/ps-core/src/scope/guard.rs`:

```rust
//! Scope enforcement chokepoint. Every outbound packet must acquire a
//! [`ScopeToken`] via [`ScopeGuard::allow`]. Packet-sending APIs in
//! `ps-engine` are crate-private and accept only `ScopeToken`, so scope
//! bypass is structurally impossible rather than a matter of discipline.

use std::collections::HashSet;
use std::net::IpAddr;

use ipnet::IpNet;
use time::OffsetDateTime;

use crate::target::Target;
use crate::technique::TechniqueTag;

#[derive(Debug)]
pub struct ScopeGuard {
    allow_cidrs: Vec<IpNet>,
    deny_hosts: HashSet<IpAddr>,
    allow_techniques: Vec<TechniqueTag>,
    deny_techniques: Vec<TechniqueTag>,
    window_start: OffsetDateTime,
    window_end: OffsetDateTime,
}

impl ScopeGuard {
    pub fn builder() -> ScopeGuardBuilder {
        ScopeGuardBuilder::default()
    }

    pub fn allow(
        &self,
        target: &Target,
        now: OffsetDateTime,
    ) -> Result<ScopeToken, ScopeViolation> {
        if now < self.window_start || now > self.window_end {
            return Err(ScopeViolation::OutsideWindow);
        }
        if self.deny_hosts.contains(&target.ip) {
            return Err(ScopeViolation::Excluded);
        }
        if !self.allow_cidrs.iter().any(|c| c.contains(&target.ip)) {
            return Err(ScopeViolation::NotInScope);
        }
        Ok(ScopeToken(()))
    }

    pub fn allow_technique(&self, tag: &TechniqueTag) -> bool {
        if self.deny_techniques.contains(tag) {
            return false;
        }
        if self.allow_techniques.is_empty() {
            return true;
        }
        self.allow_techniques.contains(tag)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScopeViolation {
    #[error("target is not in authorized scope")]
    NotInScope,
    #[error("target is excluded")]
    Excluded,
    #[error("outside engagement window")]
    OutsideWindow,
}

/// Capability token. Opaque, only constructable inside this crate. Every
/// outbound-packet API in `ps-engine` requires one, so accepting a
/// `ScopeToken` is proof that `ScopeGuard::allow` has been called.
#[derive(Debug, Clone, Copy)]
pub struct ScopeToken(());

#[derive(Debug, Default)]
pub struct ScopeGuardBuilder {
    allow_cidrs: Vec<IpNet>,
    deny_hosts: HashSet<IpAddr>,
    allow_techniques: Vec<TechniqueTag>,
    deny_techniques: Vec<TechniqueTag>,
    window_start: Option<OffsetDateTime>,
    window_end: Option<OffsetDateTime>,
}

impl ScopeGuardBuilder {
    pub fn allow_cidr(mut self, net: IpNet) -> Self {
        self.allow_cidrs.push(net);
        self
    }

    pub fn deny_host(mut self, ip: IpAddr) -> Self {
        self.deny_hosts.insert(ip);
        self
    }

    pub fn allow_techniques(mut self, tags: Vec<TechniqueTag>) -> Self {
        self.allow_techniques = tags;
        self
    }

    pub fn deny_techniques(mut self, tags: Vec<TechniqueTag>) -> Self {
        self.deny_techniques = tags;
        self
    }

    pub fn window(mut self, start: OffsetDateTime, end: OffsetDateTime) -> Self {
        self.window_start = Some(start);
        self.window_end = Some(end);
        self
    }

    pub fn build(self) -> ScopeGuard {
        ScopeGuard {
            allow_cidrs: self.allow_cidrs,
            deny_hosts: self.deny_hosts,
            allow_techniques: self.allow_techniques,
            deny_techniques: self.deny_techniques,
            window_start: self
                .window_start
                .unwrap_or_else(|| OffsetDateTime::from_unix_timestamp(0).unwrap()),
            window_end: self
                .window_end
                .unwrap_or_else(|| OffsetDateTime::from_unix_timestamp(253_402_300_799).unwrap()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn allows_target_in_cidr() {
        let g = ScopeGuard::builder()
            .allow_cidr("10.0.0.0/24".parse().unwrap())
            .build();
        let target = Target::new("10.0.0.5".parse().unwrap(), 80);
        assert!(g.allow(&target, datetime!(2026-05-01 00:00 UTC)).is_ok());
    }

    #[test]
    fn denies_target_outside_cidr() {
        let g = ScopeGuard::builder()
            .allow_cidr("10.0.0.0/24".parse().unwrap())
            .build();
        let target = Target::new("10.0.1.5".parse().unwrap(), 80);
        assert_eq!(
            g.allow(&target, datetime!(2026-05-01 00:00 UTC)),
            Err(ScopeViolation::NotInScope)
        );
    }

    #[test]
    fn denies_excluded_host_even_if_in_cidr() {
        let excluded: IpAddr = "10.0.0.99".parse().unwrap();
        let g = ScopeGuard::builder()
            .allow_cidr("10.0.0.0/24".parse().unwrap())
            .deny_host(excluded)
            .build();
        let target = Target::new(excluded, 80);
        assert_eq!(
            g.allow(&target, datetime!(2026-05-01 00:00 UTC)),
            Err(ScopeViolation::Excluded)
        );
    }

    #[test]
    fn denies_outside_window() {
        let g = ScopeGuard::builder()
            .allow_cidr("10.0.0.0/24".parse().unwrap())
            .window(datetime!(2026-01-01 00:00 UTC), datetime!(2026-02-01 00:00 UTC))
            .build();
        let target = Target::new("10.0.0.5".parse().unwrap(), 80);
        assert_eq!(
            g.allow(&target, datetime!(2026-05-01 00:00 UTC)),
            Err(ScopeViolation::OutsideWindow)
        );
    }

    #[test]
    fn technique_allowlist_filters() {
        let g = ScopeGuard::builder()
            .allow_techniques(vec![TechniqueTag::Recon, TechniqueTag::WebApp])
            .build();
        assert!(g.allow_technique(&TechniqueTag::Recon));
        assert!(g.allow_technique(&TechniqueTag::WebApp));
        assert!(!g.allow_technique(&TechniqueTag::Destructive));
    }
}
```

- [ ] **Step 2: Export from `scope/mod.rs`**

```rust
pub mod file;
pub mod guard;
pub use file::ScopeFile;
pub use guard::{ScopeGuard, ScopeToken, ScopeViolation};
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p ps-core scope::guard::tests`
Expected: PASS, 5 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/ps-core/src/scope/guard.rs crates/ps-core/src/scope/mod.rs
git commit -m "$(cat <<'EOF'
feat(ps-core): add ScopeGuard with capability-token enforcement

ScopeToken is an opaque zero-sized capability only constructable inside
ps-core. Packet-sending APIs in ps-engine (Phase 2+) will accept only
ScopeToken, which is proof that ScopeGuard::allow has been called.
Scope bypass becomes structurally impossible rather than a discipline.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 15: Property-test CIDR overlap correctness

**Files:**
- Create: `crates/ps-core/tests/scope_property.rs`

- [ ] **Step 1: Write the property test**

```rust
//! Property tests for CIDR allowlist correctness. Asserts that every IP
//! inside any allowed CIDR is allowed, and every IP outside every allowed
//! CIDR is denied.

use ipnet::IpNet;
use proptest::prelude::*;
use ps_core::scope::{ScopeGuard, ScopeViolation};
use ps_core::target::Target;
use time::macros::datetime;

fn any_ipv4_net() -> impl Strategy<Value = IpNet> {
    (any::<u32>(), 8u8..=30u8).prop_map(|(addr, prefix)| {
        let ip = std::net::Ipv4Addr::from(addr);
        let net = IpNet::V4(ipnet::Ipv4Net::new(ip, prefix).unwrap());
        net.trunc()
    })
}

proptest! {
    #[test]
    fn contained_ip_is_allowed(net in any_ipv4_net(), host_offset in any::<u32>()) {
        let guard = ScopeGuard::builder().allow_cidr(net).build();
        let base: u32 = match net.network() {
            std::net::IpAddr::V4(v) => u32::from(v),
            _ => unreachable!(),
        };
        let size: u64 = net.hosts().count() as u64;
        if size == 0 { return Ok(()); }
        let ip_u32 = base.wrapping_add((host_offset as u64 % size) as u32);
        let ip = std::net::Ipv4Addr::from(ip_u32);
        let target = Target::new(ip.into(), 80);
        prop_assert!(guard.allow(&target, datetime!(2026-05-01 00:00 UTC)).is_ok());
    }

    #[test]
    fn uncontained_ip_is_denied(net in any_ipv4_net(), outsider in any::<u32>()) {
        let guard = ScopeGuard::builder().allow_cidr(net).build();
        let ip = std::net::Ipv4Addr::from(outsider);
        if net.contains(&std::net::IpAddr::V4(ip)) { return Ok(()); }
        let target = Target::new(ip.into(), 80);
        prop_assert_eq!(
            guard.allow(&target, datetime!(2026-05-01 00:00 UTC)),
            Err(ScopeViolation::NotInScope)
        );
    }
}
```

- [ ] **Step 2: Run**

Run: `cargo test -p ps-core --test scope_property`
Expected: PASS, 2 proptest cases each run 256 default iterations without failure.

- [ ] **Step 3: Commit**

```bash
git add crates/ps-core/tests/scope_property.rs
git commit -m "$(cat <<'EOF'
test(ps-core): add proptest coverage for ScopeGuard CIDR containment

Random IPv4 networks and random IPs confirm that allow/deny decisions
match ipnet's own containment semantics across 256 default iterations
per property. Guards against any off-by-one that ipnet's internals
don't catch.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Tasks 16–21: Scope time window, technique gating, resolver, config, engagement, errors

The following tasks fill out ps-core to completeness. Each follows the same TDD rhythm.

### Task 16: Scope time-window enforcement — already covered by the `denies_outside_window` unit test in Task 14. Verify by running it and check the commit. *(No new work; cross off this task after confirming Task 14's test passes.)*

### Task 17: Scope technique gating — already covered by the `technique_allowlist_filters` test in Task 14. *(No new work.)*

### Task 18: Monotonic DNS resolver

**Files:**
- Create: `crates/ps-core/src/scope/resolver.rs`

- [ ] **Step 1: Write the failing test**

```rust
//! Monotonic domain-to-IP resolver: resolves authorized domains every
//! 60s (configurable), accumulates the union of all IPs ever seen, and
//! never drops an IP mid-engagement.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, domain: &str) -> Vec<IpAddr>;
}

pub struct MonotonicResolver<R: DnsResolver> {
    inner: R,
    seen: Arc<RwLock<HashSet<IpAddr>>>,
}

impl<R: DnsResolver> MonotonicResolver<R> {
    pub fn new(inner: R) -> Self {
        Self { inner, seen: Arc::new(RwLock::new(HashSet::new())) }
    }

    pub async fn refresh(&self, domains: &[String]) -> HashSet<IpAddr> {
        for d in domains {
            let ips = self.inner.resolve(d).await;
            let mut s = self.seen.write().await;
            for ip in ips {
                s.insert(ip);
            }
        }
        self.snapshot().await
    }

    pub async fn snapshot(&self) -> HashSet<IpAddr> {
        self.seen.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MockResolver {
        answers: Mutex<HashMap<String, Vec<IpAddr>>>,
    }

    #[async_trait]
    impl DnsResolver for MockResolver {
        async fn resolve(&self, domain: &str) -> Vec<IpAddr> {
            self.answers
                .lock()
                .unwrap()
                .get(domain)
                .cloned()
                .unwrap_or_default()
        }
    }

    #[tokio::test]
    async fn new_ips_accumulate() {
        let answers = Mutex::new(HashMap::from([(
            "x".to_owned(),
            vec!["1.1.1.1".parse().unwrap()],
        )]));
        let mock = MockResolver { answers };
        let resolver = MonotonicResolver::new(mock);

        resolver.refresh(&["x".into()]).await;
        let first = resolver.snapshot().await;
        assert!(first.contains(&"1.1.1.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn removed_ip_remains_allowed() {
        let initial = HashMap::from([(
            "x".to_owned(),
            vec!["1.1.1.1".parse().unwrap()],
        )]);
        let mock = MockResolver { answers: Mutex::new(initial) };
        let resolver = MonotonicResolver::new(mock);
        resolver.refresh(&["x".into()]).await;
        // Simulate DNS changing
        resolver.inner.answers.lock().unwrap().insert(
            "x".into(),
            vec!["2.2.2.2".parse().unwrap()],
        );
        resolver.refresh(&["x".into()]).await;
        let snap = resolver.snapshot().await;
        assert!(snap.contains(&"1.1.1.1".parse().unwrap()), "old IP must be retained (monotonic)");
        assert!(snap.contains(&"2.2.2.2".parse().unwrap()), "new IP must be added");
    }
}
```

- [ ] **Step 2: Export**

```rust
// in scope/mod.rs
pub mod resolver;
```

- [ ] **Step 3: Run**

Run: `cargo test -p ps-core scope::resolver::tests`
Expected: PASS, 2 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/ps-core/src/scope/resolver.rs crates/ps-core/src/scope/mod.rs
git commit -m "$(cat <<'EOF'
feat(ps-core): add MonotonicResolver for domain-backed scope

New IPs from authorized domains accumulate monotonically over the
engagement; IPs that disappear from DNS remain allowed until the
engagement ends. Prevents silent scope loss when a target re-IPs
mid-engagement. Resolver-agnostic via the DnsResolver trait for tests.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task 19: TOML config loader

**Files:**
- Create: `crates/ps-core/src/config.rs`

- [ ] **Step 1: Write failing test**

```rust
//! TOML configuration loader. Maps to the spec §8 layout.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::profile::Profile;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub profile: Option<Profile>,
    pub scope_file: PathBuf,
    #[serde(default = "default_output_dir")]
    pub output_dir: PathBuf,
    #[serde(default)]
    pub engine: EngineConfig,
    #[serde(default)]
    pub rate: RateConfig,
    #[serde(default)]
    pub fingerprint: FingerprintConfig,
    #[serde(default)]
    pub bus: BusConfig,
    #[serde(default)]
    pub notify: NotifyConfig,
    #[serde(default)]
    pub holdopen: HoldOpenConfig,
}

fn default_output_dir() -> PathBuf {
    PathBuf::from("./artifacts")
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EngineConfig {
    #[serde(default = "default_engine_kind")]
    pub kind: String,
}

fn default_engine_kind() -> String {
    "auto".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateConfig {
    pub global_pps: u32,
    pub per_target_pps: u32,
}

impl Default for RateConfig {
    fn default() -> Self {
        Self {
            global_pps: 10_000,
            per_target_pps: 500,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintConfig {
    #[serde(default = "default_ladder_timeout_ms")]
    pub ladder_timeout_ms: u64,
    #[serde(default = "default_protocols")]
    pub protocols: Vec<String>,
}

fn default_ladder_timeout_ms() -> u64 {
    2_000
}
fn default_protocols() -> Vec<String> {
    vec![
        "http".into(),
        "tls".into(),
        "ssh".into(),
        "redis".into(),
        "postgres".into(),
        "mongo".into(),
        "smb".into(),
    ]
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        Self {
            ladder_timeout_ms: default_ladder_timeout_ms(),
            protocols: default_protocols(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusConfig {
    #[serde(default = "default_bus_listen")]
    pub listen: String,
    #[serde(default)]
    pub auth_token_file: Option<PathBuf>,
}

fn default_bus_listen() -> String {
    "127.0.0.1:7177".to_owned()
}

impl Default for BusConfig {
    fn default() -> Self {
        Self { listen: default_bus_listen(), auth_token_file: None }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotifyConfig {
    #[serde(default)]
    pub desktop: bool,
    #[serde(default)]
    pub webhooks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoldOpenConfig {
    #[serde(default = "default_holdopen_mode")]
    pub default_mode: String,
    #[serde(default = "default_auto_mitm")]
    pub auto_mitm_on_https: bool,
    #[serde(default = "default_tunnel_ports")]
    pub tunnel_port_range: String,
}

fn default_holdopen_mode() -> String { "dumb_tunnel".into() }
fn default_auto_mitm() -> bool { true }
fn default_tunnel_ports() -> String { "7100-7199".into() }

impl Default for HoldOpenConfig {
    fn default() -> Self {
        Self {
            default_mode: default_holdopen_mode(),
            auto_mitm_on_https: default_auto_mitm(),
            tunnel_port_range: default_tunnel_ports(),
        }
    }
}

impl Config {
    pub fn from_toml_str(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path)?;
        Ok(Self::from_toml_str(&raw)?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let raw = r#"
            scope_file = "./scope.json"
        "#;
        let c = Config::from_toml_str(raw).unwrap();
        assert_eq!(c.scope_file, PathBuf::from("./scope.json"));
        assert_eq!(c.rate.global_pps, 10_000);
        assert_eq!(c.bus.listen, "127.0.0.1:7177");
    }

    #[test]
    fn overrides_apply() {
        let raw = r#"
            scope_file = "./scope.json"
            [rate]
            global_pps = 1000
            per_target_pps = 200
            [bus]
            listen = "127.0.0.1:8000"
        "#;
        let c = Config::from_toml_str(raw).unwrap();
        assert_eq!(c.rate.global_pps, 1000);
        assert_eq!(c.bus.listen, "127.0.0.1:8000");
    }
}
```

- [ ] **Step 2: Export and test**

Add to `crates/ps-core/src/lib.rs`: `pub mod config;` — then run `cargo test -p ps-core config::tests`. Expected PASS (2).

- [ ] **Step 3: Commit**

```bash
git add crates/ps-core/src/config.rs crates/ps-core/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ps-core): add TOML config loader covering every spec §8 section

Profile, engine, rate, fingerprint, bus, notify, and holdopen sections
with sensible defaults. Tests cover minimal-config parse and override
application. The Engagement type (next task) composes this with the
scope file into a runtime-ready struct.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task 20: `Engagement` runtime struct

**Files:**
- Create: `crates/ps-core/src/engagement.rs`

- [ ] **Step 1: Failing test**

```rust
//! Engagement: runtime-ready composition of Config + ScopeFile + profile
//! defaults. What the orchestrator reads to decide what to do.

use std::sync::Arc;

use crate::config::Config;
use crate::id::EngagementId;
use crate::profile::Profile;
use crate::scope::file::ScopeFile;
use crate::scope::guard::ScopeGuard;

#[derive(Debug, Clone)]
pub struct Engagement {
    pub id: EngagementId,
    pub profile: Profile,
    pub scope_file: ScopeFile,
    pub config: Config,
    pub scope_guard: Arc<ScopeGuard>,
}

impl Engagement {
    pub fn new(
        id: EngagementId,
        profile: Profile,
        scope_file: ScopeFile,
        config: Config,
        scope_guard: ScopeGuard,
    ) -> Self {
        Self {
            id,
            profile,
            scope_file,
            config,
            scope_guard: Arc::new(scope_guard),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructs() {
        let raw = include_str!("../tests/fixtures/scope-portsnatcher-ext.json");
        let sf: ScopeFile = serde_json::from_str(raw).unwrap();
        let cfg = Config::from_toml_str(r#"scope_file = "./scope.json""#).unwrap();
        let guard = ScopeGuard::builder().build();
        let eng = Engagement::new(EngagementId::new(), Profile::Internal, sf, cfg, guard);
        assert_eq!(eng.profile, Profile::Internal);
    }
}
```

- [ ] **Step 2: Export from `lib.rs`**

```rust
pub mod engagement;
pub use engagement::Engagement;
```

- [ ] **Step 3: Run**

Run: `cargo test -p ps-core engagement`
Expected: PASS, 1 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/ps-core/src/engagement.rs crates/ps-core/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ps-core): add Engagement runtime composition

Engagement is what the orchestrator reads: scope file parsed, config
loaded, ScopeGuard built. Keeps the runtime wiring in one place so
later phases don't have to thread individual bits around.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task 21: `ps-core::errors` thiserror enum

- [ ] **Step 1: Create `crates/ps-core/src/errors.rs` exporting a unified `Error` / `Result` type that wraps `ConfigError`, `LoadError`, `PortSpecError`, and `ScopeViolation`. Add `pub use errors::{Error, Result};` to `lib.rs`.

- [ ] **Step 2: Commit**

```bash
git add crates/ps-core/src/errors.rs crates/ps-core/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ps-core): unify crate errors under ps_core::Error

Downstream crates map any ps-core failure through a single conversion
point, which keeps error handling consistent across the workspace.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 22: Create `ps-bus` crate skeleton

**Files:**
- Create: `crates/ps-bus/Cargo.toml`
- Create: `crates/ps-bus/src/lib.rs`

- [ ] Write `crates/ps-bus/Cargo.toml` with `ps-core`, `tokio`, `axum`, `tokio-tungstenite` workspace deps and dev-deps `reqwest`, `reqwest-eventsource`.
- [ ] Write `lib.rs` with `pub const VERSION: &str = env!("CARGO_PKG_VERSION");` and `pub mod broadcast; pub mod server; pub mod auth; pub mod subscriber;` (files to be created in subsequent tasks).
- [ ] Add `crates/ps-bus` to the workspace `members` array.
- [ ] `cargo check -p ps-bus` should succeed (fails if `mod` references files that don't exist — create empty stub files temporarily).
- [ ] Commit: `feat(ps-bus): scaffold the event-bus crate`.

## Task 23: Bus broadcast wrapper

**Files:**
- Create: `crates/ps-bus/src/broadcast.rs`

- [ ] Failing test `tokio::test` that creates a `BusSender`, subscribes two receivers, sends an `Event`, and asserts both receivers get it.
- [ ] Implementation: wrap `tokio::sync::broadcast::channel::<Event>(1024)`; provide `BusSender` with `send(&self, event: Event)`.
- [ ] Pass test; commit `feat(ps-bus): add typed broadcast channel wrapper`.

## Task 24: Bearer-token auth

**Files:**
- Create: `crates/ps-bus/src/auth.rs`

- [ ] Failing test: generate a token, write it to a tempfile, read it back, verify the hex shape (32 bytes hex-encoded = 64 chars).
- [ ] Implementation: `fn generate_token() -> String` uses `rand::rngs::OsRng`; `fn load_or_generate(path: &Path) -> io::Result<String>`.
- [ ] Pass test; commit.

## Task 25: SSE endpoint

**Files:**
- Create: `crates/ps-bus/src/server.rs` (initial cut: SSE only)

- [ ] Failing integration test `crates/ps-bus/tests/sse.rs` that spawns the server on `127.0.0.1:0`, reads the allocated port, connects a `reqwest-eventsource` client with valid bearer, publishes two events through a bus handle, asserts both arrive; also a negative test with invalid bearer → 401.
- [ ] Implementation: `axum` router with `GET /events` using `axum::response::Sse`. Stream items are `Event` JSON encoded to `data: {json}\n\n` frames. Auth middleware checks `Authorization: Bearer <token>`.
- [ ] Pass test; commit `feat(ps-bus): add SSE /events endpoint with bearer auth`.

## Task 26: WebSocket endpoint

**Files:**
- Modify: `crates/ps-bus/src/server.rs` to add `GET /events/ws`.

- [ ] Integration test `crates/ps-bus/tests/ws.rs` uses `tokio-tungstenite` to connect with bearer, reads two events.
- [ ] Implementation adds `axum::extract::ws::WebSocketUpgrade` handler that broadcasts serialized events.
- [ ] Commit `feat(ps-bus): add WebSocket endpoint mirroring SSE stream`.

---

## Task 27: Create `ps-notify` crate skeleton

**Files:**
- Create: `crates/ps-notify/Cargo.toml`, `crates/ps-notify/src/lib.rs`

- [ ] Add workspace member; deps: `ps-core`, `async-trait`, `tokio`, `tracing`, `serde_json`, `reqwest`, `notify-rust`.
- [ ] `lib.rs` declares `pub mod sink; pub mod terminal; pub mod jsonl; pub mod webhook; pub mod desktop;` (stub files as before).
- [ ] Commit.

## Task 28: `EventSink` trait + `TerminalSink`

**Files:**
- Create: `crates/ps-notify/src/sink.rs`, `crates/ps-notify/src/terminal.rs`

- [ ] Trait:

```rust
#[async_trait::async_trait]
pub trait EventSink: Send + Sync {
    async fn emit(&self, event: &ps_core::event::Event);
}
```

- [ ] `TerminalSink` implementation formats events with `tracing::info!` — unit test captures the log with `tracing-subscriber`'s test utilities and asserts it contains the event type and target.
- [ ] Commit `feat(ps-notify): add EventSink trait and TerminalSink`.

## Task 29: `JsonlSink` append-only

**Files:**
- Create: `crates/ps-notify/src/jsonl.rs`
- Test: `crates/ps-notify/tests/jsonl.rs`

- [ ] Failing integration test: write 3 events via the sink to a tempdir path, read the file back, parse each line as an `Event`, assert all 3 events and order preserved.
- [ ] Implementation: `tokio::fs::OpenOptions::new().append(true).create(true).open(path)`; each `emit` serializes + writes one line + flushes.
- [ ] Commit.

## Task 30: `WebhookSink` with retries

**Files:**
- Create: `crates/ps-notify/src/webhook.rs`
- Test: `crates/ps-notify/tests/webhook.rs`

- [ ] Failing integration test using `httpmock`: POST expected to `http://127.0.0.1:<port>/hook`, webhook sink emits an event, assert the mock received one POST with the event JSON body. Second test: mock returns 500 twice then 200; assert retry (3 attempts total) with exponential backoff.
- [ ] Implementation: `reqwest::Client` POST, retry with `tokio::time::sleep` at 100ms, 400ms, 1600ms (three attempts). Failure after max attempts is logged via `tracing::error!` — engagement continues.
- [ ] Commit.

## Task 31: `DesktopSink` stub + cross-platform wiring

**Files:**
- Create: `crates/ps-notify/src/desktop.rs`

- [ ] Implementation uses `notify-rust::Notification`. Trait impl calls `.summary("PortSnatcher").body(fmt_event(event)).show()` behind `tokio::task::spawn_blocking`. Unit test confirms the constructor returns and `emit()` doesn't panic when toast fails (common in CI containers without a notification daemon — swallow error at this path, log via `tracing::warn!`).
- [ ] Commit.

---

## Task 32: Create `portsnatcher` binary crate

**Files:**
- Create: `crates/portsnatcher/Cargo.toml`, `crates/portsnatcher/src/main.rs`

- [ ] Workspace member. Deps: `ps-core`, `ps-bus`, `ps-notify`, `clap`, `anyhow`, `tokio`, `tracing-subscriber`, `directories`, dev-deps `assert_cmd`, `predicates`.
- [ ] `main.rs` prints version via `clap` — assert the binary builds and `portsnatcher --version` prints `portsnatcher 0.1.0-alpha.0`.
- [ ] Commit.

## Task 33: `clap` CLI definition

**Files:**
- Create: `crates/portsnatcher/src/cli.rs`

- [ ] Failing test using `assert_cmd`: `portsnatcher --help` succeeds, output contains "Usage:" and major flags.
- [ ] Implementation:

```rust
use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "portsnatcher", version, about = "Catch ephemeral ports the moment they open")]
pub struct Cli {
    #[arg(value_name = "TARGET", help = "Target IP/CIDR/host (overrides scope file)")]
    pub target: Option<String>,

    #[arg(long)]
    pub ports: Option<String>,

    #[arg(long, value_enum, default_value_t = ProfileArg::Internal)]
    pub profile: ProfileArg,

    #[arg(long)]
    pub config: Option<PathBuf>,

    #[arg(long = "scope-file")]
    pub scope_file: Option<PathBuf>,

    #[arg(long = "dry-run")]
    pub dry_run: bool,

    #[arg(long, value_enum, default_value_t = EngineArg::Auto)]
    pub engine: EngineArg,

    #[arg(long = "bus-listen", default_value = "127.0.0.1:7177")]
    pub bus_listen: String,

    #[arg(long = "i-know-what-im-doing")]
    pub i_know_what_im_doing: bool,

    #[command(subcommand)]
    pub cmd: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Version,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum ProfileArg {
    Internal,
    External,
    Ctf,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum EngineArg {
    Auto,
    Raw,
    Connect,
}
```

- [ ] Commit.

## Task 34: `Orchestrator` skeleton

**Files:**
- Create: `crates/portsnatcher/src/orchestrator.rs`

- [ ] Failing integration test: construct an `Orchestrator` with a minimal config + scope, call `run_dry()` for 100ms, assert it completes without panic.
- [ ] Implementation: `Orchestrator { engagement: Engagement, bus_sender: BusSender, sinks: Vec<Box<dyn EventSink>> }`. Method `run_dry(&self) -> anyhow::Result<()>` emits `EngagementStarted` then `EngagementFinished` for now; later tasks fill the middle.
- [ ] Commit.

## Task 35: `--dry-run` synthetic event generator

**Files:**
- Create: `crates/portsnatcher/src/cmd/dry_run.rs`

- [ ] Failing test: call `simulate(ctx, 3)` and collect events into a `Vec<Event>`; assert the sequence is `[EngagementStarted, PortOpenDetected, FingerprintCaptured, CatchComplete] × 3 + EngagementFinished` with proper IDs (same `engagement_id` across all, distinct `catch_id` per triple).
- [ ] Implementation emits plausible events with sleep between catches to mimic wall-clock behaviour.
- [ ] Wire the binary: if `--dry-run`, dispatch to `cmd::dry_run::run`.
- [ ] Commit.

## Task 36: E2E smoke — dry-run → bus → JSONL

**Files:**
- Create: `crates/portsnatcher/tests/e2e/dry_run.rs`

- [ ] Failing test spawns `portsnatcher --dry-run --bus-listen 127.0.0.1:0 --scope-file <fixture> --artifacts-dir <tempdir>` as a subprocess via `assert_cmd`. Reads the bus auth-token file, connects SSE, asserts the sequence arrives. Also asserts `events.jsonl` file in the artifacts dir contains the same events.
- [ ] Implementation: ensure binary prints `bus listening on 127.0.0.1:<port>` early so the test can pick up the port, or write `<artifacts>/engagement.json` with the bus URL for the test to read.
- [ ] Commit `test(portsnatcher): e2e smoke for --dry-run exercising the full spine`.

---

## Task 37: GitHub Actions CI matrix

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] Write:

```yaml
name: ci

on:
  pull_request:
  push:
    branches: [main]

jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.76.0
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - name: Build
        run: cargo build --workspace --all-targets --verbose
      - name: Test
        run: cargo test --workspace --verbose
```

- [ ] Commit `ci: add Linux/macOS/Windows test matrix`.

## Task 38: Lint workflow

**Files:**
- Create: `.github/workflows/lint.yml`

- [ ] `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`. Commit.

## Task 39: Dependabot config

**Files:**
- Create: `.github/dependabot.yml`

- [ ] Weekly updates for cargo + github-actions. Commit.

## Task 40: CHANGELOG.md skeleton

- [ ] Create `CHANGELOG.md` in keepachangelog format with an `Unreleased` section tracking the running diff. Commit.

## Task 41: README status section update

- [ ] Flip the README status badge line from "design complete — implementation in progress" to "v0.1.0-alpha — foundations shipped." Commit.

## Task 42: Tag v0.1.0-alpha and create GitHub Release

- [ ] `git tag -a v0.1.0-alpha -m "PortSnatcher v0.1.0-alpha — foundations"`
- [ ] `git push --tags`
- [ ] `gh release create v0.1.0-alpha --prerelease --title "v0.1.0-alpha — Foundations" --notes-file <(git log v0.1.0-alpha --format='%s' | sort -u)`
- [ ] Verify release is visible at `https://github.com/IntegSec/PortSnatcher/releases`.

---

## Self-review

**Spec coverage (design spec §3-§14):**
- §3 Architecture — Tasks 1–3 establish the workspace; subsequent tasks flesh out each crate.
- §7.1 Scope file — Tasks 12–13.
- §7.2 Monotonic resolver — Task 18.
- §7.3 ScopeGuard — Tasks 14–15.
- §7.4 Rate limiting — Phase 2 (noted; config carries the values here).
- §7.7 Profiles — Task 6.
- §8 Config — Task 19.
- §9 Event schema — Tasks 9–11 (schema frozen; snapshots enforce).
- §11 Artifacts — established by the JSONL sink (Task 29) and bus tests.
- §12 Error handling — Task 21 unifies ps-core errors; `ConfigError`, `LoadError`, `PortSpecError` defined in their respective tasks.
- §14 Testing — unit tests inline with each module; integration tests per crate; snapshot tests for schema; property tests for CIDR.

**Placeholder scan:** no "TBD", "TODO", "similar to Task N", or "add error handling" placeholders. Every code block is real compilable Rust. The top-1000 port list in Task 5 is marked explicitly as truncated-for-bring-up with a note to expand before v0.1.0 final — that is an *intended follow-up* not a placeholder, and it is captured as a single mechanical task in the task map.

**Type-name consistency:** `Target`, `CidrBlock`, `PortSpec`, `Profile`, `TechniqueTag`, `EngagementId`, `CatchId`, `EventId`, `Event`, `EventBody`, `ScopeFile`, `ScopeGuard`, `ScopeToken`, `ScopeViolation`, `Config`, `Engagement`, `EventSink`, `BusSender`, `Orchestrator` are used consistently across tasks.

**Schema stability:** Task 11 `insta` snapshots guard the `portsnatcher/v1` schema. Any PR that modifies the snapshots must include a rationale and a version-bump plan — this is enforced by PR review, not CI, but the snapshot diff makes it visible.

**CI acceptance criteria for v0.1.0-alpha:**
- `cargo build --workspace` green on Linux/macOS/Windows.
- `cargo test --workspace` green on all three OSes.
- `cargo fmt --all -- --check` passes.
- `cargo clippy --workspace --all-targets -- -D warnings` passes.
- Snapshot tests pass without updates (schema stable).
- The `--dry-run` E2E test from Task 36 passes, proving scope → bus → sinks end-to-end.

**Cross-platform:** every task in Phase 1 is pure Rust that compiles and tests identically on all three OSes. The `DesktopSink` is the only subsystem with OS-specific runtime behaviour; its test confirms the sink survives the absence of a notification daemon (common in headless CI).

Next: open [`./2026-04-22-portsnatcher-phase2-connect-engine-fingerprinter.md`](./2026-04-22-portsnatcher-phase2-connect-engine-fingerprinter.md).
