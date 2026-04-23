# Contributing to PortSnatcher

Thanks for considering a contribution. PortSnatcher is a safety-first
port catcher used on authorized pentests — we are conservative about
changes that touch the scope guard, the event schema, or the
orchestrator. This document is the short version of how to work with
us without surprising anyone.

## Development Setup

1. Install the pinned toolchain. The repo uses `rust-toolchain.toml`
   to pin the MSRV; running any `cargo` command will auto-install the
   correct version via rustup.
2. Clone the repo and run the workspace build:
   ```
   cargo build --workspace
   ```
3. Run the full test suite:
   ```
   cargo test --workspace
   ```
4. Before opening a PR, run the same lints CI runs:
   ```
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo deny check
   ```

If you plan to work on the raw engine or firewall-rollback code,
you will need Linux with `CAP_NET_RAW` available (or a root shell).
The connect-engine tests are rootless-friendly and run everywhere.

## Rust Toolchain Guidance

- The MSRV is pinned in `Cargo.toml` under `workspace.package.rust-version`.
  Do not bump it casually; MSRV is a compatibility contract.
- Code must build on stable. We use nightly only for `cargo-fuzz`.
- Unsafe code is reviewed on a case-by-case basis. Every `unsafe`
  block needs a comment explaining the invariant it upholds and
  why the safe alternative is inadequate.

## Commit Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/)
for commit titles. Acceptable types:

- `feat:` — new behaviour exposed to operators.
- `fix:` — bug fix.
- `perf:` — performance improvement with no behaviour change.
- `refactor:` — internal reshape, no behaviour change.
- `test:` — test-only changes.
- `docs:` — documentation-only changes.
- `chore:` — build / CI / dep updates.
- `ci:` — GitHub Actions or release-pipeline changes.

Scope is optional but encouraged:

```
feat(tui): color rate gauge red when within 5% of cap
fix(scope): reject CIDR blocks that cross address families
test(engine): tighten connect-engine race-harness threshold
```

Every commit must carry a `Co-Authored-By:` footer listing any
humans or AI assistants that contributed. For Claude-assisted
commits, include:

```
Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

Keep commits small and individually reviewable. Stacked commits are
preferred over squashed megacommits — reviewing an architecture
change alongside its test turns up fewer bugs than reviewing the
combined diff.

## Test Expectations

CI must stay green. That is a hard rule: no "I'll fix it in the next
PR", no "flaky, please rerun". If CI is red on main, whoever broke
it owns the rollback or forward-fix.

What CI runs on every PR:

- `cargo fmt --all --check` (style).
- `cargo clippy --workspace --all-targets -- -D warnings` (lints).
- `cargo test --workspace --all-targets` (unit + integration).
- `cargo deny check` (licenses + advisories).
- Race-conformance tight tier (`cargo test --test race_conformance`).

What CI runs nightly:

- `cargo fuzz run <target> -- -max_total_time=300` per target.
- Race-conformance soak tier (1000 targets, 10 minutes).

When adding new functionality, write the test first. When fixing a
bug, the fix commit should include a regression test that would have
failed on the previous commit.

## Schema Stability

The `portsnatcher/v1` event schema is **frozen** as of v1.0.0. That
means:

- **Additive-only changes** are allowed: new event variants, new
  optional fields. Existing consumers continue to work.
- **Breaking changes** — removing fields, renaming, changing types,
  making optional fields required — require a `v2` schema bump and
  a migration guide. We do not do breaking changes on `v1` under any
  circumstances.
- The `insta` snapshots under `crates/ps-core/tests/` enforce this
  at compile time. If you touch `event::payload`, the snapshots
  will detect it and force an explicit `cargo insta review`.

Scope-file changes follow the same rule: additive-only. The scope
schema is owned upstream by
[IntegSec/agentic-pentest-proxy](https://github.com/IntegSec/agentic-pentest-proxy);
we accept its shape verbatim. If you need to store PortSnatcher-specific
data, put it under the `portsnatcher` extension object, not at the
top level.

## Pull-Request Checklist

Before you hit "ready for review":

- [ ] Branch is rebased on `main`.
- [ ] All tests pass locally (`cargo test --workspace`).
- [ ] `cargo clippy` and `cargo fmt` are clean.
- [ ] New public items have `///` doc comments.
- [ ] `CHANGELOG.md` has an entry under `## [Unreleased]`.
- [ ] Any new dep is justified in the PR description and has a
      compatible license per `deny.toml`.
- [ ] If the change touches scope, events, or the orchestrator:
      linked a design-doc update or justified why one is not needed.

Thanks for helping make PortSnatcher safer and faster.
