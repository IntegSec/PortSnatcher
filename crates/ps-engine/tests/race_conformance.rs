//! Race-conformance suite (spec §14.3).
//!
//! Runs the `ConnectEngine` against the `ephemeral-flapper` test
//! binary on loopback and asserts catch-rate thresholds:
//!
//! - `open_window_ms = 500`: catches per cycle >= 90%
//! - `open_window_ms = 100`: catches per cycle >= 50%
//!
//! The flapper is invoked via the `CARGO_BIN_EXE_ephemeral-flapper`
//! environment variable that `cargo test` injects when
//! `ephemeral-flapper` is listed as a workspace member. If the env
//! var is absent (e.g. somebody runs the test from an isolated
//! checkout of ps-engine alone), the test is skipped with a clear
//! message rather than failing.
//!
//! A `RawEngine` stub is included as `#[ignore]` — the real raw
//! conformance gate depends on rootful CI (raw sockets / `CAP_NET_RAW`)
//! and will land in a Phase 5 follow-up.

use std::io::Write;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ps_bus::broadcast::BusSender;
use ps_core::config::Config;
use ps_core::engagement::Engagement;
use ps_core::event::payload::EventBody;
use ps_core::id::EngagementId;
use ps_core::profile::Profile;
use ps_core::scope::file::ScopeFile;
use ps_core::scope::guard::ScopeGuard;
use ps_engine::engine::{EngineContext, ProbeEngine};
use ps_engine::{ConnectEngine, RateLimiter};
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Pick an unused TCP port by binding to :0 and asking the kernel.
fn reserve_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind free port");
    l.local_addr().unwrap().port()
}

fn minimal_engagement() -> Engagement {
    let raw = include_str!("../../ps-core/tests/fixtures/scope-portsnatcher-ext.json");
    let sf: ScopeFile = serde_json::from_str(raw).expect("parse scope fixture");
    let cfg = Config::from_toml_str(r#"scope_file = "./scope.json""#).expect("parse config");
    let guard = ScopeGuard::builder()
        .allow_cidr("127.0.0.0/8".parse().unwrap())
        .build();
    Engagement::new(EngagementId::new(), Profile::Internal, sf, cfg, guard)
}

/// Result of one run against the flapper.
struct RunResult {
    /// Unique `PortOpenDetected` events observed.
    catches: u64,
    /// Cycles the flapper completed.
    cycles: u64,
}

/// Spawn the `ephemeral-flapper`, run `ConnectEngine` for `duration`,
/// return the distinct catches and expected cycle count.
async fn run_one(port: u16, open_ms: u64, close_ms: u64, duration: Duration) -> Option<RunResult> {
    let flapper_path = match std::env::var_os("CARGO_BIN_EXE_ephemeral-flapper") {
        Some(p) => p,
        None => {
            eprintln!(
                "skipping race_conformance: CARGO_BIN_EXE_ephemeral-flapper is unset.\n\
                 Re-run with the `ephemeral-flapper` crate in the workspace."
            );
            return None;
        }
    };

    let cycle_ms = open_ms + close_ms;
    let expected_cycles = (duration.as_millis() as u64 / cycle_ms).saturating_add(1);
    let manifest = format!(
        "[[ports]]\nport = {port}\nopen_window_ms = {open_ms}\nclose_window_ms = {close_ms}\ncount = {expected_cycles}\n",
    );

    let mut child = Command::new(flapper_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ephemeral-flapper");
    {
        let mut stdin = child.stdin.take().expect("flapper stdin");
        stdin
            .write_all(manifest.as_bytes())
            .expect("write flapper manifest");
    }

    // Give the flapper a moment to bind for the first time.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let engagement = minimal_engagement();
    let (bus_tx, mut bus_rx): (BusSender, _) = BusSender::new(1024);
    let bus_sub = bus_tx.clone();
    let (catch_tx, _catch_rx) = mpsc::channel(64);
    let rate = Arc::new(RateLimiter::new(100_000, 10_000));

    let ctx = EngineContext {
        engagement,
        rate_limiter: rate,
        catch_tx,
        bus: bus_sub,
        plan: vec![("127.0.0.1".parse().unwrap(), port)],
    };

    let engine = Box::new(ConnectEngine::new());
    let handle = engine.start(ctx).await.expect("start connect engine");

    // Drain events for `duration`, counting distinct PortOpenDetected
    // events (dedupe by catch_id so we never double-count a single
    // open window even if we happen to reconnect to the same cycle).
    let mut seen_catches: std::collections::HashSet<ps_core::id::CatchId> =
        std::collections::HashSet::new();
    let mut fallback_catches: u64 = 0;
    let deadline = Instant::now() + duration;
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;
        match timeout(remaining, bus_rx.recv()).await {
            Ok(Ok(ev)) => {
                if let EventBody::PortOpenDetected(p) = &ev.body {
                    if p.port == port {
                        if let Some(cid) = ev.catch_id {
                            seen_catches.insert(cid);
                        } else {
                            // Fallback — shouldn't happen for connect
                            // engine but treat as a catch either way.
                            fallback_catches = fallback_catches.saturating_add(1);
                        }
                    }
                }
            }
            Ok(Err(_)) => break, // bus closed
            Err(_) => break,     // deadline elapsed
        }
    }

    handle.stop();
    let _ = child.kill();
    let _ = child.wait();

    Some(RunResult {
        catches: seen_catches.len() as u64 + fallback_catches,
        cycles: expected_cycles,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_engine_500ms_windows_catches_at_least_90_percent() {
    let port = reserve_free_port();
    let Some(result) = run_one(port, 500, 500, Duration::from_secs(15)).await else {
        return;
    };
    let ratio = (result.catches as f64) / (result.cycles.max(1) as f64);
    assert!(
        ratio >= 0.9,
        "connect engine caught {} of {} 500ms windows ({:.0}%); threshold is 90%",
        result.catches,
        result.cycles,
        ratio * 100.0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_engine_100ms_windows_catches_at_least_50_percent() {
    let port = reserve_free_port();
    let Some(result) = run_one(port, 100, 400, Duration::from_secs(15)).await else {
        return;
    };
    let ratio = (result.catches as f64) / (result.cycles.max(1) as f64);
    assert!(
        ratio >= 0.5,
        "connect engine caught {} of {} 100ms windows ({:.0}%); threshold is 50%",
        result.catches,
        result.cycles,
        ratio * 100.0
    );
}

/// Placeholder for the RawEngine conformance gate.
///
/// The real test needs raw sockets (`CAP_NET_RAW` on Linux, admin on
/// Windows, BPF device on macOS) and therefore runs behind rootful CI.
/// It is scheduled for a Phase 5 follow-up; for now this exists only
/// to document the intent and reserve the test name so the gate slots
/// in without renaming.
#[ignore = "rootful CI follow-up: see spec §14.3 RawEngine thresholds (>=95% of 50ms, >=70% of 20ms)"]
#[test]
fn raw_engine_race_conformance_stub() {
    // Intentionally left unimplemented. See module docs.
}
