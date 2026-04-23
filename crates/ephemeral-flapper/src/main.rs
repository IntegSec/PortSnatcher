//! `ephemeral-flapper`: open-and-close TCP ports on a programmable schedule.
//!
//! Reads a TOML manifest from stdin describing one or more ports to
//! flap. For each entry, a dedicated task alternates between binding a
//! `TcpListener` on `127.0.0.1:<port>` for `open_window_ms` and
//! dropping it for `close_window_ms`, repeating until the requested
//! `count` is exhausted (or forever).
//!
//! While the listener is bound, we accept incoming connections and
//! immediately close them — just enough for a probing client to
//! observe the port as "open". When the listener is dropped, the OS
//! returns RST/connection-refused for the close window.
//!
//! ## Manifest format
//! ```toml
//! [[ports]]
//! port = 49200
//! open_window_ms = 80
//! close_window_ms = 3000
//! count = "forever"      # or count = 5
//! ```
//!
//! ## Termination
//! Exits cleanly on SIGINT (Ctrl-C) on Unix, or Ctrl-C/Ctrl-Break on
//! Windows. All listener tasks are cancelled and their bindings
//! released before the process returns.

use std::io::Read;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio::time::{sleep, Instant};

/// Top-level manifest: a list of port entries to flap concurrently.
#[derive(Debug, Deserialize)]
struct Manifest {
    #[serde(default)]
    ports: Vec<PortSpec>,
}

/// One port to flap.
#[derive(Debug, Deserialize, Clone)]
struct PortSpec {
    /// TCP port on 127.0.0.1 to bind.
    port: u16,
    /// How long to keep the listener bound per cycle.
    open_window_ms: u64,
    /// How long to leave the port closed per cycle.
    close_window_ms: u64,
    /// Number of open/close cycles, or `"forever"`.
    #[serde(default = "default_count")]
    count: Count,
}

fn default_count() -> Count {
    Count::Forever
}

/// Cycle count: bounded or unbounded.
#[derive(Debug, Clone, Copy)]
enum Count {
    Forever,
    N(u64),
}

impl<'de> Deserialize<'de> for Count {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Word(String),
            Num(u64),
        }
        match Raw::deserialize(d)? {
            Raw::Word(s) if s == "forever" => Ok(Count::Forever),
            Raw::Word(s) => Err(D::Error::custom(format!(
                "count must be a positive integer or \"forever\", got {s:?}"
            ))),
            Raw::Num(n) => Ok(Count::N(n)),
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    init_tracing();

    let manifest = read_manifest().context("reading manifest from stdin")?;
    if manifest.ports.is_empty() {
        tracing::warn!("manifest contains no ports; exiting");
        return Ok(());
    }

    let mut set = JoinSet::new();
    for spec in manifest.ports {
        set.spawn(async move {
            if let Err(err) = flap(spec).await {
                tracing::error!(%err, "flap task terminated with error");
            }
        });
    }

    tokio::select! {
        _ = shutdown_signal() => {
            tracing::info!("shutdown signal received; cancelling flap tasks");
        }
        _ = wait_for_all(&mut set) => {
            tracing::info!("all flap tasks completed naturally");
        }
    }

    set.abort_all();
    while set.join_next().await.is_some() {}
    Ok(())
}

async fn wait_for_all(set: &mut JoinSet<()>) {
    while set.join_next().await.is_some() {}
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

fn read_manifest() -> Result<Manifest> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    let manifest: Manifest = toml::from_str(&buf).context("parsing TOML manifest")?;
    Ok(manifest)
}

async fn flap(spec: PortSpec) -> Result<()> {
    let mut cycles_done: u64 = 0;
    loop {
        if let Count::N(n) = spec.count {
            if cycles_done >= n {
                tracing::info!(port = spec.port, cycles_done, "flap finished");
                return Ok(());
            }
        }

        let cycle_start = Instant::now();
        let listener = match TcpListener::bind(("127.0.0.1", spec.port)).await {
            Ok(l) => l,
            Err(err) => {
                tracing::warn!(
                    port = spec.port,
                    %err,
                    "bind failed; retrying after close window"
                );
                sleep(Duration::from_millis(spec.close_window_ms)).await;
                continue;
            }
        };
        tracing::info!(
            port = spec.port,
            open_ms = spec.open_window_ms,
            cycle = cycles_done,
            "port open"
        );

        let open_deadline = cycle_start + Duration::from_millis(spec.open_window_ms);
        loop {
            let now = Instant::now();
            if now >= open_deadline {
                break;
            }
            let remaining = open_deadline - now;
            tokio::select! {
                _ = sleep(remaining) => break,
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _peer)) => {
                            // Drop immediately — client sees the port
                            // as open, then the connection goes away.
                            drop(stream);
                        }
                        Err(err) => {
                            tracing::debug!(port = spec.port, %err, "accept error");
                        }
                    }
                }
            }
        }

        drop(listener);
        tracing::info!(
            port = spec.port,
            close_ms = spec.close_window_ms,
            cycle = cycles_done,
            "port closed"
        );
        sleep(Duration::from_millis(spec.close_window_ms)).await;
        cycles_done = cycles_done.saturating_add(1);
    }
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = int.recv() => {},
        _ = term.recv() => {},
    }
}

#[cfg(windows)]
async fn shutdown_signal() {
    use tokio::signal::windows::{ctrl_break, ctrl_c};
    let mut c = ctrl_c().expect("install Ctrl-C handler");
    let mut b = ctrl_break().expect("install Ctrl-Break handler");
    tokio::select! {
        _ = c.recv() => {},
        _ = b.recv() => {},
    }
}
