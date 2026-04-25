//! TUI application state.
//!
//! `TuiApp` is a pure data model: it takes [`ps_core::event::Event`]s
//! in via [`TuiApp::apply`] and mutates internal vectors that the
//! widget module renders. There is deliberately no terminal I/O here,
//! so these transitions are trivially unit-testable.
//!
//! The model intentionally mirrors only the facets the screen shows.
//! Anything the four panels do not display (audit artefact paths, raw
//! banner bytes, etc.) is summarised into the event log and then
//! dropped.

use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

use ps_core::event::payload::EventBody;
use ps_core::event::Event;
use ps_core::id::CatchId;

/// Maximum number of event-log lines kept in memory. The display only
/// ever shows the tail, but we retain a small window so operators can
/// see a burst of activity before it scrolls off-screen.
pub const EVENT_LOG_CAPACITY: usize = 50;

/// Lifecycle state of a catch row in the Catches table.
///
/// Transitions: `Detecting` -> `Holding` (on `HoldOpenReady`) ->
/// `Complete` (on `CatchComplete`). Fingerprint events do not move the
/// row, they only enrich the `protocol` / `confidence` fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatchStatus {
    /// Port has been caught but the hold-open tunnel has not yet started.
    Detecting,
    /// Hold-open tunnel is live; operator can connect via `tunnel_port`.
    Holding,
    /// Catch has finished (upstream closed, engagement ended, etc.).
    Complete,
}

/// One row in the Catches table. Mutable in place as events flow in.
#[derive(Debug, Clone)]
pub struct CatchRow {
    /// Stable catch identifier.
    pub catch_id: CatchId,
    /// Display string for the target (e.g. `"10.0.0.5"`).
    pub target: String,
    /// TCP port caught upstream.
    pub port: u16,
    /// Engine that caught it (e.g. `"connect"`, `"raw"`).
    pub engine: String,
    /// Best-known protocol guess from the fingerprint ladder.
    pub protocol: Option<String>,
    /// Confidence of `protocol`, 0.0-1.0.
    pub confidence: Option<f32>,
    /// Local port the hold-open tunnel is listening on, if any.
    pub tunnel_port: Option<u16>,
    /// Current lifecycle state.
    pub status: CatchStatus,
}

/// Port-level status independent of catch lifecycle. The Port Status
/// table in the TUI aggregates across the engagement by `(target,
/// port)`, so always-open services (HTTPS 443) show as a single stable
/// row and ephemeral flappers show their flip count + last change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortLiveState {
    Open,
    Closed,
    /// Was open at least once, then accumulated >=4 Open↔Closed
    /// transitions in this engagement (i.e. two full down-up cycles).
    /// Cosmetic — the scheduler's real state machine lives in
    /// [`ps_engine::port_state`]; this enum only drives the TUI's
    /// row colouring. Threshold tuned for ephemeral pentest targets:
    /// a single down-up is just an ephemeral service, two cycles is
    /// genuinely flapping.
    Flapping,
}

#[derive(Debug, Clone)]
pub struct PortStatus {
    pub target: String,
    pub port: u16,
    pub state: PortLiveState,
    /// When the current `state` started. Drives the "OPEN 4m20s"
    /// column display.
    pub since: Instant,
    /// Total open↔closed transitions observed in this engagement.
    pub flips: u32,
    /// Best-known protocol and confidence from the most recent
    /// FingerprintCaptured for this `(target, port)`.
    pub protocol: Option<String>,
    pub confidence: Option<f32>,
    /// Local port of an active hold-open tunnel for this target, if any.
    pub tunnel_port: Option<u16>,
}

/// One row in the Holds list (active hold-open tunnels).
#[derive(Debug, Clone)]
pub struct HoldRow {
    /// Catch this hold-open is bound to.
    pub catch_id: CatchId,
    /// Local port the tunnel is listening on (typically 7101+).
    pub local_port: u16,
    /// Upstream string (e.g. `"10.0.0.5:54283"`).
    pub upstream: String,
    /// Hold-open mode (`"dumb_tunnel"`, `"tls_mitm"`).
    pub mode: String,
}

/// Top-level TUI model.
///
/// Owning: `catches` (rows), `holds` (active tunnels), `rate_gauge`
/// (current / cap as a 0.0..=1.0 ratio), `event_log` (capped ring of
/// summary strings). Also tracks `paused` (auto-scroll pause) and
/// `selected` (index into `catches` for clipboard copy).
#[derive(Debug, Default)]
pub struct TuiApp {
    /// Catch rows; append-only until the user presses `c`.
    pub catches: Vec<CatchRow>,
    /// Per-(target, port) live status, keyed on `"{target}:{port}"` for
    /// sort stability. Always-open services show as a single row that
    /// ages in place; flappers flip between `Open` and `Closed`.
    pub port_status: BTreeMap<String, PortStatus>,
    /// Active hold-open tunnels.
    pub holds: Vec<HoldRow>,
    /// Current pps divided by cap pps, clamped to 0.0-1.0.
    pub rate_gauge: f64,
    /// Most recent pps figures; surfaced in the gauge title.
    pub current_pps: u32,
    /// Configured pps cap (from `RateCapEngaged`).
    pub cap_pps: u32,
    /// Capped ring of summary strings; widget renders the tail.
    pub event_log: VecDeque<String>,
    /// Number of scope-violation audit lines seen, for the gauge title.
    pub audit_count: u64,
    /// Whether auto-scroll of the event log is currently paused.
    pub paused: bool,
    /// Index into `catches` selected for clipboard copy.
    pub selected: usize,
    /// Set when the user presses `q`; the runtime observes and exits.
    pub quit: bool,
}

impl TuiApp {
    /// Create an empty, unpaused app state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a single event from the bus, updating model state.
    ///
    /// This is the only mutation point for bus-driven data. Always
    /// pushes a one-line summary onto the event log in addition to
    /// updating the relevant table/list.
    pub fn apply(&mut self, ev: &Event) {
        self.push_log(summarize(ev));
        match &ev.body {
            EventBody::PortOpenDetected(p) => {
                let cid = ev.catch_id.unwrap_or_default();
                self.catches.push(CatchRow {
                    catch_id: cid,
                    target: p.target.clone(),
                    port: p.port,
                    engine: p.engine.clone(),
                    protocol: None,
                    confidence: None,
                    tunnel_port: None,
                    status: CatchStatus::Detecting,
                });

                // Port Status aggregation: transition or new entry.
                let key = format!("{}:{}", p.target, p.port);
                self.port_status
                    .entry(key)
                    .and_modify(|s| {
                        if s.state != PortLiveState::Open {
                            s.flips = s.flips.saturating_add(1);
                            s.state = if s.flips >= 4 {
                                PortLiveState::Flapping
                            } else {
                                PortLiveState::Open
                            };
                            s.since = Instant::now();
                        }
                    })
                    .or_insert_with(|| PortStatus {
                        target: p.target.clone(),
                        port: p.port,
                        state: PortLiveState::Open,
                        since: Instant::now(),
                        flips: 0,
                        protocol: None,
                        confidence: None,
                        tunnel_port: None,
                    });
            }
            EventBody::PortClosedDetected(p) => {
                let key = format!("{}:{}", p.target, p.port);
                if let Some(s) = self.port_status.get_mut(&key) {
                    if s.state == PortLiveState::Open {
                        s.flips = s.flips.saturating_add(1);
                        s.state = if s.flips >= 4 {
                            PortLiveState::Flapping
                        } else {
                            PortLiveState::Closed
                        };
                        s.since = Instant::now();
                    }
                }
            }
            EventBody::HoldOpenReady(h) => {
                if let Some(cid) = ev.catch_id {
                    if let Some(row) = self.catches.iter_mut().find(|r| r.catch_id == cid) {
                        row.tunnel_port = Some(h.local_port);
                        row.status = CatchStatus::Holding;
                    }
                    self.holds.push(HoldRow {
                        catch_id: cid,
                        local_port: h.local_port,
                        upstream: h.upstream.clone(),
                        mode: h.mode.clone(),
                    });
                }
                // Surface the tunnel port on the matching PortStatus row
                // too. HoldOpenReady.upstream has shape "ip:port".
                if let Some((ip, port)) = split_upstream(&h.upstream) {
                    let key = format!("{ip}:{port}");
                    if let Some(s) = self.port_status.get_mut(&key) {
                        s.tunnel_port = Some(h.local_port);
                    }
                }
            }
            EventBody::HoldOpenClosed(_) => {
                if let Some(cid) = ev.catch_id {
                    self.holds.retain(|h| h.catch_id != cid);
                }
            }
            EventBody::FingerprintCaptured(f) => {
                if let Some(cid) = ev.catch_id {
                    if let Some(row) = self.catches.iter_mut().find(|r| r.catch_id == cid) {
                        row.protocol = f.protocol_guess.clone();
                        row.confidence = Some(f.confidence);
                        // Enrich the PortStatus row too.
                        let key = format!("{}:{}", row.target, row.port);
                        if let Some(s) = self.port_status.get_mut(&key) {
                            s.protocol = f.protocol_guess.clone();
                            s.confidence = Some(f.confidence);
                        }
                    }
                }
            }
            EventBody::CatchComplete(c) => {
                if let Some(cid) = ev.catch_id {
                    if let Some(row) = self.catches.iter_mut().find(|r| r.catch_id == cid) {
                        row.status = CatchStatus::Complete;
                        if row.protocol.is_none() {
                            row.protocol = c.final_protocol.clone();
                        }
                    }
                }
            }
            EventBody::RateCapEngaged(r) => {
                self.current_pps = r.current_pps;
                self.cap_pps = r.cap_pps;
                let ratio = if r.cap_pps == 0 {
                    0.0
                } else {
                    (r.current_pps as f64) / (r.cap_pps as f64)
                };
                self.rate_gauge = ratio.clamp(0.0, 1.0);
            }
            EventBody::ScopeViolationBlocked(_) => {
                self.audit_count = self.audit_count.saturating_add(1);
            }
            EventBody::EngagementStarted(_)
            | EventBody::EngagementFinished(_)
            | EventBody::ProbeAttempted(_) => {
                // Already logged via `push_log`; no table mutation.
            }
        }
    }

    /// Toggle the paused flag. When paused, the runtime still applies
    /// events but does not auto-scroll the event log view.
    pub fn toggle_pause(&mut self) {
        self.paused = !self.paused;
    }

    /// Drop every `Complete` catch from the table. Triggered by `c`.
    pub fn clear_completed(&mut self) {
        self.catches.retain(|r| r.status != CatchStatus::Complete);
        if self.selected >= self.catches.len() {
            self.selected = self.catches.len().saturating_sub(1);
        }
    }

    /// Mark the app for shutdown. The runtime observes on next tick.
    pub fn request_quit(&mut self) {
        self.quit = true;
    }

    /// Return the currently selected row, if any.
    pub fn selected_row(&self) -> Option<&CatchRow> {
        self.catches.get(self.selected)
    }

    /// Move the selection cursor up (towards index 0).
    pub fn select_prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    /// Move the selection cursor down (towards the last row).
    pub fn select_next(&mut self) {
        if self.selected + 1 < self.catches.len() {
            self.selected += 1;
        }
    }

    fn push_log(&mut self, line: String) {
        if self.event_log.len() == EVENT_LOG_CAPACITY {
            self.event_log.pop_front();
        }
        self.event_log.push_back(line);
    }

    /// Port-status rows sorted by `(state-order, target, port)`:
    /// Open first, then Flapping, then Closed. Ties broken
    /// alphabetically by target then numerically by port.
    pub fn port_status_sorted(&self) -> Vec<&PortStatus> {
        let mut rows: Vec<&PortStatus> = self.port_status.values().collect();
        rows.sort_by_key(|s| {
            let state_rank = match s.state {
                PortLiveState::Open => 0,
                PortLiveState::Flapping => 1,
                PortLiveState::Closed => 2,
            };
            (state_rank, s.target.clone(), s.port)
        });
        rows
    }
}

/// Parse an `"ip:port"` or `"[v6]:port"` upstream string. Returns None
/// on malformed input — such events are ignored for PortStatus
/// enrichment but still flow through the rest of the TUI normally.
fn split_upstream(upstream: &str) -> Option<(String, u16)> {
    if let Some((host, port)) = upstream.rsplit_once(':') {
        if let Ok(p) = port.parse::<u16>() {
            let host = host.trim_matches(['[', ']']);
            return Some((host.to_owned(), p));
        }
    }
    None
}

/// One-line event summary used in the event-log panel.
fn summarize(ev: &Event) -> String {
    match &ev.body {
        EventBody::EngagementStarted(e) => {
            format!(
                "engagement started profile={} engine={}",
                e.profile, e.engine
            )
        }
        EventBody::PortOpenDetected(p) => {
            format!(
                "open {}:{} in {}ms via {}",
                p.target, p.port, p.detect_latency_ms, p.engine
            )
        }
        EventBody::PortClosedDetected(p) => {
            format!(
                "closed {}:{} ({}){}",
                p.target,
                p.port,
                p.reason,
                match p.was_open_for_ms {
                    Some(ms) => format!(" after {ms}ms open"),
                    None => String::new(),
                }
            )
        }
        EventBody::HoldOpenReady(h) => {
            format!("hold ready localhost:{} -> {}", h.local_port, h.upstream)
        }
        EventBody::HoldOpenClosed(h) => {
            format!("hold closed reason={} after {}ms", h.reason, h.duration_ms)
        }
        EventBody::ProbeAttempted(p) => {
            format!("probe {} outcome={}", p.probe, p.outcome)
        }
        EventBody::FingerprintCaptured(f) => {
            format!(
                "fingerprint {} conf={:.2}",
                f.protocol_guess.as_deref().unwrap_or("?"),
                f.confidence
            )
        }
        EventBody::CatchComplete(c) => {
            format!(
                "catch complete in {}ms proto={}",
                c.total_duration_ms,
                c.final_protocol.as_deref().unwrap_or("?")
            )
        }
        EventBody::ScopeViolationBlocked(s) => {
            format!(
                "scope blocked {}:{} ({})",
                s.attempted_target, s.attempted_port, s.reason
            )
        }
        EventBody::RateCapEngaged(r) => {
            format!("rate cap {}/{} pps", r.current_pps, r.cap_pps)
        }
        EventBody::EngagementFinished(f) => {
            format!(
                "engagement finished catches={} reason={}",
                f.catches_total, f.reason
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ps_core::event::payload::{
        CatchComplete, EventBody, FingerprintCaptured, HoldOpenClosed, HoldOpenReady,
        PortOpenDetected, RateCapEngaged, ScopeViolationBlocked,
    };
    use ps_core::event::Event;
    use ps_core::id::{CatchId, EngagementId};

    fn ev_with(body: EventBody, cid: Option<CatchId>) -> Event {
        Event::new(EngagementId::new(), cid, body)
    }

    fn port_open(cid: CatchId, port: u16) -> Event {
        ev_with(
            EventBody::PortOpenDetected(PortOpenDetected {
                target: "10.0.0.5".into(),
                port,
                detect_latency_ms: 42,
                engine: "connect".into(),
                syn_rtt_ms: None,
            }),
            Some(cid),
        )
    }

    #[test]
    fn new_app_is_empty() {
        let app = TuiApp::new();
        assert!(app.catches.is_empty());
        assert!(app.holds.is_empty());
        assert!(app.event_log.is_empty());
        assert!(!app.paused);
        assert!(!app.quit);
    }

    #[test]
    fn port_open_appends_catch_row() {
        let mut app = TuiApp::new();
        let cid = CatchId::new();
        app.apply(&port_open(cid, 8080));
        assert_eq!(app.catches.len(), 1);
        assert_eq!(app.catches[0].port, 8080);
        assert_eq!(app.catches[0].catch_id, cid);
        assert_eq!(app.catches[0].status, CatchStatus::Detecting);
    }

    #[test]
    fn hold_open_transitions_to_holding() {
        let mut app = TuiApp::new();
        let cid = CatchId::new();
        app.apply(&port_open(cid, 8080));
        app.apply(&ev_with(
            EventBody::HoldOpenReady(HoldOpenReady {
                local_port: 7101,
                upstream: "10.0.0.5:8080".into(),
                mode: "dumb_tunnel".into(),
                ca_fingerprint: None,
            }),
            Some(cid),
        ));
        assert_eq!(app.catches[0].status, CatchStatus::Holding);
        assert_eq!(app.catches[0].tunnel_port, Some(7101));
        assert_eq!(app.holds.len(), 1);
    }

    #[test]
    fn hold_close_removes_hold() {
        let mut app = TuiApp::new();
        let cid = CatchId::new();
        app.apply(&port_open(cid, 8080));
        app.apply(&ev_with(
            EventBody::HoldOpenReady(HoldOpenReady {
                local_port: 7101,
                upstream: "10.0.0.5:8080".into(),
                mode: "dumb_tunnel".into(),
                ca_fingerprint: None,
            }),
            Some(cid),
        ));
        app.apply(&ev_with(
            EventBody::HoldOpenClosed(HoldOpenClosed {
                reason: "upstream_closed".into(),
                duration_ms: 1234,
            }),
            Some(cid),
        ));
        assert!(app.holds.is_empty());
    }

    #[test]
    fn fingerprint_fills_protocol() {
        let mut app = TuiApp::new();
        let cid = CatchId::new();
        app.apply(&port_open(cid, 8080));
        app.apply(&ev_with(
            EventBody::FingerprintCaptured(FingerprintCaptured {
                protocol_guess: Some("http/1.1".into()),
                confidence: 0.92,
                banner_excerpt: "HTTP/1.1 200 OK".into(),
                tls_info: None,
                artifacts_path: "artifacts/x".into(),
            }),
            Some(cid),
        ));
        assert_eq!(app.catches[0].protocol.as_deref(), Some("http/1.1"));
        assert_eq!(app.catches[0].confidence, Some(0.92));
    }

    #[test]
    fn catch_complete_marks_complete() {
        let mut app = TuiApp::new();
        let cid = CatchId::new();
        app.apply(&port_open(cid, 8080));
        app.apply(&ev_with(
            EventBody::CatchComplete(CatchComplete {
                total_duration_ms: 1500,
                probes_run: 3,
                final_protocol: Some("http/1.1".into()),
                artifacts_path: "artifacts/x".into(),
            }),
            Some(cid),
        ));
        assert_eq!(app.catches[0].status, CatchStatus::Complete);
    }

    #[test]
    fn rate_cap_updates_gauge() {
        let mut app = TuiApp::new();
        app.apply(&ev_with(
            EventBody::RateCapEngaged(RateCapEngaged {
                current_pps: 25_000,
                cap_pps: 50_000,
                throttled_targets: 0,
            }),
            None,
        ));
        assert!((app.rate_gauge - 0.5).abs() < 1e-6);
    }

    #[test]
    fn scope_violation_increments_audit_count() {
        let mut app = TuiApp::new();
        app.apply(&ev_with(
            EventBody::ScopeViolationBlocked(ScopeViolationBlocked {
                attempted_target: "8.8.8.8".into(),
                attempted_port: 53,
                reason: "out of scope".into(),
            }),
            None,
        ));
        assert_eq!(app.audit_count, 1);
    }

    #[test]
    fn event_log_is_capped() {
        let mut app = TuiApp::new();
        for i in 0..(EVENT_LOG_CAPACITY + 10) {
            app.apply(&port_open(CatchId::new(), 1000 + i as u16));
        }
        assert_eq!(app.event_log.len(), EVENT_LOG_CAPACITY);
    }

    #[test]
    fn clear_completed_retains_active() {
        let mut app = TuiApp::new();
        let cid_done = CatchId::new();
        let cid_live = CatchId::new();
        app.apply(&port_open(cid_done, 1));
        app.apply(&port_open(cid_live, 2));
        app.apply(&ev_with(
            EventBody::CatchComplete(CatchComplete {
                total_duration_ms: 1,
                probes_run: 0,
                final_protocol: None,
                artifacts_path: "x".into(),
            }),
            Some(cid_done),
        ));
        app.clear_completed();
        assert_eq!(app.catches.len(), 1);
        assert_eq!(app.catches[0].catch_id, cid_live);
    }

    #[test]
    fn toggle_pause_flips_flag() {
        let mut app = TuiApp::new();
        assert!(!app.paused);
        app.toggle_pause();
        assert!(app.paused);
        app.toggle_pause();
        assert!(!app.paused);
    }
}
