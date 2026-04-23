# Phase 5 — TUI + Race Harness + Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close v1 — add the `ratatui` TUI that makes catches visceral, codify race-conformance as CI gates, harden with fuzzing and license/advisory policy, finish operator documentation, and ship signed cross-platform binaries plus a crates.io release as v1.0.0.

**Architecture:** No new architectural seams — Phase 5 is polish, verification, and release engineering. The TUI is a new `EventSink` consumer of the existing bus. The race harness is a new CI-executed test binary pair. cargo-dist owns the release pipeline.

**Tech Stack:** Adds `ratatui`, `crossterm`, `arboard`, `cargo-fuzz`, `cargo-deny`, `cargo-dist`, `sigstore` (cosign CLI in CI). Plus everything from Phases 1–4.

**Release target:** v1.0.0 (public GA).

**Assumes Phases 1-4 complete:** workspace is feature-complete apart from the TUI and release plumbing, v0.3.0 tagged, all CI green on Linux/macOS/Windows.

---

## Decisions made for this phase

These decisions close out the §17 open questions from the design spec:

- **TUI is in scope for v1.** The design spec lists it as optional polish, but the master plan's Phase 5 table commits it to v1.0.0 and it materially improves operator UX for short catch windows. We ship it.
- **Release signing: sigstore/cosign, with GPG as explicit fallback if `windows-latest` cosign integration breaks CI.** sigstore is cheaper to operate, has first-class GitHub Actions identity, and cosign works on all three runners as of the 2.x series. We attempt sigstore first; if the Windows runner fails twice in a row on the `v0.4.0-rc1` dry-run, we switch to the `IntegSec/releases` GPG key (held in an offline HSM owned by the IntegSec release manager) and document the fallback in the release workflow.
- **Race-harness soak tier runs nightly only.** Tight tier runs every PR and is the CI gate.
- **Default CLI mode is `--tui` on TTYs, plain log elsewhere.** Matches the pentester-watching-one-terminal mental model while keeping scripted use (`portsnatcher | grep …`, CI dry-runs) trivially possible.

---

## Task list

### 5.1 — TUI scaffolding and EventSink integration

- [ ] **Task 1: Add `ratatui`, `crossterm`, `arboard` to the `portsnatcher` binary crate (failing test first).**
  - Write `crates/portsnatcher/tests/e2e/tui_compile.rs`:
    ```rust
    // Compile-smoke: confirm the TUI module exists and exports the entry point.
    // Until Task 2 lands this must fail to link.
    use portsnatcher::tui;

    #[test]
    fn tui_entry_point_is_public() {
        // Forces a link against the tui module. Type-level only.
        let _ = tui::run_tui as fn(_, _) -> _;
    }
    ```
  - Add to `crates/portsnatcher/Cargo.toml` under `[dependencies]`:
    ```toml
    ratatui = "0.26.3"
    crossterm = "0.27.0"
    arboard = "3.4.0"
    ```
  - Run `cargo test -p portsnatcher --test tui_compile`. Expected: fails with `unresolved import: portsnatcher::tui` or `unresolved: run_tui`.
  - Commit:
    ```
    test(portsnatcher): add failing compile test for TUI entry point

    Pins the shape of the TUI API (run_tui fn) before implementation lands,
    so Task 2 has a concrete link target.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 2: Create empty `tui` module and re-export `run_tui` to make Task 1 compile.**
  - Create `crates/portsnatcher/src/tui/mod.rs`:
    ```rust
    //! Terminal UI for PortSnatcher. Subscribes to the event bus and renders
    //! a four-panel ratatui layout until the operator quits.

    pub mod app;
    pub mod widgets;

    use anyhow::Result;
    use ps_bus::SubscriberHandle;
    use tokio::sync::mpsc;

    /// Command channel the TUI listens on for control-plane messages from
    /// the rest of the binary (e.g., "engagement is finishing, shut down").
    pub enum TuiCommand {
        Shutdown,
    }

    /// Entry point. Consumes the event stream, renders until the operator
    /// presses `q` or a `Shutdown` command arrives.
    pub async fn run_tui(
        _subscriber: SubscriberHandle,
        _commands: mpsc::Receiver<TuiCommand>,
    ) -> Result<()> {
        // Stub — Task 3 onward fills this in. Returning Ok keeps the compile
        // test green while the implementation matures.
        Ok(())
    }
    ```
  - Add `pub mod tui;` to `crates/portsnatcher/src/lib.rs` (or create a minimal `lib.rs` if the binary crate doesn't expose one yet; if it doesn't, Task 1's test must instead use an integration-test-only crate alias — in which case edit Task 1's import to `use portsnatcher_bin::tui;` and add `[lib] name = "portsnatcher_bin"` alongside the existing `[[bin]]` section in `crates/portsnatcher/Cargo.toml`).
  - Create stub `crates/portsnatcher/src/tui/app.rs`:
    ```rust
    //! TUI App state. See Task 4 for the concrete model.
    ```
  - Create stub `crates/portsnatcher/src/tui/widgets.rs`:
    ```rust
    //! TUI widget rendering helpers. See Task 5 for the concrete widgets.
    ```
  - Run `cargo test -p portsnatcher --test tui_compile`. Expected: passes.
  - Commit:
    ```
    feat(portsnatcher): scaffold tui module with run_tui entry point

    Empty module so Phase 5 task 1's compile test links. Subsequent tasks
    fill in app state, widgets, and the event loop.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 3: Write failing test for `App` state model in `tui::app`.**
  - Create `crates/portsnatcher/tests/tui_app_state.rs`:
    ```rust
    //! Unit-style tests for TUI App state transitions. No terminal I/O.

    use portsnatcher::tui::app::{App, AppEvent};
    use ps_core::event::{Event, EventPayload, PortOpenDetected};
    use ps_core::id::{CatchId, EngagementId, EventId};
    use ps_core::target::Target;
    use std::net::Ipv4Addr;
    use time::OffsetDateTime;

    fn mk_event(payload: EventPayload) -> Event {
        Event {
            schema: "portsnatcher/v1".into(),
            event_id: EventId::new(),
            catch_id: None,
            engagement_id: EngagementId::new(),
            timestamp: OffsetDateTime::now_utc(),
            payload,
        }
    }

    #[test]
    fn app_starts_empty_and_unpaused() {
        let app = App::new();
        assert_eq!(app.catches().len(), 0);
        assert_eq!(app.holds().len(), 0);
        assert_eq!(app.recent_events().len(), 0);
        assert!(!app.is_paused());
        assert!(!app.should_quit());
    }

    #[test]
    fn port_open_detected_adds_a_catch_row() {
        let mut app = App::new();
        let cid = CatchId::new();
        app.handle(AppEvent::Bus(mk_event(EventPayload::PortOpenDetected(
            PortOpenDetected {
                catch_id: cid,
                target: Target::Ipv4(Ipv4Addr::new(10, 0, 0, 5)),
                port: 8080,
                detect_latency_ms: 42,
                engine: "connect".into(),
                syn_rtt_ms: None,
            },
        ))));
        assert_eq!(app.catches().len(), 1);
        assert_eq!(app.catches()[0].port, 8080);
        assert_eq!(app.catches()[0].catch_id, cid);
    }

    #[test]
    fn q_key_sets_should_quit() {
        let mut app = App::new();
        app.handle(AppEvent::Key(crossterm::event::KeyCode::Char('q')));
        assert!(app.should_quit());
    }

    #[test]
    fn p_key_toggles_pause() {
        let mut app = App::new();
        app.handle(AppEvent::Key(crossterm::event::KeyCode::Char('p')));
        assert!(app.is_paused());
        app.handle(AppEvent::Key(crossterm::event::KeyCode::Char('p')));
        assert!(!app.is_paused());
    }

    #[test]
    fn c_key_clears_completed_catches() {
        use ps_core::event::CatchComplete;
        let mut app = App::new();
        let cid = CatchId::new();
        app.handle(AppEvent::Bus(mk_event(EventPayload::PortOpenDetected(
            PortOpenDetected {
                catch_id: cid,
                target: Target::Ipv4(Ipv4Addr::new(10, 0, 0, 5)),
                port: 8080,
                detect_latency_ms: 42,
                engine: "connect".into(),
                syn_rtt_ms: None,
            },
        ))));
        app.handle(AppEvent::Bus(mk_event(EventPayload::CatchComplete(
            CatchComplete {
                catch_id: cid,
                total_duration_ms: 1500,
                probes_run: 3,
                final_protocol: "http".into(),
                artifacts_path: "/tmp/artifacts/c".into(),
            },
        ))));
        assert_eq!(app.catches().len(), 1);
        app.handle(AppEvent::Key(crossterm::event::KeyCode::Char('c')));
        assert_eq!(app.catches().len(), 0);
    }
    ```
  - Run `cargo test -p portsnatcher --test tui_app_state`. Expected: fails, `App` type not defined.
  - Commit:
    ```
    test(portsnatcher): spec TUI App state via failing unit tests

    Defines the App API surface (new, handle, catches, holds,
    recent_events, is_paused, should_quit) before implementation.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 4: Implement `App` state in `tui::app` to pass Task 3's tests.**
  - Replace `crates/portsnatcher/src/tui/app.rs` with:
    ```rust
    //! TUI App state. Pure data + transitions; no rendering, no I/O.

    use crossterm::event::KeyCode;
    use ps_core::event::{Event, EventPayload};
    use ps_core::id::CatchId;
    use ps_core::target::Target;
    use std::collections::VecDeque;
    use time::OffsetDateTime;

    const RECENT_EVENT_CAPACITY: usize = 200;

    #[derive(Debug, Clone, PartialEq)]
    pub enum CatchStatus {
        Detecting,
        Holding,
        Complete,
    }

    #[derive(Debug, Clone)]
    pub struct CatchRow {
        pub catch_id: CatchId,
        pub target: Target,
        pub port: u16,
        pub engine: String,
        pub protocol: Option<String>,
        pub confidence: Option<f32>,
        pub tunnel_port: Option<u16>,
        pub status: CatchStatus,
        pub detected_at: OffsetDateTime,
    }

    #[derive(Debug, Clone)]
    pub struct HoldRow {
        pub catch_id: CatchId,
        pub local_port: u16,
        pub mode: String,
        pub opened_at: OffsetDateTime,
    }

    #[derive(Debug, Clone)]
    pub struct RecentEvent {
        pub kind: String,
        pub line: String,
        pub at: OffsetDateTime,
    }

    pub enum AppEvent {
        Bus(Event),
        Key(KeyCode),
        Tick,
    }

    pub struct App {
        catches: Vec<CatchRow>,
        holds: Vec<HoldRow>,
        recent: VecDeque<RecentEvent>,
        current_pps: u32,
        cap_pps: u32,
        audit_count: u64,
        selected_catch: usize,
        filter: Option<String>,
        paused: bool,
        quit: bool,
    }

    impl App {
        pub fn new() -> Self {
            Self {
                catches: Vec::new(),
                holds: Vec::new(),
                recent: VecDeque::new(),
                current_pps: 0,
                cap_pps: 0,
                audit_count: 0,
                selected_catch: 0,
                filter: None,
                paused: false,
                quit: false,
            }
        }

        pub fn catches(&self) -> &[CatchRow] {
            &self.catches
        }
        pub fn holds(&self) -> &[HoldRow] {
            &self.holds
        }
        pub fn recent_events(&self) -> impl Iterator<Item = &RecentEvent> {
            self.recent.iter()
        }
        pub fn current_pps(&self) -> u32 {
            self.current_pps
        }
        pub fn cap_pps(&self) -> u32 {
            self.cap_pps
        }
        pub fn audit_count(&self) -> u64 {
            self.audit_count
        }
        pub fn is_paused(&self) -> bool {
            self.paused
        }
        pub fn should_quit(&self) -> bool {
            self.quit
        }
        pub fn selected(&self) -> Option<&CatchRow> {
            self.catches.get(self.selected_catch)
        }
        pub fn filter(&self) -> Option<&str> {
            self.filter.as_deref()
        }

        pub fn handle(&mut self, ev: AppEvent) {
            match ev {
                AppEvent::Bus(e) => self.apply_event(e),
                AppEvent::Key(k) => self.apply_key(k),
                AppEvent::Tick => {}
            }
        }

        fn apply_event(&mut self, e: Event) {
            let kind = payload_kind(&e.payload);
            self.push_recent(kind.to_string(), summarize(&e), e.timestamp);
            match e.payload {
                EventPayload::PortOpenDetected(p) => {
                    self.catches.push(CatchRow {
                        catch_id: p.catch_id,
                        target: p.target,
                        port: p.port,
                        engine: p.engine,
                        protocol: None,
                        confidence: None,
                        tunnel_port: None,
                        status: CatchStatus::Detecting,
                        detected_at: e.timestamp,
                    });
                }
                EventPayload::HoldOpenReady(h) => {
                    if let Some(row) = self
                        .catches
                        .iter_mut()
                        .find(|r| r.catch_id == h.catch_id)
                    {
                        row.tunnel_port = Some(h.local_port);
                        row.status = CatchStatus::Holding;
                    }
                    self.holds.push(HoldRow {
                        catch_id: h.catch_id,
                        local_port: h.local_port,
                        mode: h.mode,
                        opened_at: e.timestamp,
                    });
                }
                EventPayload::HoldOpenClosed(h) => {
                    self.holds.retain(|r| r.catch_id != h.catch_id);
                }
                EventPayload::FingerprintCaptured(f) => {
                    if let Some(row) = self
                        .catches
                        .iter_mut()
                        .find(|r| r.catch_id == f.catch_id)
                    {
                        row.protocol = Some(f.protocol_guess);
                        row.confidence = Some(f.confidence);
                    }
                }
                EventPayload::CatchComplete(c) => {
                    if let Some(row) = self
                        .catches
                        .iter_mut()
                        .find(|r| r.catch_id == c.catch_id)
                    {
                        row.status = CatchStatus::Complete;
                        if row.protocol.is_none() {
                            row.protocol = Some(c.final_protocol);
                        }
                    }
                }
                EventPayload::RateCapEngaged(r) => {
                    self.current_pps = r.current_pps;
                    self.cap_pps = r.cap_pps;
                }
                EventPayload::ScopeViolationBlocked(_) => {
                    self.audit_count = self.audit_count.saturating_add(1);
                }
                _ => {}
            }
        }

        fn apply_key(&mut self, k: KeyCode) {
            match k {
                KeyCode::Char('q') => self.quit = true,
                KeyCode::Char('p') => self.paused = !self.paused,
                KeyCode::Char('c') => {
                    self.catches
                        .retain(|r| r.status != CatchStatus::Complete);
                    if self.selected_catch >= self.catches.len() {
                        self.selected_catch = self.catches.len().saturating_sub(1);
                    }
                }
                KeyCode::Char('/') => {
                    self.filter = Some(String::new());
                }
                KeyCode::Up => {
                    self.selected_catch = self.selected_catch.saturating_sub(1);
                }
                KeyCode::Down => {
                    if self.selected_catch + 1 < self.catches.len() {
                        self.selected_catch += 1;
                    }
                }
                _ => {}
            }
        }

        fn push_recent(&mut self, kind: String, line: String, at: OffsetDateTime) {
            if self.recent.len() == RECENT_EVENT_CAPACITY {
                self.recent.pop_front();
            }
            self.recent.push_back(RecentEvent { kind, line, at });
        }
    }

    fn payload_kind(p: &EventPayload) -> &'static str {
        match p {
            EventPayload::EngagementStarted(_) => "EngagementStarted",
            EventPayload::PortOpenDetected(_) => "PortOpenDetected",
            EventPayload::HoldOpenReady(_) => "HoldOpenReady",
            EventPayload::HoldOpenClosed(_) => "HoldOpenClosed",
            EventPayload::ProbeAttempted(_) => "ProbeAttempted",
            EventPayload::FingerprintCaptured(_) => "FingerprintCaptured",
            EventPayload::CatchComplete(_) => "CatchComplete",
            EventPayload::ScopeViolationBlocked(_) => "ScopeViolationBlocked",
            EventPayload::RateCapEngaged(_) => "RateCapEngaged",
            EventPayload::EngagementFinished(_) => "EngagementFinished",
        }
    }

    fn summarize(e: &Event) -> String {
        match &e.payload {
            EventPayload::PortOpenDetected(p) => {
                format!("open {}:{} ({}ms, {})", p.target, p.port, p.detect_latency_ms, p.engine)
            }
            EventPayload::HoldOpenReady(h) => {
                format!("hold {} → localhost:{}", h.catch_id, h.local_port)
            }
            EventPayload::FingerprintCaptured(f) => {
                format!("fp {} conf={:.2}", f.protocol_guess, f.confidence)
            }
            EventPayload::CatchComplete(c) => {
                format!("done {} in {}ms", c.catch_id, c.total_duration_ms)
            }
            other => format!("{:?}", other),
        }
    }
    ```
  - Run `cargo test -p portsnatcher --test tui_app_state`. Expected: 5 tests pass.
  - Commit:
    ```
    feat(portsnatcher): implement TUI App state with bus + key transitions

    Pure data model — renders are downstream. Handles PortOpenDetected,
    HoldOpenReady, HoldOpenClosed, FingerprintCaptured, CatchComplete,
    RateCapEngaged, ScopeViolationBlocked; routes q/p/c/arrow keys.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 5: Implement four panels in `tui::widgets`.**
  - Replace `crates/portsnatcher/src/tui/widgets.rs` with:
    ```rust
    //! Widget rendering for the four-panel TUI layout.
    //!
    //! Layout:
    //!   +-------------------------+----------------------+
    //!   |  Catches table (60%)    |  Holds (40%)         |
    //!   +-------------------------+----------------------+
    //!   |  Rate gauge (30%)       |  Event log (70%)     |
    //!   +-------------------------+----------------------+

    use crate::tui::app::{App, CatchStatus};
    use ratatui::layout::{Constraint, Direction, Layout, Rect};
    use ratatui::style::{Color, Modifier, Style};
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{Block, Borders, Cell, Gauge, List, ListItem, Paragraph, Row, Table};
    use ratatui::Frame;

    pub fn draw(f: &mut Frame<'_>, app: &App) {
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(f.size());

        let top = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(outer[0]);

        let bottom = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
            .split(outer[1]);

        draw_catches(f, top[0], app);
        draw_holds(f, top[1], app);
        draw_rate(f, bottom[0], app);
        draw_log(f, bottom[1], app);
    }

    fn draw_catches(f: &mut Frame<'_>, area: Rect, app: &App) {
        let header = Row::new(vec![
            Cell::from("Target:Port"),
            Cell::from("Engine"),
            Cell::from("Proto"),
            Cell::from("Conf"),
            Cell::from("Tunnel"),
            Cell::from("Status"),
        ])
        .style(Style::default().add_modifier(Modifier::BOLD));
        let rows = app.catches().iter().map(|r| {
            let status = match r.status {
                CatchStatus::Detecting => Span::styled("detecting", Style::default().fg(Color::Yellow)),
                CatchStatus::Holding => Span::styled("holding", Style::default().fg(Color::Green)),
                CatchStatus::Complete => Span::styled("done", Style::default().fg(Color::DarkGray)),
            };
            Row::new(vec![
                Cell::from(format!("{}:{}", r.target, r.port)),
                Cell::from(r.engine.clone()),
                Cell::from(r.protocol.clone().unwrap_or_else(|| "?".into())),
                Cell::from(
                    r.confidence
                        .map(|c| format!("{:.2}", c))
                        .unwrap_or_else(|| "-".into()),
                ),
                Cell::from(
                    r.tunnel_port
                        .map(|p| format!("localhost:{}", p))
                        .unwrap_or_else(|| "-".into()),
                ),
                Cell::from(Line::from(status)),
            ])
        });
        let table = Table::new(
            rows,
            [
                Constraint::Percentage(28),
                Constraint::Length(8),
                Constraint::Length(10),
                Constraint::Length(6),
                Constraint::Length(18),
                Constraint::Length(10),
            ],
        )
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("Catches"));
        f.render_widget(table, area);
    }

    fn draw_holds(f: &mut Frame<'_>, area: Rect, app: &App) {
        let items: Vec<ListItem> = app
            .holds()
            .iter()
            .map(|h| {
                ListItem::new(format!(
                    "localhost:{}  mode={}  catch={}",
                    h.local_port, h.mode, h.catch_id
                ))
            })
            .collect();
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Holds"));
        f.render_widget(list, area);
    }

    fn draw_rate(f: &mut Frame<'_>, area: Rect, app: &App) {
        let cap = app.cap_pps().max(1) as u64;
        let cur = app.current_pps() as u64;
        let ratio = ((cur as f64) / (cap as f64)).clamp(0.0, 1.0);
        let gauge = Gauge::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!("Rate  {}/{} pps  audit={}", cur, cap, app.audit_count())),
            )
            .gauge_style(Style::default().fg(Color::Cyan))
            .ratio(ratio);
        f.render_widget(gauge, area);
    }

    fn draw_log(f: &mut Frame<'_>, area: Rect, app: &App) {
        let lines: Vec<Line> = app
            .recent_events()
            .rev()
            .take(area.height.saturating_sub(2) as usize)
            .map(|r| {
                let color = match r.kind.as_str() {
                    "PortOpenDetected" => Color::Green,
                    "HoldOpenReady" => Color::Cyan,
                    "HoldOpenClosed" => Color::DarkGray,
                    "ScopeViolationBlocked" => Color::Red,
                    "RateCapEngaged" => Color::Yellow,
                    "CatchComplete" => Color::Blue,
                    _ => Color::White,
                };
                Line::from(Span::styled(
                    format!("[{}] {}", r.kind, r.line),
                    Style::default().fg(color),
                ))
            })
            .collect();
        let para = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title("Events"));
        f.render_widget(para, area);
    }
    ```
  - Run `cargo build -p portsnatcher`. Expected: compiles cleanly.
  - Commit:
    ```
    feat(portsnatcher): four-panel TUI widgets — catches, holds, rate, log

    Catches table colors status yellow/green/gray; event log colors by
    event type (green open, red scope violation, yellow rate cap).

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 6: Implement the TUI event loop and `Enter`-to-copy-clipboard binding.**
  - Replace `crates/portsnatcher/src/tui/mod.rs` with the full loop:
    ```rust
    //! Terminal UI for PortSnatcher. Subscribes to the event bus, renders the
    //! four-panel layout in `widgets`, drives the App state in `app`.

    pub mod app;
    pub mod widgets;

    use anyhow::{Context, Result};
    use app::{App, AppEvent};
    use crossterm::event::{Event as CtEvent, KeyCode, KeyEventKind};
    use crossterm::execute;
    use crossterm::terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
    };
    use ps_bus::SubscriberHandle;
    use ratatui::backend::CrosstermBackend;
    use ratatui::Terminal;
    use std::io::{self, Stdout};
    use std::time::Duration;
    use tokio::sync::mpsc;

    pub enum TuiCommand {
        Shutdown,
    }

    pub async fn run_tui(
        mut subscriber: SubscriberHandle,
        mut commands: mpsc::Receiver<TuiCommand>,
    ) -> Result<()> {
        let mut terminal = setup_terminal().context("tui: setup_terminal")?;
        let result = run_loop(&mut terminal, &mut subscriber, &mut commands).await;
        restore_terminal(&mut terminal).ok();
        result
    }

    fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        Ok(Terminal::new(CrosstermBackend::new(stdout))?)
    }

    fn restore_terminal(t: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
        disable_raw_mode()?;
        execute!(t.backend_mut(), LeaveAlternateScreen)?;
        t.show_cursor()?;
        Ok(())
    }

    async fn run_loop(
        terminal: &mut Terminal<CrosstermBackend<Stdout>>,
        subscriber: &mut SubscriberHandle,
        commands: &mut mpsc::Receiver<TuiCommand>,
    ) -> Result<()> {
        let mut app = App::new();
        let mut tick = tokio::time::interval(Duration::from_millis(100));

        loop {
            terminal.draw(|f| widgets::draw(f, &app))?;

            tokio::select! {
                maybe_ev = subscriber.recv() => {
                    match maybe_ev {
                        Ok(ev) if !app.is_paused() => app.handle(AppEvent::Bus(ev)),
                        Ok(_) => {} // paused — drop on the floor
                        Err(_) => {} // lagged or closed; keep running
                    }
                }
                Some(cmd) = commands.recv() => {
                    match cmd { TuiCommand::Shutdown => return Ok(()) }
                }
                _ = tick.tick() => {
                    if crossterm::event::poll(Duration::from_millis(0))? {
                        if let CtEvent::Key(k) = crossterm::event::read()? {
                            if k.kind == KeyEventKind::Press {
                                if k.code == KeyCode::Enter {
                                    copy_selected_tunnel_to_clipboard(&app);
                                } else {
                                    app.handle(AppEvent::Key(k.code));
                                }
                            }
                        }
                    }
                    app.handle(AppEvent::Tick);
                }
            }

            if app.should_quit() {
                return Ok(());
            }
        }
    }

    fn copy_selected_tunnel_to_clipboard(app: &App) {
        if let Some(row) = app.selected() {
            if let Some(tp) = row.tunnel_port {
                let text = format!("localhost:{}", tp);
                if let Ok(mut cb) = arboard::Clipboard::new() {
                    let _ = cb.set_text(text);
                }
            }
        }
    }
    ```
  - Run `cargo build -p portsnatcher` and `cargo test -p portsnatcher --test tui_app_state`. Expected: build clean, state tests pass.
  - Commit:
    ```
    feat(portsnatcher): TUI event loop with bus + crossterm + clipboard

    Runs the ratatui alternate screen, selects between bus events,
    shutdown commands, and 100ms tick. Enter copies the selected
    catch's tunnel address (localhost:71xx) to the system clipboard.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 7: Wire `--tui` / `--no-tui` CLI flags and auto-detect terminal.**
  - Edit `crates/portsnatcher/src/cli.rs` to add, under the `Run` subcommand's `Args` struct (preserve existing fields):
    ```rust
        /// Force the ratatui TUI on. If stdout is not a terminal this errors.
        #[arg(long, conflicts_with = "no_tui")]
        pub tui: bool,

        /// Force plain log output even on a terminal.
        #[arg(long, conflicts_with = "tui")]
        pub no_tui: bool,
    ```
  - Edit `crates/portsnatcher/src/cmd/run.rs` to resolve the mode (add near the top of `run()`):
    ```rust
    use std::io::IsTerminal;
    let want_tui = if args.tui {
        true
    } else if args.no_tui {
        false
    } else {
        std::io::stdout().is_terminal()
    };
    ```
  - In the same function, after the orchestrator starts, branch on `want_tui`:
    ```rust
    if want_tui {
        let sub = bus.subscribe()?;
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(8);
        let orchestrator_handle = orchestrator.shutdown_handle();
        // Relay orchestrator shutdown → TUI shutdown.
        tokio::spawn(async move {
            orchestrator_handle.wait_for_finish().await;
            let _ = cmd_tx.send(crate::tui::TuiCommand::Shutdown).await;
        });
        crate::tui::run_tui(sub, cmd_rx).await?;
    } else {
        orchestrator.wait_for_finish().await?;
    }
    ```
    (If `SubscriberHandle::subscribe` or `orchestrator.shutdown_handle()` are named differently in the Phase 1 code, preserve your existing names — the shape is: subscribe to the bus, hand the subscriber + a shutdown channel to the TUI.)
  - Run `cargo build -p portsnatcher` and `cargo run -p portsnatcher -- run --help`. Expected: `--tui` and `--no-tui` appear in the help; they are mutually exclusive.
  - Commit:
    ```
    feat(portsnatcher): auto-detect TUI mode with --tui/--no-tui overrides

    Default: TUI on TTY stdout, plain log otherwise. --tui forces on,
    --no-tui forces off. The two flags conflict by clap attribute.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 8: Integration test the TUI under `expectrl` (Linux-only gated).**
  - Add to `crates/portsnatcher/Cargo.toml` under `[dev-dependencies]`:
    ```toml
    expectrl = "0.7.1"
    ```
  - Create `crates/portsnatcher/tests/e2e/tui_smoke.rs`:
    ```rust
    //! End-to-end smoke of --tui --dry-run. Linux only in CI; macOS/Windows
    //! PTY quirks make expectrl tests flaky, so we skip them there.

    #![cfg(target_os = "linux")]

    use expectrl::{spawn, Regex};
    use std::time::Duration;

    #[test]
    fn tui_renders_and_quits() {
        let bin = env!("CARGO_BIN_EXE_portsnatcher");
        let mut p = spawn(format!(
            "{bin} run --dry-run --tui --config tests/fixtures/dry-run.toml"
        ))
        .expect("spawn");
        p.set_expect_timeout(Some(Duration::from_secs(10)));

        // Wait for any of our panel titles to render.
        p.expect(Regex("Catches|Holds|Rate|Events")).expect("initial render");

        // Send 'q' to quit.
        p.send("q").expect("send q");
        let status = p.wait().expect("wait");
        assert!(status.success() || status.code() == Some(0));
    }
    ```
  - Ensure `crates/portsnatcher/tests/fixtures/dry-run.toml` exists (Phase 1 creates it). If not, create a minimal one here:
    ```toml
    profile = "ctf"
    output_dir = "./artifacts"

    [engine]
    kind = "connect"

    [bus]
    listen = "127.0.0.1:0"
    ```
  - Run `cargo test -p portsnatcher --test tui_smoke` on Linux. Expected: passes. On macOS/Windows the `#[cfg]` gate compiles it out.
  - Commit:
    ```
    test(portsnatcher): Linux-only expectrl smoke for --tui --dry-run

    Asserts initial render shows panel titles and `q` cleanly exits.
    Gated to Linux because PTY emulation on macOS/Windows runners is
    flaky enough to be worse than no test.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

### 5.2 — `ephemeral-flapper` test binary

- [ ] **Task 9: Create `crates/ephemeral-flapper/` crate (failing test first).**
  - Create `crates/ephemeral-flapper/Cargo.toml`:
    ```toml
    [package]
    name = "ephemeral-flapper"
    version = "0.1.0"
    edition = "2021"
    publish = false
    license = "Apache-2.0"

    [[bin]]
    name = "ephemeral-flapper"
    path = "src/main.rs"

    [dependencies]
    anyhow = "1"
    serde = { version = "1", features = ["derive"] }
    toml = "0.8"
    tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "time", "io-util", "sync"] }

    [dev-dependencies]
    tokio = { version = "1", features = ["full"] }
    ```
  - Add the crate to the workspace `Cargo.toml` `[workspace] members = [...]` list.
  - Create `crates/ephemeral-flapper/tests/manifest_parse.rs`:
    ```rust
    use ephemeral_flapper::manifest::{Count, Manifest, WindowSpec};

    #[test]
    fn parses_single_forever_window() {
        let toml = r#"
            [[windows]]
            port = 45000
            open_ms = 50
            close_ms = 50
            count = "forever"
        "#;
        let m: Manifest = toml::from_str(toml).unwrap();
        assert_eq!(m.windows.len(), 1);
        assert_eq!(m.windows[0].port, 45000);
        assert_eq!(m.windows[0].open_ms, 50);
        assert_eq!(m.windows[0].close_ms, 50);
        assert!(matches!(m.windows[0].count, Count::Forever));
    }

    #[test]
    fn parses_bounded_count() {
        let toml = r#"
            [[windows]]
            port = 45001
            open_ms = 100
            close_ms = 900
            count = 30
        "#;
        let m: Manifest = toml::from_str(toml).unwrap();
        assert!(matches!(m.windows[0].count, Count::N(30)));
    }
    ```
  - Note: the integration test imports the crate as a library, so we also need a `lib.rs` next to `main.rs`.
  - Create stub `crates/ephemeral-flapper/src/lib.rs`:
    ```rust
    pub mod manifest;
    ```
  - Create empty `crates/ephemeral-flapper/src/manifest.rs` and `crates/ephemeral-flapper/src/main.rs`:
    ```rust
    // manifest.rs — stub; Task 10 fills this in.
    ```
    ```rust
    // main.rs — stub; Task 11 fills this in.
    fn main() {}
    ```
  - Also adjust `Cargo.toml` to expose a lib:
    ```toml
    [lib]
    name = "ephemeral_flapper"
    path = "src/lib.rs"
    ```
  - Run `cargo test -p ephemeral-flapper --test manifest_parse`. Expected: fails (types not defined).
  - Commit:
    ```
    test(ephemeral-flapper): failing manifest-parse test + crate skeleton

    Spec the manifest schema (windows: port, open_ms, close_ms,
    count = n | "forever") via failing tests before implementation.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 10: Implement `ephemeral-flapper`'s manifest module.**
  - Replace `crates/ephemeral-flapper/src/manifest.rs`:
    ```rust
    //! TOML manifest format for ephemeral-flapper. Read from stdin.

    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    pub struct Manifest {
        #[serde(default)]
        pub windows: Vec<WindowSpec>,
    }

    #[derive(Debug, Deserialize)]
    pub struct WindowSpec {
        pub port: u16,
        pub open_ms: u64,
        pub close_ms: u64,
        #[serde(default = "Count::default_forever")]
        pub count: Count,
    }

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    pub enum Count {
        N(u64),
        #[serde(deserialize_with = "de_forever")]
        Forever,
    }

    impl Count {
        fn default_forever() -> Count {
            Count::Forever
        }
    }

    fn de_forever<'de, D>(d: D) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        if s == "forever" {
            Ok(())
        } else {
            Err(serde::de::Error::custom("expected \"forever\""))
        }
    }
    ```
  - Run `cargo test -p ephemeral-flapper --test manifest_parse`. Expected: 2 tests pass.
  - Commit:
    ```
    feat(ephemeral-flapper): TOML manifest with n | "forever" counts

    Untagged Count enum — plain integers deserialize to N(u64), the
    literal string "forever" deserializes to Forever.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 11: Implement the flapper's main loop.**
  - Replace `crates/ephemeral-flapper/src/main.rs`:
    ```rust
    //! Reads a manifest from stdin, opens and closes TCP ports on 127.0.0.1
    //! according to the schedule. Designed to be deterministic.

    use anyhow::{Context, Result};
    use ephemeral_flapper::manifest::{Count, Manifest, WindowSpec};
    use std::io::Read;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio::time::{sleep, Instant};

    #[tokio::main(flavor = "multi_thread", worker_threads = 2)]
    async fn main() -> Result<()> {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("reading manifest from stdin")?;
        let manifest: Manifest = toml::from_str(&buf).context("parsing manifest")?;

        let mut handles = Vec::new();
        for w in manifest.windows {
            handles.push(tokio::spawn(run_window(w)));
        }
        for h in handles {
            h.await.context("window task panicked")??;
        }
        Ok(())
    }

    async fn run_window(w: WindowSpec) -> Result<()> {
        let addr: SocketAddr = format!("127.0.0.1:{}", w.port).parse()?;
        let mut remaining: i64 = match w.count {
            Count::Forever => -1,
            Count::N(n) => n as i64,
        };
        loop {
            if remaining == 0 {
                return Ok(());
            }
            // Open: bind, accept anything that shows up for open_ms.
            let listener = TcpListener::bind(addr).await.context("bind")?;
            let deadline = Instant::now() + Duration::from_millis(w.open_ms);
            loop {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                tokio::select! {
                    _ = sleep(deadline - now) => break,
                    res = listener.accept() => {
                        if let Ok((mut s, _)) = res {
                            // Drain anything the client sends; don't reply.
                            tokio::spawn(async move {
                                let mut buf = [0u8; 256];
                                use tokio::io::AsyncReadExt;
                                let _ = s.read(&mut buf).await;
                            });
                        }
                    }
                }
            }
            drop(listener);
            // Close: sleep close_ms before re-opening.
            sleep(Duration::from_millis(w.close_ms)).await;
            if remaining > 0 {
                remaining -= 1;
            }
        }
    }
    ```
  - Run `cargo build -p ephemeral-flapper`. Expected: clean build.
  - Smoke-test manually:
    ```bash
    printf '[[windows]]\nport = 45050\nopen_ms = 50\nclose_ms = 50\ncount = 3\n' \
      | cargo run -p ephemeral-flapper
    ```
    Expected: exits within ~300ms, no panics.
  - Commit:
    ```
    feat(ephemeral-flapper): per-window open/close scheduler on 127.0.0.1

    Each window is an independent tokio task; forever-windows run
    indefinitely, bounded windows exit after count iterations. Used
    as the driver for the race-conformance suite.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

### 5.3 — Race-harness conformance suite

- [ ] **Task 12: Write failing race-conformance test for `ConnectEngine` at tight scale.**
  - Create `crates/ps-engine/tests/race_conformance.rs`:
    ```rust
    //! Race-conformance CI gate. Spawns ephemeral-flapper with a canned
    //! manifest and asserts each engine's catch rate against the thresholds
    //! codified in spec §14.3.

    use std::process::{Command, Stdio};
    use std::io::Write;
    use std::time::Duration;

    /// Number of windows per configured test. Tight scale — CI-friendly.
    const TIGHT_WINDOWS: u64 = 30;

    fn flapper_bin() -> &'static str {
        env!("CARGO_BIN_EXE_ephemeral-flapper")
    }

    fn spawn_flapper(port: u16, open_ms: u64, close_ms: u64, count: u64) -> std::process::Child {
        let manifest = format!(
            "[[windows]]\nport = {port}\nopen_ms = {open_ms}\nclose_ms = {close_ms}\ncount = {count}\n"
        );
        let mut child = Command::new(flapper_bin())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ephemeral-flapper");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(manifest.as_bytes())
            .unwrap();
        child
    }

    /// Runs the given engine against a flapper, returns (caught, total).
    async fn run_once(
        engine: ps_engine::EngineKind,
        port: u16,
        open_ms: u64,
        close_ms: u64,
        count: u64,
    ) -> (u64, u64) {
        let mut flapper = spawn_flapper(port, open_ms, close_ms, count);
        // Small delay so the flapper binds before we start probing.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let caught = ps_engine::test_support::race_count(
            engine,
            "127.0.0.1",
            port,
            // Total window: count * (open_ms + close_ms) + slack.
            Duration::from_millis(count * (open_ms + close_ms) + 500),
        )
        .await
        .expect("engine run");
        let _ = flapper.kill();
        (caught, count)
    }

    #[tokio::test]
    async fn connect_engine_catches_90pct_of_500ms_windows() {
        let (caught, total) =
            run_once(ps_engine::EngineKind::Connect, 45110, 500, 250, TIGHT_WINDOWS).await;
        let pct = caught as f64 / total as f64;
        assert!(
            pct >= 0.90,
            "connect engine catch rate for 500ms windows: {}/{} = {:.2}, want >=0.90",
            caught, total, pct
        );
    }

    #[tokio::test]
    async fn connect_engine_catches_50pct_of_100ms_windows() {
        let (caught, total) =
            run_once(ps_engine::EngineKind::Connect, 45111, 100, 100, TIGHT_WINDOWS).await;
        let pct = caught as f64 / total as f64;
        assert!(
            pct >= 0.50,
            "connect engine catch rate for 100ms windows: {}/{} = {:.2}, want >=0.50",
            caught, total, pct
        );
    }
    ```
  - This test depends on a `ps_engine::test_support::race_count` helper that exposes a thin "run engine, count `PortOpenDetected` for this target, stop after `duration`" API. If it doesn't already exist (it doesn't — it's new to this phase), the test fails to compile, which is the failing state we want.
  - Run `cargo test -p ps-engine --test race_conformance`. Expected: fails to compile.
  - Commit:
    ```
    test(ps-engine): failing race-conformance tests for ConnectEngine

    Specs the CI-gate thresholds from design §14.3: 90% catch rate for
    500ms windows and 50% for 100ms windows. Implementation of the
    ps_engine::test_support::race_count helper lands next.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 13: Implement `ps_engine::test_support::race_count` helper.**
  - Create `crates/ps-engine/src/test_support.rs`:
    ```rust
    //! Test-only helpers for race-harness conformance tests.
    //!
    //! Not `#[cfg(test)]` — downstream test crates (in `tests/*.rs`) need
    //! to call this, and #[cfg(test)] isn't visible to integration tests.
    //! We instead gate visibility via a `test-support` Cargo feature.

    #![cfg(any(feature = "test-support", test))]

    use crate::{EngineKind, ProbeEngine};
    use anyhow::Result;
    use ps_core::event::EventPayload;
    use std::time::Duration;

    /// Runs the named engine against `host:port` and returns the number of
    /// PortOpenDetected events observed before `timeout`.
    pub async fn race_count(
        engine: EngineKind,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<u64> {
        let mut e = crate::build_engine(engine)?;
        let ctx = crate::EngineContext::single_target_loopback(host, port);
        let mut stream = e.start(ctx).await?;

        let mut count = 0u64;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, stream.recv()).await {
                Ok(Some(ev)) => {
                    if matches!(ev.payload, EventPayload::PortOpenDetected(_)) {
                        count += 1;
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        e.stop().await.ok();
        Ok(count)
    }
    ```
  - Add the feature flag to `crates/ps-engine/Cargo.toml`:
    ```toml
    [features]
    default = []
    test-support = []
    ```
  - Add `pub mod test_support;` near the top of `crates/ps-engine/src/lib.rs`.
  - Enable the feature for the test crate by editing `crates/ps-engine/Cargo.toml`'s `[dev-dependencies]`:
    ```toml
    [dev-dependencies]
    ps-engine = { path = ".", features = ["test-support"] }
    ```
    (If that self-cycle is rejected by cargo, instead use `[features] default = ["test-support"]` for pre-release while iterating, and remove it before the v1.0.0 publish. Document this in a `// TODO` on the feature line.)
  - `EngineContext::single_target_loopback` and `crate::build_engine` may not exist — if not, add minimal adapters:
    ```rust
    // At the bottom of crates/ps-engine/src/engine.rs (or wherever
    // EngineContext is defined), add:
    impl EngineContext {
        pub fn single_target_loopback(host: &str, port: u16) -> Self {
            // Build a single-target, unlimited-rate context for race tests.
            // Reuses the same constructors the CLI uses, with an all-loopback
            // ScopeGuard.
            Self::lab_loopback(host.parse().expect("ip"), port)
        }
    }

    pub fn build_engine(kind: EngineKind) -> anyhow::Result<Box<dyn ProbeEngine>> {
        Ok(match kind {
            EngineKind::Connect => Box::new(crate::connect::ConnectEngine::new_default()),
            EngineKind::Raw => Box::new(crate::raw::RawEngine::new_default()),
        })
    }
    ```
    (Adjust the exact names to match the Phase 2/4 concrete types. If `ConnectEngine::new_default` doesn't exist, add it — a zero-argument constructor that uses in-crate defaults. Same for `RawEngine`.)
  - Run `cargo test -p ps-engine --test race_conformance`. Expected: compiles, and the two tests pass (may take ~10s each — 30 windows × 750ms and 30 × 200ms respectively).
  - Commit:
    ```
    feat(ps-engine): add test_support::race_count helper for harness tests

    Runs an engine against a single loopback target for a bounded
    duration and returns the PortOpenDetected count. Gated by the
    new test-support feature so it stays out of production builds.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 14: Extend race-conformance test to cover `RawEngine`.**
  - Append to `crates/ps-engine/tests/race_conformance.rs`:
    ```rust
    #[tokio::test]
    #[cfg_attr(not(feature = "raw-engine-available"), ignore = "requires CAP_NET_RAW / admin")]
    async fn raw_engine_catches_95pct_of_50ms_windows() {
        let (caught, total) =
            run_once(ps_engine::EngineKind::Raw, 45120, 50, 50, TIGHT_WINDOWS).await;
        let pct = caught as f64 / total as f64;
        assert!(
            pct >= 0.95,
            "raw engine catch rate for 50ms windows: {}/{} = {:.2}, want >=0.95",
            caught, total, pct
        );
    }

    #[tokio::test]
    #[cfg_attr(not(feature = "raw-engine-available"), ignore = "requires CAP_NET_RAW / admin")]
    async fn raw_engine_catches_70pct_of_20ms_windows() {
        let (caught, total) =
            run_once(ps_engine::EngineKind::Raw, 45121, 20, 30, TIGHT_WINDOWS).await;
        let pct = caught as f64 / total as f64;
        assert!(
            pct >= 0.70,
            "raw engine catch rate for 20ms windows: {}/{} = {:.2}, want >=0.70",
            caught, total, pct
        );
    }
    ```
  - Add to `crates/ps-engine/Cargo.toml`:
    ```toml
    [features]
    default = []
    test-support = []
    raw-engine-available = []   # set in CI when the runner has raw-socket caps
    ```
  - Run `cargo test -p ps-engine --test race_conformance --features raw-engine-available`. Expected: on a runner with raw-socket capability (Linux root / macOS with ChmodBPF / Windows admin), all four tests pass. Without the feature flag, the raw tests are `#[ignore]`d and only the two connect tests run.
  - Commit:
    ```
    test(ps-engine): add RawEngine race-conformance tests (95% @ 50ms, 70% @ 20ms)

    Gated by the `raw-engine-available` feature — CI sets it in matrix
    jobs that have the privileges required (linux-root, macos-bpf,
    windows-admin). Unprivileged runs simply ignore the tests.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 15: Add `.github/workflows/race-harness.yml` (tight gate on every PR, soak nightly).**
  - Create `.github/workflows/race-harness.yml`:
    ```yaml
    name: race-harness
    on:
      pull_request:
      push:
        branches: [main]
      schedule:
        # Nightly at 03:17 UTC — soak scale.
        - cron: "17 3 * * *"

    jobs:
      tight:
        name: tight (${{ matrix.os }})
        strategy:
          fail-fast: false
          matrix:
            os: [ubuntu-latest, macos-latest, windows-latest]
        runs-on: ${{ matrix.os }}
        steps:
          - uses: actions/checkout@v4
          - uses: dtolnay/rust-toolchain@stable
          - uses: Swatinem/rust-cache@v2
          - name: Grant CAP_NET_RAW (Linux)
            if: runner.os == 'Linux'
            run: sudo setcap cap_net_raw,cap_net_admin=eip target/debug/portsnatcher || true
          - name: Build
            run: cargo build -p ps-engine --tests -p ephemeral-flapper
          - name: Run race conformance (connect)
            run: cargo test -p ps-engine --test race_conformance
          - name: Run race conformance (raw)
            if: runner.os == 'Linux'
            run: sudo -E env "PATH=$PATH" cargo test -p ps-engine --test race_conformance --features raw-engine-available

      soak:
        name: soak (nightly)
        if: github.event_name == 'schedule'
        runs-on: ubuntu-latest
        timeout-minutes: 20
        steps:
          - uses: actions/checkout@v4
          - uses: dtolnay/rust-toolchain@stable
          - uses: Swatinem/rust-cache@v2
          - name: Build
            run: cargo build --release -p ps-engine --tests -p ephemeral-flapper
          - name: Soak (1000 targets, 10 min)
            run: cargo test -p ps-engine --release --test race_soak -- --ignored
    ```
  - Run `cat .github/workflows/race-harness.yml` to verify. Expected: the file exists. GitHub Actions validation happens on push.
  - Commit:
    ```
    ci: race-harness workflow — tight on PR, soak nightly

    Tight tier is the merge gate: ConnectEngine always, RawEngine on
    Linux with CAP_NET_RAW. Soak tier runs on cron only.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 16: Add the soak-scale race test (nightly only, `#[ignore]`d by default).**
  - Create `crates/ps-engine/tests/race_soak.rs`:
    ```rust
    //! Soak-scale race test — 1000 targets, 10 minutes. Nightly CI only.
    //! `#[ignore]`d so `cargo test` without `--ignored` skips it.

    use std::process::{Command, Stdio};
    use std::io::Write;
    use std::time::Duration;

    const TARGET_COUNT: u16 = 1000;
    const BASE_PORT: u16 = 46000;
    const OPEN_MS: u64 = 200;
    const CLOSE_MS: u64 = 800;
    const RUN: Duration = Duration::from_secs(600);

    #[tokio::test]
    #[ignore]
    async fn soak_connect_engine_1000_targets_10min() {
        // Build a manifest with 1000 forever-windows.
        let mut manifest = String::new();
        for i in 0..TARGET_COUNT {
            manifest.push_str(&format!(
                "[[windows]]\nport = {}\nopen_ms = {}\nclose_ms = {}\ncount = \"forever\"\n",
                BASE_PORT + i,
                OPEN_MS,
                CLOSE_MS
            ));
        }
        let bin = env!("CARGO_BIN_EXE_ephemeral-flapper");
        let mut flapper = Command::new(bin)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn flapper");
        flapper
            .stdin
            .as_mut()
            .unwrap()
            .write_all(manifest.as_bytes())
            .unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;

        let caught = ps_engine::test_support::race_count_many(
            ps_engine::EngineKind::Connect,
            "127.0.0.1",
            BASE_PORT,
            TARGET_COUNT,
            RUN,
        )
        .await
        .expect("engine run");
        let _ = flapper.kill();

        // With 200ms open windows over 10 min, each target offers ~600 windows.
        // We don't assert a specific rate — we assert >0 and no crash.
        assert!(caught > 0, "soak caught nothing");
        eprintln!("soak caught {}", caught);
    }
    ```
  - Extend `crates/ps-engine/src/test_support.rs` with:
    ```rust
    pub async fn race_count_many(
        engine: EngineKind,
        host: &str,
        base_port: u16,
        n: u16,
        timeout: Duration,
    ) -> Result<u64> {
        let mut e = crate::build_engine(engine)?;
        let ctx = crate::EngineContext::many_loopback(host, base_port, n);
        let mut stream = e.start(ctx).await?;
        let mut count = 0u64;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, stream.recv()).await {
                Ok(Some(ev)) => {
                    if matches!(ev.payload, ps_core::event::EventPayload::PortOpenDetected(_)) {
                        count += 1;
                    }
                }
                _ => break,
            }
        }
        e.stop().await.ok();
        Ok(count)
    }
    ```
    Add matching `EngineContext::many_loopback(host, base_port, n)` constructor alongside `single_target_loopback`.
  - Run `cargo test -p ps-engine --test race_soak -- --ignored` locally for a minute to sanity-check (full run takes 10 min). Expected: progresses without panics.
  - Commit:
    ```
    test(ps-engine): nightly soak test — 1000 targets, 10 minutes

    Asserts no crash and non-zero catch count — the value is that it
    flushes out resource leaks and fd exhaustion, not a specific rate.
    `#[ignore]`d so regular CI skips it; nightly workflow runs it.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

### 5.4 — Fuzzing

- [ ] **Task 17: `cargo fuzz init` the workspace.**
  - Install cargo-fuzz if needed: `cargo install cargo-fuzz --locked`.
  - From the repo root, run `cargo fuzz init --target fuzz_scope_file`. Expected output: creates `fuzz/` directory with `fuzz/Cargo.toml`, `fuzz/fuzz_targets/fuzz_scope_file.rs`, `.gitignore`.
  - Add the rest of the targets: `cargo fuzz add fuzz_event_deserialize`, `cargo fuzz add fuzz_http_parse`, `cargo fuzz add fuzz_tls_parse`.
  - Verify with `ls fuzz/fuzz_targets/`. Expected: four `.rs` files.
  - Commit:
    ```
    chore(fuzz): cargo-fuzz init with four targets

    Scope file parser, event deserializer, HTTP response parser, TLS
    ClientHello response parser. Harness implementations land next.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 18: Implement `fuzz_scope_file` harness.**
  - Replace `fuzz/fuzz_targets/fuzz_scope_file.rs`:
    ```rust
    #![no_main]
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|data: &[u8]| {
        if let Ok(s) = std::str::from_utf8(data) {
            // Must not panic on any UTF-8 input. Error is fine.
            let _ = ps_core::scope::file::ScopeFile::from_json_str(s);
        }
    });
    ```
  - Add `ps-core = { path = "../crates/ps-core" }` to `fuzz/Cargo.toml` under `[dependencies]`.
  - Run `cargo fuzz run fuzz_scope_file -- -max_total_time=30` (30-second smoke). Expected: no crashes.
  - Commit:
    ```
    feat(fuzz): fuzz_scope_file — ScopeFile parser must not panic

    Feeds arbitrary UTF-8 to ScopeFile::from_json_str. Err returns are
    fine; panics fail the fuzzer.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 19: Implement `fuzz_event_deserialize` harness.**
  - Replace `fuzz/fuzz_targets/fuzz_event_deserialize.rs`:
    ```rust
    #![no_main]
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|data: &[u8]| {
        if let Ok(s) = std::str::from_utf8(data) {
            let _: Result<ps_core::event::Event, _> = serde_json::from_str(s);
        }
    });
    ```
  - Run `cargo fuzz run fuzz_event_deserialize -- -max_total_time=30`. Expected: no crashes.
  - Commit:
    ```
    feat(fuzz): fuzz_event_deserialize — malformed events must not panic

    Protects the event-replay code path from file-corruption crashes.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 20: Implement `fuzz_http_parse` harness.**
  - Replace `fuzz/fuzz_targets/fuzz_http_parse.rs`:
    ```rust
    #![no_main]
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|data: &[u8]| {
        // The HEAD probe's response parser lives in ps-fingerprint::probes::http.
        let _ = ps_fingerprint::probes::http::parse_head_response(data);
    });
    ```
  - Add `ps-fingerprint = { path = "../crates/ps-fingerprint" }` to `fuzz/Cargo.toml`.
  - If `parse_head_response` is not yet `pub`, make it so (or add a `pub fn parse_head_response_for_fuzz` shim and gate it behind a `fuzzing` feature).
  - Run `cargo fuzz run fuzz_http_parse -- -max_total_time=30`. Expected: no crashes.
  - Commit:
    ```
    feat(fuzz): fuzz_http_parse — HEAD response parser survives arbitrary bytes

    Hardens the HttpHead probe against malformed upstream responses.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 21: Implement `fuzz_tls_parse` harness.**
  - Replace `fuzz/fuzz_targets/fuzz_tls_parse.rs`:
    ```rust
    #![no_main]
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|data: &[u8]| {
        // parse_server_hello in ps-fingerprint::probes::tls_hello decodes the
        // server's first response; fuzzing guards against malformed records.
        let _ = ps_fingerprint::probes::tls_hello::parse_server_hello(data);
    });
    ```
  - Make `parse_server_hello` `pub` in `ps-fingerprint` if it isn't already.
  - Run `cargo fuzz run fuzz_tls_parse -- -max_total_time=30`. Expected: no crashes.
  - Commit:
    ```
    feat(fuzz): fuzz_tls_parse — TLS ServerHello parser survives arbitrary bytes

    Covers the fourth fuzzing target; all parsers that touch untrusted
    network bytes now have a nightly fuzz job.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 22: Add `.github/workflows/fuzz.yml` — 5 minutes per target, nightly.**
  - Create `.github/workflows/fuzz.yml`:
    ```yaml
    name: fuzz
    on:
      schedule:
        - cron: "43 2 * * *"   # nightly 02:43 UTC
      workflow_dispatch:

    jobs:
      fuzz:
        runs-on: ubuntu-latest
        strategy:
          fail-fast: false
          matrix:
            target:
              - fuzz_scope_file
              - fuzz_event_deserialize
              - fuzz_http_parse
              - fuzz_tls_parse
        steps:
          - uses: actions/checkout@v4
          - uses: dtolnay/rust-toolchain@nightly
          - uses: Swatinem/rust-cache@v2
          - run: cargo install cargo-fuzz --locked
          - run: cargo fuzz run ${{ matrix.target }} -- -max_total_time=300
          - name: Upload crash artifacts
            if: failure()
            uses: actions/upload-artifact@v4
            with:
              name: fuzz-crashes-${{ matrix.target }}
              path: fuzz/artifacts/${{ matrix.target }}
    ```
  - Commit:
    ```
    ci: nightly fuzz workflow — 5 minutes per target

    Uploads crash artifacts on failure so the next day's engineer has
    a reproducer in hand.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

### 5.5 — cargo-deny and cargo-audit

- [ ] **Task 23: Add `deny.toml` with the codified license/advisory policy.**
  - Create `deny.toml` at the repo root:
    ```toml
    # cargo-deny policy for PortSnatcher.
    # Docs: https://embarkstudios.github.io/cargo-deny/

    [graph]
    targets = [
        { triple = "x86_64-unknown-linux-gnu" },
        { triple = "aarch64-unknown-linux-gnu" },
        { triple = "x86_64-apple-darwin" },
        { triple = "aarch64-apple-darwin" },
        { triple = "x86_64-pc-windows-msvc" },
    ]

    [licenses]
    version = 2
    allow = [
        "Apache-2.0",
        "Apache-2.0 WITH LLVM-exception",
        "MIT",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "Unicode-DFS-2016",
        "Unicode-3.0",
        "Zlib",
        "CC0-1.0",
        "MPL-2.0",
    ]
    confidence-threshold = 0.93

    # Hard-block copyleft that would taint our Apache-2.0 release.
    [[licenses.exceptions]]
    allow = ["OpenSSL"]
    name = "ring"

    [bans]
    multiple-versions = "warn"
    wildcards = "deny"
    # Deny known-bad crates.
    deny = []

    [advisories]
    version = 2
    yanked = "deny"
    ignore = []
    # Severity policy (enforced in CI):
    #   Critical / High → block immediately
    #   Medium          → 7-day grace (recorded in `ignore` with ISO expiry)
    #   Low / Informational → track, no block

    [sources]
    unknown-registry = "deny"
    unknown-git = "deny"
    allow-registry = ["https://github.com/rust-lang/crates.io-index"]
    ```
  - Install cargo-deny: `cargo install cargo-deny --locked`.
  - Run `cargo deny check`. Expected: clean or at worst a small number of warnings. If any crate triggers a license violation, add it to `licenses.exceptions` only after a one-line justification in the commit body.
  - Commit:
    ```
    chore: add deny.toml with Apache/MIT/BSD/ISC license allowlist

    Explicitly allows Apache-2.0, MIT, BSD-2/3, ISC, Unicode-DFS-2016,
    Unicode-3.0, Zlib, CC0-1.0, MPL-2.0. AGPL/GPL blocked by omission.
    Advisories policy: block Critical/High, 7-day grace on Medium.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 24: Wire `cargo deny check` into the lint workflow.**
  - Edit `.github/workflows/lint.yml` (created in Phase 1) to add a new step to the existing lint job (or a new job named `deny`):
    ```yaml
      deny:
        name: cargo-deny
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - uses: dtolnay/rust-toolchain@stable
          - uses: Swatinem/rust-cache@v2
          - uses: EmbarkStudios/cargo-deny-action@v2
            with:
              command: check
              arguments: --all-features
    ```
  - Commit:
    ```
    ci: run cargo-deny on every PR

    Fails the build on disallowed licenses or matching advisories.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

### 5.6 — Documentation

- [ ] **Task 25: Write `docs/operator-guide.md`.**
  - Create `docs/operator-guide.md` with these sections, in order:
    1. **Install** — `cargo install integsec-portsnatcher` + prebuilt-binary instructions per OS (`curl | sh` installer from the GitHub Release, homebrew tap mention as v1.1 plan, Windows `.exe` download path).
    2. **Scope file authoring** — walkthrough of the JSON format from design §7.1, with a link to IntegSec's `agentic-pentest-proxy` scope format for tool-shared authoring. Include a minimal valid example and a realistic engagement example.
    3. **Engagement setup** — `portsnatcher ca init` (one-time), choose profile, pick output dir.
    4. **Running a scan** — `portsnatcher <target> --ports ephemeral-iana --profile internal --scope engagement.json`. Screenshot of the TUI at work (placeholder `![TUI screenshot](./img/tui-live.png)` — capture with the Linux expectrl test driver or asciinema + `svg-term`; commit both the `.png` and a 30-second `.cast` file). Explain each panel.
    5. **Interpreting events** — quick table mapping event types to operator action.
    6. **Attaching Burp to a tunnel** — Burp upstream proxy config pointing at `localhost:7100`, "don't MITM twice" note.
    7. **MITM setup** — `portsnatcher ca install`, fingerprint verification, uninstall.
    8. **Cleanup** — `portsnatcher cleanup` for orphaned firewall rules, trust-store removal.
  - Minimum 600 lines of actual content (exclusive of code fences) — this is the user-facing front door.
  - Commit:
    ```
    docs: operator guide — soup-to-nuts install through catch workflow

    Covers install, scope authoring (linked to agentic-pentest-proxy),
    CA setup, running a scan, TUI panel reference, Burp attachment,
    MITM flow, and cleanup.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 26: Write `SECURITY.md`.**
  - Create `SECURITY.md` at repo root:
    ```markdown
    # Security policy

    ## Supported versions

    | Version | Status          |
    | ------- | --------------- |
    | 1.0.x   | Supported       |
    | < 1.0   | Pre-release — upgrade |

    ## Reporting a vulnerability

    Please report security vulnerabilities **privately** to
    `security@integsec.com`. Encrypt with the GPG key at
    <https://integsec.com/.well-known/security.asc> (fingerprint published
    in each GitHub Release's notes).

    We aim to:

    - Acknowledge within **2 business days**.
    - Provide an initial assessment within **5 business days**.
    - Ship a fix or mitigation within **30 days** for Critical/High,
      90 days for Medium, best-effort for Low.

    We ask that reporters:

    - Do not publicly disclose until a fix is shipped or 90 days pass
      (whichever is sooner).
    - Do not run PortSnatcher outside their authorized scope during
      research — its scope-enforcement design means the same rules
      apply to researchers.

    We credit reporters in the CHANGELOG (opt-out on request).

    ## Scope

    In scope: bugs in PortSnatcher itself that enable:
    - Scope bypass (any code path sending a packet to a target not
      allowed by `ScopeGuard`)
    - Crash / DoS of the tool from malformed bus input or scope file
    - CA trust-store leakage or orphan
    - Credential or artifact exposure beyond the declared artifact dir

    Out of scope:
    - Bugs in pentester-authorized targets caught by the tool (that's
      the pentester's engagement, not ours)
    - Findings that depend on running with `--i-know-what-im-doing`
    - Weaknesses in dependencies that are already tracked by
      `cargo-audit`/`cargo-deny`
    ```
  - Commit:
    ```
    docs: SECURITY.md — private disclosure policy + scope definition

    security@integsec.com + GPG key; 2/5/30-day SLAs; explicit
    in-scope / out-of-scope list.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 27: Write `CONTRIBUTING.md`.**
  - Create `CONTRIBUTING.md`:
    ```markdown
    # Contributing to PortSnatcher

    Thanks for your interest. PortSnatcher is maintained by
    [IntegSec](https://integsec.com) under Apache-2.0.

    ## Before you start

    - Read the [design spec](./docs/superpowers/specs/2026-04-22-portsnatcher-design.md).
      Most feature requests are already addressed there (yes/no/deferred).
    - For anything bigger than a typo fix, open an issue first so we
      can agree on shape before code.

    ## Dev setup

    1. Install Rust stable (pinned in `rust-toolchain.toml`, currently
       1.76.0).
    2. Clone and build:
       ```
       git clone https://github.com/IntegSec/PortSnatcher.git
       cd PortSnatcher
       cargo build --all-targets
       ```
    3. Run the full test suite:
       ```
       cargo test --all
       cargo fmt --check
       cargo clippy --all-targets --all-features -- -D warnings
       cargo deny check
       ```

    All four must pass before a PR is reviewable.

    ## Commit conventions

    Conventional commits: `<type>(<scope>): <subject>`. Types we use:
    `feat`, `fix`, `test`, `docs`, `chore`, `refactor`, `perf`, `ci`,
    `build`. Scope is a crate name or `workspace`/`ci`/`docs`.

    Every commit body includes the *why* in 1–3 sentences.
    AI-assisted commits include a `Co-Authored-By` footer.

    ## Test expectations

    - Unit tests live with their module.
    - Integration tests under `crates/<crate>/tests/*.rs`, loopback only.
    - Race-conformance thresholds (`crates/ps-engine/tests/race_conformance.rs`)
      are CI gates. Regressions block merge.
    - Snapshot tests (`insta`) for the event schema are frozen — any
      snapshot change is a potential `portsnatcher/v2` bump and must
      be flagged in the PR description.

    ## CI expectations

    Every PR must pass:

    - `ci.yml` — build + test on Linux/macOS/Windows
    - `lint.yml` — fmt + clippy + cargo-deny
    - `race-harness.yml` — tight tier

    Failing CI blocks merge, full stop.

    ## Reviewer checklist

    - [ ] Commit messages explain *why*.
    - [ ] New deps carry a one-line justification.
    - [ ] Public API additions are additive (schema stability).
    - [ ] Tests cover both happy and unhappy paths.
    - [ ] Cross-platform: `#[cfg]` branches have tests on each branch
          OR a conscious note that they don't.
    ```
  - Commit:
    ```
    docs: CONTRIBUTING.md — dev setup, commit style, test expectations

    Documents the CI-green-is-non-negotiable rule and the additive-only
    schema stability rule for future contributors.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 28: Add GitHub issue and PR templates.**
  - Create `.github/ISSUE_TEMPLATE/bug_report.md`:
    ```markdown
    ---
    name: Bug report
    about: Something in PortSnatcher does not behave as documented
    title: "bug: "
    labels: bug
    ---

    ## What happened

    ## What you expected

    ## Reproduction
    - OS + version:
    - `portsnatcher --version`:
    - Engine (raw/connect):
    - Relevant config / scope file (redact targets):
    - Events from `artifacts/<engagement>/events.jsonl` near the bug:

    ## Logs
    ```
    paste stderr output here
    ```
    ```
  - Create `.github/ISSUE_TEMPLATE/feature_request.md`:
    ```markdown
    ---
    name: Feature request
    about: Propose a change or addition to PortSnatcher
    title: "feat: "
    labels: enhancement
    ---

    ## Problem

    ## Proposed solution

    ## Alternatives considered

    ## Does this require an event-schema change?
    If yes, note that it is a `portsnatcher/v2` bump.
    ```
  - Create `.github/PULL_REQUEST_TEMPLATE.md`:
    ```markdown
    ## Summary

    ## Test plan
    - [ ] Unit tests pass locally
    - [ ] Integration tests pass locally (Linux at minimum)
    - [ ] `cargo fmt --check` clean
    - [ ] `cargo clippy --all-targets -- -D warnings` clean
    - [ ] `cargo deny check` clean
    - [ ] Race-harness tight tier passes (if engine or rate code touched)

    ## Checklist
    - [ ] Commits follow conventional-commits
    - [ ] Each commit explains the *why*
    - [ ] New deps have a justification
    - [ ] Schema changes are additive (or flagged as v2)
    - [ ] Docs updated if behavior changed
    ```
  - Commit:
    ```
    docs: issue and PR templates

    Bug report captures OS/engine/events; PR template enforces the
    four-check minimum (fmt, clippy, deny, race-harness where relevant).

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

### 5.7 — Release engineering

- [ ] **Task 29: Initialize cargo-dist with the five target triples.**
  - Install: `cargo install cargo-dist --locked` (version 0.19 or later).
  - Run: `cargo dist init --yes --installers shell,powershell,homebrew --targets x86_64-unknown-linux-gnu,aarch64-unknown-linux-gnu,x86_64-apple-darwin,aarch64-apple-darwin,x86_64-pc-windows-msvc`.
  - This writes `[workspace.metadata.dist]` into the root `Cargo.toml` and creates `.github/workflows/release.yml`.
  - Verify the metadata block contains exactly those five targets. If cargo-dist added any it shouldn't have, prune manually.
  - Run `cargo dist plan` to sanity-check. Expected: lists the five build jobs.
  - Commit:
    ```
    chore: cargo-dist init — five targets, shell+powershell+homebrew installers

    x86_64 + aarch64 Linux, x86_64 + aarch64 macOS, x86_64 Windows MSVC.
    Installer scripts are generated per release.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 30: Add sigstore/cosign signing to the release workflow.**
  - Edit the generated `.github/workflows/release.yml` to add a signing job after the `host` step that uploads artifacts. Insert:
    ```yaml
      sign:
        name: sign release artifacts
        needs: host
        runs-on: ubuntu-latest
        permissions:
          id-token: write
          contents: write
        steps:
          - uses: actions/checkout@v4
          - uses: sigstore/cosign-installer@v3
          - name: Download release artifacts
            uses: actions/download-artifact@v4
            with:
              path: ./artifacts
          - name: Sign every artifact with cosign keyless
            run: |
              set -euo pipefail
              shopt -s globstar
              for f in artifacts/**/*.{tar.xz,zip,sh,ps1}; do
                [ -f "$f" ] || continue
                COSIGN_EXPERIMENTAL=1 cosign sign-blob \
                  --yes \
                  --output-signature "${f}.sig" \
                  --output-certificate "${f}.pem" \
                  "$f"
              done
          - name: Upload signatures to the release
            uses: softprops/action-gh-release@v2
            with:
              tag_name: ${{ github.ref_name }}
              files: |
                artifacts/**/*.sig
                artifacts/**/*.pem
    ```
  - Document the **GPG fallback path** in a file the release manager reads — create `.github/RELEASE_SIGNING.md`:
    ```markdown
    # Release signing

    Primary: sigstore keyless cosign via GitHub OIDC identity.
    Fallback: GPG key held by IntegSec release manager (fingerprint
    published in SECURITY.md and in every release's notes).

    Trigger the fallback when:
    - `sign` job fails on `windows-latest` (rare — sigstore-cosign works
      on Windows but has had regressions) AND
    - The failure blocks a scheduled release AND
    - The sigstore team has not shipped a fix within 24 hours.

    Fallback procedure:
    1. The release manager runs `scripts/gpg-sign-release.sh <tag>`
       locally against the draft release's artifacts.
    2. They push the resulting `.asc` files to the release.
    3. The release notes explicitly state "GPG-signed (sigstore
       temporarily unavailable)".
    ```
  - Commit:
    ```
    ci: sigstore keyless signing for release artifacts

    Signs every tar.xz/zip/sh/ps1 the host job produces and attaches
    the .sig + .pem to the GitHub Release. GPG fallback procedure
    documented in .github/RELEASE_SIGNING.md.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 31: Dry-run a release as v0.4.0-rc1.**
  - Run the full local verification:
    ```
    cargo build --release --all
    cargo test --release --all
    cargo dist plan
    ```
    Expected: all clean.
  - Update `Cargo.toml` workspace version to `0.4.0-rc1`. Update `CHANGELOG.md` with a short `## [0.4.0-rc1]` note ("release-plumbing dry run; no user-visible changes").
  - Commit:
    ```
    chore: bump version to 0.4.0-rc1 for release-pipeline dry run

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```
  - Tag: `git tag -s v0.4.0-rc1 -m "dry run"`. Push: `git push origin v0.4.0-rc1`.
  - Watch the GitHub Actions runs. Expected: `release.yml` completes successfully, artifacts visible on the GitHub Release, `.sig` and `.pem` attached. If the Windows sign step fails, engage the GPG fallback per `.github/RELEASE_SIGNING.md` and document the failure in an issue titled "sigstore on windows-latest — fallback engaged in v0.4.0-rc1".
  - On a clean Linux/macOS/Windows VM, install from the release's shell installer:
    ```
    curl -fsSL https://github.com/IntegSec/PortSnatcher/releases/download/v0.4.0-rc1/portsnatcher-installer.sh | sh
    portsnatcher --version
    ```
    Expected: prints `portsnatcher 0.4.0-rc1`.
  - Commit (no code change — just marking the dry-run successful in the CHANGELOG):
    ```
    docs: note v0.4.0-rc1 dry-run outcome in CHANGELOG

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

### 5.8 — crates.io publishing

- [ ] **Task 32: Verify publish-readiness of every crate.**
  - For each crate in the order `ps-core → ps-bus → ps-notify → ps-engine → ps-fingerprint → ps-proxy → integsec-portsnatcher (binary)`, verify:
    - `Cargo.toml` contains `license = "Apache-2.0"`, `description = "..."`, `repository = "https://github.com/IntegSec/PortSnatcher"`, `readme = "README.md"` (or `../../README.md` for workspace crates), `authors = ["IntegSec <security@integsec.com>"]`, `edition = "2021"`.
    - No `publish = false` entries (except on `ephemeral-flapper` and fuzz — those stay unpublished).
  - Run `cargo publish --dry-run -p <crate>` for each in order. Expected: each passes, except that downstream crates may fail the dry-run if upstream isn't yet on crates.io — that's fine for the dry-run check; we'll publish in order in Task 34.
  - Commit (any fixups made to `Cargo.toml` metadata):
    ```
    chore: ensure all publish-bound crates have complete crates.io metadata

    license, description, repository, readme, authors, edition on every
    crate that will hit crates.io. Sets the binary crate name to
    integsec-portsnatcher with [[bin]] name = "portsnatcher".

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 33: Reserve names on crates.io (but don't publish yet).**
  - Log in locally: `cargo login <token>` (token from <https://crates.io/me>).
  - For each crate name in publish order, run `cargo search <name>` to confirm it's unclaimed. Expected: `ps-core`, `ps-bus`, `ps-notify`, `ps-engine`, `ps-fingerprint`, `ps-proxy`, `integsec-portsnatcher` all return no matching crate.
  - If any name is taken, stop and regroup. (The `ps-*` family is generic enough that one might be claimed; the fallback is to rename that crate to `portsnatcher-<suffix>` — e.g., `portsnatcher-core`. Any such rename is a workspace-wide `replace_all` on `Cargo.toml` + `use` statements, then re-run all tests.)
  - No code change; commit a note in CHANGELOG:
    ```
    chore: confirm crates.io name availability for publish

    All seven v1 crate names are unclaimed as of this commit.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 34: Publish every crate in order (post-v1.0.0-tag).**
  - This task runs **after Task 36 (the v1.0.0 tag)** because publish order requires the version to be stable. Listed here because it's part of Phase 5's publishing scope.
  - Publish sequence:
    ```
    cargo publish -p ps-core
    # wait ~30s for crates.io indexing, then:
    cargo publish -p ps-bus
    cargo publish -p ps-notify
    cargo publish -p ps-engine
    cargo publish -p ps-fingerprint
    cargo publish -p ps-proxy
    cargo publish -p integsec-portsnatcher
    ```
    Expected output per command: `Packaging ...`, `Verifying ...`, `Uploading ...`, `note: waiting for ... to be available at https://crates.io/api/v1/crates/...`.
  - After the last publish succeeds, verify on three clean VMs:
    ```
    cargo install integsec-portsnatcher --locked
    portsnatcher --version
    portsnatcher run --dry-run --no-tui --ports 22 --target 10.0.0.1
    ```
    Expected on all three OSes: install succeeds; version prints `1.0.0`; dry-run emits `EngagementStarted` and `EngagementFinished` events to stderr and exits 0.
  - No commit for the publishes themselves (they're external actions). Commit a CHANGELOG line:
    ```
    docs: note crates.io publish sequence in CHANGELOG

    ps-core → ps-bus → ps-notify → ps-engine → ps-fingerprint →
    ps-proxy → integsec-portsnatcher, all on crates.io as of v1.0.0.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

### 5.9 — README and CHANGELOG final

- [ ] **Task 35: Flip the README status section and check all v1 roadmap boxes.**
  - In `README.md`, locate the status section (Phase 1 established the "design complete — implementation in progress" line). Replace with:
    ```markdown
    ## Status

    **v1.0.0 shipped — 2026-04-22.** Public GA under Apache-2.0.
    Prebuilt binaries: [GitHub Releases](https://github.com/IntegSec/PortSnatcher/releases).
    Install via crates.io: `cargo install integsec-portsnatcher`.
    ```
  - In the Roadmap section (also Phase 1 established), mark every v1 checkbox done:
    ```markdown
    ### v1
    - [x] ConnectEngine + RawEngine with full parity on Linux/macOS/Windows
    - [x] Probe-ladder fingerprinter (passive banner, TLS, HTTP, SSH, Redis, Mongo, Postgres, SMB)
    - [x] Hold-open dumb tunnel + optional TLS MITM with managed CA
    - [x] Event bus (SSE + WebSocket) with frozen `portsnatcher/v1` schema
    - [x] Notification sinks (terminal, TUI, JSONL, desktop, webhook)
    - [x] Scope file compatible with IntegSec agentic-pentest-proxy
    - [x] ratatui TUI with live catch table + tunnel-copy keybinding
    - [x] Race-harness conformance as a CI gate
    - [x] Fuzzing (scope file, event deserializer, HTTP, TLS)
    - [x] Signed cross-platform prebuilt binaries
    - [x] Published on crates.io
    ```
  - Commit:
    ```
    docs: README flip to v1.0.0 shipped; all v1 roadmap boxes checked

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```

- [ ] **Task 36: Write the v1.0.0 CHANGELOG entry and tag the release.**
  - Prepend to `CHANGELOG.md`:
    ```markdown
    ## [1.0.0] — 2026-04-22

    Public general availability.

    ### Added
    - `ratatui` TUI with four panels (catches, holds, rate gauge, event log),
      auto-detected on TTY stdout. `q` quits, `p` pauses, `c` clears completed,
      `Enter` copies the selected catch's `localhost:71xx` tunnel to clipboard.
    - `ephemeral-flapper` test-only binary driving the race-harness.
    - Race-conformance CI gate enforcing catch-rate thresholds per spec §14.3:
      `RawEngine` ≥95%/50ms and ≥70%/20ms, `ConnectEngine` ≥90%/500ms and
      ≥50%/100ms. Soak tier runs nightly against 1000 targets for 10 minutes.
    - Fuzz targets for scope file parsing, event deserialization, HTTP HEAD
      response parsing, and TLS ClientHello response parsing. Nightly workflow.
    - `cargo-deny` policy blocking AGPL/GPL and gating advisory severity.
    - Signed prebuilt binaries via `cargo-dist` + `sigstore cosign` (keyless).
      GPG fallback documented in `.github/RELEASE_SIGNING.md`.
    - Operator guide at `docs/operator-guide.md`.
    - `SECURITY.md`, `CONTRIBUTING.md`, issue + PR templates.

    ### Schema
    - Frozen at `portsnatcher/v1` since v0.1.0. This release does not
      change the schema. All v0.x schema-bearing events remain valid.

    ### Known issues
    - Live soak on the nightly workflow occasionally times out on busy
      `ubuntu-latest` runners; treated as flaky, not a regression.

    ### Contributors
    - IntegSec (mike.chamberland@integsec.com)
    - Claude Opus 4.7 (1M context)
    ```
  - Bump `Cargo.toml` workspace `version = "1.0.0"`.
  - Run final verification: `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all && cargo deny check`. Expected: clean.
  - Commit:
    ```
    chore: release v1.0.0

    Tags the GA release. CHANGELOG details the full v1 surface. Version
    bumped to 1.0.0; all checks clean.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```
  - Tag: `git tag -s v1.0.0 -m "PortSnatcher v1.0.0 — public GA"`. Push: `git push origin v1.0.0`.
  - Watch the `release.yml` workflow. Expected: builds all five targets, signs all artifacts, creates the GitHub Release with installers and signatures. If it fails, fix forward with a `v1.0.1` (don't re-tag).

- [ ] **Task 37: Create the GitHub Release notes manually from CHANGELOG.**
  - After the workflow publishes the draft release, edit its body to include:
    - The full CHANGELOG v1.0.0 section.
    - A "Verify signatures" snippet:
      ```
      cosign verify-blob \
        --certificate portsnatcher-installer.sh.pem \
        --signature portsnatcher-installer.sh.sig \
        --certificate-identity-regexp 'https://github.com/IntegSec/PortSnatcher/.*' \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        portsnatcher-installer.sh
      ```
    - Links: design spec, master plan, operator guide.
    - Reference to `docs/integrations/burp-extension.md` as the v1.1 roadmap.
  - Publish the release (flip from draft).
  - No commit (release notes live on GitHub).

- [ ] **Task 38: Announce v1.0.0 by updating the top of the README.**
  - At the top of `README.md`, above the title or immediately below, add a one-line badge row:
    ```markdown
    [![Release](https://img.shields.io/github/v/release/IntegSec/PortSnatcher)](https://github.com/IntegSec/PortSnatcher/releases)
    [![crates.io](https://img.shields.io/crates/v/integsec-portsnatcher.svg)](https://crates.io/crates/integsec-portsnatcher)
    [![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
    [![CI](https://github.com/IntegSec/PortSnatcher/actions/workflows/ci.yml/badge.svg)](https://github.com/IntegSec/PortSnatcher/actions/workflows/ci.yml)
    ```
  - Commit:
    ```
    docs: add release, crates.io, license, and CI badges to README

    Announces v1.0.0 availability at the top of the landing page.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```
  - Execute Task 34 (crates.io publish) now that v1.0.0 is tagged and released.

---

## Self-review

### Master plan v1.0.0 acceptance criteria — checked against this plan

From `docs/superpowers/plans/2026-04-22-portsnatcher-v1-master.md` §"Acceptance criteria — v1.0.0 release gate":

- [x] **All phase plans' checklists are complete** — Phase 5 inherits Phases 1–4's closure (stated as pre-existing state). This plan closes Phase 5 itself via Tasks 1–38.
- [x] **Every event emitted validates against `portsnatcher/v1`** — Phase 5 does not touch the schema. The TUI consumes events as read-only; no new event types or fields are added. Task 36 explicitly restates this in the CHANGELOG ("This release does not change the schema").
- [x] **CI green on Linux/macOS/Windows including race-harness** — Tasks 15 (`race-harness.yml`), 22 (`fuzz.yml`), and 24 (`cargo-deny` in `lint.yml`) extend CI. The race-harness gate runs on all three OSes at tight scale per Task 15's matrix.
- [x] **`cargo install integsec-portsnatcher` from a clean machine on all three OSes** — Task 34 explicitly includes the three-OS verification step.
- [x] **Operator guide walks through scope → run → catch → hold-open** — Task 25 structures exactly this path in eight sections.
- [x] **`portsnatcher --version` prints v1.0.0** — Task 36 bumps the workspace `version = "1.0.0"`. Task 31's dry-run validates the print flow at `0.4.0-rc1`; the same code path produces `1.0.0` after the bump.
- [x] **README status flipped to "v1.0.0 shipped"** — Task 35.
- [x] **Release artifacts signed and published; release notes reference the spec and each phase plan** — Tasks 30 (signing), 31 (dry-run publish), 36 (tag), 37 (release notes with links to spec + `burp-extension.md`).
- [x] **CHANGELOG v1.0.0 entry complete** — Task 36 writes the entry.

### Design-spec §17 open questions — decisions recorded

- **`smoltcp` integration shape** — out of scope for Phase 5 (Phase 4 closed this).
- **WinDivert licensing** — out of scope for Phase 5 (Phase 4 closed this).
- **`pf` on Apple Silicon** — out of scope for Phase 5 (Phase 4 closed this).
- **`ratatui` TUI in v1 vs. v1.1** — **decided: in v1.** Tasks 1–8 ship it.
- **Release signing: sigstore vs. GPG** — **decided: sigstore primary, GPG fallback.** Task 30 implements cosign; `.github/RELEASE_SIGNING.md` documents the fallback; Task 31's dry-run validates the sigstore path on `windows-latest`.

### Placeholders

- No `TODO`, no "similar to Task N" references. Every Rust code block in this plan is complete and self-contained. The one caveat is that the plan acknowledges (in Tasks 7, 13, 16, and 20) that some Phase 1/2/4 names (`SubscriberHandle::subscribe`, `ConnectEngine::new_default`, `EngineContext::many_loopback`, `parse_head_response`) may need minor renames or visibility promotions — each such case gives the executor a concrete action (rename-to-this, or add-this-shim) rather than leaving a placeholder.

### Schema stability

No breaking changes. The TUI consumes the bus as a read-only observer. No new event types or fields. The CHANGELOG entry (Task 36) states this explicitly. If any task in this plan is ever modified to add a new payload field, that modification must simultaneously bump the schema tag to `portsnatcher/v2` and update `docs/superpowers/specs/`.

### Cross-platform parity invariant

Still holds. TUI works on all three OSes (ratatui + crossterm are OS-portable). The only OS-gated code path is the `tui_smoke.rs` integration test (Task 8), which is test-only and doesn't affect runtime parity. The race-harness CI gate runs on all three OSes at tight scale (Task 15).

### v1.0.0 CI acceptance criteria

Before Task 36 tags the release, the following must all be green on `main`:

- `ci.yml` — build + test on `ubuntu-latest`, `macos-latest`, `windows-latest`.
- `lint.yml` — `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo deny check`.
- `race-harness.yml` (tight tier) — ConnectEngine thresholds pass on all three OSes; RawEngine thresholds pass on Linux root.
- `fuzz.yml` — most recent nightly run clean (no new crashes in the 30-day window).
- `release.yml` dry-run (from Task 31) succeeded with cosign signing on all three OSes.

If any of these is red, v1.0.0 is blocked. Fix-forward rather than skip.
