//! Async runtime that drives the TUI.
//!
//! Runs an event loop that `tokio::select!`s between:
//! - incoming [`ps_core::event::Event`]s from the broadcast bus
//! - crossterm key presses (polled on a 100ms tick)
//! - the caller-supplied [`CancellationToken`] for orderly shutdown
//!
//! Keybindings:
//! - `q` — request shutdown (triggers `CancellationToken`)
//! - `p` — pause/resume auto-scroll of the event log
//! - `c` — clear completed catches from the table
//! - `Enter` — copy `localhost:<tunnel_port>` of the selected catch
//!   to the system clipboard via [`arboard`]
//! - `Up`/`Down` — move the selection cursor in the catches table
//!
//! Terminal state (raw mode, alternate screen) is always restored on
//! exit, including panics — see [`setup_panic_hook`].

use std::io::{self, Stdout};
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{Event as CtEvent, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ps_bus::broadcast::BusSender;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio_util::sync::CancellationToken;

use crate::tui::app::TuiApp;
use crate::tui::widgets;

/// How often we poll for terminal input. 100ms keeps the UI feeling
/// responsive without burning CPU on idle.
const TICK: Duration = Duration::from_millis(100);

/// Install a panic hook that restores the terminal before unwinding.
///
/// Without this, a panic inside `run` leaves the user's shell in raw
/// mode with no cursor and an alternate-screen buffer still active.
/// Safe to call multiple times; the hook chains to the previous one.
pub fn setup_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = restore_raw_terminal();
        prev(info);
    }));
}

fn restore_raw_terminal() -> io::Result<()> {
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}

/// Run the TUI until `q` is pressed or `shutdown` fires.
///
/// The returned future completes once the terminal has been restored
/// to its pre-TUI state. Any error from the inner loop is propagated
/// after cleanup.
pub async fn run(bus: BusSender, shutdown: CancellationToken) -> Result<()> {
    setup_panic_hook();
    let mut terminal = setup_terminal().context("tui: failed to initialise terminal")?;
    let result = run_loop(&mut terminal, bus, shutdown.clone()).await;
    let _ = restore_terminal(&mut terminal);
    shutdown.cancel();
    result
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Ok(Terminal::new(backend)?)
}

fn restore_terminal(t: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(t.backend_mut(), LeaveAlternateScreen)?;
    t.show_cursor().ok();
    Ok(())
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    bus: BusSender,
    shutdown: CancellationToken,
) -> Result<()> {
    let mut app = TuiApp::new();
    let mut rx = bus.subscribe();
    let mut tick = tokio::time::interval(TICK);

    loop {
        terminal.draw(|f| widgets::draw(f, &app))?;

        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return Ok(()),
            maybe_ev = rx.recv() => {
                match maybe_ev {
                    Ok(ev) => app.apply(&ev),
                    Err(_) => {
                        // `Closed` or `Lagged` — keep running; lagged
                        // subscribers recover by themselves.
                    }
                }
            }
            _ = tick.tick() => {
                pump_keys(&mut app)?;
                if app.quit {
                    return Ok(());
                }
            }
        }
    }
}

fn pump_keys(app: &mut TuiApp) -> Result<()> {
    while crossterm::event::poll(Duration::from_millis(0))? {
        let ev = crossterm::event::read()?;
        if let CtEvent::Key(k) = ev {
            if k.kind != KeyEventKind::Press {
                continue;
            }
            match k.code {
                KeyCode::Char('q') | KeyCode::Char('Q') => {
                    app.request_quit();
                    return Ok(());
                }
                KeyCode::Char('p') | KeyCode::Char('P') => app.toggle_pause(),
                KeyCode::Char('c') | KeyCode::Char('C') => app.clear_completed(),
                KeyCode::Up => app.select_prev(),
                KeyCode::Down => app.select_next(),
                KeyCode::Enter => copy_selected_tunnel(app),
                _ => {}
            }
        }
    }
    Ok(())
}

/// Copy the selected row's `localhost:<tunnel_port>` address to the
/// system clipboard. No-op if there is no selection or no hold-open.
fn copy_selected_tunnel(app: &TuiApp) {
    let Some(row) = app.selected_row() else {
        return;
    };
    let Some(tp) = row.tunnel_port else { return };
    let text = format!("localhost:{tp}");
    if let Ok(mut cb) = arboard::Clipboard::new() {
        let _ = cb.set_text(text);
    }
}
