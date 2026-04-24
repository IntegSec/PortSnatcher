//! ratatui widgets for the live TUI.
//!
//! ```text
//! +-----------------------------------------------+
//! |  Port Status (50%)                            |
//! +-------------------------+---------------------+
//! |  Catches table (60%)    |  Holds list (40%)   |
//! +-------------------------+---------------------+
//! |  Rate gauge (30%)       |  Event log (70%)    |
//! +-------------------------+---------------------+
//! ```
//!
//! Every widget reads directly from [`crate::tui::app::TuiApp`] —
//! there is no widget-local mutable state. Widgets are re-rendered
//! every frame and every tick.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Gauge, List, ListItem, Paragraph, Row, Table, TableState,
};
use ratatui::Frame;

use crate::tui::app::{CatchStatus, PortLiveState, TuiApp};

/// Render the entire TUI for one frame.
pub fn draw(f: &mut Frame<'_>, app: &TuiApp) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(30),
            Constraint::Percentage(20),
        ])
        .split(f.area());

    let middle = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(outer[1]);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(outer[2]);

    draw_port_status(f, outer[0], app);
    draw_catches(f, middle[0], app);
    draw_holds(f, middle[1], app);
    draw_rate(f, bottom[0], app);
    draw_log(f, bottom[1], app);
}

/// Live port status aggregated per `(target, port)`. Always-open
/// services show as a single row aging in place; flappers flip between
/// OPEN and CLOSED with a visible flip counter.
fn draw_port_status(f: &mut Frame<'_>, area: Rect, app: &TuiApp) {
    let header = Row::new(vec![
        Cell::from("Target:Port"),
        Cell::from("Status"),
        Cell::from("Since"),
        Cell::from("Flips"),
        Cell::from("Protocol"),
        Cell::from("Conf"),
        Cell::from("Tunnel"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let rows_data = app.port_status_sorted();
    let rows: Vec<Row> = rows_data
        .iter()
        .map(|s| {
            let (label, colour) = match s.state {
                PortLiveState::Open => ("OPEN", Color::Green),
                PortLiveState::Flapping => ("FLAPPING", Color::Yellow),
                PortLiveState::Closed => ("CLOSED", Color::Red),
            };
            let since = format_since(s.since.elapsed());
            Row::new(vec![
                Cell::from(format!("{}:{}", s.target, s.port)),
                Cell::from(Line::from(Span::styled(
                    label,
                    Style::default().fg(colour).add_modifier(Modifier::BOLD),
                ))),
                Cell::from(since),
                Cell::from(s.flips.to_string()),
                Cell::from(s.protocol.clone().unwrap_or_else(|| "-".into())),
                Cell::from(
                    s.confidence
                        .map(|c| format!("{c:.2}"))
                        .unwrap_or_else(|| "-".into()),
                ),
                Cell::from(
                    s.tunnel_port
                        .map(|p| format!("localhost:{p}"))
                        .unwrap_or_else(|| "-".into()),
                ),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(28),
        Constraint::Length(10),
        Constraint::Length(9),
        Constraint::Length(6),
        Constraint::Length(12),
        Constraint::Length(6),
        Constraint::Length(18),
    ];
    let open_count = rows_data
        .iter()
        .filter(|s| s.state == PortLiveState::Open)
        .count();
    let flap_count = rows_data
        .iter()
        .filter(|s| s.state == PortLiveState::Flapping)
        .count();
    let closed_count = rows_data
        .iter()
        .filter(|s| s.state == PortLiveState::Closed)
        .count();
    let title = format!(
        "Port Status  open={} flapping={} closed={}  total={}",
        open_count,
        flap_count,
        closed_count,
        rows_data.len()
    );
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(table, area);
}

/// Short human duration `"4m20s"`, `"12s"`, `"1h07m"`.
fn format_since(d: std::time::Duration) -> String {
    let total = d.as_secs();
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    if h > 0 {
        format!("{h}h{m:02}m")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}

fn draw_catches(f: &mut Frame<'_>, area: Rect, app: &TuiApp) {
    let header = Row::new(vec![
        Cell::from("Target:Port"),
        Cell::from("Engine"),
        Cell::from("Proto"),
        Cell::from("Conf"),
        Cell::from("Tunnel"),
        Cell::from("Status"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = app
        .catches
        .iter()
        .map(|r| {
            let status_span = match r.status {
                CatchStatus::Detecting => {
                    Span::styled("detecting", Style::default().fg(Color::Yellow))
                }
                CatchStatus::Holding => Span::styled("holding", Style::default().fg(Color::Green)),
                CatchStatus::Complete => Span::styled("done", Style::default().fg(Color::DarkGray)),
            };
            Row::new(vec![
                Cell::from(format!("{}:{}", r.target, r.port)),
                Cell::from(r.engine.clone()),
                Cell::from(r.protocol.clone().unwrap_or_else(|| "?".into())),
                Cell::from(
                    r.confidence
                        .map(|c| format!("{c:.2}"))
                        .unwrap_or_else(|| "-".into()),
                ),
                Cell::from(
                    r.tunnel_port
                        .map(|p| format!("localhost:{p}"))
                        .unwrap_or_else(|| "-".into()),
                ),
                Cell::from(Line::from(status_span)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(30),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Length(18),
        Constraint::Length(10),
    ];
    let title = format!("Catches ({})", app.catches.len());
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    let mut state = TableState::default();
    if !app.catches.is_empty() {
        state.select(Some(app.selected.min(app.catches.len() - 1)));
    }
    f.render_stateful_widget(table, area, &mut state);
}

fn draw_holds(f: &mut Frame<'_>, area: Rect, app: &TuiApp) {
    let items: Vec<ListItem> = app
        .holds
        .iter()
        .map(|h| {
            ListItem::new(format!(
                "localhost:{} -> {} mode={}",
                h.local_port, h.upstream, h.mode
            ))
        })
        .collect();
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Holds ({})", app.holds.len())),
    );
    f.render_widget(list, area);
}

fn draw_rate(f: &mut Frame<'_>, area: Rect, app: &TuiApp) {
    let title = format!(
        "Rate  {}/{} pps  audit={}",
        app.current_pps, app.cap_pps, app.audit_count
    );
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(title))
        .gauge_style(Style::default().fg(Color::Cyan))
        .ratio(app.rate_gauge.clamp(0.0, 1.0));
    f.render_widget(gauge, area);
}

fn draw_log(f: &mut Frame<'_>, area: Rect, app: &TuiApp) {
    let visible = area.height.saturating_sub(2) as usize;
    let lines: Vec<Line> = app
        .event_log
        .iter()
        .rev()
        .take(visible)
        .map(|line| {
            let color = classify_color(line);
            Line::from(Span::styled(line.clone(), Style::default().fg(color)))
        })
        .collect();
    let title = if app.paused {
        "Events (paused)"
    } else {
        "Events"
    };
    let para = Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(para, area);
}

/// Pick a color for an event log line based on its prefix. Keeps the
/// log scannable at a glance: green for opens, red for audit fails,
/// yellow for throttling.
fn classify_color(line: &str) -> Color {
    if line.starts_with("open ") {
        Color::Green
    } else if line.starts_with("hold ready") {
        Color::Cyan
    } else if line.starts_with("hold closed") {
        Color::DarkGray
    } else if line.starts_with("scope blocked") {
        Color::Red
    } else if line.starts_with("rate cap") {
        Color::Yellow
    } else if line.starts_with("catch complete") {
        Color::Blue
    } else if line.starts_with("fingerprint") {
        Color::Magenta
    } else {
        Color::White
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_open() {
        assert_eq!(
            classify_color("open 10.0.0.5:8080 in 42ms via connect"),
            Color::Green
        );
    }

    #[test]
    fn classify_scope_blocked() {
        assert_eq!(classify_color("scope blocked 8.8.8.8:53 (out)"), Color::Red);
    }

    #[test]
    fn classify_unknown_falls_through_to_white() {
        assert_eq!(classify_color("something unexpected"), Color::White);
    }
}
