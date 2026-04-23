//! ratatui widgets for the four-panel TUI layout.
//!
//! ```text
//! +-------------------------+----------------------+
//! |  Catches table (60%)    |  Holds list (40%)    |
//! +-------------------------+----------------------+
//! |  Rate gauge (30%)       |  Event log (70%)     |
//! +-------------------------+----------------------+
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

use crate::tui::app::{CatchStatus, TuiApp};

/// Render the entire TUI for one frame.
pub fn draw(f: &mut Frame<'_>, app: &TuiApp) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(f.area());

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
