//! Terminal UI: a ratatui view over scored findings.

use crate::checks::{CheckResult, Severity};
use ratatui::{
    crossterm::event::{self, Event, KeyCode},
    layout::{Constraint, Layout},
    style::{Color, Style},
    widgets::{Block, Paragraph, Row, Table},
    Frame,
};

fn color(s: Severity) -> Color {
    match s {
        Severity::Critical | Severity::High => Color::Red,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Cyan,
        Severity::Info => Color::Gray,
    }
}

/// Draw the score header and the findings table.
pub fn render_frame(frame: &mut Frame, score: u8, findings: &[CheckResult]) {
    let [head, body] =
        Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).areas(frame.area());
    frame.render_widget(
        Paragraph::new(format!("Score: {score}/100  (q to quit)"))
            .block(Block::bordered().title("ble-doctor")),
        head,
    );
    let rows = findings.iter().map(|f| {
        Row::new([
            crate::report::sanitize(&f.id),
            f.severity.as_str().to_string(),
            if f.passed { "PASS" } else { "FAIL" }.to_string(),
            crate::report::sanitize(&f.detail),
        ])
        .style(Style::new().fg(color(f.severity)))
    });
    let widths = [
        Constraint::Length(28),
        Constraint::Length(8),
        Constraint::Length(5),
        Constraint::Min(10),
    ];
    frame.render_widget(
        Table::new(rows, widths)
            .header(Row::new(["id", "severity", "ok", "detail"]).style(Style::new().bold()))
            .block(Block::bordered().title("Findings")),
        body,
    );
}

/// Interactive loop: draw until the user presses 'q'.
pub fn run_tui(score: u8, findings: &[CheckResult]) -> std::io::Result<()> {
    let mut term = ratatui::init();
    let res = (|| loop {
        term.draw(|f| render_frame(f, score, findings))?;
        if let Event::Key(k) = event::read()? {
            if k.code == KeyCode::Char('q') {
                return Ok(());
            }
        }
    })();
    ratatui::restore();
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};

    #[test]
    fn renders_score_and_findings() {
        let fs = [
            CheckResult::new("dfu-entry-point", Severity::High, false, "DFU exposed"),
            CheckResult::new("mac-rotation", Severity::Info, true, "rotates"),
        ];
        let mut t = Terminal::new(TestBackend::new(90, 12)).unwrap();
        t.draw(|f| render_frame(f, 73, &fs)).unwrap();
        let text: String = t
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        for s in [
            "73/100",
            "dfu-entry-point",
            "high",
            "FAIL",
            "mac-rotation",
            "info",
            "PASS",
        ] {
            assert!(text.contains(s), "missing {s}");
        }
    }
}
