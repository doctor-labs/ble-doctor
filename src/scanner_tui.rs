//! Live scan TUI (`scan --tui`, no `--target`): a continuously-updating device list as devices
//! are discovered, instead of one static frame (nRF Connect's main scanner screen, #113). Distinct
//! from `doctor_kit::tui` (the per-device findings explorer `scan --tui --target <addr>` still
//! opens).

use crate::radio::{sort_devices, Central, DiscoveredDevice, SortKey};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, List, ListItem, ListState};
use ratatui::Frame;
use std::sync::mpsc;
use std::time::Duration;

/// Insert or update `d` in `devices` (matched by id), then re-sort strongest-signal-first (nRF
/// Connect's default order). The one piece of this screen's logic that doesn't need a terminal.
pub fn upsert(devices: &mut Vec<DiscoveredDevice>, d: DiscoveredDevice) {
    match devices.iter_mut().find(|x| x.id == d.id) {
        Some(slot) => *slot = d,
        None => devices.push(d),
    }
    sort_devices(devices, SortKey::Rssi);
}

fn label(d: &DiscoveredDevice) -> String {
    let name = d
        .adv_local_name
        .as_deref()
        .or(d.name.as_deref())
        .unwrap_or("(unnamed)");
    let rssi = d.rssi.map_or("?".into(), |r| format!("{r}"));
    let addr = d.address.as_deref().unwrap_or(&d.id);
    format!("{rssi:>5} dBm  {name:<24}  {addr}")
}

fn draw(f: &mut Frame, devices: &[DiscoveredDevice], state: &mut ListState) {
    let items: Vec<ListItem> = devices.iter().map(|d| ListItem::new(label(d))).collect();
    let list = List::new(items)
        .block(Block::bordered().title(format!(
            " ble-doctor scan — {} device(s), q to quit ",
            devices.len()
        )))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(list, f.area(), state);
}

fn is_quit(code: KeyCode) -> bool {
    matches!(code, KeyCode::Char('q') | KeyCode::Esc)
}

/// Run the live scanner for `timeout` (or until `q`/Esc/Ctrl-C). `central.scan_live` runs on its
/// own thread (`std::thread::scope`, so it can borrow `central` without `Clone`/`'static`) while
/// this thread redraws every time a device arrives or every 200ms, whichever is first.
pub fn run<C: Central + Sync>(central: &C, timeout: Duration) -> std::io::Result<()> {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
        return Err(std::io::Error::other(
            "scan --tui needs an interactive terminal; use `scan` (plain) in scripts",
        ));
    }
    let handle = tokio::runtime::Handle::current();
    std::thread::scope(|scope| {
        let (tx, rx) = mpsc::channel::<DiscoveredDevice>();
        scope.spawn(move || {
            let _ = handle.block_on(central.scan_live(timeout, |d| {
                let _ = tx.send(d.clone());
            }));
        });
        let mut term = ratatui::try_init()?;
        let mut devices = Vec::new();
        let mut state = ListState::default();
        let deadline = std::time::Instant::now() + timeout + Duration::from_millis(300);
        let res = (|| -> std::io::Result<()> {
            loop {
                while let Ok(d) = rx.try_recv() {
                    upsert(&mut devices, d);
                }
                term.draw(|f| draw(f, &devices, &mut state))?;
                if event::poll(Duration::from_millis(200))? {
                    if let Event::Key(k) = event::read()? {
                        if k.kind == KeyEventKind::Press
                            && (is_quit(k.code)
                                || (k.code == KeyCode::Char('c')
                                    && k.modifiers.contains(event::KeyModifiers::CONTROL)))
                        {
                            return Ok(());
                        }
                    }
                }
                if std::time::Instant::now() >= deadline {
                    return Ok(());
                }
            }
        })();
        ratatui::restore();
        res
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};

    fn dev(id: &str, name: &str, rssi: i16) -> DiscoveredDevice {
        DiscoveredDevice {
            id: id.into(),
            adv_local_name: Some(name.into()),
            rssi: Some(rssi),
            ..Default::default()
        }
    }

    #[test]
    fn upsert_inserts_updates_and_keeps_strongest_first() {
        let mut devices = vec![];
        upsert(&mut devices, dev("a", "Weak", -90));
        upsert(&mut devices, dev("b", "Strong", -30));
        assert_eq!(
            devices.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(),
            ["b", "a"]
        );
        // Same id seen again (RSSI improved): updates in place, not a duplicate entry.
        upsert(&mut devices, dev("a", "Weak", -10));
        assert_eq!(devices.len(), 2);
        assert_eq!(
            devices.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
    }

    #[test]
    fn draw_renders_every_device_and_the_count() {
        let devices = vec![dev("a", "Thermo", -40), dev("b", "Lock", -70)];
        let backend = TestBackend::new(60, 6);
        let mut term = Terminal::new(backend).unwrap();
        let mut state = ListState::default();
        term.draw(|f| draw(f, &devices, &mut state)).unwrap();
        let rendered: String = term
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(rendered.contains("2 device(s)"), "{rendered}");
        assert!(
            rendered.contains("Thermo") && rendered.contains("Lock"),
            "{rendered}"
        );
        assert!(
            rendered.contains("-40") && rendered.contains("-70"),
            "{rendered}"
        );
    }

    #[test]
    fn quit_keys() {
        assert!(is_quit(KeyCode::Char('q')));
        assert!(is_quit(KeyCode::Esc));
        assert!(!is_quit(KeyCode::Char('x')));
    }
}
