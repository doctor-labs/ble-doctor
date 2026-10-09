//! Recon: native GATT inventory (primary) + optional bluesploit cross-check (external, heuristic, INFO-only).

use crate::gatt::GattInfo;
use serde::Serialize;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const BLUESPLOIT_BIN: &str = "bluesploit";
pub const BLUESPLOIT_LIST_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReconChar {
    pub uuid: String,
    pub properties: Vec<String>,
    pub writable: bool,
    /// notify or indicate
    pub subscribable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReconService {
    pub uuid: String,
    pub characteristics: Vec<ReconChar>,
}

/// Native inventory. Source: `GattInfo`, which only retains writable/subscribable
/// characteristics, so read-only characteristics are not listed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReconInventory {
    pub target: String,
    pub target_name: Option<String>,
    pub services: Vec<ReconService>,
}

/// Human-readable inventory; every device-derived string goes through [`crate::report::sanitize`].
pub fn render(inv: &ReconInventory) -> String {
    use crate::report::sanitize as san;
    let mut out = format!(
        "target: {} ({})\n",
        san(&inv.target),
        san(inv.target_name.as_deref().unwrap_or("-"))
    );
    for s in &inv.services {
        out.push_str(&format!("service {}\n", san(&s.uuid)));
        for c in &s.characteristics {
            out.push_str(&format!(
                "  char {} [{}] writable={} subscribable={}\n",
                san(&c.uuid),
                san(&c.properties.join(",")),
                c.writable,
                c.subscribable
            ));
        }
    }
    out
}

pub fn inventory(gatt: &GattInfo) -> ReconInventory {
    let mut services: Vec<ReconService> = gatt
        .service_uuids
        .iter()
        .map(|u| ReconService {
            uuid: u.clone(),
            characteristics: vec![],
        })
        .collect();
    let mut add = |svc: &str, uuid: &str, props: &[String]| {
        if !services.iter().any(|s| s.uuid == svc) {
            services.push(ReconService {
                uuid: svc.into(),
                characteristics: vec![],
            });
        }
        let s = services.iter_mut().find(|s| s.uuid == svc).unwrap();
        if !s.characteristics.iter().any(|c| c.uuid == uuid) {
            s.characteristics.push(ReconChar {
                uuid: uuid.into(),
                properties: vec![],
                writable: false,
                subscribable: false,
            });
        }
        let c = s
            .characteristics
            .iter_mut()
            .find(|c| c.uuid == uuid)
            .unwrap();
        for p in props {
            if !c.properties.contains(p) {
                c.properties.push(p.clone());
            }
        }
        c.writable = crate::gatt::is_writable(&c.properties);
        c.subscribable = c
            .properties
            .iter()
            .any(|p| matches!(p.to_lowercase().as_str(), "notify" | "indicate"));
    };
    for w in &gatt.writable_chars {
        add(&w.service_uuid, &w.uuid, &w.properties);
    }
    for s in &gatt.subscribe_chars {
        add(&s.service_uuid, &s.uuid, &s.properties);
    }
    ReconInventory {
        target: gatt.target.clone(),
        target_name: gatt.target_name.clone(),
        services,
    }
}

/// Result of the external bluesploit cross-check. Always heuristic, never scored.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BluesploitRecon {
    pub available: bool,
    pub reason: Option<String>,
    pub version: Option<String>,
    pub module_count: Option<usize>,
    pub modules_by_category: Option<std::collections::BTreeMap<String, usize>>,
    pub recon_modules: Option<Vec<String>>,
    pub parse_warning: Option<String>,
    pub elapsed_seconds: Option<f64>,
    pub timeout_seconds: f64,
    /// "heuristic": a best-effort scrape of an unpublished output format.
    pub parser: &'static str,
    pub scored: bool,
    pub external: bool,
}

/// Canonical "could not cross-check" shape (every key present).
pub fn bluesploit_unavailable(reason: impl Into<String>, timeout: Duration) -> BluesploitRecon {
    BluesploitRecon {
        available: false,
        reason: Some(reason.into()),
        version: None,
        module_count: None,
        modules_by_category: None,
        recon_modules: None,
        parse_warning: None,
        elapsed_seconds: None,
        timeout_seconds: timeout.as_secs_f64(),
        parser: "heuristic",
        scored: false,
        external: true,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedList {
    pub version: Option<String>,
    pub module_count: usize,
    pub modules_by_category: Option<std::collections::BTreeMap<String, usize>>,
    pub recon_modules: Vec<String>,
    pub parse_warning: Option<String>,
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\x1b' && it.peek() == Some(&'[') {
            it.next();
            for n in it.by_ref() {
                if n.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// "BlueSploit v<ver> - Available Modules (<n>)"
fn parse_banner(line: &str) -> Option<(String, usize)> {
    let rest = line.split_once("BlueSploit v")?.1;
    let (ver, rest) = rest.split_once(char::is_whitespace)?;
    let rest = rest.trim_start().strip_prefix('-')?.trim_start();
    let rest = rest.strip_prefix("Available")?.trim_start();
    let rest = rest.strip_prefix("Modules")?.trim_start();
    let rest = rest.strip_prefix('(')?.trim_start();
    let n: String = rest.chars().take_while(char::is_ascii_digit).collect();
    Some((ver.into(), n.parse().ok()?))
}

fn is_word(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// "    category: N" (4-space indent, no slash)
fn parse_category(line: &str) -> Option<(String, usize)> {
    let rest = line.strip_prefix("    ")?;
    if rest.starts_with(' ') {
        return None;
    }
    let (cat, n) = rest.split_once(':')?;
    let first = cat.chars().next()?;
    (first.is_ascii_alphabetic() && is_word(cat)).then_some(())?;
    Some((cat.into(), n.trim().parse().ok()?))
}

/// "  category/name[/more]  description" (2-space indent)
fn parse_module(line: &str) -> Option<String> {
    let rest = line.strip_prefix("  ")?;
    let path = rest.split("  ").next()?.trim_end();
    if path.is_empty() || path.contains(char::is_whitespace) {
        return None;
    }
    let mut parts = path.split('/');
    let first = parts.next()?;
    let tail: Vec<&str> = parts.collect();
    (first.starts_with(|c: char| c.is_ascii_lowercase())
        && is_word(first)
        && !tail.is_empty()
        && tail.iter().all(|p| is_word(p)))
    .then(|| path.to_string())
}

/// Heuristic scrape of `bluesploit --list` stdout (port of v1 parse_bluesploit_list_output).
pub fn parse_bluesploit_list_output(output: &str) -> ParsedList {
    let text = strip_ansi(output).replace("\r\n", "\n");
    let banner = text.lines().find_map(parse_banner);
    let (version, declared) = match banner {
        Some((v, n)) => (Some(v), Some(n)),
        None => (None, None),
    };
    let mut cats = std::collections::BTreeMap::new();
    for (c, n) in text.lines().filter_map(parse_category) {
        cats.insert(c, n);
    }
    let modules: Vec<String> = text.lines().filter_map(parse_module).collect();
    let mut warning = None;
    if modules.is_empty() && declared.is_some_and(|n| n > 0) {
        warning = Some(format!(
            "bluesploit --list declared {} modules but no module rows were recognised; the listing format may have changed",
            declared.unwrap()
        ));
    }
    if declared.is_none() && modules.is_empty() {
        warning = Some(
            "output did not look like a bluesploit --list listing (no banner, no module rows)"
                .into(),
        );
    }
    if cats.is_empty() {
        for m in &modules {
            *cats
                .entry(m.split('/').next().unwrap().to_string())
                .or_insert(0) += 1;
        }
    }
    let mut recon_modules: Vec<String> = modules
        .iter()
        .filter(|m| m.starts_with("recon/"))
        .cloned()
        .collect();
    recon_modules.sort();
    ParsedList {
        version,
        module_count: declared.unwrap_or(modules.len()),
        modules_by_category: (!cats.is_empty()).then_some(cats),
        recon_modules,
        parse_warning: warning,
    }
}

/// Run `<bin> --list` with a bounded timeout. Never panics; every failure is `unavailable`.
pub fn bluesploit_recon_with(bin: &str, timeout: Duration) -> BluesploitRecon {
    let started = Instant::now();
    let mut child = match Command::new(bin)
        .arg("--list")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return bluesploit_unavailable(
                format!("bluesploit is not installed ({bin} not on PATH); cross-check skipped"),
                timeout,
            )
        }
        Err(e) => {
            return bluesploit_unavailable(
                format!("bluesploit --list could not be run: {e}"),
                timeout,
            )
        }
    };
    let mut out = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.read_to_end(&mut b);
        String::from_utf8_lossy(&b).into_owned()
    });
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if started.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return bluesploit_unavailable(
                    format!(
                        "bluesploit --list timed out after {}s",
                        timeout.as_secs_f64()
                    ),
                    timeout,
                );
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => {
                return bluesploit_unavailable(format!("bluesploit --list failed: {e}"), timeout)
            }
        }
    };
    let elapsed = Some((started.elapsed().as_secs_f64() * 1000.0).round() / 1000.0);
    if !status.success() {
        let mut r = bluesploit_unavailable(format!("bluesploit --list exited {status}"), timeout);
        r.elapsed_seconds = elapsed;
        return r;
    }
    let p = parse_bluesploit_list_output(&reader.join().unwrap_or_default());
    if let (Some(w), true) = (&p.parse_warning, p.recon_modules.is_empty()) {
        let mut r = bluesploit_unavailable(
            format!("bluesploit --list output not understood: {}", w),
            timeout,
        );
        r.version = p.version;
        r.elapsed_seconds = elapsed;
        return r;
    }
    BluesploitRecon {
        available: true,
        reason: None,
        version: p.version,
        module_count: Some(p.module_count),
        modules_by_category: p.modules_by_category,
        recon_modules: Some(p.recon_modules),
        parse_warning: p.parse_warning,
        elapsed_seconds: elapsed,
        timeout_seconds: timeout.as_secs_f64(),
        parser: "heuristic",
        scored: false,
        external: true,
    }
}

/// Cross-check via the `bluesploit` binary on PATH (external, heuristic, INFO-only, never scored).
pub fn bluesploit_recon() -> BluesploitRecon {
    bluesploit_recon_with(BLUESPLOIT_BIN, BLUESPLOIT_LIST_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gatt::extract_gatt_fields;
    use crate::testkit::{FakeCharacteristic as C, FakeGattTree};

    const SAMPLE: &str = "\x1b[1mBlueSploit v1.0.5.dev10 - Available Modules (4)\x1b[0m\n\n  Categories:\n    recon: 2\n    exploit: 2\n\n  recon/ble_target_enum        Enumerate target\n  recon/ble_scan_full          Full scan\n  exploit/dos/flood            (failed to load)\n  exploit/hid_inject           Inject keys\n";

    #[test]
    fn render_strips_escape_sequences_from_device_strings() {
        let inv = ReconInventory {
            target: "AA:BB\x1b]0;pwn\x07".into(),
            target_name: Some("evil\x1b[2Jname\u{202e}".into()),
            services: vec![ReconService {
                uuid: "180f\x1b".into(),
                characteristics: vec![],
            }],
        };
        let out = render(&inv);
        assert!(!out.contains('\x1b') && !out.contains('\x07') && !out.contains('\u{202e}'));
        assert!(out.contains("evil[2Jname"));
    }

    #[test]
    fn parses_sample_listing() {
        let p = parse_bluesploit_list_output(SAMPLE);
        assert_eq!(p.version.as_deref(), Some("1.0.5.dev10"));
        assert_eq!(p.module_count, 4);
        assert_eq!(
            p.recon_modules,
            vec!["recon/ble_scan_full", "recon/ble_target_enum"]
        );
        assert_eq!(p.modules_by_category.unwrap()["recon"], 2);
        assert!(p.parse_warning.is_none());
        assert!(parse_bluesploit_list_output("hello")
            .parse_warning
            .is_some());
    }

    #[test]
    fn absent_binary_is_canonical_unavailable() {
        let r = bluesploit_recon_with("definitely-not-bluesploit-xyz", Duration::from_secs(1));
        assert!(!r.available && !r.scored && r.external && r.parser == "heuristic");
        assert!(r.reason.is_some());
        let v = serde_json::to_value(&r).unwrap();
        for k in [
            "available",
            "reason",
            "version",
            "module_count",
            "modules_by_category",
            "recon_modules",
            "parse_warning",
            "elapsed_seconds",
            "timeout_seconds",
            "parser",
            "scored",
            "external",
        ] {
            assert!(v.get(k).is_some(), "missing key {k}");
        }
    }

    #[test]
    fn native_inventory_from_fake_gatt() {
        let s = "0000180f-0000-1000-8000-00805f9b34fb";
        let tree = FakeGattTree::new()
            .service(
                s,
                vec![C::new("c1", s, &["write"]), C::notify_with_cccd("c2", s)],
            )
            .service(
                "custom",
                vec![C::new("c3", "custom", &["read", "write", "notify"])],
            );
        let g = extract_gatt_fields(&tree.to_services(), "AA", Some("dev"));
        let inv = inventory(&g);
        assert_eq!(inv.services.len(), 2);
        let ch = &inv.services[0].characteristics;
        assert_eq!(ch.len(), 2);
        assert!(ch[0].writable && !ch[0].subscribable);
        assert!(!ch[1].writable && ch[1].subscribable);
        let c3 = &inv.services[1].characteristics[0];
        assert!(c3.writable && c3.subscribable);
        assert!(serde_json::to_string(&inv).is_ok());
    }
}
