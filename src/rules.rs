//! Rule catalog (v1 `rules.py`): one entry per emitted check id; prose in `rule_docs/<id>.md`.

use serde::Serialize;

/// A catalogued check. `id` is the stable public address (the `id` of every finding).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Rule {
    pub id: &'static str,
    pub title: &'static str,
    pub severities: &'static [&'static str],
    pub category: &'static str,
}

/// Every check id the code emits. Add a rule AND `rule_docs/<id>.md` with a new check
/// (the catalog-contract test enforces both).
pub const RULES: &[Rule] = &[
    Rule {
        id: "unauthenticated_writes",
        title: "GATT characteristics writable without bonding",
        severities: &["high", "info"],
        category: "gatt",
    },
    Rule {
        id: "mac_rotation",
        title: "Advertising address rotation",
        severities: &["medium", "info"],
        category: "privacy",
    },
    Rule {
        id: "dfu_entry_point",
        title: "DFU control point reachable without bonding",
        severities: &["high", "info"],
        category: "dfu",
    },
    Rule {
        id: "dfu_signing_enforced",
        title: "Firmware signature verification",
        severities: &["high", "medium", "info"],
        category: "dfu",
    },
    Rule {
        id: "dfu_surface_absent",
        title: "No DFU/OTA surface present",
        severities: &["info"],
        category: "dfu",
    },
];

const DOCS: &[(&str, &str)] = &[
    (
        "unauthenticated_writes",
        include_str!("rule_docs/unauthenticated_writes.md"),
    ),
    ("mac_rotation", include_str!("rule_docs/mac_rotation.md")),
    (
        "dfu_entry_point",
        include_str!("rule_docs/dfu_entry_point.md"),
    ),
    (
        "dfu_signing_enforced",
        include_str!("rule_docs/dfu_signing_enforced.md"),
    ),
    (
        "dfu_surface_absent",
        include_str!("rule_docs/dfu_surface_absent.md"),
    ),
];

pub fn rules() -> &'static [Rule] {
    RULES
}

pub fn get(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}

/// The rule's markdown doc, if any.
pub fn rule_text(id: &str) -> Option<&'static str> {
    DOCS.iter().find(|(i, _)| *i == id).map(|(_, t)| *t)
}

/// The "How to fix" section of the rule doc as one line (doctor/1 `remedy`); None without a doc.
pub fn remedy(id: &str) -> Option<String> {
    let body = rule_text(id)?.split("## How to fix").nth(1)?;
    let text = body
        .split("\n## ")
        .next()?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    (!text.is_empty()).then_some(text)
}

/// Closest rule ids to `id` (shared-prefix / edit-distance based), best first.
pub fn near_misses(id: &str) -> Vec<&'static str> {
    let mut v: Vec<(usize, &str)> = RULES
        .iter()
        .map(|r| (edit_distance(id, r.id), r.id))
        .filter(|(d, rid)| *d <= 3.max(rid.len() / 3) || rid.contains(id) || id.contains(rid))
        .collect();
    v.sort();
    v.into_iter().map(|(_, r)| r).take(3).collect()
}

fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            cur.push(
                (prev[j] + usize::from(ca != *cb))
                    .min(prev[j + 1] + 1)
                    .min(cur[j] + 1),
            );
        }
        prev = cur;
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Ids emitted by non-test code: `CheckResult::new("id"` or `let id = "id"`.
    fn emitted_ids() -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for e in std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/src")).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_none_or(|x| x != "rs") || p.ends_with("rules.rs") {
                continue;
            }
            let src = std::fs::read_to_string(&p).unwrap();
            let src = src.split("#[cfg(test)]").next().unwrap();
            for pat in ["CheckResult::new(", "let id = "] {
                for part in src.split(pat).skip(1) {
                    let t = part.trim_start();
                    if let Some(rest) = t.strip_prefix('"') {
                        out.insert(rest.split('"').next().unwrap().to_string());
                    }
                }
            }
        }
        out
    }

    #[test]
    fn catalog_matches_emitted_ids() {
        let cat: BTreeSet<String> = RULES.iter().map(|r| r.id.to_string()).collect();
        assert_eq!(emitted_ids(), cat, "emitted check ids != RULES keys");
    }

    #[test]
    fn every_rule_has_four_headings() {
        for r in RULES {
            let doc = rule_text(r.id).unwrap_or_else(|| panic!("no doc for {}", r.id));
            for h in [
                "## What it means",
                "## Why it matters",
                "## How to fix",
                "## How to verify",
            ] {
                assert!(doc.contains(h), "{} missing {h}", r.id);
            }
        }
    }

    #[test]
    fn remedy_is_how_to_fix_one_line() {
        let r = remedy("mac_rotation").unwrap();
        assert!(r.starts_with("If the advertising address is static") && !r.contains('\n'));
        assert!(remedy("nope").is_none());
    }

    #[test]
    fn near_miss_suggests() {
        assert_eq!(near_misses("mac_rotaton"), ["mac_rotation"]);
        assert!(near_misses("zzzzzzzzzzzzzzzz").is_empty());
    }
}
