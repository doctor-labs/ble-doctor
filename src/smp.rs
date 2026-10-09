//! SMP (Security Manager Protocol, Core Spec Vol 3 Part H) pairing analysis of a capture.
//! `capture.rs` hands over the reassembled CID 0x0006 PDUs; this decodes them into `data.smp`
//! and turns the pairing parameters into checks.

use crate::capture::{classify_pairing_method, PairingSide};
use crate::checks::{CheckResult, Severity};
use serde_json::{json, Value};

const IO_CAPS: [&str; 5] = [
    "DisplayOnly",
    "DisplayYesNo",
    "KeyboardOnly",
    "NoInputNoOutput",
    "KeyboardDisplay",
];

const FAIL_REASONS: [&str; 15] = [
    "Passkey Entry Failed",
    "OOB Not Available",
    "Authentication Requirements",
    "Confirm Value Failed",
    "Pairing Not Supported",
    "Encryption Key Size",
    "Command Not Supported",
    "Unspecified Reason",
    "Repeated Attempts",
    "Invalid Parameters",
    "DHKey Check Failed",
    "Numeric Comparison Failed",
    "BR/EDR Pairing In Progress",
    "Cross-transport Key Derivation Not Allowed",
    "Key Rejected",
];

fn pdu_name(code: u8) -> &'static str {
    match code {
        1 => "pairing_request",
        2 => "pairing_response",
        3 => "pairing_confirm",
        4 => "pairing_random",
        5 => "pairing_failed",
        6 => "encryption_information",
        7 => "central_identification",
        8 => "identity_information",
        9 => "identity_address_information",
        0x0A => "signing_information",
        0x0B => "security_request",
        0x0C => "pairing_public_key",
        0x0D => "pairing_dhkey_check",
        0x0E => "pairing_keypress_notification",
        _ => "unknown",
    }
}

/// One side's Pairing Request/Response parameters.
struct Params {
    io: u8,
    oob: bool,
    auth: u8,
    max_key: u8,
}

impl Params {
    fn parse(pdu: &[u8]) -> Option<Self> {
        let [_, io, oob, auth, max_key, _, _] = pdu[..7.min(pdu.len())] else {
            return None;
        };
        Some(Params {
            io,
            oob: oob == 1,
            auth,
            max_key,
        })
    }
    fn mitm(&self) -> bool {
        self.auth & 4 != 0
    }
    fn sc(&self) -> bool {
        self.auth & 8 != 0
    }
    fn side(&self) -> PairingSide {
        PairingSide {
            io: self.io,
            oob: self.oob,
            mitm: self.mitm(),
            sc: self.sc(),
        }
    }
}

fn describe(pdu: &[u8]) -> Value {
    let code = pdu.first().copied().unwrap_or(0);
    let mut v = json!({"code": code, "name": pdu_name(code), "length": pdu.len()});
    match (code, Params::parse(pdu)) {
        (1 | 2, Some(p)) => {
            v["io_capability"] = json!(IO_CAPS.get(p.io as usize).copied().unwrap_or("unknown"));
            v["oob"] = json!(p.oob);
            v["bonding"] = json!(p.auth & 3 == 1);
            v["mitm"] = json!(p.mitm());
            v["secure_connections"] = json!(p.sc());
            v["keypress"] = json!(p.auth & 0x10 != 0);
            v["ct2"] = json!(p.auth & 0x20 != 0);
            v["max_key_size"] = json!(p.max_key);
            let keys = |b: u8| {
                ["enc_key", "id_key", "sign", "link_key"]
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| b >> i & 1 == 1)
                    .map(|(_, n)| *n)
                    .collect::<Vec<_>>()
            };
            v["initiator_key_dist"] = json!(keys(pdu[5]));
            v["responder_key_dist"] = json!(keys(pdu[6]));
        }
        (5, _) => {
            if let Some(&r) = pdu.get(1) {
                v["reason_code"] = json!(r);
                v["reason"] = json!(r
                    .checked_sub(1)
                    .and_then(|i| FAIL_REASONS.get(i as usize))
                    .copied()
                    .unwrap_or("unknown"));
            }
        }
        _ => {}
    }
    v
}

/// Decoded SMP exchange (`data.smp`), the checks it yields, and a human summary.
pub struct SmpReport {
    pub data: Value,
    pub checks: Vec<CheckResult>,
    pub summary: Vec<String>,
}

/// Analyze the SMP PDUs of a capture. No SMP -> `{"seen": false}` and no checks.
pub fn analyze(pdus: &[Vec<u8>]) -> SmpReport {
    let mut r = SmpReport {
        data: json!({"seen": false}),
        checks: vec![],
        summary: vec![],
    };
    if pdus.is_empty() {
        return r;
    }
    let req = pdus.iter().position(|p| p.first() == Some(&1));
    let rsp = req.and_then(|i| pdus[i + 1..].iter().find(|p| p.first() == Some(&2)));
    let mut data = json!({
        "seen": true,
        "pdus": pdus.iter().map(|p| describe(p)).collect::<Vec<_>>(),
    });
    r.summary.push(format!("smp: {} PDUs", pdus.len()));
    if let (Some(Some(a)), Some(b)) = (
        req.map(|i| Params::parse(&pdus[i])),
        rsp.and_then(|p| Params::parse(p)),
    ) {
        let method = classify_pairing_method(a.side(), b.side());
        let sc = a.sc() && b.sc();
        let key = a.max_key.min(b.max_key);
        data["pairing"] = json!({"method": method, "secure_connections": sc, "max_key_size": key});
        r.summary.push(format!(
            "smp: pairing method {method}, {}, max key size {key}",
            if sc {
                "LE Secure Connections"
            } else {
                "legacy pairing"
            }
        ));
        let jw = method == "just_works";
        let ksev = if key <= 7 {
            Severity::High
        } else {
            Severity::Medium
        };
        let msg = |fail: bool, bad: String, ok: &str| if fail { bad } else { ok.into() };
        r.checks.extend([
            CheckResult::new(
                "smp_legacy_pairing",
                Severity::High,
                sc,
                msg(!sc, "SMP legacy pairing: LE Secure Connections not set by both sides; the key exchange is passively crackable.".into(), "LE Secure Connections pairing."),
            ),
            CheckResult::new(
                "smp_just_works",
                Severity::Medium,
                !jw,
                msg(jw, "SMP Just Works association: unauthenticated, no MITM protection.".into(), "Pairing is authenticated (not Just Works)."),
            ),
            CheckResult::new(
                "smp_key_size",
                ksev,
                key >= 16,
                msg(key < 16, format!("SMP maximum encryption key size is {key} bytes (<16); brute-forceable, KNOB-style downgrade."), "Encryption key size is 16 bytes."),
            ),
        ]);
    }
    if let Some(f) = pdus.iter().find(|p| p.first() == Some(&5)) {
        let d = describe(f);
        let reason = d["reason"].as_str().unwrap_or("unknown");
        r.summary.push(format!("smp: pairing failed ({reason})"));
        r.checks.push(CheckResult::new(
            "smp_pairing_failed",
            Severity::Info,
            false,
            format!("SMP Pairing Failed: {reason} (code {}).", d["reason_code"]),
        ));
    }
    r.data = data;
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    /// code, io, oob, authreq, max key, init dist, resp dist
    fn pair(code: u8, io: u8, auth: u8, key: u8) -> Vec<u8> {
        vec![code, io, 0, auth, key, 3, 3]
    }
    fn ids(r: &SmpReport) -> Vec<(&str, bool)> {
        r.checks.iter().map(|c| (c.id.as_str(), c.passed)).collect()
    }

    #[test]
    fn sc_numeric_comparison_is_clean() {
        let a = 0x0D; // bonding + MITM + SC
        let r = analyze(&[pair(1, 1, a, 16), pair(2, 1, a, 16)]);
        assert_eq!(r.data["pairing"]["method"], "numeric_comparison");
        assert!(r.checks.iter().all(|c| c.passed), "{:?}", ids(&r));
        assert_eq!(r.data["pdus"][0]["io_capability"], "DisplayYesNo");
    }

    #[test]
    fn legacy_just_works_and_short_key() {
        let r = analyze(&[pair(1, 3, 1, 7), pair(2, 3, 1, 16)]);
        let failed: Vec<_> = r
            .checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| (c.id.as_str(), c.severity))
            .collect();
        assert_eq!(
            failed,
            [
                ("smp_legacy_pairing", Severity::High),
                ("smp_just_works", Severity::Medium),
                ("smp_key_size", Severity::High)
            ]
        );
        assert_eq!(r.data["pairing"]["max_key_size"], 7);
    }

    #[test]
    fn pairing_failed_and_no_smp() {
        let r = analyze(&[vec![5, 4]]);
        assert_eq!(ids(&r), [("smp_pairing_failed", false)]);
        assert!(r.checks[0].detail.contains("Confirm Value Failed"));
        let none = analyze(&[]);
        assert!(none.checks.is_empty());
        assert_eq!(none.data["seen"], false);
    }
}
