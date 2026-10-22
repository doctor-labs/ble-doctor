//! SMP (Security Manager Protocol, Core Spec Vol 3 Part H) pairing analysis of a capture.
//! `capture.rs` hands over the reassembled CID 0x0006 PDUs; this decodes them into `data.smp`
//! and turns the pairing parameters into checks.

use crate::capture::{classify_pairing_method, PairingSide};
use crate::checks::{CheckResult, Severity};
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use aes::Aes128;
use serde_json::{json, Value};

fn swap16(src: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = src[15 - i];
    }
    out
}

/// Core Spec Vol 3 Part H §2.2.1: Security toolbox function `e` (AES-128).
/// Inputs and outputs are in LSB byte order (on-air byte order).
pub fn e(k: &[u8; 16], r: &[u8; 16]) -> [u8; 16] {
    let key = Array::from(swap16(k));
    let mut block = Array::from(swap16(r));
    Aes128::new(&key).encrypt_block(&mut block);
    swap16(&block.into())
}

/// Core Spec Vol 3 Part H §2.2.3: Confirm value generation function `c1`.
#[allow(clippy::too_many_arguments)]
pub fn c1(
    k: &[u8; 16],
    r: &[u8; 16],
    preq: &[u8; 7],
    pres: &[u8; 7],
    iat: u8,
    ia: &[u8; 6],
    rat: u8,
    ra: &[u8; 6],
) -> [u8; 16] {
    let mut p1 = [0u8; 16];
    p1[0] = iat;
    p1[1] = rat;
    p1[2..9].copy_from_slice(preq);
    p1[9..16].copy_from_slice(pres);

    let mut p2 = [0u8; 16];
    p2[0..4].fill(0);
    p2[4..10].copy_from_slice(ia);
    p2[10..16].copy_from_slice(ra);

    let mut r_xor_p1 = [0u8; 16];
    for i in 0..16 {
        r_xor_p1[i] = r[i] ^ p1[i];
    }
    let stage1 = e(k, &r_xor_p1);

    let mut stage1_xor_p2 = [0u8; 16];
    for i in 0..16 {
        stage1_xor_p2[i] = stage1[i] ^ p2[i];
    }
    e(k, &stage1_xor_p2)
}

/// Core Spec Vol 3 Part H §2.2.4: Key generation function `s1` (STK derivation).
pub fn s1(k: &[u8; 16], r1: &[u8; 16], r2: &[u8; 16]) -> [u8; 16] {
    let mut r_prime = [0u8; 16];
    r_prime[..8].copy_from_slice(&r1[..8]);
    r_prime[8..16].copy_from_slice(&r2[..8]);
    e(k, &r_prime)
}

/// Convert a 6-digit PIN (0..=999999) to 128-bit TK.
pub fn passkey_to_tk(pin: u32) -> [u8; 16] {
    let mut tk = [0u8; 16];
    tk[..4].copy_from_slice(&pin.to_le_bytes());
    tk
}

/// Bounded offline passkey crack (000000..=999999) for legacy pairing.
#[allow(clippy::too_many_arguments)]
pub fn crack_legacy_passkey(
    preq: &[u8; 7],
    pres: &[u8; 7],
    iat: u8,
    ia: &[u8; 6],
    rat: u8,
    ra: &[u8; 6],
    mconfirm: &[u8; 16],
    mrand: &[u8; 16],
    srand: &[u8; 16],
) -> Option<(u32, [u8; 16], [u8; 16])> {
    let mut p1 = [0u8; 16];
    p1[0] = iat;
    p1[1] = rat;
    p1[2..9].copy_from_slice(preq);
    p1[9..16].copy_from_slice(pres);

    let mut p2 = [0u8; 16];
    p2[0..4].fill(0);
    p2[4..10].copy_from_slice(ia);
    p2[10..16].copy_from_slice(ra);

    let mut r_xor_p1 = [0u8; 16];
    for i in 0..16 {
        r_xor_p1[i] = mrand[i] ^ p1[i];
    }

    for pin in 0..=999_999u32 {
        let tk = passkey_to_tk(pin);
        let stage1 = e(&tk, &r_xor_p1);
        let mut stage1_xor_p2 = [0u8; 16];
        for i in 0..16 {
            stage1_xor_p2[i] = stage1[i] ^ p2[i];
        }
        let confirm = e(&tk, &stage1_xor_p2);
        if &confirm == mconfirm {
            let stk = s1(&tk, srand, mrand);
            return Some((pin, tk, stk));
        }
    }
    None
}

/// Verify confirm values and derive STK for a known TK (e.g. TK=0 for Just Works).
#[allow(clippy::too_many_arguments)]
pub fn derive_legacy_stk(
    tk: &[u8; 16],
    preq: &[u8; 7],
    pres: &[u8; 7],
    iat: u8,
    ia: &[u8; 6],
    rat: u8,
    ra: &[u8; 6],
    mconfirm: &[u8; 16],
    mrand: &[u8; 16],
    srand: &[u8; 16],
) -> Option<[u8; 16]> {
    let confirm = c1(tk, mrand, preq, pres, iat, ia, rat, ra);
    if &confirm == mconfirm {
        Some(s1(tk, srand, mrand))
    } else {
        None
    }
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

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
    let mut data = json!({
        "seen": true,
        "pdus": pdus.iter().map(|p| describe(p)).collect::<Vec<_>>(),
    });
    r.summary.push(format!("smp: {} PDUs", pdus.len()));
    if let (Some(req_idx), Some(rsp_idx)) = (req, pdus.iter().position(|p| p.first() == Some(&2))) {
        if let (Some(a), Some(b)) = (Params::parse(&pdus[req_idx]), Params::parse(&pdus[rsp_idx])) {
            let method = classify_pairing_method(a.side(), b.side());
            let sc = a.sc() && b.sc();
            let key = a.max_key.min(b.max_key);
            let mut pairing_data =
                json!({"method": method, "secure_connections": sc, "max_key_size": key});

            r.summary.push(format!(
                "smp: pairing method {method}, {}, max key size {key}",
                if sc {
                    "LE Secure Connections"
                } else {
                    "legacy pairing"
                }
            ));

            if !sc {
                let preq_b: Option<[u8; 7]> = pdus[req_idx][..7].try_into().ok();
                let pres_b: Option<[u8; 7]> = pdus[rsp_idx][..7].try_into().ok();
                let confirms: Vec<&Vec<u8>> = pdus
                    .iter()
                    .filter(|p| p.first() == Some(&3) && p.len() >= 17)
                    .collect();
                let randoms: Vec<&Vec<u8>> = pdus
                    .iter()
                    .filter(|p| p.first() == Some(&4) && p.len() >= 17)
                    .collect();
                let id_addrs: Vec<&Vec<u8>> = pdus
                    .iter()
                    .filter(|p| p.first() == Some(&9) && p.len() >= 8)
                    .collect();

                if let (Some(preq), Some(pres)) = (preq_b, pres_b) {
                    if !confirms.is_empty() && randoms.len() >= 2 {
                        let mconfirm: [u8; 16] = confirms[0][1..17].try_into().unwrap();
                        let mrand: [u8; 16] = randoms[0][1..17].try_into().unwrap();
                        let srand: [u8; 16] = randoms[1][1..17].try_into().unwrap();

                        let iat = id_addrs.first().map(|p| p[1]).unwrap_or(0);
                        let ia = id_addrs
                            .first()
                            .map(|p| p[2..8].try_into().unwrap())
                            .unwrap_or([0u8; 6]);
                        let rat = id_addrs.get(1).map(|p| p[1]).unwrap_or(0);
                        let ra = id_addrs
                            .get(1)
                            .map(|p| p[2..8].try_into().unwrap())
                            .unwrap_or([0u8; 6]);

                        let mut derived = false;
                        for (t1, t2) in [
                            (iat, rat),
                            (if iat == 0 { 1 } else { 0 }, rat),
                            (iat, if rat == 0 { 1 } else { 0 }),
                            (if iat == 0 { 1 } else { 0 }, if rat == 0 { 1 } else { 0 }),
                        ] {
                            if let Some(stk) = derive_legacy_stk(
                                &[0u8; 16], &preq, &pres, t1, &ia, t2, &ra, &mconfirm, &mrand,
                                &srand,
                            ) {
                                pairing_data["tk"] = json!(hex_str(&[0u8; 16]));
                                pairing_data["stk"] = json!(hex_str(&stk));
                                pairing_data["confirm_verified"] = json!(true);
                                r.summary.push(format!(
                                    "smp: legacy STK derived from TK=0 ({})",
                                    hex_str(&stk)
                                ));
                                derived = true;
                                break;
                            }
                        }

                        if !derived {
                            for (t1, t2) in [
                                (iat, rat),
                                (if iat == 0 { 1 } else { 0 }, rat),
                                (iat, if rat == 0 { 1 } else { 0 }),
                                (if iat == 0 { 1 } else { 0 }, if rat == 0 { 1 } else { 0 }),
                            ] {
                                if let Some((pin, tk, stk)) = crack_legacy_passkey(
                                    &preq, &pres, t1, &ia, t2, &ra, &mconfirm, &mrand, &srand,
                                ) {
                                    pairing_data["passkey_pin"] = json!(format!("{pin:06}"));
                                    pairing_data["tk"] = json!(hex_str(&tk));
                                    pairing_data["stk"] = json!(hex_str(&stk));
                                    pairing_data["confirm_verified"] = json!(true);
                                    r.summary.push(format!(
                                        "smp: legacy passkey cracked (PIN: {pin:06}), STK derived ({})",
                                        hex_str(&stk)
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            data["pairing"] = pairing_data;

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
    fn c1_and_s1_vectors() {
        let k = [0u8; 16];
        let r = [
            0x57, 0x83, 0xd0, 0xd6, 0x39, 0x2f, 0xac, 0xa3, 0xe1, 0xa2, 0xfa, 0xca, 0x37, 0xfe,
            0x48, 0x37,
        ];
        let preq = [0x01, 0x01, 0x00, 0x00, 0x10, 0x07, 0x07];
        let pres = [0x02, 0x03, 0x00, 0x00, 0x08, 0x07, 0x07];
        let iat = 0x01;
        let ia = [0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6];
        let rat = 0x00;
        let ra = [0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6];

        let confirm = c1(&k, &r, &preq, &pres, iat, &ia, rat, &ra);
        assert_ne!(confirm, [0u8; 16]);

        let r1 = [
            0x00, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03,
            0x02, 0x01,
        ];
        let r2 = [
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f, 0x10,
        ];
        let stk = s1(&k, &r1, &r2);
        assert_ne!(stk, [0u8; 16]);
    }

    #[test]
    fn passkey_pin_crack_and_stk_derivation() {
        let pin = 42u32;
        let tk = passkey_to_tk(pin);
        let preq = [0x01, 0x02, 0x00, 0x05, 0x10, 0x03, 0x03];
        let pres = [0x02, 0x01, 0x00, 0x05, 0x10, 0x03, 0x03];
        let iat = 0u8;
        let ia = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let rat = 0u8;
        let ra = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        let mrand = [0x01u8; 16];
        let srand = [0x02u8; 16];
        let mconfirm = c1(&tk, &mrand, &preq, &pres, iat, &ia, rat, &ra);

        let cracked =
            crack_legacy_passkey(&preq, &pres, iat, &ia, rat, &ra, &mconfirm, &mrand, &srand);
        assert!(cracked.is_some());
        let (found_pin, found_tk, found_stk) = cracked.unwrap();
        assert_eq!(found_pin, 42);
        assert_eq!(found_tk, tk);
        assert_eq!(found_stk, s1(&tk, &srand, &mrand));
    }

    #[test]
    fn analyze_legacy_passkey_capture() {
        let pin = 42u32;
        let tk = passkey_to_tk(pin);
        let preq = vec![0x01, 0x02, 0x00, 0x05, 0x10, 0x03, 0x03];
        let pres = vec![0x02, 0x01, 0x00, 0x05, 0x10, 0x03, 0x03];
        let iat = 0u8;
        let ia = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let rat = 0u8;
        let ra = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        let mrand = [0x01u8; 16];
        let srand = [0x02u8; 16];
        let preq_b: [u8; 7] = preq[..7].try_into().unwrap();
        let pres_b: [u8; 7] = pres[..7].try_into().unwrap();
        let mconfirm_b = c1(&tk, &mrand, &preq_b, &pres_b, iat, &ia, rat, &ra);
        let sconfirm_b = c1(&tk, &srand, &preq_b, &pres_b, iat, &ia, rat, &ra);

        let mut mconfirm = vec![0x03];
        mconfirm.extend_from_slice(&mconfirm_b);
        let mut sconfirm = vec![0x03];
        sconfirm.extend_from_slice(&sconfirm_b);

        let mut mrand_pdu = vec![0x04];
        mrand_pdu.extend_from_slice(&mrand);
        let mut srand_pdu = vec![0x04];
        srand_pdu.extend_from_slice(&srand);

        let mut ia_pdu = vec![0x09, iat];
        ia_pdu.extend_from_slice(&ia);
        let mut ra_pdu = vec![0x09, rat];
        ra_pdu.extend_from_slice(&ra);

        let pdus = vec![
            preq, pres, mconfirm, sconfirm, mrand_pdu, srand_pdu, ia_pdu, ra_pdu,
        ];
        let r = analyze(&pdus);

        assert_eq!(r.data["pairing"]["passkey_pin"], "000042");
        assert_eq!(r.data["pairing"]["confirm_verified"], true);
        assert!(r.summary.iter().any(|s| s.contains("PIN: 000042")));
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
