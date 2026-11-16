//! SweynTooth-class link-layer fuzzing: the **named case catalog** and the
//! **offline detection signatures**.
//!
//! Two halves, deliberately kept apart:
//!
//! * *signatures* — what a capture can prove about a pairing **without sending
//!   the target anything**: the defensive half #25 offers as its lighter first
//!   step ("ship DETECTION SIGNATURES for the known CVEs (version/behaviour
//!   checks over GATT) instead of the fuzzer"). Fully offline: the SMP PDUs
//!   are already reassembled by `capture.rs`.
//! * *injection* — driving a malformed link-layer PDU at a target. That needs
//!   an injection-capable radio (an nRF52 board running custom radio firmware,
//!   or a Ubertooth One); a stock controller cannot emit malformed LL PDUs.
//!   This build has no injection backend, so `fuzz --injection` refuses and
//!   names the hardware it needs instead of pretending to run.
//!
//! AGENTS.md: "No new exploit code in this repo." The catalog therefore names
//! the cases and what each one exercises; it ships no malformed-PDU payloads
//! and no mutator. The injection campaign stays a recorded deferred test
//! (`docs/DEFERRED-TESTS.md`).

use crate::checks::CheckResult;

/// The layer a case sits in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// Link layer (the SweynTooth malformed-LL family).
    Ll,
    /// L2CAP / ATT.
    Att,
    /// Security Manager Protocol.
    Smp,
    /// Host-controller interface.
    Hci,
}

impl Layer {
    pub fn as_str(&self) -> &'static str {
        match self {
            Layer::Ll => "LL",
            Layer::Att => "ATT",
            Layer::Smp => "SMP",
            Layer::Hci => "HCI",
        }
    }
}

/// How a case is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detection {
    /// An offline signature over a capture (no radio, no injection).
    Signature(&'static str),
    /// Only observable by driving the case at the target: needs injection
    /// hardware.
    InjectionOnly,
}

/// One named case.
#[derive(Debug, Clone, Copy)]
pub struct FuzzCase {
    /// Stable id, the case's name in the issue.
    pub id: &'static str,
    /// One-line title.
    pub title: &'static str,
    /// The protocol layer the case exercises.
    pub layer: Layer,
    /// What the case does to the target's stack.
    pub summary: &'static str,
    /// How the case is detected.
    pub detection: Detection,
    /// The hardware the case needs to be *driven* ("" when a capture is enough).
    pub hardware: &'static str,
}

/// The radio an injection campaign needs: a stock controller cannot emit a
/// malformed LL PDU.
pub const INJECTION_HARDWARE: &str =
    "an injection-capable BLE radio: an nRF52 board flashed with custom radio firmware, or a \
     Ubertooth One";

/// The cases this build knows about.
///
/// The first group is the named case list from #89 (SweynTooth-class malformed
/// link-layer input); each one is only observable by injecting it. The second
/// group is the offline signatures: a capture proves them without a radio.
pub const CASES: &[FuzzCase] = &[
    FuzzCase {
        id: "ll_version_ind",
        title: "Malformed LL_VERSION_IND",
        layer: Layer::Ll,
        summary: "an LL_VERSION_IND whose length field is not the expected one",
        detection: Detection::InjectionOnly,
        hardware: INJECTION_HARDWARE,
    },
    FuzzCase {
        id: "ll_length_req",
        title: "Malformed LL_LENGTH_REQ",
        layer: Layer::Ll,
        summary: "an LL_LENGTH_REQ whose length field disagrees with its payload",
        detection: Detection::InjectionOnly,
        hardware: INJECTION_HARDWARE,
    },
    FuzzCase {
        id: "malformed_connect_req",
        title: "Malformed CONNECT_REQ",
        layer: Layer::Ll,
        summary: "a CONNECT_REQ with an inconsistent header",
        detection: Detection::InjectionOnly,
        hardware: INJECTION_HARDWARE,
    },
    FuzzCase {
        id: "ll_enc_req_zero_ltk",
        title: "LL_ENC_REQ with a zero LTK",
        layer: Layer::Ll,
        summary: "an LL_ENC_REQ carrying an all-zero long-term key",
        detection: Detection::InjectionOnly,
        hardware: INJECTION_HARDWARE,
    },
    FuzzCase {
        id: "channel_map_0",
        title: "CONNECT_IND with an all-zero channel map",
        layer: Layer::Ll,
        summary: "a CONNECT_IND whose channel map is all zeros",
        detection: Detection::InjectionOnly,
        hardware: INJECTION_HARDWARE,
    },
    FuzzCase {
        id: "att_sequence",
        title: "Malformed ATT transaction sequence",
        layer: Layer::Att,
        summary: "an ATT sequence that leaves the peer's ATT state machine inconsistent",
        detection: Detection::InjectionOnly,
        hardware: INJECTION_HARDWARE,
    },
    FuzzCase {
        id: "esp32_hci_desync",
        title: "ESP32 HCI desync",
        layer: Layer::Hci,
        summary: "the HCI command sequence that desynchronises an ESP32 BLE controller",
        detection: Detection::InjectionOnly,
        hardware: INJECTION_HARDWARE,
    },
    FuzzCase {
        id: "smp_legacy_pairing",
        title: "SMP legacy pairing (no LE Secure Connections)",
        layer: Layer::Smp,
        summary: "the pairing negotiates legacy pairing: the temporary key travels in the clear",
        detection: Detection::Signature("smp_legacy_pairing"),
        hardware: "",
    },
    FuzzCase {
        id: "smp_just_works",
        title: "SMP Just Works association",
        layer: Layer::Smp,
        summary: "the pairing is unauthenticated: no MITM protection",
        detection: Detection::Signature("smp_just_works"),
        hardware: "",
    },
    FuzzCase {
        id: "smp_key_size",
        title: "SMP encryption key size below 16 bytes",
        layer: Layer::Smp,
        summary: "the negotiated maximum encryption key size is below 16 bytes (KNOB-style)",
        detection: Detection::Signature("smp_key_size"),
        hardware: "",
    },
    FuzzCase {
        id: "smp_dhkey_check_skipped",
        title: "SMP DHKey Check skipped",
        layer: Layer::Smp,
        summary: "LE Secure Connections bonded both sides without verifying the derived key",
        detection: Detection::Signature("smp_dhkey_check_skipped"),
        hardware: "",
    },
];

/// Every case this build knows about.
pub fn cases() -> &'static [FuzzCase] {
    CASES
}

/// The cases an offline signature can decide (no radio, no injection).
pub fn signature_cases() -> impl Iterator<Item = &'static FuzzCase> {
    CASES
        .iter()
        .filter(|c| matches!(c.detection, Detection::Signature(_)))
}

/// The cases that only an injection campaign can decide.
pub fn injection_cases() -> impl Iterator<Item = &'static FuzzCase> {
    CASES
        .iter()
        .filter(|c| matches!(c.detection, Detection::InjectionOnly))
}

/// The offline detection signatures over the SMP PDUs of a capture.
///
/// Pure: the PDUs come from `capture.rs`, the checks from `smp.rs`. No radio,
/// no injection, no target.
pub fn run_signatures(pdus: &[Vec<u8>]) -> Vec<CheckResult> {
    crate::smp::analyze(pdus).checks
}

/// Why `--injection` cannot run here, and what it would need.
pub fn injection_refusal() -> String {
    format!(
        "injection mode needs {INJECTION_HARDWARE}; this build ships no injection backend \
         (defensive scope: detection signatures only)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_covers_the_named_case_list() {
        let ids: Vec<&str> = CASES.iter().map(|c| c.id).collect();
        for want in [
            "ll_version_ind",
            "ll_length_req",
            "malformed_connect_req",
            "ll_enc_req_zero_ltk",
            "channel_map_0",
            "att_sequence",
            "esp32_hci_desync",
        ] {
            assert!(ids.contains(&want), "case {want} missing from the catalog");
        }
        // The list is also a set: no duplicates.
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len());
    }

    #[test]
    fn every_injection_case_names_its_hardware() {
        for c in injection_cases() {
            assert!(!c.hardware.is_empty(), "{} names no hardware", c.id);
            assert!(c.hardware.contains("nRF52") || c.hardware.contains("Ubertooth"));
        }
    }

    #[test]
    fn signature_cases_point_at_a_rule_that_exists() {
        for c in signature_cases() {
            let Detection::Signature(id) = c.detection else {
                panic!("{} is not a signature case", c.id);
            };
            assert!(
                crate::rules::get(id).is_some(),
                "signature {id} has no rule in the catalog"
            );
            assert!(c.hardware.is_empty(), "{} needs no hardware", c.id);
        }
    }

    #[test]
    fn signatures_run_over_smp_pdus_without_a_radio() {
        // A legacy Just Works pairing: the SMP signatures fire.
        let pdus = vec![vec![1u8, 3, 0, 1, 16, 3, 3], vec![2u8, 3, 0, 1, 16, 3, 3]];
        let checks = run_signatures(&pdus);
        let ids: Vec<&str> = checks.iter().map(|c| c.id.as_str()).collect();
        assert!(ids.contains(&"smp_legacy_pairing"), "{ids:?}");
        assert!(ids.contains(&"smp_just_works"), "{ids:?}");
    }

    #[test]
    fn signatures_are_silent_without_smp() {
        assert!(run_signatures(&[]).is_empty());
    }

    #[test]
    fn injection_refusal_names_the_hardware() {
        let msg = injection_refusal();
        assert!(msg.contains("nRF52"));
        assert!(msg.contains("Ubertooth"));
    }
}
