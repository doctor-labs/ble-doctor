//! DFU probing (v1 `write_probe` DFU extensions, issue #10).
//!
//! Two opt-in, write-based probes. Both write to the device, so both are gated behind
//! `--allow-dangerous` at the CLI layer and are never reachable from `mcp` (see src/mcp.rs,
//! which only shells out to `scan`/`analyze`).

use crate::probe::write::{classify_att, WriteProbeOutcome};
use crate::radio::{GattClient, WriteError};

/// The three-state signing verdict a live probe can reach, plus "no evidence either way".
/// String form matches what `GattInfo::dfu_probe` carries and what
/// `checks::check_dfu_signing_enforced` reads (v1 `DFU_PROBE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DfuVerdict {
    /// A bootloader refused an unsigned image (response 0x0B, extended error 0x06).
    Enforced,
    /// A signature was present but did not verify (response 0x06).
    SignatureInvalid,
    /// The bootloader accepted an unsigned image (response 0x01).
    NotEnforced,
    /// No usable response (wrong shape, empty, or an unrecognised code).
    Inconclusive,
}

pub const DFU_VERDICT_ENFORCED: &str = "enforced";
pub const DFU_VERDICT_SIGNATURE_INVALID: &str = "signature_present_but_invalid";
pub const DFU_VERDICT_NOT_ENFORCED: &str = "not_enforced";
pub const DFU_VERDICT_INCONCLUSIVE: &str = "inconclusive";

impl DfuVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            DfuVerdict::Enforced => DFU_VERDICT_ENFORCED,
            DfuVerdict::SignatureInvalid => DFU_VERDICT_SIGNATURE_INVALID,
            DfuVerdict::NotEnforced => DFU_VERDICT_NOT_ENFORCED,
            DfuVerdict::Inconclusive => DFU_VERDICT_INCONCLUSIVE,
        }
    }
}

/// Classify a Secure DFU control-point response to an unsigned init packet.
/// `0x0B` followed by extended error `0x06` -> enforced; a bare `0x06` -> signature present but
/// invalid; a bare `0x01` -> not enforced; anything else (including empty) -> inconclusive.
pub fn classify_dfu_response(resp: &[u8]) -> DfuVerdict {
    match (resp.first(), resp.get(1)) {
        (Some(0x0B), Some(0x06)) => DfuVerdict::Enforced,
        (Some(0x06), _) => DfuVerdict::SignatureInvalid,
        (Some(0x01), _) => DfuVerdict::NotEnforced,
        _ => DfuVerdict::Inconclusive,
    }
}

/// Nordic Buttonless DFU: no bond sharing (any peer, bonded or not, can trigger the reboot into
/// the bootloader).
pub const BUTTONLESS_NO_BOND_UUID: &str = "8ec90003-f315-4f60-9fb8-838830daea50";
/// Nordic Buttonless DFU: with bond sharing (the bootloader inherits the caller's bond).
pub const BUTTONLESS_BOND_SHARING_UUID: &str = "8ec90004-f315-4f60-9fb8-838830daea50";

/// The byte the buttonless characteristic expects: "Enter Bootloader" (Nordic DFU spec).
pub const BUTTONLESS_ENTER_BOOTLOADER: [u8; 1] = [0x01];

/// Outcome of writing to one buttonless-DFU characteristic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ButtonlessProbeResult {
    pub uuid: String,
    pub outcome: WriteProbeOutcome,
    /// True when an unbonded peer could make this write land (the write was accepted, or
    /// rejected only on its payload — both mean the control point itself was reachable).
    pub triggerable_unbonded: bool,
}

/// Write the single "enter bootloader" byte to a buttonless-DFU characteristic (no-bond-sharing
/// by default; bond-sharing when `bond_sharing` is true) and report whether an unbonded peer can
/// trigger it. Opt-in: callers gate this behind `--allow-dangerous`.
pub async fn probe_buttonless<C: GattClient>(
    client: &C,
    bond_sharing: bool,
) -> ButtonlessProbeResult {
    let uuid = if bond_sharing {
        BUTTONLESS_BOND_SHARING_UUID
    } else {
        BUTTONLESS_NO_BOND_UUID
    };
    let outcome = match client.write(uuid, &BUTTONLESS_ENTER_BOOTLOADER).await {
        Ok(()) => WriteProbeOutcome::Accepted,
        Err(WriteError::Att(code)) => classify_att(code),
        Err(WriteError::Ble(_)) => WriteProbeOutcome::Inconclusive,
    };
    ButtonlessProbeResult {
        uuid: uuid.to_string(),
        triggerable_unbonded: matches!(
            outcome,
            WriteProbeOutcome::Accepted | WriteProbeOutcome::ValueRejected
        ),
        outcome,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{FakeClient, FakeGattTree, WriteOutcome};

    #[test]
    fn classify_each_response_class() {
        assert_eq!(classify_dfu_response(&[0x0B, 0x06]), DfuVerdict::Enforced);
        assert_eq!(
            classify_dfu_response(&[0x0B, 0x06, 0xAA]),
            DfuVerdict::Enforced
        );
        assert_eq!(classify_dfu_response(&[0x06]), DfuVerdict::SignatureInvalid);
        assert_eq!(
            classify_dfu_response(&[0x06, 0x00]),
            DfuVerdict::SignatureInvalid
        );
        assert_eq!(classify_dfu_response(&[0x01]), DfuVerdict::NotEnforced);
        assert_eq!(
            classify_dfu_response(&[0x01, 0xFF]),
            DfuVerdict::NotEnforced
        );
        assert_eq!(classify_dfu_response(&[]), DfuVerdict::Inconclusive);
        assert_eq!(classify_dfu_response(&[0x99]), DfuVerdict::Inconclusive);
        // 0x0B WITHOUT extended error 0x06 is not evidence of enforcement.
        assert_eq!(
            classify_dfu_response(&[0x0B, 0x01]),
            DfuVerdict::Inconclusive
        );
    }

    #[test]
    fn verdict_strings_match_contract() {
        assert_eq!(DfuVerdict::Enforced.as_str(), "enforced");
        assert_eq!(
            DfuVerdict::SignatureInvalid.as_str(),
            "signature_present_but_invalid"
        );
        assert_eq!(DfuVerdict::NotEnforced.as_str(), "not_enforced");
        assert_eq!(DfuVerdict::Inconclusive.as_str(), "inconclusive");
    }

    #[tokio::test]
    async fn buttonless_writes_enter_bootloader_byte_to_no_bond_uuid() {
        let c = FakeClient::new(FakeGattTree::new())
            .script_write(BUTTONLESS_NO_BOND_UUID, WriteOutcome::Accept);
        let r = probe_buttonless(&c, false).await;
        assert_eq!(r.uuid, BUTTONLESS_NO_BOND_UUID);
        assert_eq!(r.outcome, WriteProbeOutcome::Accepted);
        assert!(r.triggerable_unbonded);
        assert_eq!(
            c.writes(),
            vec![(BUTTONLESS_NO_BOND_UUID.to_string(), vec![0x01])]
        );
    }

    #[tokio::test]
    async fn buttonless_bond_sharing_targets_the_other_uuid() {
        let c = FakeClient::new(FakeGattTree::new())
            .script_write(BUTTONLESS_BOND_SHARING_UUID, WriteOutcome::Accept);
        let r = probe_buttonless(&c, true).await;
        assert_eq!(r.uuid, BUTTONLESS_BOND_SHARING_UUID);
        assert!(r.triggerable_unbonded);
    }

    #[tokio::test]
    async fn buttonless_auth_required_is_not_triggerable_unbonded() {
        let c = FakeClient::new(FakeGattTree::new()).script_write(
            BUTTONLESS_NO_BOND_UUID,
            WriteOutcome::AttError(crate::testkit::ATT_INSUFFICIENT_AUTHENTICATION),
        );
        let r = probe_buttonless(&c, false).await;
        assert_eq!(r.outcome, WriteProbeOutcome::AuthRequired);
        assert!(!r.triggerable_unbonded);
    }
}
