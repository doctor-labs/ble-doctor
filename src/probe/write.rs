//! Empirical unauthenticated-write probing (v1 `write_probe.py`, issue #8).
//!
//! `check_unauthenticated_writes` (#7) wants `requires_bonding` per writable characteristic.
//! Reading the GATT declaration is not evidence: a plain spec-defined control point (Heart
//! Rate Control Point 0x2A39) happily accepts a write from a never-bonded client, so the only
//! way to know is to connect WITHOUT bonding and try. This is opt-in (`--allow-dangerous`),
//! never reachable from `mcp` (see src/mcp.rs), and refuses firmware/DFU characteristics
//! outright regardless of the flag.

use crate::gatt::WritableChar;
use crate::radio::{GattClient, WriteError};

/// Outcome of one write attempt. Only `Accepted`/`ValueRejected` are findings (an
/// unauthenticated client could write here); the rest must not appear in the writable set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteProbeOutcome {
    /// The write landed, unauthenticated. FINDING.
    Accepted,
    /// ATT 0x03 WRITE_NOT_PERMITTED — not actually writable. Excluded.
    NotWritable,
    /// ATT 0x0D/0x13 — writable and unauthenticated, rejected only on this payload. FINDING.
    ValueRejected,
    /// ATT 0x05/0x08/0x0C/0x0F — the server asked for a link-layer security procedure.
    AuthRequired,
    /// Never written: dangerous (firmware/DFU) or not opted into.
    SkippedUnsafe,
    /// Written, but the answer was a transport failure (disconnect, timeout, unmapped code),
    /// never an ATT verdict. Excluded — a dropped link is not evidence of anything.
    Inconclusive,
}

/// ATT error code -> outcome (Core Spec Vol 3, Part F, §3.4.1.1).
pub fn classify_att(code: u8) -> WriteProbeOutcome {
    match code {
        0x03 => WriteProbeOutcome::NotWritable,
        0x05 | 0x08 | 0x0C | 0x0F => WriteProbeOutcome::AuthRequired,
        0x0D | 0x13 => WriteProbeOutcome::ValueRejected,
        _ => WriteProbeOutcome::Inconclusive,
    }
}

/// `WriteError` -> outcome. A transport error (`Ble`, i.e. no ATT response at all) is always
/// `Inconclusive`: never read a disconnect as an ATT verdict.
fn classify_write_error(e: &WriteError) -> WriteProbeOutcome {
    match e {
        WriteError::Att(code) => classify_att(*code),
        WriteError::Ble(_) => WriteProbeOutcome::Inconclusive,
    }
}

/// Default probe payload (v1 `DEFAULT_PROBE_PAYLOAD`): inert bytes, kept fixed so results are
/// comparable across runs.
pub const DEFAULT_PROBE_PAYLOAD: [u8; 4] = [0x01, 0x02, 0x03, 0x04];

/// Firmware/DFU characteristics: writing to them has a real-world consequence (arms a firmware
/// update, erases flash). Refused even with `--allow-dangerous` named true — "dangerous" here
/// means "skip unless told otherwise", not "unlock this".
const DANGEROUS_CHARACTERISTIC_UUIDS: &[&str] = &[
    "8ec90001-f315-4f60-9fb8-838830daea50", // Nordic Secure DFU Control Point
    "8ec90002-f315-4f60-9fb8-838830daea50", // Nordic Secure DFU Packet
    "8ec90003-f315-4f60-9fb8-838830daea50", // Buttonless DFU Without Bond Sharing
    "8ec90004-f315-4f60-9fb8-838830daea50", // Buttonless DFU With Bond Sharing
    "f000ffc4-0451-4000-b000-000000000000", // TI OAD Image
    "f000ffc5-0451-4000-b000-000000000000", // TI OAD Control
    "e95d93b0-251d-470a-a062-fa1922dfa9a8", // micro:bit DFU Control
    "e95d93b1-251d-470a-a062-fa1922dfa9a8", // micro:bit DFU Data
    "1d5579ec-1fa6-4c50-b2f8-1ece332fd1d5", // Silicon Labs Bootloader
    "e6fe0002-8796-4b9e-a802-2c7db6e6bb3b", // Nordic System Control / Reset
];

/// Same rationale, matched on the service the characteristic lives in.
const DANGEROUS_SERVICE_UUIDS: &[&str] = &[
    "0000fe59-0000-1000-8000-00805f9b34fb", // Nordic Secure DFU
    "8e400001-f315-4f60-9fb8-838830daea50", // Nordic Experimental Buttonless DFU
    "00001530-1212-efde-1523-785feabcd123", // Nordic Legacy DFU
    "f000ffc0-0451-4000-b000-000000000000", // TI OAD
    "e95d93b0-251d-470a-a062-fa1922dfa9a8", // micro:bit DFU Control
    "e95d93b1-251d-470a-a062-fa1922dfa9a8", // micro:bit DFU Data
    "1d5579ec-1fa6-4c50-b2f8-1ece332fd1d5", // Silicon Labs Bootloader
    "e6fe0001-8796-4b9e-a802-2c7db6e6bb3b", // Nordic System Control
    "fdb159db-036c-49e3-b3db-6326ac3e8b60", // SL (EFM) OTA control
    "a9b3cd50-1a1b-4d3a-9a3e-9e2b0e4a0d3b", // OTA reboot (vendor-named variant)
];

/// Denylisted independent of any allow flag — firmware/DFU characteristics always refuse.
pub fn is_dangerous(uuid: &str, service_uuid: &str) -> bool {
    let u = uuid.to_lowercase();
    let s = service_uuid.to_lowercase();
    DANGEROUS_CHARACTERISTIC_UUIDS.contains(&u.as_str())
        || DANGEROUS_SERVICE_UUIDS.contains(&s.as_str())
}

/// One probed characteristic's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub uuid: String,
    pub service_uuid: String,
    pub outcome: WriteProbeOutcome,
    /// The `requires_bonding` value this outcome implies, or `None` when the characteristic
    /// must be excluded from the writable set entirely (not writable at all, or never probed).
    pub requires_bonding: Option<bool>,
}

fn requires_bonding_for(outcome: WriteProbeOutcome) -> Option<bool> {
    match outcome {
        WriteProbeOutcome::Accepted | WriteProbeOutcome::ValueRejected => Some(false),
        WriteProbeOutcome::AuthRequired => Some(true),
        WriteProbeOutcome::NotWritable
        | WriteProbeOutcome::SkippedUnsafe
        | WriteProbeOutcome::Inconclusive => None,
    }
}

/// Probe every writable characteristic: dangerous ones are always skipped (never written to);
/// everything else gets `DEFAULT_PROBE_PAYLOAD` written and the ATT response classified.
/// `allow_all` opts into probing non-dangerous characteristics at all (default-safe callers
/// pass `true` only from the explicit `--allow-dangerous`-gated CLI path; it never unlocks the
/// denylist above).
pub async fn probe_write_access<C: GattClient>(
    client: &C,
    chars: &[WritableChar],
    allow_all: bool,
) -> Vec<ProbeResult> {
    let mut out = Vec::with_capacity(chars.len());
    for c in chars {
        let outcome = if is_dangerous(&c.uuid, &c.service_uuid) || !allow_all {
            WriteProbeOutcome::SkippedUnsafe
        } else {
            match client.write(&c.uuid, &DEFAULT_PROBE_PAYLOAD).await {
                Ok(()) => WriteProbeOutcome::Accepted,
                Err(e) => classify_write_error(&e),
            }
        };
        out.push(ProbeResult {
            uuid: c.uuid.clone(),
            service_uuid: c.service_uuid.clone(),
            requires_bonding: requires_bonding_for(outcome),
            outcome,
        });
    }
    out
}

/// Collapse probe results to the `WritableChar`-shaped list `check_unauthenticated_writes`
/// (#7) reads, dropping any result excluded from the writable set (not writable, skipped,
/// inconclusive). Reuses #7's check rather than adding a new one.
pub fn results_to_writable_chars(results: &[ProbeResult]) -> Vec<WritableChar> {
    results
        .iter()
        .filter_map(|r| {
            let requires_bonding = r.requires_bonding?;
            Some(WritableChar {
                uuid: r.uuid.clone(),
                requires_bonding,
                bonding_basis: "empirical-write-probe".into(),
                service_uuid: r.service_uuid.clone(),
                properties: vec![],
                description: None,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BleError;
    use crate::testkit::{
        FakeClient, FakeGattTree, WriteOutcome, ATT_INSUFFICIENT_AUTHENTICATION,
        ATT_INVALID_ATTRIBUTE_VALUE_LENGTH, ATT_VALUE_NOT_ALLOWED, ATT_WRITE_NOT_PERMITTED,
    };

    fn wchar(uuid: &str, service: &str) -> WritableChar {
        WritableChar {
            uuid: uuid.into(),
            requires_bonding: false,
            bonding_basis: "test".into(),
            service_uuid: service.into(),
            properties: vec!["write".into()],
            description: None,
        }
    }

    #[test]
    fn classify_att_maps_every_code() {
        assert_eq!(classify_att(0x03), WriteProbeOutcome::NotWritable);
        assert_eq!(classify_att(0x05), WriteProbeOutcome::AuthRequired);
        assert_eq!(classify_att(0x08), WriteProbeOutcome::AuthRequired);
        assert_eq!(classify_att(0x0C), WriteProbeOutcome::AuthRequired);
        assert_eq!(classify_att(0x0F), WriteProbeOutcome::AuthRequired);
        assert_eq!(classify_att(0x0D), WriteProbeOutcome::ValueRejected);
        assert_eq!(classify_att(0x13), WriteProbeOutcome::ValueRejected);
        assert_eq!(classify_att(0x99), WriteProbeOutcome::Inconclusive);
    }

    #[test]
    fn transport_error_is_inconclusive_never_an_att_verdict() {
        assert_eq!(
            classify_write_error(&WriteError::Ble(BleError::Disconnected)),
            WriteProbeOutcome::Inconclusive
        );
    }

    #[test]
    fn dangerous_denylist_covers_dfu_uuids() {
        assert!(is_dangerous(
            "8EC90002-F315-4F60-9FB8-838830DAEA50",
            "irrelevant"
        ));
        assert!(is_dangerous(
            "anything",
            "0000fe59-0000-1000-8000-00805f9b34fb"
        ));
        assert!(!is_dangerous("0000aaa1-0000-1000-8000-aabbccddeeff", "s"));
    }

    #[tokio::test]
    async fn accepted_write_is_a_finding_without_bonding() {
        let c = FakeClient::new(FakeGattTree::new()).script_write("aaa1", WriteOutcome::Accept);
        let chars = vec![wchar("aaa1", "svc")];
        let results = probe_write_access(&c, &chars, true).await;
        assert_eq!(results[0].outcome, WriteProbeOutcome::Accepted);
        assert_eq!(results[0].requires_bonding, Some(false));
        let found = results_to_writable_chars(&results);
        assert_eq!(found.len(), 1);
        assert!(!found[0].requires_bonding);
    }

    #[tokio::test]
    async fn auth_required_requires_bonding_true() {
        let c = FakeClient::new(FakeGattTree::new()).script_write(
            "aaa1",
            WriteOutcome::AttError(ATT_INSUFFICIENT_AUTHENTICATION),
        );
        let chars = vec![wchar("aaa1", "svc")];
        let results = probe_write_access(&c, &chars, true).await;
        assert_eq!(results[0].outcome, WriteProbeOutcome::AuthRequired);
        let found = results_to_writable_chars(&results);
        assert!(found[0].requires_bonding);
    }

    #[tokio::test]
    async fn not_writable_is_excluded() {
        let c = FakeClient::new(FakeGattTree::new())
            .script_write("aaa1", WriteOutcome::AttError(ATT_WRITE_NOT_PERMITTED));
        let chars = vec![wchar("aaa1", "svc")];
        let results = probe_write_access(&c, &chars, true).await;
        assert_eq!(results[0].outcome, WriteProbeOutcome::NotWritable);
        assert_eq!(results[0].requires_bonding, None);
        assert!(results_to_writable_chars(&results).is_empty());
    }

    #[tokio::test]
    async fn value_rejected_is_still_a_finding() {
        let c = FakeClient::new(FakeGattTree::new())
            .script_write("aaa1", WriteOutcome::AttError(ATT_VALUE_NOT_ALLOWED));
        let chars = vec![wchar("aaa1", "svc")];
        let results = probe_write_access(&c, &chars, true).await;
        assert_eq!(results[0].outcome, WriteProbeOutcome::ValueRejected);
        assert_eq!(results[0].requires_bonding, Some(false));

        let c2 = FakeClient::new(FakeGattTree::new()).script_write(
            "aaa1",
            WriteOutcome::AttError(ATT_INVALID_ATTRIBUTE_VALUE_LENGTH),
        );
        let results2 = probe_write_access(&c2, &chars, true).await;
        assert_eq!(results2[0].outcome, WriteProbeOutcome::ValueRejected);
    }

    #[tokio::test]
    async fn dangerous_characteristic_never_written_and_skipped() {
        let c = FakeClient::new(FakeGattTree::new())
            .script_write("8ec90002-f315-4f60-9fb8-838830daea50", WriteOutcome::Accept);
        let chars = vec![wchar(
            "8ec90002-f315-4f60-9fb8-838830daea50",
            "0000fe59-0000-1000-8000-00805f9b34fb",
        )];
        let results = probe_write_access(&c, &chars, true).await;
        assert_eq!(results[0].outcome, WriteProbeOutcome::SkippedUnsafe);
        assert_eq!(results[0].requires_bonding, None);
        assert!(
            c.writes().is_empty(),
            "dangerous char must never be written"
        );
    }

    #[tokio::test]
    async fn allow_all_false_skips_everything_without_writing() {
        let c = FakeClient::new(FakeGattTree::new()).script_write("aaa1", WriteOutcome::Accept);
        let chars = vec![wchar("aaa1", "svc")];
        let results = probe_write_access(&c, &chars, false).await;
        assert_eq!(results[0].outcome, WriteProbeOutcome::SkippedUnsafe);
        assert!(c.writes().is_empty());
    }
}
