//! Opt-in value reads (v1 `read_probe.py`, issue #9).
//!
//! Reads characteristics that declare READ on NON-SIG (vendor) services and lists the length
//! plus a printable preview. LISTS ONLY: no credential flagging. A read can change device
//! state, so this is its own subcommand, never reachable from `mcp`, and firmware/DFU
//! characteristics are refused (shared denylist with #8).

use crate::gatt::{is_sig_assigned_uuid, GattService};
use crate::probe::write::is_dangerous;
use crate::radio::GattClient;

/// A characteristic considered for reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadChar {
    pub uuid: String,
    pub service_uuid: String,
    pub properties: Vec<String>,
}

/// Flatten an enumerated GATT tree into `ReadChar`s.
pub fn read_chars(services: &[GattService]) -> Vec<ReadChar> {
    services
        .iter()
        .flat_map(|s| {
            s.characteristics.iter().map(|c| ReadChar {
                uuid: c.uuid.clone(),
                service_uuid: s.uuid.clone(),
                properties: c.properties.clone(),
            })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadDecision {
    Read,
    Skip(&'static str),
}

/// Read only READ-capable characteristics of non-SIG, non-DFU/firmware services.
pub fn should_read(uuid: &str, service_uuid: &str, properties: &[String]) -> ReadDecision {
    if !properties.iter().any(|p| p == "read") {
        ReadDecision::Skip("not readable")
    } else if is_dangerous(uuid, service_uuid) {
        ReadDecision::Skip("firmware/DFU characteristic refused")
    } else if is_sig_assigned_uuid(service_uuid) {
        ReadDecision::Skip("SIG-assigned service")
    } else {
        ReadDecision::Read
    }
}

/// Printable ASCII as-is, everything else `\xNN`.
pub fn preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match b {
            0x20..=0x7e => (b as char).to_string(),
            _ => format!("\\x{b:02x}"),
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadOutcome {
    Value { len: usize, preview: String },
    Skipped(&'static str),
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadResult {
    pub uuid: String,
    pub service_uuid: String,
    pub outcome: ReadOutcome,
}

/// Read every eligible characteristic; skips and read errors are recorded, never fatal.
pub async fn read_values<C: GattClient>(client: &C, chars: &[ReadChar]) -> Vec<ReadResult> {
    let mut out = Vec::with_capacity(chars.len());
    for c in chars {
        let outcome = match should_read(&c.uuid, &c.service_uuid, &c.properties) {
            ReadDecision::Skip(why) => ReadOutcome::Skipped(why),
            ReadDecision::Read => match client.read(&c.uuid).await {
                Ok(b) => ReadOutcome::Value {
                    len: b.len(),
                    preview: preview(&b),
                },
                Err(e) => ReadOutcome::Error(e.to_string()),
            },
        };
        out.push(ReadResult {
            uuid: c.uuid.clone(),
            service_uuid: c.service_uuid.clone(),
            outcome,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{FakeClient, FakeGattTree};

    const VENDOR_SVC: &str = "6e400001-b5a3-f393-e0a9-e50e24dcca9e";
    const VENDOR_CH: &str = "6e400003-b5a3-f393-e0a9-e50e24dcca9e";
    const SIG_SVC: &str = "0000180a-0000-1000-8000-00805f9b34fb";
    const SIG_CH: &str = "00002a29-0000-1000-8000-00805f9b34fb";
    const DFU_CH: &str = "8ec90002-f315-4f60-9fb8-838830daea50";
    const DFU_SVC: &str = "0000fe59-0000-1000-8000-00805f9b34fb";

    fn rc(uuid: &str, svc: &str) -> ReadChar {
        ReadChar {
            uuid: uuid.into(),
            service_uuid: svc.into(),
            properties: vec!["read".into()],
        }
    }

    #[test]
    fn preview_printable_and_non_printable() {
        assert_eq!(preview(b"hello"), "hello");
        assert_eq!(preview(&[0x00, 0x01, 0xff]), "\\x00\\x01\\xff");
    }

    #[tokio::test]
    async fn vendor_listed_sig_and_dfu_skipped() {
        let c = FakeClient::new(FakeGattTree::new())
            .script_read(VENDOR_CH, b"hi\x00")
            .script_read(SIG_CH, b"acme")
            .script_read(DFU_CH, b"secret");
        let chars = vec![
            rc(VENDOR_CH, VENDOR_SVC),
            rc(SIG_CH, SIG_SVC),
            rc(DFU_CH, DFU_SVC),
        ];
        let r = read_values(&c, &chars).await;
        assert_eq!(
            r[0].outcome,
            ReadOutcome::Value {
                len: 3,
                preview: "hi\\x00".into()
            }
        );
        assert_eq!(r[1].outcome, ReadOutcome::Skipped("SIG-assigned service"));
        assert!(matches!(r[2].outcome, ReadOutcome::Skipped(w) if w.contains("DFU")));
    }

    #[tokio::test]
    async fn read_error_recorded_not_fatal() {
        let c = FakeClient::new(FakeGattTree::new());
        let r = read_values(&c, &[rc(VENDOR_CH, VENDOR_SVC)]).await;
        assert!(matches!(r[0].outcome, ReadOutcome::Error(_)));
    }

    #[test]
    fn non_read_property_skipped() {
        let p = vec!["write".to_string()];
        assert_eq!(
            should_read(VENDOR_CH, VENDOR_SVC, &p),
            ReadDecision::Skip("not readable")
        );
    }
}
