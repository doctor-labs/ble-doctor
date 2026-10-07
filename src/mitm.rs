//! GATT MITM: act as central to the real device and present a cloned
//! peripheral to the victim, relaying + logging every GATT read/write.
//! Absorbs GATTacker/BtleJuice/Mirage-MITM without external tools.
//!
//! The relay logic below (`MitmRelay`) is pure and radio-free: it takes any
//! `GattClient` (fake or real) as the device side and records the exchange.
//! The clone/serve half (building a peripheral with bluster and driving it
//! alongside a central to the real device) is Linux-only and needs 2 adapters
//! + peripheral mode — see the `live` module.

use crate::error::BleError;
use crate::radio::{GattClient, WriteError};

/// Direction of one relayed exchange, from the victim's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayOp {
    /// Victim wrote `bytes` to `uuid`; forwarded to the real device.
    Write,
    /// Victim read `uuid`; `bytes` is the real device's value, forwarded back.
    Read,
}

/// One relayed GATT exchange, in order (`seq` is a monotonic sequence number,
/// not a wall-clock timestamp, so logs stay deterministic under test).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmLogEntry {
    pub seq: u64,
    pub op: RelayOp,
    pub uuid: String,
    pub bytes: Vec<u8>,
}

/// Relays victim GATT requests to the real device and logs every exchange.
/// No radio: driven in tests by a `GattClient` fake (the device side); in the
/// live path the device side is a real central connection (see `live::serve`).
#[derive(Debug, Default)]
pub struct MitmRelay {
    log: Vec<MitmLogEntry>,
    seq: u64,
}

impl MitmRelay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything relayed so far, in order.
    pub fn log(&self) -> &[MitmLogEntry] {
        &self.log
    }

    fn next_seq(&mut self) -> u64 {
        let s = self.seq;
        self.seq += 1;
        s
    }

    /// Forward a victim write of `data` to `uuid` on the real `device`, log
    /// it, and return the device's response (its own error, unmasked by the
    /// MITM) to the victim.
    pub async fn relay_write<C: GattClient>(
        &mut self,
        device: &C,
        uuid: &str,
        data: &[u8],
    ) -> Result<(), WriteError> {
        let result = device.write(uuid, data).await;
        let seq = self.next_seq();
        self.log.push(MitmLogEntry {
            seq,
            op: RelayOp::Write,
            uuid: uuid.to_string(),
            bytes: data.to_vec(),
        });
        result
    }

    /// Forward a victim read of `uuid` to the real `device`, log the value
    /// returned, and hand it back to the victim.
    pub async fn relay_read<C: GattClient>(
        &mut self,
        device: &C,
        uuid: &str,
    ) -> Result<Vec<u8>, BleError> {
        let value = device.read(uuid).await?;
        let seq = self.next_seq();
        self.log.push(MitmLogEntry {
            seq,
            op: RelayOp::Read,
            uuid: uuid.to_string(),
            bytes: value.clone(),
        });
        Ok(value)
    }
}

/// Live clone/serve path: build a peripheral mirroring the target's GATT
/// (via bluster) and drive it alongside a central connection to the real
/// device. Needs Linux + 2 adapters + peripheral mode (bluster is Linux-only,
/// see Cargo.toml); gated by `capability::require(Feature::Mitm)` plus an
/// adapter-count check, never run on macOS/Windows or with one adapter.
#[cfg(target_os = "linux")]
pub mod live {
    use crate::capability::{self, Feature, Platform, Support};

    /// Check the static (feature x platform) verdict, then the live hardware
    /// precondition (>=2 adapters). Returns the remediation text to print on
    /// failure; `Ok(())` means the live MITM may proceed.
    pub async fn require_mitm() -> Result<(), String> {
        match capability::support(Feature::Mitm, Platform::current()) {
            Support::Unsupported => {
                return Err(format!(
                    "{:?} unsupported on {:?}",
                    Feature::Mitm,
                    Platform::current()
                ))
            }
            Support::NeedsCapability(_) | Support::Supported => {}
        }
        let count = adapter_count().await.map_err(|e| e.to_string())?;
        if count < 2 {
            return Err(format!(
                "mitm needs a second adapter + peripheral mode (found {count} adapter(s))"
            ));
        }
        Ok(())
    }

    async fn adapter_count() -> Result<usize, crate::error::BleError> {
        use btleplug::api::Manager as _;
        let manager = btleplug::platform::Manager::new().await.map_err(|e| {
            crate::error::BleError::OsError {
                context: e.to_string(),
            }
        })?;
        let adapters = manager
            .adapters()
            .await
            .map_err(|e| crate::error::BleError::OsError {
                context: e.to_string(),
            })?;
        Ok(adapters.len())
    }

    /// Clone the target's GATT onto a bluster peripheral and relay traffic
    /// to/from a central connection to the real device, logging every
    /// exchange via `MitmRelay`.
    ///
    /// TODO(#20): wire bluster's peripheral API (advertise a GATT mirroring
    /// `target`'s services, accept the victim's connection, and for every
    /// characteristic access call `MitmRelay::relay_read`/`relay_write`
    /// against a `BtleplugClient` connected to `target` on the second
    /// adapter). bluster's service/characteristic builder API needs hardware
    /// to exercise, so it is stubbed here rather than guessed at; the relay
    /// logic it would call is already implemented and tested above.
    pub async fn serve(target: &str, _allow_dangerous: bool) -> Result<(), String> {
        require_mitm().await?;
        Err(format!(
            "mitm: live relay against '{target}' not yet implemented (bluster peripheral loop, see TODO(#20))"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{FakeClient, FakeGattTree, WriteOutcome};

    #[tokio::test]
    async fn victim_write_is_forwarded_and_logged() {
        let device = FakeClient::new(FakeGattTree::new()).script_write("c1", WriteOutcome::Accept);
        let mut relay = MitmRelay::new();
        relay.relay_write(&device, "c1", &[1, 2, 3]).await.unwrap();
        assert_eq!(device.writes(), vec![("c1".to_string(), vec![1, 2, 3])]);
        assert_eq!(
            relay.log(),
            [MitmLogEntry {
                seq: 0,
                op: RelayOp::Write,
                uuid: "c1".into(),
                bytes: vec![1, 2, 3],
            }]
        );
    }

    #[tokio::test]
    async fn victim_read_returns_devices_value_and_is_logged() {
        let device = FakeClient::new(FakeGattTree::new()).script_read("c2", &[9, 9]);
        let mut relay = MitmRelay::new();
        let got = relay.relay_read(&device, "c2").await.unwrap();
        assert_eq!(got, vec![9, 9]);
        assert_eq!(
            relay.log(),
            [MitmLogEntry {
                seq: 0,
                op: RelayOp::Read,
                uuid: "c2".into(),
                bytes: vec![9, 9],
            }]
        );
    }

    #[tokio::test]
    async fn sequence_increments_across_mixed_exchanges() {
        let device = FakeClient::new(FakeGattTree::new())
            .script_write("w", WriteOutcome::Accept)
            .script_read("r", &[5]);
        let mut relay = MitmRelay::new();
        relay.relay_write(&device, "w", &[1]).await.unwrap();
        relay.relay_read(&device, "r").await.unwrap();
        let seqs: Vec<u64> = relay.log().iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![0, 1]);
    }

    #[test]
    fn capability_gate_matches_current_platform() {
        use crate::capability::{self, Feature, Platform, Support};
        let verdict = capability::support(Feature::Mitm, Platform::current());
        if cfg!(target_os = "linux") {
            assert_eq!(
                verdict,
                Support::NeedsCapability("second adapter + peripheral mode")
            );
        } else {
            assert_eq!(verdict, Support::Unsupported);
        }
    }
}
