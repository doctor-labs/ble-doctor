//! No-radio test harness: Rust port of v1's synthetic Fake* classes.
//! Always compiled (tiny, no hardware); the `test-support` feature is kept for gating later if it grows.

use crate::error::BleError;
use crate::gatt::{GattChar, GattDescriptor, GattService};
use crate::radio::{Central, DiscoveredDevice, GattClient, WriteError};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

/// ATT error codes (mirrors v1 test_write_probe.py).
pub const ATT_WRITE_NOT_PERMITTED: u8 = 0x03;
pub const ATT_INSUFFICIENT_AUTHENTICATION: u8 = 0x05;
pub const ATT_INSUFFICIENT_ENCRYPTION: u8 = 0x0F;
pub const ATT_INVALID_ATTRIBUTE_VALUE_LENGTH: u8 = 0x0D;
pub const ATT_VALUE_NOT_ALLOWED: u8 = 0x13;

pub const CCCD_UUID: &str = "00002902-0000-1000-8000-00805f9b34fb";

/// Scripted central: `scan()` returns the devices, or the scripted error.
pub struct FakeCentral {
    pub devices: Vec<DiscoveredDevice>,
    pub scan_error: Option<BleError>,
}

impl FakeCentral {
    pub fn new(devices: Vec<DiscoveredDevice>) -> Self {
        Self {
            devices,
            scan_error: None,
        }
    }

    pub fn failing(err: BleError) -> Self {
        Self {
            devices: vec![],
            scan_error: Some(err),
        }
    }
}

impl Central for FakeCentral {
    async fn scan(&self, _timeout: Duration) -> Result<Vec<DiscoveredDevice>, BleError> {
        match &self.scan_error {
            Some(e) => Err(e.clone()),
            None => Ok(self.devices.clone()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeDescriptor {
    pub uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeCharacteristic {
    pub uuid: String,
    pub service_uuid: String,
    pub properties: Vec<String>,
    /// `None` = backend did not expose descriptors (macOS / CCCD-unknown).
    pub descriptors: Option<Vec<FakeDescriptor>>,
}

impl FakeCharacteristic {
    pub fn new(uuid: &str, service_uuid: &str, props: &[&str]) -> Self {
        Self {
            uuid: uuid.into(),
            service_uuid: service_uuid.into(),
            properties: props.iter().map(|p| p.to_string()).collect(),
            descriptors: Some(vec![]),
        }
    }

    fn with_descriptors(mut self, d: Option<Vec<FakeDescriptor>>) -> Self {
        self.descriptors = d;
        self
    }

    /// Notify characteristic with a CCCD (0x2902) descriptor.
    pub fn notify_with_cccd(uuid: &str, service_uuid: &str) -> Self {
        Self::new(uuid, service_uuid, &["notify"]).with_descriptors(Some(vec![FakeDescriptor {
            uuid: CCCD_UUID.into(),
        }]))
    }

    /// Notify characteristic whose descriptors are present but lack a CCCD.
    pub fn notify_without_cccd(uuid: &str, service_uuid: &str) -> Self {
        Self::new(uuid, service_uuid, &["notify"]).with_descriptors(Some(vec![]))
    }

    /// Notify characteristic with descriptors not exposed (CCCD unknown).
    pub fn notify_unknown_cccd(uuid: &str, service_uuid: &str) -> Self {
        Self::new(uuid, service_uuid, &["notify"]).with_descriptors(None)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeService {
    pub uuid: String,
    pub characteristics: Vec<FakeCharacteristic>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FakeGattTree {
    pub services: Vec<FakeService>,
}

impl FakeGattTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: add a service; each characteristic's `service_uuid` is set to it.
    pub fn service(mut self, uuid: &str, mut chars: Vec<FakeCharacteristic>) -> Self {
        for c in &mut chars {
            c.service_uuid = uuid.into();
        }
        self.services.push(FakeService {
            uuid: uuid.into(),
            characteristics: chars,
        });
        self
    }

    /// Convert to the enumeration types `GattClient::services` returns.
    pub fn to_services(&self) -> Vec<GattService> {
        self.services
            .iter()
            .map(|s| GattService {
                uuid: s.uuid.clone(),
                characteristics: s
                    .characteristics
                    .iter()
                    .map(|c| GattChar {
                        uuid: c.uuid.clone(),
                        properties: c.properties.clone(),
                        description: None,
                        descriptors: c.descriptors.as_ref().map(|d| {
                            d.iter()
                                .map(|d| GattDescriptor {
                                    uuid: d.uuid.clone(),
                                })
                                .collect()
                        }),
                    })
                    .collect(),
            })
            .collect()
    }

    pub fn characteristics(&self) -> impl Iterator<Item = &FakeCharacteristic> {
        self.services.iter().flat_map(|s| &s.characteristics)
    }
}

/// Scripted write result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    Accept,
    AttError(u8),
}

/// Fake GATT client: scripted per-UUID reads/writes, records every write.
/// Unscripted writes are accepted; unscripted reads give `CharNotFound`.
#[derive(Default)]
pub struct FakeClient {
    pub tree: FakeGattTree,
    pub write_outcomes: HashMap<String, WriteOutcome>,
    pub read_values: HashMap<String, Vec<u8>>,
    writes: Mutex<Vec<(String, Vec<u8>)>>,
}

impl FakeClient {
    pub fn new(tree: FakeGattTree) -> Self {
        Self {
            tree,
            ..Default::default()
        }
    }

    pub fn script_write(mut self, uuid: &str, outcome: WriteOutcome) -> Self {
        self.write_outcomes.insert(uuid.into(), outcome);
        self
    }

    pub fn script_read(mut self, uuid: &str, bytes: &[u8]) -> Self {
        self.read_values.insert(uuid.into(), bytes.to_vec());
        self
    }

    /// Every write attempted so far, in order (uuid, payload).
    pub fn writes(&self) -> Vec<(String, Vec<u8>)> {
        self.writes.lock().unwrap().clone()
    }
}

impl GattClient for FakeClient {
    async fn services(&self) -> Result<Vec<GattService>, BleError> {
        Ok(self.tree.to_services())
    }

    async fn write(&self, uuid: &str, data: &[u8]) -> Result<(), WriteError> {
        self.writes
            .lock()
            .unwrap()
            .push((uuid.into(), data.to_vec()));
        match self.write_outcomes.get(uuid) {
            Some(WriteOutcome::AttError(c)) => Err(WriteError::Att(*c)),
            _ => Ok(()),
        }
    }

    async fn read(&self, uuid: &str) -> Result<Vec<u8>, BleError> {
        self.read_values
            .get(uuid)
            .cloned()
            .ok_or(BleError::CharNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::radio::select_target_device;

    #[tokio::test]
    async fn fake_central_returns_scripted_devices() {
        let d = DiscoveredDevice {
            id: "A".into(),
            adv_local_name: Some("Lock".into()),
            ..Default::default()
        };
        let c = FakeCentral::new(vec![d.clone()]);
        let got = c.scan(Duration::ZERO).await.unwrap();
        assert_eq!(got, vec![d]);
        assert_eq!(select_target_device(&got, "lock").unwrap().id, "A");
        let e = FakeCentral::failing(BleError::AdapterOff);
        assert_eq!(e.scan(Duration::ZERO).await, Err(BleError::AdapterOff));
    }

    #[test]
    fn descriptor_states() {
        let tree = FakeGattTree::new().service(
            "svc",
            vec![
                FakeCharacteristic::notify_with_cccd("a", "x"),
                FakeCharacteristic::notify_without_cccd("b", "x"),
                FakeCharacteristic::notify_unknown_cccd("c", "x"),
            ],
        );
        let cs: Vec<_> = tree.characteristics().collect();
        assert!(cs.iter().all(|c| c.service_uuid == "svc"));
        let has = |c: &FakeCharacteristic| {
            c.descriptors
                .as_ref()
                .map(|d| d.iter().any(|d| d.uuid == CCCD_UUID))
        };
        assert_eq!(has(cs[0]), Some(true));
        assert_eq!(has(cs[1]), Some(false));
        assert_eq!(has(cs[2]), None);
    }

    #[tokio::test]
    async fn client_scripted_writes_and_reads() {
        let c = FakeClient::new(FakeGattTree::new())
            .script_write("ro", WriteOutcome::AttError(ATT_WRITE_NOT_PERMITTED))
            .script_write(
                "auth",
                WriteOutcome::AttError(ATT_INSUFFICIENT_AUTHENTICATION),
            )
            .script_write("ok", WriteOutcome::Accept)
            .script_read("r", &[1, 2]);
        assert_eq!(c.write("ro", &[0]).await, Err(WriteError::Att(0x03)));
        assert_eq!(c.write("auth", &[0]).await, Err(WriteError::Att(0x05)));
        assert_eq!(c.write("ok", &[9]).await, Ok(()));
        assert_eq!(c.write("unscripted", &[]).await, Ok(()));
        assert_eq!(c.writes().len(), 4);
        assert_eq!(c.writes()[2], ("ok".to_string(), vec![9]));
        assert_eq!(c.read("r").await.unwrap(), vec![1, 2]);
        assert_eq!(c.read("nope").await, Err(BleError::CharNotFound));
    }
}
