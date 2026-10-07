//! Linux client over BlueZ (bluer) that keeps a discovery session open across
//! `connect()`, avoiding the kernel 6.15+ `le-connection-abort-by-local` failure
//! (bluez#2503) that follows btleplug's stop-scan-then-connect.

use super::{GattClient, WriteError};
use crate::error::BleError;
use crate::gatt::{GattChar, GattDescriptor, GattService};
use bluer::gatt::remote::Characteristic;
use bluer::gatt::CharacteristicFlags;
use std::str::FromStr;
use std::time::Duration;

/// Aborts the discovery-drain task on drop, which drops the stream and stops discovery.
struct DrainGuard(tokio::task::JoinHandle<()>);

impl Drop for DrainGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub struct BluerGattClient {
    device: bluer::Device,
    _drain: DrainGuard,
}

fn map_err(e: bluer::Error) -> BleError {
    let s = e.to_string();
    let l = s.to_lowercase();
    if l.contains("abort") {
        BleError::OsError { context: s }
    } else if l.contains("not authorized") || l.contains("permission") || l.contains("access") {
        BleError::PermissionDenied
    } else if l.contains("not found") || l.contains("does not exist") {
        BleError::DeviceNotFound
    } else if l.contains("timeout") || l.contains("timed out") {
        BleError::ConnectTimeout
    } else {
        BleError::OsError { context: s }
    }
}

fn flag_names(f: &CharacteristicFlags) -> Vec<String> {
    [
        (f.broadcast, "broadcast"),
        (f.read, "read"),
        (f.write_without_response, "write-without-response"),
        (f.write, "write"),
        (f.notify, "notify"),
        (f.indicate, "indicate"),
        (f.authenticated_signed_writes, "authenticated-signed-writes"),
        (f.extended_properties, "extended-properties"),
    ]
    .into_iter()
    .filter(|(b, _)| *b)
    .map(|(_, n)| n.to_string())
    .collect()
}

impl BluerGattClient {
    /// Connect to `addr` on `adapter_name` (default adapter when `None`) with
    /// discovery held open for the whole connect attempt and the client's lifetime.
    /// `_timeout` is unused: connect retries are bounded (6 x 500ms gaps) instead.
    pub async fn connect(
        adapter_name: Option<&str>,
        addr: &str,
        _timeout: Duration,
    ) -> Result<Self, BleError> {
        use futures::StreamExt;
        let session = bluer::Session::new().await.map_err(map_err)?;
        let adapter = match adapter_name {
            Some(n) => session.adapter(n).map_err(|_| BleError::AdapterNotFound)?,
            None => session
                .default_adapter()
                .await
                .map_err(|_| BleError::AdapterNotFound)?,
        };
        adapter.set_powered(true).await.map_err(map_err)?;
        let a = bluer::Address::from_str(addr).map_err(|_| BleError::DeviceNotFound)?;

        // Hold discovery: bluer stops it when this stream is dropped.
        let mut events = adapter.discover_devices().await.map_err(map_err)?;
        let drain = tokio::spawn(async move { while events.next().await.is_some() {} });
        let guard = DrainGuard(drain);
        tokio::time::sleep(Duration::from_millis(500)).await;

        // On any error below `guard` drops and aborts discovery.
        let device = adapter.device(a).map_err(map_err)?;
        let mut last = None;
        for _ in 0..6 {
            match device.connect().await {
                Ok(()) => {
                    last = None;
                    break;
                }
                Err(e) => {
                    last = Some(e);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
        if let Some(e) = last {
            return Err(map_err(e));
        }
        Ok(Self {
            device,
            _drain: guard,
        })
    }

    async fn find(&self, uuid: &str) -> Result<Characteristic, BleError> {
        let want = uuid.to_lowercase();
        for s in self.device.services().await.map_err(map_err)? {
            for c in s.characteristics().await.map_err(map_err)? {
                if c.uuid().await.map_err(map_err)?.to_string() == want {
                    return Ok(c);
                }
            }
        }
        Err(BleError::CharNotFound)
    }
}

impl GattClient for BluerGattClient {
    async fn services(&self) -> Result<Vec<GattService>, BleError> {
        let mut out = Vec::new();
        for s in self.device.services().await.map_err(map_err)? {
            let su = s.uuid().await.map_err(map_err)?;
            let mut chars = Vec::new();
            for c in s.characteristics().await.map_err(map_err)? {
                let cu = c.uuid().await.map_err(map_err)?;
                let flags = c.flags().await.map_err(map_err)?;
                let mut ds = Vec::new();
                for d in c.descriptors().await.map_err(map_err)? {
                    ds.push(GattDescriptor {
                        uuid: d.uuid().await.map_err(map_err)?.to_string(),
                    });
                }
                chars.push(GattChar {
                    uuid: cu.to_string(),
                    properties: flag_names(&flags),
                    description: None,
                    descriptors: Some(ds),
                });
            }
            out.push(GattService {
                uuid: su.to_string(),
                characteristics: chars,
            });
        }
        Ok(out)
    }

    async fn write(&self, uuid: &str, data: &[u8]) -> Result<(), WriteError> {
        let c = self.find(uuid).await?;
        // ponytail: bluer does not expose ATT error codes; all failures map to Ble.
        c.write(data).await.map_err(|e| WriteError::Ble(map_err(e)))
    }

    async fn read(&self, uuid: &str) -> Result<Vec<u8>, BleError> {
        self.find(uuid).await?.read().await.map_err(map_err)
    }
}
