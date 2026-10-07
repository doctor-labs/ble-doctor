//! Radio abstraction: traits the rest of the code (and fakes) work against,
//! a btleplug-backed implementation, and pure target selection.

pub mod raw;

use crate::error::BleError;
use std::collections::BTreeMap;
use std::time::Duration;

/// One device seen during a scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveredDevice {
    /// Backend identifier (CoreBluetooth UUID on macOS, address elsewhere).
    pub id: String,
    /// Bluetooth address, when the OS exposes it (not on macOS).
    pub address: Option<String>,
    /// Name reported by the OS/GAP cache.
    pub name: Option<String>,
    /// Local name from the advertisement itself (may differ from `name`).
    pub adv_local_name: Option<String>,
    pub rssi: Option<i16>,
    /// Company id -> payload.
    pub manufacturer_data: BTreeMap<u16, Vec<u8>>,
    pub service_uuids: Vec<String>,
}

/// A BLE central able to scan. Fakes implement this in tests.
#[allow(async_fn_in_trait)]
pub trait Central {
    async fn scan(&self, timeout: Duration) -> Result<Vec<DiscoveredDevice>, BleError>;
}

/// btleplug-backed central using the first adapter.
pub struct BtleplugCentral;

fn map_err(e: btleplug::Error) -> BleError {
    use btleplug::Error as E;
    match e {
        E::PermissionDenied => BleError::PermissionDenied,
        E::DeviceNotFound => BleError::DeviceNotFound,
        E::NotConnected => BleError::Disconnected,
        E::TimedOut(_) => BleError::ConnectTimeout,
        E::NoSuchCharacteristic => BleError::CharNotFound,
        E::NotSupported(f) => BleError::Unsupported {
            feature: f,
            platform: std::env::consts::OS.into(),
        },
        other => BleError::OsError {
            context: other.to_string(),
        },
    }
}

impl Central for BtleplugCentral {
    async fn scan(&self, timeout: Duration) -> Result<Vec<DiscoveredDevice>, BleError> {
        use btleplug::api::{Central as _, Manager as _, Peripheral as _, ScanFilter};
        let manager = btleplug::platform::Manager::new().await.map_err(map_err)?;
        let adapter = manager
            .adapters()
            .await
            .map_err(map_err)?
            .into_iter()
            .next()
            .ok_or(BleError::AdapterNotFound)?;
        adapter
            .start_scan(ScanFilter::default())
            .await
            .map_err(map_err)?;
        tokio::time::sleep(timeout).await;
        let _ = adapter.stop_scan().await;
        let mut out = Vec::new();
        for p in adapter.peripherals().await.map_err(map_err)? {
            let Some(props) = p.properties().await.map_err(map_err)? else {
                continue;
            };
            let addr = props.address.to_string();
            out.push(DiscoveredDevice {
                id: p.id().to_string(),
                // CoreBluetooth reports 00:00:00:00:00:00
                address: (addr != "00:00:00:00:00:00").then_some(addr),
                name: None,
                adv_local_name: props.local_name.clone(),
                rssi: props.rssi,
                manufacturer_data: props.manufacturer_data.into_iter().collect(),
                service_uuids: props.services.iter().map(|u| u.to_string()).collect(),
            });
        }
        Ok(out)
    }
}

fn hex_only(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, ':' | '-' | ' ' | '.'))
        .collect::<String>()
        .to_lowercase()
}

fn is_address(s: &str) -> bool {
    let h = hex_only(s);
    h.len() == 12 && h.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(n, p)| p.len() == *n && p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn describe(d: &DiscoveredDevice) -> String {
    format!(
        "{} (addr={}, name={}, adv={})",
        d.id,
        d.address.as_deref().unwrap_or("-"),
        d.name.as_deref().unwrap_or("-"),
        d.adv_local_name.as_deref().unwrap_or("-")
    )
}

/// Pick the target device. Errors are `BleError::OsError` with a message
/// listing candidates for the ambiguous / no-match cases, and
/// `DeviceNotFound` when there is nothing to choose from.
// ponytail: ambiguity/no-match reuse OsError{context}; add dedicated variants if callers need to match on them.
pub fn select_target_device<'a>(
    devices: &'a [DiscoveredDevice],
    selector: &str,
) -> Result<&'a DiscoveredDevice, BleError> {
    let list = |ds: &[&DiscoveredDevice]| {
        ds.iter()
            .map(|d| describe(d))
            .collect::<Vec<_>>()
            .join("; ")
    };
    let all: Vec<&DiscoveredDevice> = devices.iter().collect();
    let sel = selector.trim();
    if devices.is_empty() {
        return Err(BleError::DeviceNotFound);
    }
    if sel.is_empty() {
        return match devices {
            [only] => Ok(only),
            _ => Err(BleError::OsError {
                context: format!("multiple devices found, pass a target: {}", list(&all)),
            }),
        };
    }
    let no_match = || BleError::OsError {
        context: format!("no device matches '{sel}'; candidates: {}", list(&all)),
    };
    if is_uuid(sel) {
        return devices
            .iter()
            .find(|d| d.id.eq_ignore_ascii_case(sel))
            .ok_or_else(no_match);
    }
    if is_address(sel) {
        let want = hex_only(sel);
        return devices
            .iter()
            .find(|d| d.address.as_deref().is_some_and(|a| hex_only(a) == want))
            .ok_or_else(no_match);
    }
    let names = |d: &DiscoveredDevice| [d.name.clone(), d.adv_local_name.clone()];
    let exact: Vec<&DiscoveredDevice> = devices
        .iter()
        .filter(|d| names(d).iter().flatten().any(|n| n == sel))
        .collect();
    let hits = if exact.is_empty() {
        let low = sel.to_lowercase();
        devices
            .iter()
            .filter(|d| {
                names(d)
                    .iter()
                    .flatten()
                    .any(|n| n.to_lowercase().contains(&low))
            })
            .collect()
    } else {
        exact
    };
    match hits.as_slice() {
        [one] => Ok(one),
        [] => Err(no_match()),
        many => Err(BleError::OsError {
            context: format!("'{sel}' is ambiguous: {}", list(many)),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(
        id: &str,
        addr: Option<&str>,
        name: Option<&str>,
        adv: Option<&str>,
    ) -> DiscoveredDevice {
        DiscoveredDevice {
            id: id.into(),
            address: addr.map(Into::into),
            name: name.map(Into::into),
            adv_local_name: adv.map(Into::into),
            ..Default::default()
        }
    }

    const U1: &str = "6F1B2C3D-0000-4000-8000-00805F9B34FB";
    const U2: &str = "11111111-2222-3333-4444-555555555555";

    fn sample() -> Vec<DiscoveredDevice> {
        vec![
            dev(
                U1,
                Some("AA:BB:CC:DD:EE:01"),
                Some("Thermo"),
                Some("ThermoAdv"),
            ),
            dev(U2, Some("AA:BB:CC:DD:EE:02"), None, Some("Lock-One")),
            dev("x3", None, Some("Lock-Two"), None),
        ]
    }

    #[test]
    fn address_any_separator_and_case() {
        let d = sample();
        assert_eq!(
            select_target_device(&d, "aa-bb-cc-dd-ee-02").unwrap().id,
            U2
        );
        assert_eq!(select_target_device(&d, "AABBCCDDEE01").unwrap().id, U1);
        assert!(select_target_device(&d, "AA:BB:CC:DD:EE:99").is_err());
    }

    #[test]
    fn identifier_match() {
        let d = sample();
        assert_eq!(select_target_device(&d, &U1.to_lowercase()).unwrap().id, U1);
        assert!(select_target_device(&d, "00000000-0000-0000-0000-000000000000").is_err());
    }

    #[test]
    fn exact_and_substring_name() {
        let d = sample();
        assert_eq!(select_target_device(&d, "Thermo").unwrap().id, U1);
        assert_eq!(select_target_device(&d, "lock-t").unwrap().id, "x3");
    }

    #[test]
    fn exact_beats_substring() {
        let d = vec![
            dev("a", None, Some("Lock"), None),
            dev("b", None, Some("Lock-Two"), None),
        ];
        assert_eq!(select_target_device(&d, "Lock").unwrap().id, "a");
    }

    #[test]
    fn advertised_name_differs_from_name() {
        let d = sample();
        // matches adv_local_name only (name is "Thermo")
        assert_eq!(select_target_device(&d, "ThermoAdv").unwrap().id, U1);
        assert_eq!(select_target_device(&d, "lock-one").unwrap().id, U2);
    }

    #[test]
    fn ambiguous_substring_refused() {
        let d = sample();
        let e = select_target_device(&d, "lock").unwrap_err();
        assert!(e.to_string().contains("ambiguous"), "{e}");
    }

    #[test]
    fn empty_selector_sole_vs_many() {
        let d = sample();
        assert_eq!(select_target_device(&d[..1], "").unwrap().id, U1);
        assert!(select_target_device(&d, "").is_err());
        assert_eq!(select_target_device(&[], ""), Err(BleError::DeviceNotFound));
    }

    #[test]
    fn no_match_lists_candidates() {
        let d = sample();
        let e = select_target_device(&d, "nothing").unwrap_err().to_string();
        assert!(e.contains("Thermo") && e.contains("Lock-One"), "{e}");
    }

    struct Fake(Vec<DiscoveredDevice>);
    impl Central for Fake {
        async fn scan(&self, _: Duration) -> Result<Vec<DiscoveredDevice>, BleError> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn fake_central_works_through_trait() {
        let f = Fake(sample());
        let found = f.scan(Duration::ZERO).await.unwrap();
        assert_eq!(select_target_device(&found, "ThermoAdv").unwrap().id, U1);
    }
}
