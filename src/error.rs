//! Crate-wide error type.

/// Errors returned by ble-doctor.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Feature not implemented yet.
    #[error("not yet implemented (#{0})")]
    NotImplemented(u32),
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Unified BLE error: every backend failure is mapped to one of these so no
/// raw OS/backend error reaches the user. Modeled on universal_ble's
/// `UniversalBleErrorCode`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BleError {
    #[error("no Bluetooth adapter found")]
    AdapterNotFound,
    #[error("Bluetooth adapter is off")]
    AdapterOff,
    #[error("Bluetooth permission denied")]
    PermissionDenied,
    #[error("device not found")]
    DeviceNotFound,
    #[error("connection timed out")]
    ConnectTimeout,
    #[error("device disconnected")]
    Disconnected,
    #[error("{feature} is not supported on {platform}")]
    Unsupported { feature: String, platform: String },
    #[error("characteristic not found")]
    CharNotFound,
    #[error("descriptor not exposed by the OS")]
    DescriptorNotExposed,
    #[error("Bluetooth stack is busy")]
    Busy,
    /// Catch-all for unmapped backend errors.
    #[error("unexpected OS Bluetooth error: {context}")]
    OsError { context: String },
}

impl BleError {
    /// One-line actionable fix for the user (Busy text mirrors v1 bleak_retry.py `BLUEZ_RESTART_COMMAND`).
    pub fn remediation(&self) -> &'static str {
        match self {
            Self::AdapterNotFound => "Plug in or enable a Bluetooth adapter, then retry.",
            Self::AdapterOff => "Turn the Bluetooth adapter on (e.g. `bluetoothctl power on`, or the OS Bluetooth toggle).",
            Self::PermissionDenied => {
                if cfg!(target_os = "macos") {
                    "Enable Bluetooth for your terminal in System Settings > Privacy & Security > Bluetooth."
                } else {
                    "Grant Bluetooth access to this program (add your user to the `bluetooth` group or check OS privacy settings)."
                }
            }
            Self::DeviceNotFound => "Move the device closer, make sure it is advertising, and rescan.",
            Self::ConnectTimeout => "Move closer, wake the device, and retry the connection.",
            Self::Disconnected => "Reconnect to the device; it may have gone out of range or powered off.",
            Self::Unsupported { .. } => "This feature is not available on this platform; use a different OS or backend.",
            Self::CharNotFound => "The characteristic is not on this device; rerun discovery and check the UUID.",
            Self::DescriptorNotExposed => "The OS hides this descriptor; use the characteristic-level API instead.",
            Self::Busy => "Run `sudo systemctl restart bluetooth` (BlueZ) or wait for the current operation to finish.",
            Self::OsError { .. } => "Retry; if it persists, toggle Bluetooth off/on and rerun with --verbose.",
        }
    }

    fn os(context: impl Into<String>) -> Self {
        Self::OsError {
            context: context.into(),
        }
    }

    /// Map a BlueZ D-Bus error name (`org.bluez.Error.*`).
    /// Source: BlueZ doc/org.bluez.Device.rst and doc/org.bluez.Adapter.rst error lists.
    pub fn from_bluez_dbus(name: &str) -> Self {
        let short = name.strip_prefix("org.bluez.Error.").unwrap_or(name);
        match short {
            "InProgress" | "AlreadyExists" => Self::Busy,
            "NotReady" => Self::AdapterOff,
            "NotPermitted" | "AccessDenied" | "AuthenticationRejected" => Self::PermissionDenied,
            "Failed" | "ConnectionAttemptFailed" | "AuthenticationTimeout" => Self::ConnectTimeout,
            "DoesNotExist" | "NotAvailable" => Self::DeviceNotFound,
            "NotConnected" => Self::Disconnected,
            "NotSupported" => Self::Unsupported {
                feature: "operation".into(),
                platform: "linux (BlueZ)".into(),
            },
            _ => Self::os(name),
        }
    }

    /// Map a CoreBluetooth `CBError` code (Apple CBError.h, `CBErrorDomain`).
    /// Code 8 doubles as CBATTError.insufficientAuthorization, the not-authorized case.
    pub fn from_core_bluetooth(code: i64) -> Self {
        match code {
            3 | 7 => Self::Disconnected, // notConnected, peripheralDisconnected
            6 | 10 | 15 => Self::ConnectTimeout, // connectionTimeout, connectionFailed, encryptionTimedOut
            8 => Self::PermissionDenied,         // uuidNotAllowed / insufficientAuthorization
            11 => Self::Busy,                    // connectionLimitReached
            12 => Self::DeviceNotFound,          // unknownDevice
            13 => Self::Unsupported {
                feature: "operation".into(),
                platform: "macos (CoreBluetooth)".into(),
            },
            c => Self::os(format!("CBError {c}")),
        }
    }

    /// Map a WinRT/Win32 HRESULT (Microsoft winerror.h).
    pub fn from_winrt_hresult(hr: i32) -> Self {
        const E_ACCESSDENIED: i32 = 0x8007_0005_u32 as i32;
        const RPC_E_DISCONNECTED: i32 = 0x8001_0108_u32 as i32;
        const ERROR_DEVICE_NOT_AVAILABLE: i32 = 0x8007_10DF_u32 as i32; // radio off
        const ERROR_TIMEOUT: i32 = 0x8007_05B4_u32 as i32;
        const ERROR_NOT_FOUND: i32 = 0x8007_0490_u32 as i32;
        match hr {
            E_ACCESSDENIED => Self::PermissionDenied,
            RPC_E_DISCONNECTED => Self::Disconnected,
            ERROR_DEVICE_NOT_AVAILABLE => Self::AdapterOff,
            ERROR_TIMEOUT => Self::ConnectTimeout,
            ERROR_NOT_FOUND => Self::DeviceNotFound,
            h => Self::os(format!("HRESULT {:#010x}", h as u32)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bluez_mapping() {
        for (n, want) in [
            ("org.bluez.Error.InProgress", BleError::Busy),
            ("org.bluez.Error.NotReady", BleError::AdapterOff),
            ("org.bluez.Error.NotPermitted", BleError::PermissionDenied),
            ("org.bluez.Error.AccessDenied", BleError::PermissionDenied),
            ("org.bluez.Error.Failed", BleError::ConnectTimeout),
            ("org.bluez.Error.DoesNotExist", BleError::DeviceNotFound),
        ] {
            assert_eq!(BleError::from_bluez_dbus(n), want, "{n}");
        }
    }

    #[test]
    fn core_bluetooth_mapping() {
        assert_eq!(BleError::from_core_bluetooth(6), BleError::ConnectTimeout);
        assert_eq!(BleError::from_core_bluetooth(7), BleError::Disconnected);
        assert_eq!(BleError::from_core_bluetooth(8), BleError::PermissionDenied);
    }

    #[test]
    fn winrt_mapping() {
        assert_eq!(
            BleError::from_winrt_hresult(0x8007_0005_u32 as i32),
            BleError::PermissionDenied
        );
        assert_eq!(
            BleError::from_winrt_hresult(0x8001_0108_u32 as i32),
            BleError::Disconnected
        );
        assert_eq!(
            BleError::from_winrt_hresult(0x8007_10DF_u32 as i32),
            BleError::AdapterOff
        );
    }

    #[test]
    fn unknown_falls_to_os_error() {
        assert!(matches!(
            BleError::from_bluez_dbus("org.bluez.Error.Weird"),
            BleError::OsError { .. }
        ));
        assert!(matches!(
            BleError::from_core_bluetooth(9999),
            BleError::OsError { .. }
        ));
        assert!(matches!(
            BleError::from_winrt_hresult(0x1234),
            BleError::OsError { .. }
        ));
    }

    #[test]
    fn every_variant_has_remediation() {
        let all = [
            BleError::AdapterNotFound,
            BleError::AdapterOff,
            BleError::PermissionDenied,
            BleError::DeviceNotFound,
            BleError::ConnectTimeout,
            BleError::Disconnected,
            BleError::Unsupported {
                feature: "f".into(),
                platform: "p".into(),
            },
            BleError::CharNotFound,
            BleError::DescriptorNotExposed,
            BleError::Busy,
            BleError::OsError {
                context: "x".into(),
            },
        ];
        for e in all {
            assert!(!e.remediation().is_empty(), "{e:?}");
        }
        assert!(BleError::Busy
            .remediation()
            .contains("sudo systemctl restart bluetooth"));
    }
}
