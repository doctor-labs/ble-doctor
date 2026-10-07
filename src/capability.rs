//! Static capability table {feature x platform} -> verdict, consulted before any radio op.

/// Host platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    MacOs,
    Windows,
}

impl Platform {
    /// Platform this binary was compiled for (non-mac/windows falls back to Linux).
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Platform::MacOs
        } else if cfg!(target_os = "windows") {
            Platform::Windows
        } else {
            Platform::Linux
        }
    }
}

/// A BLE operation whose availability varies by platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    Scan,
    Enumerate,
    Descriptors,
    Read,
    Write,
    Subscribe,
    RetrieveMtu,
    RequestExactMtu,
    SetRandomAddress,
    RawL2cap,
    Sniff,
    Mitm,
}

/// Verdict for a (feature, platform) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Support {
    Supported,
    Unsupported,
    /// Possible, but only with the named privilege or hardware.
    NeedsCapability(&'static str),
}

/// Look up the verdict for `feature` on `platform`.
pub fn support(feature: Feature, platform: Platform) -> Support {
    use Feature::*;
    use Platform::*;
    match (feature, platform) {
        (Scan | Enumerate | Descriptors | Read | Write | Subscribe | RetrieveMtu, _) => {
            Support::Supported
        }
        (RequestExactMtu, Linux) => Support::Supported,
        (SetRandomAddress, Linux) => Support::NeedsCapability("CAP_NET_ADMIN"),
        (RawL2cap, Linux) => Support::NeedsCapability("CAP_NET_RAW"),
        (RequestExactMtu | SetRandomAddress | RawL2cap, MacOs | Windows) => Support::Unsupported,
        (Sniff, _) => Support::NeedsCapability("sniffer hardware"),
        (Mitm, Linux) => Support::NeedsCapability("second adapter + peripheral mode"),
        (Mitm, MacOs | Windows) => Support::Unsupported,
    }
}

/// Fail cleanly if `feature` is Unsupported on the current platform.
// TODO(#2): return `crate::error::BleError::Unsupported{feature, platform}` once #2 merges.
pub fn require(feature: Feature) -> Result<(), String> {
    let platform = Platform::current();
    match support(feature, platform) {
        Support::Unsupported => Err(format!("{feature:?} unsupported on {platform:?}")),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Platform; 3] = [Platform::Linux, Platform::MacOs, Platform::Windows];

    #[test]
    fn scan_supported_everywhere() {
        for p in ALL {
            assert_eq!(support(Feature::Scan, p), Support::Supported);
        }
    }

    #[test]
    fn exact_mtu_matrix() {
        assert_eq!(
            support(Feature::RequestExactMtu, Platform::MacOs),
            Support::Unsupported
        );
        assert_eq!(
            support(Feature::RequestExactMtu, Platform::Windows),
            Support::Unsupported
        );
        assert_eq!(
            support(Feature::RequestExactMtu, Platform::Linux),
            Support::Supported
        );
    }

    #[test]
    fn privileged_and_hardware_verdicts() {
        assert_eq!(
            support(Feature::RawL2cap, Platform::Linux),
            Support::NeedsCapability("CAP_NET_RAW")
        );
        assert_eq!(
            support(Feature::Mitm, Platform::Windows),
            Support::Unsupported
        );
        for p in ALL {
            assert!(matches!(
                support(Feature::Sniff, p),
                Support::NeedsCapability(_)
            ));
        }
    }

    #[test]
    fn require_gates_on_current_platform() {
        assert!(require(Feature::Scan).is_ok());
        if Platform::current() != Platform::Linux {
            assert!(require(Feature::RawL2cap).is_err());
        }
    }
}
