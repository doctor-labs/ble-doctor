//! Raw ATT/L2CAP + HCI transport foundation (Linux). The wire codecs are pure
//! and cross-platform; the radio-touching part is `#[cfg(target_os = "linux")]`.
//! #16 (exact MTU) and #17 (set random address) build on this.

use crate::capability::{support, Feature, Platform, Support};
use crate::error::BleError;

const ATT_EXCHANGE_MTU_REQ: u8 = 0x02;
const ATT_EXCHANGE_MTU_RSP: u8 = 0x03;
/// HCI opcode = OGF << 10 | OCF; LE Set Random Address = OGF 0x08, OCF 0x0005.
const HCI_LE_SET_RANDOM_ADDRESS: u16 = (0x08 << 10) | 0x0005;

/// Fail with `BleError::Unsupported` where raw L2CAP/HCI cannot work (non-Linux).
pub fn ensure_raw_supported() -> Result<(), BleError> {
    let platform = Platform::current();
    match support(Feature::RawL2cap, platform) {
        Support::Unsupported => Err(BleError::Unsupported {
            feature: "raw L2CAP/HCI".into(),
            platform: std::env::consts::OS.into(),
        }),
        _ => Ok(()),
    }
}

/// ATT Exchange MTU Request: opcode 0x02 + client MTU (little-endian).
pub fn encode_att_exchange_mtu_request(mtu: u16) -> [u8; 3] {
    let m = mtu.to_le_bytes();
    [ATT_EXCHANGE_MTU_REQ, m[0], m[1]]
}

/// Parse an ATT Exchange MTU Response (opcode 0x03 + server MTU); `None` if malformed.
pub fn parse_att_exchange_mtu_response(pdu: &[u8]) -> Option<u16> {
    match pdu {
        [ATT_EXCHANGE_MTU_RSP, lo, hi] => Some(u16::from_le_bytes([*lo, *hi])),
        _ => None,
    }
}

/// HCI LE Set Random Address command (without the H4 0x01 indicator):
/// opcode 0x2005 (LE), plen 6, address on the wire little-endian.
/// `addr` is in display order (`AA:BB:CC:DD:EE:FF` -> `[0xAA, .., 0xFF]`).
pub fn encode_hci_le_set_random_address(addr: [u8; 6]) -> Vec<u8> {
    let op = HCI_LE_SET_RANDOM_ADDRESS.to_le_bytes();
    let mut v = vec![op[0], op[1], 6];
    v.extend(addr.iter().rev());
    v
}

/// The CTF needs exactly this MTU (flag 16).
pub const CTF_MTU: u16 = 444;

/// Succeed only if the peer negotiated exactly what we asked for.
pub fn check_negotiated(requested: u16, got: u16) -> Result<u16, BleError> {
    if got == requested {
        Ok(got)
    } else {
        Err(BleError::OsError {
            context: format!("MTU negotiated {got}, requested {requested}"),
        })
    }
}

/// Request exactly `mtu` from `peer` (LE public address) over a raw ATT channel.
/// Unsupported off Linux; errors if the negotiated MTU differs from `mtu`.
pub async fn request_exact_mtu(peer: &str, mtu: u16) -> Result<u16, BleError> {
    ensure_raw_supported()?;
    crate::capability::require(Feature::RequestExactMtu).map_err(|_| BleError::Unsupported {
        feature: "exact MTU request".into(),
        platform: std::env::consts::OS.into(),
    })?;
    request_exact_mtu_impl(peer, mtu).await
}

/// Parse `AA:BB:CC:DD:EE:FF` (6 hex octets, any case) into display-order bytes.
pub fn parse_bd_addr(s: &str) -> Result<[u8; 6], BleError> {
    let bad = || BleError::OsError {
        context: format!("invalid BLE address {s:?} (want AA:BB:CC:DD:EE:FF)"),
    };
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for b in out.iter_mut() {
        let p = parts.next().ok_or_else(bad)?;
        if p.len() != 2 {
            return Err(bad());
        }
        *b = u8::from_str_radix(p, 16).map_err(|_| bad())?;
    }
    if parts.next().is_some() {
        return Err(bad());
    }
    Ok(out)
}

/// Set the controller's random address to `addr`, then connect to `peer`
/// so the peer sees `addr`. Unsupported off Linux.
pub async fn set_random_address_and_connect(addr: &str, peer: &str) -> Result<(), BleError> {
    ensure_raw_supported()?;
    crate::capability::require(Feature::SetRandomAddress).map_err(|_| BleError::Unsupported {
        feature: "set random address".into(),
        platform: std::env::consts::OS.into(),
    })?;
    set_random_address_and_connect_impl(parse_bd_addr(addr)?, peer).await
}

#[cfg(target_os = "linux")]
async fn set_random_address_and_connect_impl(addr: [u8; 6], peer: &str) -> Result<(), BleError> {
    let peer: bluer::Address = peer.parse().map_err(|_| BleError::OsError {
        context: format!("invalid address {peer}"),
    })?;
    // ponytail: hci0 only; the kernel picks own_address_type, so the random
    // address is used only if the controller/kernel selects it (live-verify, #17 deferred).
    send_hci_command(0, &encode_hci_le_set_random_address(addr))?;
    open_att_channel(peer).await.map(drop)
}

#[cfg(not(target_os = "linux"))]
async fn set_random_address_and_connect_impl(_addr: [u8; 6], _peer: &str) -> Result<(), BleError> {
    Err(BleError::Unsupported {
        feature: "set random address".into(),
        platform: std::env::consts::OS.into(),
    })
}

#[cfg(target_os = "linux")]
async fn request_exact_mtu_impl(peer: &str, mtu: u16) -> Result<u16, BleError> {
    let addr: bluer::Address = peer.parse().map_err(|_| BleError::OsError {
        context: format!("invalid address {peer}"),
    })?;
    let mut ch = open_att_channel(addr).await?;
    check_negotiated(mtu, exchange_mtu(&mut ch, mtu).await?)
}

#[cfg(not(target_os = "linux"))]
async fn request_exact_mtu_impl(_peer: &str, _mtu: u16) -> Result<u16, BleError> {
    Err(BleError::Unsupported {
        feature: "exact MTU request".into(),
        platform: std::env::consts::OS.into(),
    })
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use bluer::l2cap::{SocketAddr, Stream};
    use bluer::{Address, AddressType};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// ATT PSM (0x001F). ponytail: bluer's l2cap API addresses by PSM, not
    /// fixed CID 4; switch to a raw L2CAP socket if a peer needs the fixed channel.
    const ATT_PSM: u16 = 0x001F;

    fn os_err(e: impl std::fmt::Display) -> BleError {
        BleError::OsError {
            context: e.to_string(),
        }
    }

    /// Open an L2CAP ATT channel to `peer` (LE public address).
    pub async fn open_att_channel(peer: Address) -> Result<Stream, BleError> {
        ensure_raw_supported()?;
        Stream::connect(SocketAddr::new(peer, AddressType::LePublic, ATT_PSM))
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::PermissionDenied => BleError::PermissionDenied,
                std::io::ErrorKind::TimedOut => BleError::ConnectTimeout,
                _ => os_err(e),
            })
    }

    /// Send our MTU request on an open ATT channel and return the server MTU.
    pub async fn exchange_mtu(stream: &mut Stream, mtu: u16) -> Result<u16, BleError> {
        stream
            .write_all(&encode_att_exchange_mtu_request(mtu))
            .await
            .map_err(os_err)?;
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.map_err(os_err)?;
        parse_att_exchange_mtu_response(&buf[..n]).ok_or_else(|| BleError::OsError {
            context: "malformed ATT MTU response".into(),
        })
    }

    #[repr(C)]
    struct SockaddrHci {
        family: libc::sa_family_t,
        dev: u16,
        channel: u16,
    }

    /// Send a raw HCI command (as from the `encode_hci_*` helpers) on adapter `hci_dev`.
    /// Needs CAP_NET_RAW (and CAP_NET_ADMIN for most commands).
    pub fn send_hci_command(hci_dev: u16, cmd: &[u8]) -> Result<(), BleError> {
        ensure_raw_supported()?;
        const BTPROTO_HCI: libc::c_int = 1;
        const HCI_CHANNEL_RAW: u16 = 0;
        const HCI_COMMAND_PKT: u8 = 0x01;
        // SAFETY: plain syscalls; the fd is wrapped in OwnedFd immediately.
        let fd = unsafe {
            let raw = libc::socket(
                libc::AF_BLUETOOTH,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                BTPROTO_HCI,
            );
            if raw < 0 {
                return Err(map_errno());
            }
            OwnedFd::from_raw_fd(raw)
        };
        let addr = SockaddrHci {
            family: libc::AF_BLUETOOTH as libc::sa_family_t,
            dev: hci_dev,
            channel: HCI_CHANNEL_RAW,
        };
        let mut pkt = vec![HCI_COMMAND_PKT];
        pkt.extend_from_slice(cmd);
        // SAFETY: addr/pkt outlive the calls and sizes match.
        unsafe {
            if libc::bind(
                fd.as_raw_fd(),
                &addr as *const SockaddrHci as *const libc::sockaddr,
                std::mem::size_of::<SockaddrHci>() as libc::socklen_t,
            ) < 0
                || libc::write(fd.as_raw_fd(), pkt.as_ptr().cast(), pkt.len()) < 0
            {
                return Err(map_errno());
            }
        }
        Ok(())
    }

    fn map_errno() -> BleError {
        let e = std::io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EPERM | libc::EACCES) => BleError::PermissionDenied,
            Some(libc::ENODEV) => BleError::AdapterNotFound,
            _ => os_err(e),
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{exchange_mtu, open_att_channel, send_hci_command};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtu_request_bytes() {
        assert_eq!(encode_att_exchange_mtu_request(444), [0x02, 0xBC, 0x01]);
        assert_eq!(encode_att_exchange_mtu_request(23), [0x02, 0x17, 0x00]);
    }

    #[test]
    fn mtu_response_roundtrip() {
        let req = encode_att_exchange_mtu_request(444);
        let rsp = [ATT_EXCHANGE_MTU_RSP, req[1], req[2]];
        assert_eq!(parse_att_exchange_mtu_response(&rsp), Some(444));
        assert_eq!(parse_att_exchange_mtu_response(&req), None);
        assert_eq!(parse_att_exchange_mtu_response(&[0x03, 0x17]), None);
    }

    #[test]
    fn set_random_address_bytes() {
        assert_eq!(
            encode_hci_le_set_random_address([0xC1, 0x22, 0x33, 0x44, 0x55, 0x66]),
            [0x05, 0x20, 0x06, 0x66, 0x55, 0x44, 0x33, 0x22, 0xC1]
        );
    }

    #[test]
    fn parse_bd_addr_ok_and_errors() {
        assert_eq!(
            parse_bd_addr("11:22:33:44:55:66").unwrap(),
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
        );
        assert_eq!(parse_bd_addr("aA:bb:CC:dd:EE:ff").unwrap()[0], 0xAA);
        for bad in [
            "11:22:33:44:55",
            "11:22:33:44:55:66:77",
            "11:22:33:44:55:GG",
            "112233445566",
            "",
        ] {
            assert!(parse_bd_addr(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn set_random_address_hci_bytes_for_ctf_addr() {
        let a = parse_bd_addr("11:22:33:44:55:66").unwrap();
        assert_eq!(
            encode_hci_le_set_random_address(a),
            [0x05, 0x20, 0x06, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
        );
    }

    #[test]
    fn set_random_address_unsupported_off_linux() {
        if cfg!(target_os = "linux") {
            return;
        }
        let r = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(set_random_address_and_connect(
                "11:22:33:44:55:66",
                "AA:BB:CC:DD:EE:FF",
            ));
        assert!(matches!(r, Err(BleError::Unsupported { .. })));
    }

    #[test]
    fn negotiated_must_match() {
        assert_eq!(check_negotiated(444, 444).unwrap(), 444);
        assert!(check_negotiated(444, 185).is_err());
    }

    #[test]
    fn exact_mtu_request_unsupported_off_linux() {
        let r = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(request_exact_mtu("AA:BB:CC:DD:EE:FF", CTF_MTU));
        if !cfg!(target_os = "linux") {
            assert!(matches!(r, Err(BleError::Unsupported { .. })));
        }
        assert_eq!(encode_att_exchange_mtu_request(CTF_MTU), [0x02, 0xBC, 0x01]);
    }

    #[test]
    fn gate_matches_platform() {
        let r = ensure_raw_supported();
        if cfg!(target_os = "linux") {
            assert!(r.is_ok());
        } else {
            assert!(matches!(r, Err(BleError::Unsupported { .. })));
        }
    }
}
