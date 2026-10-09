//! HCI Read Remote Supported/Extended Features + Read Remote Version Information
//! (Core Spec Vol 4 Part E 7.1.21 / 7.1.22 / 7.1.23). The codecs and the request/response
//! loop are pure and run over the [`HciIo`] trait; only [`linux`] touches a raw HCI socket.
//! Live validation against a real controller + dual-mode target is tracked in #70.

use crate::fingerprint::{parse_lmp, LmpInfo};

pub const OP_READ_REMOTE_FEATURES: u16 = (0x01 << 10) | 0x001B;
pub const OP_READ_REMOTE_EXT_FEATURES: u16 = (0x01 << 10) | 0x001C;
pub const OP_READ_REMOTE_VERSION: u16 = (0x01 << 10) | 0x001D;
pub const EVT_COMMAND_STATUS: u8 = 0x0F;
pub const EVT_REMOTE_FEATURES_COMPLETE: u8 = 0x0B;
pub const EVT_REMOTE_VERSION_COMPLETE: u8 = 0x0C;
pub const EVT_REMOTE_EXT_FEATURES_COMPLETE: u8 = 0x23;
const HCI_EVENT_PKT: u8 = 0x04;

/// A transport that sends HCI commands and yields raw H4 event packets
/// (`0x04, event code, plen, params..`). `next_event` errors on timeout.
pub trait HciIo {
    fn command(&mut self, opcode: u16, params: &[u8]) -> Result<(), String>;
    fn next_event(&mut self) -> Result<Vec<u8>, String>;
}

/// Split an H4 event packet into `(event code, parameters)`.
pub fn parse_event(pkt: &[u8]) -> Option<(u8, &[u8])> {
    match pkt {
        [HCI_EVENT_PKT, code, plen, rest @ ..] => Some((*code, rest.get(..*plen as usize)?)),
        _ => None,
    }
}

/// Send `opcode`, wait for `want` (Complete event) on connection `handle`; return its parameters
/// (status, handle:2, ...). Errors on a rejected Command Status or non-zero Complete status.
fn request<T: HciIo>(
    io: &mut T,
    opcode: u16,
    params: &[u8],
    want: u8,
    handle: u16,
) -> Result<Vec<u8>, String> {
    io.command(opcode, params)?;
    loop {
        let pkt = io.next_event()?;
        match parse_event(&pkt) {
            Some((EVT_COMMAND_STATUS, [status, _, o0, o1])) => {
                if u16::from_le_bytes([*o0, *o1]) == opcode && *status != 0 {
                    return Err(format!(
                        "controller rejected HCI command 0x{opcode:04x} (status 0x{status:02x})"
                    ));
                }
            }
            Some((code, p)) if code == want && p.len() >= 3 => {
                if u16::from_le_bytes([p[1], p[2]]) & 0x0FFF != handle {
                    continue;
                }
                return match p[0] {
                    0 => Ok(p.to_vec()),
                    s => Err(format!("HCI event 0x{code:02x} status 0x{s:02x}")),
                };
            }
            _ => {}
        }
    }
}

fn page_of(p: &[u8], off: usize) -> Result<[u8; 8], String> {
    p.get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| "truncated features event".to_string())
}

/// Query the remote's LMP version and feature pages 0..=2 over ACL connection `handle`.
/// Page 0 and the version are required; pages 1/2 are best-effort (older peers lack them).
pub fn read_remote_lmp<T: HciIo>(io: &mut T, handle: u16) -> Result<LmpInfo, String> {
    let h = handle.to_le_bytes();
    let p0 = request(
        io,
        OP_READ_REMOTE_FEATURES,
        &h,
        EVT_REMOTE_FEATURES_COMPLETE,
        handle,
    )?;
    let page0 = page_of(&p0, 3)?;
    let mut pages = vec![page0];
    // Page 0 byte 7 bit 7: extended features supported.
    if page0[7] & 0x80 != 0 {
        let mut max_page = 2u8;
        let mut n = 1u8;
        while n <= max_page.min(2) {
            let Ok(p) = request(
                io,
                OP_READ_REMOTE_EXT_FEATURES,
                &[h[0], h[1], n],
                EVT_REMOTE_EXT_FEATURES_COMPLETE,
                handle,
            ) else {
                break;
            };
            // status, handle:2, page number, max page, features:8
            let (Some(&max), Ok(f)) = (p.get(4), page_of(&p, 5)) else {
                break;
            };
            max_page = max;
            pages.push(f);
            n += 1;
        }
    }
    let v = request(
        io,
        OP_READ_REMOTE_VERSION,
        &h,
        EVT_REMOTE_VERSION_COMPLETE,
        handle,
    )?;
    parse_lmp(&pages, &v)
}

#[cfg(target_os = "linux")]
pub mod linux {
    use super::*;
    use crate::error::BleError;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    #[repr(C)]
    struct SockaddrHci {
        family: libc::sa_family_t,
        dev: u16,
        channel: u16,
    }

    #[repr(C)]
    #[derive(Default)]
    struct HciFilter {
        type_mask: u32,
        event_mask: [u32; 2],
        opcode: u16,
    }

    /// Raw HCI socket on one adapter. Needs CAP_NET_RAW.
    pub struct RawHci(OwnedFd);

    fn errno() -> BleError {
        let e = std::io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EPERM | libc::EACCES) => BleError::PermissionDenied,
            Some(libc::ENODEV) => BleError::AdapterNotFound,
            _ => BleError::OsError {
                context: e.to_string(),
            },
        }
    }

    impl RawHci {
        pub fn open(hci_dev: u16, timeout_secs: u64) -> Result<Self, BleError> {
            const BTPROTO_HCI: libc::c_int = 1;
            const SOL_HCI: libc::c_int = 0;
            const HCI_FILTER: libc::c_int = 2;
            // SAFETY: plain syscalls; the fd is owned immediately; buffers outlive the calls.
            unsafe {
                let raw = libc::socket(
                    libc::AF_BLUETOOTH,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    BTPROTO_HCI,
                );
                if raw < 0 {
                    return Err(errno());
                }
                let fd = OwnedFd::from_raw_fd(raw);
                // Only the events this collector reads.
                let mut f = HciFilter {
                    type_mask: 1 << HCI_EVENT_PKT,
                    ..Default::default()
                };
                for code in [
                    EVT_COMMAND_STATUS,
                    EVT_REMOTE_FEATURES_COMPLETE,
                    EVT_REMOTE_VERSION_COMPLETE,
                    EVT_REMOTE_EXT_FEATURES_COMPLETE,
                ] {
                    f.event_mask[code as usize / 32] |= 1 << (code % 32);
                }
                let tv = libc::timeval {
                    tv_sec: timeout_secs as libc::time_t,
                    tv_usec: 0,
                };
                let a = SockaddrHci {
                    family: libc::AF_BLUETOOTH as libc::sa_family_t,
                    dev: hci_dev,
                    channel: 0, // HCI_CHANNEL_RAW
                };
                if libc::setsockopt(
                    fd.as_raw_fd(),
                    SOL_HCI,
                    HCI_FILTER,
                    (&f as *const HciFilter).cast(),
                    std::mem::size_of::<HciFilter>() as libc::socklen_t,
                ) < 0
                    || libc::setsockopt(
                        fd.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_RCVTIMEO,
                        (&tv as *const libc::timeval).cast(),
                        std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                    ) < 0
                    || libc::bind(
                        fd.as_raw_fd(),
                        (&a as *const SockaddrHci).cast(),
                        std::mem::size_of::<SockaddrHci>() as libc::socklen_t,
                    ) < 0
                {
                    return Err(errno());
                }
                Ok(Self(fd))
            }
        }

        /// ACL connection handle of `peer` (display order) via HCIGETCONNINFO.
        pub fn acl_handle(&self, peer: [u8; 6]) -> Result<u16, BleError> {
            const HCIGETCONNINFO: u32 = 0x800448D5; // _IOR('H', 213, int)
            const ACL_LINK: u8 = 1;
            // struct hci_conn_info_req { bdaddr[6]; u8 type; <pad>; hci_conn_info { u16 handle; .. } }
            let mut buf = [0u8; 24];
            for (i, b) in peer.iter().rev().enumerate() {
                buf[i] = *b;
            }
            buf[6] = ACL_LINK;
            // SAFETY: buf is large enough for the request header plus one hci_conn_info.
            if unsafe { libc::ioctl(self.0.as_raw_fd(), HCIGETCONNINFO as _, buf.as_mut_ptr()) } < 0
            {
                return Err(errno());
            }
            Ok(u16::from_le_bytes([buf[8], buf[9]]))
        }
    }

    impl HciIo for RawHci {
        fn command(&mut self, opcode: u16, params: &[u8]) -> Result<(), String> {
            let mut pkt = vec![0x01];
            pkt.extend(opcode.to_le_bytes());
            pkt.push(params.len() as u8);
            pkt.extend(params);
            // SAFETY: pkt outlives the call.
            if unsafe { libc::write(self.0.as_raw_fd(), pkt.as_ptr().cast(), pkt.len()) } < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            Ok(())
        }

        fn next_event(&mut self) -> Result<Vec<u8>, String> {
            let mut buf = [0u8; 260];
            // SAFETY: buf outlives the call.
            let n = unsafe { libc::read(self.0.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                return Err(match e.raw_os_error() {
                    Some(libc::EAGAIN) => "timed out waiting for the remote's LMP response".into(),
                    _ => e.to_string(),
                });
            }
            Ok(buf[..n as usize].to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Scripted transport: replies are queued per command opcode.
    struct Mock {
        sent: Vec<(u16, Vec<u8>)>,
        queue: VecDeque<Vec<u8>>,
        replies: Vec<(u16, Vec<Vec<u8>>)>,
    }
    impl HciIo for Mock {
        fn command(&mut self, op: u16, p: &[u8]) -> Result<(), String> {
            self.sent.push((op, p.to_vec()));
            // each scripted reply is delivered once
            if let Some(i) = self.replies.iter().position(|(o, _)| *o == op) {
                self.queue.extend(self.replies.remove(i).1);
            }
            Ok(())
        }
        fn next_event(&mut self) -> Result<Vec<u8>, String> {
            self.queue.pop_front().ok_or_else(|| "timed out".into())
        }
    }

    fn evt(code: u8, params: &[u8]) -> Vec<u8> {
        let mut v = vec![HCI_EVENT_PKT, code, params.len() as u8];
        v.extend(params);
        v
    }
    fn status(st: u8, op: u16) -> Vec<u8> {
        let o = op.to_le_bytes();
        evt(EVT_COMMAND_STATUS, &[st, 1, o[0], o[1]])
    }

    const H: u16 = 0x0040;

    fn mock(page0: [u8; 8]) -> Mock {
        let h = H.to_le_bytes();
        let mut f0 = vec![0, h[0], h[1]];
        f0.extend(page0);
        let ext = |n: u8, f: [u8; 8]| {
            let mut p = vec![0, h[0], h[1], n, 2];
            p.extend(f);
            evt(EVT_REMOTE_EXT_FEATURES_COMPLETE, &p)
        };
        Mock {
            sent: vec![],
            queue: VecDeque::new(),
            replies: vec![
                (
                    OP_READ_REMOTE_FEATURES,
                    vec![
                        status(0, OP_READ_REMOTE_FEATURES),
                        evt(EVT_REMOTE_FEATURES_COMPLETE, &f0),
                    ],
                ),
                (
                    OP_READ_REMOTE_EXT_FEATURES,
                    // an event for another handle must be skipped
                    vec![evt(
                        EVT_REMOTE_EXT_FEATURES_COMPLETE,
                        &[0, 0x41, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0],
                    )],
                ),
                (
                    OP_READ_REMOTE_VERSION,
                    vec![
                        status(0, OP_READ_REMOTE_VERSION),
                        evt(
                            EVT_REMOTE_VERSION_COMPLETE,
                            &[0, h[0], h[1], 0x0B, 0x4C, 0x00, 0x34, 0x12],
                        ),
                    ],
                ),
            ],
        }
        .with_ext(ext)
    }
    impl Mock {
        fn with_ext(mut self, ext: impl Fn(u8, [u8; 8]) -> Vec<u8>) -> Self {
            // page 1: SSP + SC host; page 2: SC controller
            let r = &mut self.replies[1].1;
            r.push(ext(1, [0x09, 0, 0, 0, 0, 0, 0, 0]));
            self
        }
    }

    #[test]
    fn event_framing() {
        assert_eq!(
            parse_event(&[4, 0x0C, 2, 9, 8, 7]),
            Some((0x0C, &[9u8, 8][..]))
        );
        assert_eq!(parse_event(&[4, 0x0C, 5, 9]), None);
        assert_eq!(parse_event(&[2, 0x0C, 0]), None);
    }

    #[test]
    fn opcodes_match_spec() {
        // Core Spec Vol 4 Part E 7.1.21/22/23: OGF 0x01, OCF 0x1B/0x1C/0x1D.
        assert_eq!(OP_READ_REMOTE_FEATURES, 0x041B);
        assert_eq!(OP_READ_REMOTE_EXT_FEATURES, 0x041C);
        assert_eq!(OP_READ_REMOTE_VERSION, 0x041D);
    }

    #[test]
    fn full_exchange_page0_and_page1() {
        // page 0: byte 7 bit 7 (extended features) set; page 1 reply stops the loop on page 2 timeout
        let mut m = mock([0xFF, 0xFF, 0x0D, 0x38, 0x00, 0x00, 0x08, 0x80]);
        let l = read_remote_lmp(&mut m, H).unwrap();
        assert_eq!(
            (l.lmp_version, l.manufacturer, l.subversion),
            (11, 0x4C, 0x1234)
        );
        assert_eq!(l.version, "Bluetooth 5.2");
        assert_eq!(l.manufacturer_name.as_deref(), Some("Apple, Inc."));
        assert_eq!(l.pages.len(), 2);
        assert!(l
            .features
            .iter()
            .any(|f| f == "Secure Simple Pairing (host)"));
        assert!(l.features.iter().any(|f| f == "Secure Connections (host)"));
        assert_eq!(m.sent[0], (OP_READ_REMOTE_FEATURES, vec![0x40, 0x00]));
        assert_eq!(
            m.sent[1],
            (OP_READ_REMOTE_EXT_FEATURES, vec![0x40, 0x00, 1])
        );
    }

    #[test]
    fn no_extended_features_skips_pages() {
        let mut m = mock([0xFF, 0xFF, 0x0D, 0x38, 0x00, 0x00, 0x08, 0x00]);
        let l = read_remote_lmp(&mut m, H).unwrap();
        assert_eq!(l.pages.len(), 1);
        assert!(m
            .sent
            .iter()
            .all(|(o, _)| *o != OP_READ_REMOTE_EXT_FEATURES));
    }

    #[test]
    fn rejected_command_and_timeout_are_errors() {
        let mut m = mock([0; 8]);
        m.replies[0].1 = vec![status(0x0C, OP_READ_REMOTE_FEATURES)];
        assert!(read_remote_lmp(&mut m, H).unwrap_err().contains("rejected"));
        let mut m = mock([0; 8]);
        m.replies[0].1.clear();
        assert!(read_remote_lmp(&mut m, H)
            .unwrap_err()
            .contains("timed out"));
        let mut m = mock([0; 8]);
        m.replies[0].1 = vec![evt(EVT_REMOTE_FEATURES_COMPLETE, &[0x08, 0x40, 0])];
        assert!(read_remote_lmp(&mut m, H)
            .unwrap_err()
            .contains("status 0x08"));
    }
}
