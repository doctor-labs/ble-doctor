//! Resolvable Private Address resolution (Core Spec Vol 3 Part H 2.2.2/2.2.3, the `ah` security
//! toolbox function) from a known IRK. Offline, no hardware: given an IRK the operator already
//! has (their own device, its Identity Information SMP PDU, or a vendor tool), this tells
//! `capture.rs` whether a captured address is that device's RPA, so a capture that looks like
//! several devices (distinct, "rotating" addresses) can be told apart from one device whose RPA
//! legitimately rotated — the same distinction `mac_rotation` already tries to make, just wrong
//! without this when the capture only has rotation to go on.
//!
//! The algorithm matches the Linux kernel's `smp_ah`/`smp_e` (net/bluetooth/smp.c, GPLv2) byte for
//! byte, verified against its self-test vector in `tests` below (same IRK/r/exp as the kernel's
//! `test_ah`). IRK and address bytes are taken in the same order as they appear on the air / in an
//! SMP PDU (`identity_information`'s 16-byte body; a pcap/btsnoop `AdvA` field) — NOT the reversed
//! colon-notation `fmt_mac` prints for display.

fn e(k: &[u8; 16], r: &[u8; 16]) -> [u8; 16] {
    crate::smp::e(k, r)
}

/// `ah(k, r) = e(k, r') mod 2^24` where `r'` is `r` (the 24-bit `prand`) zero-padded to 128 bits.
pub fn ah(irk: &[u8; 16], prand: &[u8; 3]) -> [u8; 3] {
    let mut padded = [0u8; 16];
    padded[..3].copy_from_slice(prand);
    let out = e(irk, &padded);
    [out[0], out[1], out[2]]
}

/// Whether `addr` (on-air order) carries the Resolvable Private Address type tag: the two
/// most-significant bits of its most-significant octet (the last on-air byte) are `01`.
pub fn is_resolvable_private_address(addr: &[u8; 6]) -> bool {
    addr[5] & 0xC0 == 0x40
}

/// Does `addr` (on-air order: 3 hash octets then 3 `prand` octets, matching `AdvA`/`InitA`) resolve
/// against `irk`? `false` for an address that isn't even RPA-tagged.
pub fn resolves(irk: &[u8; 16], addr: &[u8; 6]) -> bool {
    if !is_resolvable_private_address(addr) {
        return false;
    }
    let prand = [addr[3], addr[4], addr[5]];
    ah(irk, &prand) == [addr[0], addr[1], addr[2]]
}

/// Undo `capture::fmt_mac`'s reversal to recover the on-air byte order `resolves`/`ah` expect.
pub fn mac_str_to_onair_bytes(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    for (i, p) in parts.iter().enumerate() {
        out[5 - i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(out)
}

/// Parse a 32-hex-char IRK (same byte order as an Identity Information PDU / `--irk` on the CLI).
pub fn parse_irk(hex: &str) -> Result<[u8; 16], String> {
    let hex = hex.trim();
    if hex.len() != 32 {
        return Err(format!(
            "IRK must be 32 hex characters (16 bytes), got {}",
            hex.len()
        ));
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("IRK is not valid hex: {hex}"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Linux kernel `net/bluetooth/smp.c` `test_ah()` self-test vector (sample data from the Core
    /// Specification's security toolbox function definitions).
    #[test]
    fn ah_matches_kernel_self_test_vector() {
        let irk = [
            0x9b, 0x7d, 0x39, 0x0a, 0xa6, 0x10, 0x10, 0x34, 0x05, 0xad, 0xc8, 0x57, 0xa3, 0x34,
            0x02, 0xec,
        ];
        let r = [0x94, 0x81, 0x70];
        assert_eq!(ah(&irk, &r), [0xaa, 0xfb, 0x0d]);
    }

    #[test]
    fn rpa_type_tag() {
        assert!(is_resolvable_private_address(&[0, 0, 0, 0, 0, 0x40]));
        assert!(!is_resolvable_private_address(&[0, 0, 0, 0, 0, 0x00])); // non-resolvable private
        assert!(!is_resolvable_private_address(&[0, 0, 0, 0, 0, 0xC0])); // static random
        assert!(!is_resolvable_private_address(&[0, 0, 0, 0, 0, 0x80])); // reserved (top bits 10)
    }

    #[test]
    fn resolves_round_trip_against_the_self_test_vector() {
        let irk = [
            0x9b, 0x7d, 0x39, 0x0a, 0xa6, 0x10, 0x10, 0x34, 0x05, 0xad, 0xc8, 0x57, 0xa3, 0x34,
            0x02, 0xec,
        ];
        // hash = ah(irk, prand); prand's on-air MSB (prand[2]) carries the RPA type tag (01).
        let prand = [0x94, 0x81, 0x40];
        let hash = ah(&irk, &prand);
        let addr = [hash[0], hash[1], hash[2], prand[0], prand[1], prand[2]];
        assert!(resolves(&irk, &addr));
        let other_irk = {
            let mut k = irk;
            k[0] ^= 1;
            k
        };
        assert!(!resolves(&other_irk, &addr));
    }

    #[test]
    fn mac_str_undoes_capture_fmt_mac_reversal() {
        // capture::fmt_mac(le) = le.iter().rev() joined; on-air bytes are little-endian.
        let onair = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let display = "ff:ee:dd:cc:bb:aa";
        assert_eq!(mac_str_to_onair_bytes(display).unwrap(), onair);
    }

    #[test]
    fn irk_hex_parse() {
        let v = parse_irk("00112233445566778899aabbccddeeff");
        assert_eq!(
            v,
            Ok([
                0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ])
        );
        assert!(parse_irk("short").is_err());
        assert!(parse_irk("zz112233445566778899aabbccddeeff").is_err());
    }
}
