//! CTF helpers (own-gear / CTF scope only; see AGENTS.md).
//!
//! Ports the brute-write / read-N / write-then-read patterns used against
//! `hackgnar/ble_ctf`-style targets from v1's `solve_macos.py`. Pure
//! helpers are unit-testable without a radio; the `async` ones drive a
//! `GattClient` (real or `testkit::FakeClient`).

use crate::error::BleError;
use crate::radio::GattClient;

/// The full brute-force byte range `0x00..=0xff`, one byte per payload.
pub fn brute_payloads() -> impl Iterator<Item = [u8; 1]> {
    (0u8..=0xff).map(|b| [b])
}

/// Write each byte in `brute_payloads()` to `uuid`, reading `read_back` after
/// every write, until `stop` reports the read-back value as the flag (or the
/// write itself fails/the read fails, which is treated as "not it" and the
/// brute continues). Returns the first `(byte, read_back_value)` that satisfies
/// `stop`, or `None` if the whole range is exhausted.
pub async fn brute_write<C: GattClient>(
    client: &C,
    uuid: &str,
    read_back: &str,
    stop: impl Fn(&[u8]) -> bool,
) -> Option<(u8, Vec<u8>)> {
    for payload in brute_payloads() {
        if client.write(uuid, &payload).await.is_err() {
            continue;
        }
        let Ok(value) = client.read(read_back).await else {
            continue;
        };
        if stop(&value) {
            return Some((payload[0], value));
        }
    }
    None
}

/// Read `uuid` `n` times in a row, returning every value in order (some
/// challenges only progress on repeated reads).
pub async fn read_n<C: GattClient>(client: &C, uuid: &str, n: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        if let Ok(v) = client.read(uuid).await {
            out.push(v);
        }
    }
    out
}

/// Write `data` to `uuid`, then read `read_back` and return its value.
pub async fn write_then_read<C: GattClient>(
    client: &C,
    uuid: &str,
    data: &[u8],
    read_back: &str,
) -> Result<Vec<u8>, BleError> {
    client.write(uuid, data).await.map_err(|e| match e {
        crate::radio::WriteError::Att(_) => BleError::CharNotFound,
        crate::radio::WriteError::Ble(e) => e,
    })?;
    client.read(read_back).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{FakeClient, FakeGattTree};

    #[test]
    fn brute_payloads_covers_full_byte_range() {
        let v: Vec<_> = brute_payloads().collect();
        assert_eq!(v.len(), 256);
        assert_eq!(v[0], [0x00]);
        assert_eq!(v[255], [0xff]);
        assert_eq!(v[0x2a], [0x2a]);
    }

    #[tokio::test]
    async fn brute_write_finds_the_byte_that_flips_the_flag() {
        // FakeClient's scripted read-back is constant (it can't itself flip on
        // a write), so the "challenge" is simulated in `stop`: it only
        // recognizes the flag once the specific byte 0x2a has been written,
        // mirroring a ble_ctf challenge where one particular byte value is
        // the solution and every other write is a no-op.
        const CHAR: &str = "challenge-write";
        const FLAG_CHAR: &str = "challenge-read";
        const SOLUTION: u8 = 0x2a;
        let client = FakeClient::new(FakeGattTree::new()).script_read(FLAG_CHAR, b"FLAG{ok}");
        let found = brute_write(&client, CHAR, FLAG_CHAR, |v| {
            v == b"FLAG{ok}"
                && client.writes().last().map(|(_, p)| p.clone()) == Some(vec![SOLUTION])
        })
        .await;
        assert_eq!(found, Some((SOLUTION, b"FLAG{ok}".to_vec())));
        // Stopped as soon as the solution byte was written: 0x00..=0x2a inclusive.
        assert_eq!(client.writes().len(), (SOLUTION as usize) + 1);
        assert_eq!(
            client.writes().last().unwrap(),
            &(CHAR.to_string(), vec![SOLUTION])
        );
    }

    #[tokio::test]
    async fn brute_write_exhausts_the_range_when_nothing_matches() {
        const CHAR: &str = "c";
        const RB: &str = "rb";
        let client = FakeClient::new(FakeGattTree::new()).script_read(RB, b"anything");
        let found = brute_write(&client, CHAR, RB, |_| false).await;
        assert_eq!(found, None);
        assert_eq!(client.writes().len(), 256);
        assert_eq!(client.writes()[0x2a], (CHAR.to_string(), vec![0x2a]));
    }

    #[tokio::test]
    async fn read_n_returns_n_reads() {
        let client = FakeClient::new(FakeGattTree::new()).script_read("r", &[7]);
        let got = read_n(&client, "r", 5).await;
        assert_eq!(got, vec![vec![7]; 5]);
    }

    #[tokio::test]
    async fn write_then_read_writes_then_returns_scripted_read_back() {
        let client = FakeClient::new(FakeGattTree::new()).script_read("rb", b"FLAG{wtr}");
        let got = write_then_read(&client, "w", &[1, 2, 3], "rb")
            .await
            .unwrap();
        assert_eq!(got, b"FLAG{wtr}");
        assert_eq!(client.writes()[0], ("w".to_string(), vec![1, 2, 3]));
    }
}
