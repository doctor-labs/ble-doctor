//! Minimal REST API + event stream over `Central::scan` (bettercap's `ble.device.*` events and
//! REST, #107). No HTTP framework (AGENTS.md: no new dependency for a few lines of HTTP/1.1);
//! `std::net` plus a hand-rolled response is enough for two read-only GET endpoints:
//!
//! - `GET /scan`   one JSON array of discovered devices (one `Central::scan`).
//! - `GET /events` the same scan, Server-Sent Events: one `data: {...}` line per device. Each
//!   connection's events come from one batch scan, not live incremental discovery over time —
//!   that needs `Central::scan_live` (#100); wiring it in is a small follow-up once #100 lands.
//!
//! Anything else is a 404. No write endpoints: this is a read-only bridge, same scope as `mcp.rs`.

use crate::radio::{Central, DiscoveredDevice};
use serde_json::json;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

fn device_json(d: &DiscoveredDevice) -> serde_json::Value {
    json!({
        "id": d.id,
        "address": d.address,
        "name": d.name,
        "adv_local_name": d.adv_local_name,
        "rssi": d.rssi,
        "service_uuids": d.service_uuids,
    })
}

/// The request line's path ("GET /scan HTTP/1.1" -> "/scan"); anything but a bare `GET` is `None`.
fn request_path(r: &mut impl BufRead) -> Option<String> {
    let mut line = String::new();
    r.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    if parts.next()? != "GET" {
        return None;
    }
    Some(parts.next()?.to_string())
}

fn http(status: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// One connection's worth of response, written to `out`. Pure apart from the one `scan` call —
/// `central`/`timeout` are the only impure inputs, so a `FakeCentral` exercises every branch.
async fn respond<C: Central>(central: &C, path: &str, timeout: Duration, out: &mut impl Write) {
    match path {
        "/scan" => match central.scan(timeout).await {
            Ok(devs) => {
                let body = serde_json::to_string(&devs.iter().map(device_json).collect::<Vec<_>>())
                    .unwrap();
                let _ = out.write_all(http("200 OK", "application/json", &body).as_bytes());
            }
            Err(e) => {
                let body = json!({"error": e.to_string()}).to_string();
                let _ =
                    out.write_all(http("502 Bad Gateway", "application/json", &body).as_bytes());
            }
        },
        "/events" => match central.scan(timeout).await {
            Ok(devs) => {
                let _ = out.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                      Cache-Control: no-cache\r\nConnection: close\r\n\r\n",
                );
                for d in &devs {
                    let _ = write!(out, "data: {}\n\n", device_json(d));
                }
            }
            Err(e) => {
                let _ = out.write_all(
                    http(
                        "502 Bad Gateway",
                        "text/event-stream",
                        &format!("data: {{\"error\":{}}}\n\n", json!(e.to_string())),
                    )
                    .as_bytes(),
                );
            }
        },
        _ => {
            let _ = out.write_all(http("404 Not Found", "text/plain", "not found\n").as_bytes());
        }
    }
}

/// Accept and answer exactly one connection on `listener` (its own function so a test can drive
/// one request without the infinite loop `serve` runs for real).
async fn accept_one<C: Central>(listener: &TcpListener, central: &C, timeout: Duration) {
    let Ok((mut stream, _)) = listener.accept() else {
        return;
    };
    let path = {
        let mut reader = BufReader::new(stream.try_clone().expect("clone tcp stream"));
        request_path(&mut reader)
    };
    match path {
        Some(p) => respond(central, &p, timeout, &mut stream).await,
        None => {
            let _ =
                stream.write_all(http("400 Bad Request", "text/plain", "bad request\n").as_bytes());
        }
    }
}

/// Serve `GET /scan` and `GET /events` on `addr` forever (blocking the calling task); each
/// connection's scan is bounded by `timeout`. Binding failure (port in use, no permission) is the
/// only error; a per-connection failure (a bad request, a scan error) never brings the server down.
pub async fn serve<C: Central>(
    central: &C,
    addr: SocketAddr,
    timeout: Duration,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    loop {
        accept_one(&listener, central, timeout).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BleError;
    use crate::testkit::FakeCentral;
    use std::io::Read;
    use std::net::TcpStream;

    fn dev(id: &str, rssi: i16) -> DiscoveredDevice {
        DiscoveredDevice {
            id: id.into(),
            rssi: Some(rssi),
            ..Default::default()
        }
    }

    /// A real blocking client request, on its own OS thread via `spawn_blocking` so it never
    /// shares a worker thread with the server task's blocking `accept()`.
    fn get(addr: SocketAddr, path: &str) -> String {
        let mut c = TcpStream::connect(addr).unwrap();
        write!(c, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut body = String::new();
        c.read_to_string(&mut body).unwrap();
        body
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scan_endpoint_returns_json_array() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let central = FakeCentral::new(vec![dev("a", -40), dev("b", -70)]);
        let server =
            tokio::spawn(async move { accept_one(&listener, &central, Duration::ZERO).await });
        let body = tokio::task::spawn_blocking(move || get(addr, "/scan"))
            .await
            .unwrap();
        server.await.unwrap();
        assert!(body.starts_with("HTTP/1.1 200 OK"), "{body}");
        assert!(
            body.contains("\"id\":\"a\"") && body.contains("\"id\":\"b\""),
            "{body}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn events_endpoint_is_sse_with_one_event_per_device() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let central = FakeCentral::new(vec![dev("a", -40), dev("b", -70)]);
        let server =
            tokio::spawn(async move { accept_one(&listener, &central, Duration::ZERO).await });
        let body = tokio::task::spawn_blocking(move || get(addr, "/events"))
            .await
            .unwrap();
        server.await.unwrap();
        assert!(body.starts_with("HTTP/1.1 200 OK"), "{body}");
        assert!(body.contains("Content-Type: text/event-stream"), "{body}");
        assert_eq!(body.matches("data: ").count(), 2, "{body}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scan_failure_is_502_not_a_dropped_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let central = FakeCentral::failing(BleError::AdapterNotFound);
        let server =
            tokio::spawn(async move { accept_one(&listener, &central, Duration::ZERO).await });
        let body = tokio::task::spawn_blocking(move || get(addr, "/scan"))
            .await
            .unwrap();
        server.await.unwrap();
        assert!(body.starts_with("HTTP/1.1 502 Bad Gateway"), "{body}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unknown_path_is_404() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let central = FakeCentral::new(vec![]);
        let server =
            tokio::spawn(async move { accept_one(&listener, &central, Duration::ZERO).await });
        let body = tokio::task::spawn_blocking(move || get(addr, "/nope"))
            .await
            .unwrap();
        server.await.unwrap();
        assert!(body.starts_with("HTTP/1.1 404 Not Found"), "{body}");
    }
}
