//! Phase 4: Black-box proxy integration tests.
//!
//! Spawns the real `tlsn-server` binary and tests the WebSocket proxy
//! allowlist behavior via HTTP/WebSocket requests.
//!
//! NO production code is imported — exercises the actual binary with real route wiring.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Spawn `tlsn-server serve` on a random port with minimal config.
/// Returns (child process, port).
fn spawn_server() -> (Child, u16) {
    let port = portpicker::pick_unused_port().expect("no free port");

    // Write minimal config YAML to temp file
    let config_content = format!(
        r#"
host: "127.0.0.1"
port: {port}
oracle:
  contract_address: "0x5FbDB2315678afecb367f032d93F642f64180aa3"
  chain_id: 31337
  rpc_url: "http://127.0.0.1:1"
  steam_factory_address: "0x5FbDB2315678afecb367f032d93F642f64180aa3"
"#
    );
    let config_path = std::env::temp_dir().join(format!("proxy-test-{port}.yaml"));
    std::fs::write(&config_path, config_content).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_tlsn-server"))
        .arg("serve")
        .arg("--config")
        .arg(&config_path)
        .env(
            "ORACLE_SIGNING_KEY",
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn tlsn-server");

    // Wait for server to be ready by polling /health via raw TCP
    wait_for_health(port);

    (child, port)
}

/// Poll the /health endpoint until the server responds (max 10s).
/// Uses raw TCP + HTTP/1.1 to avoid reqwest blocking feature dependency.
fn wait_for_health(port: u16) {
    let addr = format!("127.0.0.1:{port}");
    for i in 0..50 {
        std::thread::sleep(Duration::from_millis(200));
        if let Ok(mut stream) = TcpStream::connect_timeout(
            &addr.parse().unwrap(),
            Duration::from_secs(1),
        ) {
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .ok();
            let req = format!("GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
            if stream.write_all(req.as_bytes()).is_ok() {
                let mut buf = [0u8; 256];
                if let Ok(n) = stream.read(&mut buf) {
                    let resp = String::from_utf8_lossy(&buf[..n]);
                    if resp.contains("200 OK") || resp.contains("200") {
                        eprintln!("[proxy_test] Server ready after {}ms", (i + 1) * 200);
                        return;
                    }
                }
            }
        }
    }
    panic!("Server did not become healthy within 10 seconds");
}

// ============================================================================
// Test 6: Proxy allows Steam hosts
// ============================================================================

#[tokio::test]
async fn test_proxy_allowed_host() {
    let (mut child, port) = spawn_server();

    let url = format!("ws://127.0.0.1:{port}/proxy?token=api.steampowered.com:443");
    let result = tokio_tungstenite::connect_async(&url).await;

    // WebSocket upgrade should succeed for allowed hosts.
    // The actual TCP connection to Steam may fail/timeout — that's fine.
    // We're testing the allowlist check happens before the upgrade response.
    assert!(
        result.is_ok(),
        "WebSocket upgrade should succeed for allowed host, got: {:?}",
        result.err()
    );

    child.kill().ok();
    child.wait().ok();
}

// ============================================================================
// Test 7: Proxy blocks non-Steam hosts
// ============================================================================

#[tokio::test]
async fn test_proxy_blocked_host() {
    let (mut child, port) = spawn_server();

    let url = format!("ws://127.0.0.1:{port}/proxy?token=evil.com:443");
    let result = tokio_tungstenite::connect_async(&url).await;

    // Server should reject BEFORE WebSocket upgrade — client sees HTTP 403
    assert!(
        result.is_err(),
        "WebSocket handshake must fail for blocked host"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("403") || err_msg.contains("Forbidden"),
        "Expected 403 rejection, got: {err_msg}"
    );

    child.kill().ok();
    child.wait().ok();
}

// ============================================================================
// Test 8: Proxy blocks localhost/private IPs
// ============================================================================

#[tokio::test]
async fn test_proxy_blocked_localhost() {
    let (mut child, port) = spawn_server();

    let url = format!("ws://127.0.0.1:{port}/proxy?token=127.0.0.1:8080");
    let result = tokio_tungstenite::connect_async(&url).await;

    assert!(
        result.is_err(),
        "WebSocket handshake must fail for localhost"
    );

    child.kill().ok();
    child.wait().ok();
}
