//! Integration tests for error injection / fault engine.

#![allow(
    clippy::print_stdout,
    clippy::redundant_closure_for_method_calls,
    clippy::unwrap_used,
    missing_docs
)]

use gvm_mock_server::{Fault, FaultKind, GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

async fn send_recv(stream: &mut UnixStream, xml: &[u8]) -> Response {
    stream.write_all(xml).await.expect("write failed");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).await.expect("read failed");
    buf.truncate(n);
    Response::new(buf)
}

// ERR-001: Server error on specific command
#[tokio::test]
async fn fault_on_specific_command() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_5)
        .inject_fault(Fault::on_command("get_tasks", FaultKind::ServerError500))
        .unix_socket_auto()
        .build()
        .await
        .expect("start");

    let path = server.socket_path().unwrap();
    let mut stream = UnixStream::connect(path).await.expect("connect");

    // get_version should work fine
    let resp = send_recv(&mut stream, b"<get_version/>").await;
    assert_eq!(resp.status_code(), Some(200));

    // get_tasks should return 500
    let resp = send_recv(&mut stream, br#"<get_tasks usage_type="scan"/>"#).await;
    assert_eq!(resp.status_code(), Some(500));

    // get_targets should also work fine
    let resp = send_recv(&mut stream, b"<get_targets/>").await;
    assert_eq!(resp.status_code(), Some(200));

    server.shutdown().await;
}

// ERR-006: Error after N commands
#[tokio::test]
async fn fault_after_n_commands() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_5)
        .inject_fault(Fault::after_commands(2, FaultKind::ServerError500))
        .unix_socket_auto()
        .build()
        .await
        .expect("start");

    let path = server.socket_path().unwrap();
    let mut stream = UnixStream::connect(path).await.expect("connect");

    // First two commands succeed
    let r1 = send_recv(&mut stream, b"<get_version/>").await;
    assert_eq!(r1.status_code(), Some(200));

    let r2 = send_recv(&mut stream, b"<get_targets/>").await;
    assert_eq!(r2.status_code(), Some(200));

    // Third command fails (count >= 2)
    let r3 = send_recv(&mut stream, b"<get_tasks/>").await;
    assert_eq!(r3.status_code(), Some(500));

    server.shutdown().await;
}

// ERR-007: Error once then recover
#[tokio::test]
async fn fault_once_then_recover() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_5)
        .inject_fault(Fault::once(FaultKind::ServerError500))
        .unix_socket_auto()
        .build()
        .await
        .expect("start");

    let path = server.socket_path().unwrap();
    let mut stream = UnixStream::connect(path).await.expect("connect");

    // First command fails
    let r1 = send_recv(&mut stream, b"<get_version/>").await;
    assert_eq!(r1.status_code(), Some(500));

    // Second command succeeds
    let r2 = send_recv(&mut stream, b"<get_version/>").await;
    assert_eq!(r2.status_code(), Some(200));

    server.shutdown().await;
}

// ERR-004: Malformed XML response
#[tokio::test]
async fn fault_malformed_xml() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_5)
        .inject_fault(Fault::once(FaultKind::MalformedXml))
        .unix_socket_auto()
        .build()
        .await
        .expect("start");

    let path = server.socket_path().unwrap();
    let mut stream = UnixStream::connect(path).await.expect("connect");

    // First command returns garbage
    stream.write_all(b"<get_version/>").await.expect("write");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).await.expect("read");
    buf.truncate(n);

    let text = std::str::from_utf8(&buf).expect("utf8");
    assert!(
        !text.starts_with('<'),
        "Malformed response should not start with XML"
    );

    server.shutdown().await;
}

// ERR-005: Truncated response
#[tokio::test]
async fn fault_truncated_response() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_5)
        .inject_fault(Fault::once(FaultKind::TruncatedResponse))
        .unix_socket_auto()
        .build()
        .await
        .expect("start");

    let path = server.socket_path().unwrap();
    let mut stream = UnixStream::connect(path).await.expect("connect");

    stream.write_all(b"<get_tasks/>").await.expect("write");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).await.expect("read");
    buf.truncate(n);

    let text = std::str::from_utf8(&buf).expect("utf8");
    // Should be truncated — no closing tag
    assert!(text.contains("get_tasks_response"));
    assert!(
        !text.contains("/>") && !text.contains("</get_tasks_response>"),
        "Truncated response should be incomplete XML"
    );

    server.shutdown().await;
}

// ERR-009: No faults by default
#[tokio::test]
async fn no_faults_by_default() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_5)
        .unix_socket_auto()
        .build()
        .await
        .expect("start");

    let path = server.socket_path().unwrap();
    let mut stream = UnixStream::connect(path).await.expect("connect");

    // 10 commands should all succeed
    for _ in 0..10 {
        let resp = send_recv(&mut stream, b"<get_version/>").await;
        assert_eq!(resp.status_code(), Some(200));
    }

    server.shutdown().await;
}

// ERR: Custom error status
#[tokio::test]
async fn fault_custom_error_status() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_5)
        .inject_fault(Fault::on_command(
            "create_alert",
            FaultKind::ErrorStatus {
                code: 409,
                message: "Resource in use".to_string(),
            },
        ))
        .unix_socket_auto()
        .build()
        .await
        .expect("start");

    let path = server.socket_path().unwrap();
    let mut stream = UnixStream::connect(path).await.expect("connect");

    let resp = send_recv(
        &mut stream,
        b"<create_alert><name>test</name></create_alert>",
    )
    .await;
    assert_eq!(resp.status_code(), Some(409));

    let text = resp.as_str().expect("utf8");
    assert!(text.contains("Resource in use"));

    server.shutdown().await;
}
