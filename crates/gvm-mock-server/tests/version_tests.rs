//! Integration tests for version-specific behavior across server modes.

#![allow(
    clippy::print_stdout,
    clippy::redundant_closure_for_method_calls,
    clippy::unwrap_used,
    missing_docs
)]

use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Helper: send XML and read response via Unix socket.
async fn send_recv(stream: &mut UnixStream, xml: &[u8]) -> Response {
    stream.write_all(xml).await.expect("write failed");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).await.expect("read failed");
    buf.truncate(n);
    Response::new(buf)
}

async fn assert_version_response(server: MockGmpServer, expected_version: &str) {
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let resp = send_recv(&mut stream, b"<get_version/>").await;

    assert_eq!(resp.status_code(), Some(200));
    let text = resp.as_str().expect("response should be valid utf8");
    assert!(
        text.contains(&format!("<version>{expected_version}</version>")),
        "response should contain version {expected_version}, got: {text}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn version_v22_4() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_4)
        .unix_socket_auto()
        .build()
        .await
        .expect("server start failed");

    assert_version_response(server, "22.4").await;
}

#[tokio::test]
async fn version_v22_5() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_5)
        .unix_socket_auto()
        .build()
        .await
        .expect("server start failed");

    assert_version_response(server, "22.5").await;
}

#[tokio::test]
async fn version_v22_6() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_6)
        .unix_socket_auto()
        .build()
        .await
        .expect("server start failed");

    assert_version_response(server, "22.6").await;
}

#[tokio::test]
async fn version_v22_7() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_7)
        .unix_socket_auto()
        .build()
        .await
        .expect("server start failed");

    assert_version_response(server, "22.7").await;
}

#[tokio::test]
async fn version_echo_mode() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_5)
        .unix_socket_auto()
        .build()
        .await
        .expect("server start failed");

    assert_version_response(server, "22.5").await;
}

#[tokio::test]
async fn version_fixture_mode() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(GmpVersion::V22_5)
        .unix_socket_auto()
        .build()
        .await
        .expect("server start failed");

    assert_version_response(server, "22.5").await;
}

#[tokio::test]
async fn version_stateful_mode() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_5)
        .credentials("admin", "secret")
        .unix_socket_auto()
        .build()
        .await
        .expect("server start failed");

    assert_version_response(server, "22.5").await;
}

#[tokio::test]
async fn version_default() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .unix_socket_auto()
        .build()
        .await
        .expect("server start failed");

    assert_version_response(server, "22.5").await;
}
