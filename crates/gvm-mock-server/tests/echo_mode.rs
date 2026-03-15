//! Integration tests for Echo mode.

#![cfg(feature = "unix-socket-tests")]
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
async fn send_recv(stream: &mut UnixStream, xml: &[u8]) -> Vec<u8> {
    stream.write_all(xml).await.expect("write failed");
    // Give the server a moment to process
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).await.expect("read failed");
    buf.truncate(n);
    buf
}

/// Helper: start an echo server on auto Unix socket.
async fn echo_server() -> MockGmpServer {
    MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_5)
        .unix_socket_auto()
        .build()
        .await
        .expect("server start failed")
}

// ECHO-001: Any recognized command returns 200
#[tokio::test]
async fn echo_get_tasks_returns_200() {
    let server = echo_server().await;
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let resp_bytes = send_recv(&mut stream, br#"<get_tasks usage_type="scan"/>"#).await;
    let resp = Response::new(resp_bytes);

    assert_eq!(resp.status_code(), Some(200));
    assert!(resp.is_success());
    assert_eq!(
        resp.root_element_name(),
        Some("get_tasks_response".to_string())
    );

    server.shutdown().await;
}

// ECHO-002: Create commands return 201 with id
#[tokio::test]
async fn echo_create_task_returns_201_with_id() {
    let server = echo_server().await;
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let resp_bytes = send_recv(
        &mut stream,
        b"<create_task><name>test</name><target id=\"t1\"/></create_task>",
    )
    .await;
    let resp = Response::new(resp_bytes);

    assert_eq!(resp.status_code(), Some(201));
    assert!(resp.is_success());
    assert!(
        resp.id().is_some(),
        "create response should have id attribute"
    );

    server.shutdown().await;
}

// ECHO-003: get_version returns configured version
#[tokio::test]
async fn echo_get_version_returns_configured_version() {
    let server = echo_server().await;
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let resp_bytes = send_recv(&mut stream, b"<get_version/>").await;
    let resp = Response::new(resp_bytes);

    assert_eq!(resp.status_code(), Some(200));
    assert_eq!(resp.child_text("version"), Some("22.5".to_string()));

    server.shutdown().await;
}

// ECHO-004: Unknown command returns 400
#[tokio::test]
async fn echo_unknown_command_returns_400() {
    let server = echo_server().await;
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let resp_bytes = send_recv(&mut stream, b"<do_something_weird/>").await;
    let resp = Response::new(resp_bytes);

    assert_eq!(resp.status_code(), Some(400));
    assert!(!resp.is_success());

    server.shutdown().await;
}

// ECHO-005: Multiple sequential commands all get valid responses
#[tokio::test]
async fn echo_multiple_commands_sequential() {
    let server = echo_server().await;
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let commands: &[&[u8]] = &[
        b"<get_version/>",
        b"<authenticate><credentials><username>admin</username><password>pass</password></credentials></authenticate>",
        br#"<get_tasks usage_type="scan"/>"#,
        br#"<get_targets/>"#,
        br#"<get_configs/>"#,
        br#"<get_scanners/>"#,
        br#"<create_task><name>t1</name><target id="0"/></create_task>"#,
        br#"<delete_task task_id="abc" ultimate="0"/>"#,
        br#"<start_task task_id="abc"/>"#,
        br#"<get_feeds/>"#,
    ];

    for cmd in commands {
        let resp_bytes = send_recv(&mut stream, cmd).await;
        let resp = Response::new(resp_bytes);
        assert!(
            resp.status_code().is_some(),
            "Response should have a status code"
        );
        // All known commands should not be 400
        let status = resp.status_code().unwrap();
        assert_ne!(status, 400, "Known command should not return 400");
    }

    server.shutdown().await;
}

// ECHO-006: Command history records all commands
#[tokio::test]
async fn echo_command_history() {
    let server = echo_server().await;
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    send_recv(&mut stream, b"<get_version/>").await;
    send_recv(&mut stream, br#"<get_tasks usage_type="scan"/>"#).await;
    send_recv(
        &mut stream,
        b"<create_task><name>t</name><target id=\"0\"/></create_task>",
    )
    .await;

    // Give a moment for history to be recorded
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let history = server.command_history();
    assert_eq!(history.len(), 3, "Should have 3 commands in history");
    assert_eq!(history[0].command_name(), "get_version");
    assert_eq!(history[1].command_name(), "get_tasks");
    assert_eq!(history[2].command_name(), "create_task");

    server.shutdown().await;
}

// ECHO-007: Response tag matches command name
#[tokio::test]
async fn echo_response_tag_matches_command() {
    let server = echo_server().await;
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let resp_bytes = send_recv(&mut stream, br#"<delete_task task_id="x" ultimate="0"/>"#).await;
    let resp = Response::new(resp_bytes);

    assert_eq!(
        resp.root_element_name(),
        Some("delete_task_response".to_string())
    );

    server.shutdown().await;
}
