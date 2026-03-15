//! Integration tests for TCP transport and connection behavior.

#![allow(
    clippy::print_stdout,
    clippy::redundant_closure_for_method_calls,
    clippy::unwrap_used,
    missing_docs
)]

use std::collections::HashSet;

use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

/// Helper: send XML and read response via TCP.
async fn send_recv(stream: &mut TcpStream, xml: &[u8]) -> Response {
    stream.write_all(xml).await.expect("write failed");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).await.expect("read failed");
    buf.truncate(n);
    Response::new(buf)
}

/// Helper: send XML and read response via Unix socket.
async fn send_recv_unix(stream: &mut UnixStream, xml: &[u8]) -> Response {
    stream.write_all(xml).await.expect("write failed");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).await.expect("read failed");
    buf.truncate(n);
    Response::new(buf)
}

async fn tcp_echo_server() -> MockGmpServer {
    MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_5)
        .tcp("127.0.0.1:0")
        .build()
        .await
        .expect("server start failed")
}

async fn tcp_stateful_server() -> MockGmpServer {
    MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_5)
        .credentials("admin", "secret")
        .tcp("127.0.0.1:0")
        .build()
        .await
        .expect("server start failed")
}

#[tokio::test]
async fn tcp_get_version() {
    let server = tcp_echo_server().await;
    let port = server.port().expect("should have TCP port");
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect failed");

    let resp = send_recv(&mut stream, b"<get_version/>").await;

    assert_eq!(resp.status_code(), Some(200));
    assert_eq!(resp.child_text("version"), Some("22.5".to_string()));

    server.shutdown().await;
}

#[tokio::test]
async fn tcp_random_port() {
    let server = tcp_echo_server().await;
    let port = server.port().expect("should have TCP port");

    assert_ne!(port, 0, "server should expose the assigned random port");

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect failed");
    let resp = send_recv(&mut stream, br#"<get_tasks usage_type="scan"/>"#).await;

    assert_eq!(resp.status_code(), Some(200));

    server.shutdown().await;
}

#[tokio::test]
async fn tcp_multiple_clients() {
    let server = tcp_echo_server().await;
    let port = server.port().expect("should have TCP port");

    let mut client_a = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("client A connect failed");
    let mut client_b = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("client B connect failed");

    let resp_a = send_recv(&mut client_a, b"<get_version/>").await;
    let resp_b = send_recv(&mut client_b, br#"<get_tasks usage_type="scan"/>"#).await;

    assert_eq!(resp_a.status_code(), Some(200));
    assert_eq!(resp_b.status_code(), Some(200));

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let history = server.command_history();
    assert_eq!(
        history.len(),
        2,
        "both clients should have issued a command"
    );

    let session_ids = history
        .iter()
        .map(|record| record.session_id())
        .collect::<HashSet<_>>();
    assert_eq!(
        session_ids.len(),
        2,
        "each client should have its own session"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn unix_reconnect() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_5)
        .unix_socket_auto()
        .build()
        .await
        .expect("server start failed");
    let path = server.socket_path().expect("should have socket path");

    let mut stream1 = UnixStream::connect(path)
        .await
        .expect("first connect failed");
    let resp1 = send_recv_unix(&mut stream1, b"<get_version/>").await;
    assert_eq!(resp1.status_code(), Some(200));
    drop(stream1);

    let mut stream2 = UnixStream::connect(path)
        .await
        .expect("second connect failed");
    let resp2 = send_recv_unix(&mut stream2, b"<get_version/>").await;
    assert_eq!(resp2.status_code(), Some(200));

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let history = server.command_history();
    assert_eq!(history.len(), 2, "both connections should be recorded");
    assert_ne!(
        history[0].session_id(),
        history[1].session_id(),
        "reconnecting should create a new session"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_session_isolation() {
    let server = tcp_stateful_server().await;
    let port = server.port().expect("should have TCP port");

    let mut client_a = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("client A connect failed");
    let auth_resp = send_recv(
        &mut client_a,
        b"<authenticate><credentials><username>admin</username><password>secret</password></credentials></authenticate>",
    )
    .await;
    assert_eq!(auth_resp.status_code(), Some(200));

    let create_resp = send_recv(
        &mut client_a,
        b"<create_task><name>Shared Task</name><target id=\"t1\"/></create_task>",
    )
    .await;
    assert_eq!(create_resp.status_code(), Some(201));

    let mut client_b = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("client B connect failed");
    let unauth_resp = send_recv(&mut client_b, b"<get_tasks/>").await;
    assert_eq!(unauth_resp.status_code(), Some(401));

    let auth_b_resp = send_recv(
        &mut client_b,
        b"<authenticate><credentials><username>admin</username><password>secret</password></credentials></authenticate>",
    )
    .await;
    assert_eq!(auth_b_resp.status_code(), Some(200));

    let tasks_resp = send_recv(&mut client_b, b"<get_tasks/>").await;
    assert_eq!(tasks_resp.status_code(), Some(200));

    let text = tasks_resp.as_str().expect("valid utf8");
    assert!(text.contains("Shared Task"));
    assert!(text.contains("<task_count>1"));

    server.shutdown().await;
}
