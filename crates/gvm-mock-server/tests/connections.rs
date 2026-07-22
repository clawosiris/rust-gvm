// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Integration tests for TCP transport and connection behavior.

#![cfg(feature = "unix-socket-tests")]
#![allow(
    clippy::print_stdout,
    clippy::redundant_closure_for_method_calls,
    clippy::unwrap_used,
    missing_docs
)]

use std::collections::HashSet;

use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::{Response, XmlReader};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

/// Helper: send XML and read response via TCP.
async fn send_recv(stream: &mut TcpStream, xml: &[u8]) -> Response {
    stream.write_all(xml).await.expect("write failed");
    let mut frames = read_frames(stream, 1).await;
    Response::new(frames.remove(0))
}

/// Helper: send XML and read response via Unix socket.
async fn send_recv_unix(stream: &mut UnixStream, xml: &[u8]) -> Response {
    stream.write_all(xml).await.expect("write failed");
    let mut frames = read_frames(stream, 1).await;
    Response::new(frames.remove(0))
}

async fn read_frames<S>(stream: &mut S, expected: usize) -> Vec<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut reader = XmlReader::new();
    let mut frames = Vec::new();
    let mut buf = [0_u8; 4096];

    while frames.len() < expected {
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("response timeout")
            .expect("response read");
        assert_ne!(n, 0, "connection closed before all responses arrived");
        reader.feed(&buf[..n]).expect("valid response XML");

        while let Some(frame) = reader.take_frame().expect("valid response XML") {
            frames.push(frame);
            if frames.len() == expected {
                break;
            }
        }
    }

    frames
}

async fn assert_stream_closed<S>(stream: &mut S)
where
    S: AsyncRead + Unpin,
{
    let mut byte = [0_u8; 1];
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut byte))
        .await
        .expect("connection close timeout")
        .expect("read after rejection");
    assert_eq!(n, 0, "rejected connection must be closed");
}

async fn tcp_echo_server() -> Option<MockGmpServer> {
    build_server(
        MockGmpServer::builder()
            .mode(ServerMode::Echo)
            .version(GmpVersion::V22_5)
            .tcp("127.0.0.1:0"),
    )
    .await
}

async fn tcp_stateful_server() -> Option<MockGmpServer> {
    build_server(
        MockGmpServer::builder()
            .mode(ServerMode::Stateful)
            .version(GmpVersion::V22_5)
            .credentials("admin", "secret")
            .tcp("127.0.0.1:0"),
    )
    .await
}

#[tokio::test]
async fn tcp_get_version() {
    let Some(server) = tcp_echo_server().await else {
        return;
    };
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
    let Some(server) = tcp_echo_server().await else {
        return;
    };
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
    let Some(server) = tcp_echo_server().await else {
        return;
    };
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
    let Some(server) = build_server(
        MockGmpServer::builder()
            .mode(ServerMode::Echo)
            .version(GmpVersion::V22_5)
            .unix_socket_auto(),
    )
    .await
    else {
        return;
    };
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
    let Some(server) = tcp_stateful_server().await else {
        return;
    };
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

#[tokio::test]
async fn tcp_coalesced_commands_are_processed_in_order() {
    let Some(server) = tcp_echo_server().await else {
        return;
    };
    let mut stream = TcpStream::connect(server.tcp_addr().expect("TCP address"))
        .await
        .expect("connect");

    stream
        .write_all(b"<get_version/><get_tasks/>")
        .await
        .expect("coalesced write");
    let frames = read_frames(&mut stream, 2).await;

    assert_eq!(
        Response::new(frames[0].clone())
            .root_element_name()
            .as_deref(),
        Some("get_version_response")
    );
    assert_eq!(
        Response::new(frames[1].clone())
            .root_element_name()
            .as_deref(),
        Some("get_tasks_response")
    );
    let history = server.command_history();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].raw_xml(), b"<get_version/>");
    assert_eq!(history[1].raw_xml(), b"<get_tasks/>");

    server.shutdown().await;
}

#[tokio::test]
async fn unix_coalesced_and_fragmented_commands_preserve_every_frame() {
    let Some(server) = build_server(
        MockGmpServer::builder()
            .mode(ServerMode::Echo)
            .version(GmpVersion::V22_5)
            .unix_socket_auto(),
    )
    .await
    else {
        return;
    };
    let mut stream = UnixStream::connect(server.socket_path().expect("socket path"))
        .await
        .expect("connect");

    stream
        .write_all(b"<get_version/><get_tasks/>")
        .await
        .expect("coalesced write");
    let frames = read_frames(&mut stream, 2).await;
    assert_eq!(
        Response::new(frames[0].clone())
            .root_element_name()
            .as_deref(),
        Some("get_version_response")
    );
    assert_eq!(
        Response::new(frames[1].clone())
            .root_element_name()
            .as_deref(),
        Some("get_tasks_response")
    );

    for byte in b"<get_version/>" {
        stream.write_all(&[*byte]).await.expect("fragmented write");
    }
    let fragmented = read_frames(&mut stream, 1).await;
    assert_eq!(
        Response::new(fragmented[0].clone()).status_code(),
        Some(200)
    );
    assert_eq!(server.command_count(), 3);

    server.shutdown().await;
}

#[tokio::test]
async fn malformed_requests_are_rejected_without_stopping_tcp_listener() {
    let Some(server) = tcp_echo_server().await else {
        return;
    };
    let address = server.tcp_addr().expect("TCP address");

    let mut bom = TcpStream::connect(address).await.expect("BOM connection");
    let bom_response = send_recv(&mut bom, b"\xEF\xBB\xBF<get_version/>").await;
    assert_eq!(bom_response.status_code(), Some(200));
    drop(bom);

    for malformed in [
        b"<get_version></wrong>".as_slice(),
        b"\xff<get_version/>".as_slice(),
        b"<get_version>&bogus;</get_version>".as_slice(),
        b"<?xml?><get_version/>".as_slice(),
        b"<1bad/>".as_slice(),
        b"<get_version>&#0;</get_version>".as_slice(),
        b"<?XML data?><get_version/>".as_slice(),
    ] {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("malformed connection");
        stream.write_all(malformed).await.expect("malformed write");
        let response = read_frames(&mut stream, 1).await;
        assert_eq!(Response::new(response[0].clone()).status_code(), Some(400));
        assert_stream_closed(&mut stream).await;
    }

    let mut fresh = TcpStream::connect(address).await.expect("fresh connection");
    let fresh_response = send_recv(&mut fresh, b"<get_version/>").await;
    assert_eq!(fresh_response.status_code(), Some(200));
    assert_eq!(
        server.command_count(),
        2,
        "rejected input must not reach history"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn malformed_request_is_rejected_and_closed_on_unix_listener() {
    let Some(server) = build_server(
        MockGmpServer::builder()
            .mode(ServerMode::Echo)
            .version(GmpVersion::V22_5)
            .unix_socket_auto(),
    )
    .await
    else {
        return;
    };
    let path = server.socket_path().expect("Unix socket path");

    let mut malformed = UnixStream::connect(path)
        .await
        .expect("malformed connection");
    malformed
        .write_all(b"<get_version></wrong>")
        .await
        .expect("malformed write");
    let response = read_frames(&mut malformed, 1).await;
    assert_eq!(Response::new(response[0].clone()).status_code(), Some(400));
    assert_stream_closed(&mut malformed).await;

    let mut fresh = UnixStream::connect(path).await.expect("fresh connection");
    assert_eq!(
        send_recv_unix(&mut fresh, b"<get_version/>")
            .await
            .status_code(),
        Some(200)
    );
    assert_eq!(server.command_count(), 1);

    server.shutdown().await;
}

#[tokio::test]
async fn request_limit_is_exact_and_oversize_does_not_stop_listener() {
    let request = b"<get_version/>";
    let Some(server) = build_server(
        MockGmpServer::builder()
            .mode(ServerMode::Echo)
            .version(GmpVersion::V22_5)
            .with_max_request_bytes(Some(request.len()))
            .tcp("127.0.0.1:0"),
    )
    .await
    else {
        return;
    };
    let address = server.tcp_addr().expect("TCP address");

    let mut exact = TcpStream::connect(address).await.expect("exact connection");
    let exact_response = send_recv(&mut exact, request).await;
    assert_eq!(exact_response.status_code(), Some(200));

    let mut oversized = TcpStream::connect(address)
        .await
        .expect("oversized connection");
    oversized
        .write_all(b"<get_version ></get_version>")
        .await
        .expect("oversized write");
    let oversized_response = read_frames(&mut oversized, 1).await;
    assert_eq!(
        Response::new(oversized_response[0].clone()).status_code(),
        Some(400)
    );
    assert_stream_closed(&mut oversized).await;

    let mut fresh = TcpStream::connect(address).await.expect("fresh connection");
    let fresh_response = send_recv(&mut fresh, request).await;
    assert_eq!(fresh_response.status_code(), Some(200));
    assert_eq!(
        server.command_count(),
        2,
        "rejected input must not reach history"
    );

    server.shutdown().await;
}
async fn build_server(builder: gvm_mock_server::MockGmpServerBuilder) -> Option<MockGmpServer> {
    match builder.build().await {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server start failed: {error}"),
    }
}
