// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(clippy::print_stdout, clippy::unwrap_used, missing_docs)]
#![cfg(feature = "unix-socket-tests")]

use std::time::Duration;

use gvm_connection::{ConnectionError, GvmConnection, UnixSocketConfig, UnixSocketConnection};
use gvm_mock_server::{Fault, FaultKind, GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::{Request, Response, XmlCommand};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

async fn start_mock() -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_5)
        .credentials("admin", "admin")
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("mock server start failed: {error}"),
    }
}

#[tokio::test]
async fn connect_and_get_version() {
    let server = start_mock().await;
    let Some(server) = server else {
        return;
    };
    let socket_path = server.socket_path().expect("should have socket");

    let config = UnixSocketConfig::new(socket_path);
    let mut conn = UnixSocketConnection::new(config);

    conn.connect().await.expect("connect failed");
    assert!(conn.is_connected());

    let cmd = XmlCommand::new("get_version");
    conn.send(&cmd.to_bytes()).await.expect("send failed");

    let response_data = conn.read().await.expect("read failed");
    let response = Response::new(response_data);
    assert_eq!(response.status_code(), Some(200));
    assert_eq!(response.child_text("version").as_deref(), Some("22.5"));

    conn.disconnect().await.expect("disconnect failed");
    assert!(!conn.is_connected());

    server.shutdown().await;
}

#[tokio::test]
async fn connect_authenticate_and_create_target() {
    let server = start_mock().await;
    let Some(server) = server else {
        return;
    };
    let socket_path = server.socket_path().expect("should have socket");

    let config = UnixSocketConfig::new(socket_path);
    let mut conn = UnixSocketConnection::new(config);

    conn.connect().await.expect("connect failed");

    let auth_xml = b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>";
    conn.send(auth_xml).await.expect("send auth failed");
    let auth_resp = conn.read().await.expect("read auth failed");
    let auth_response = Response::new(auth_resp);
    assert_eq!(auth_response.status_code(), Some(200));

    let create_xml =
        b"<create_target><name>Test Target</name><hosts>192.168.1.0/24</hosts></create_target>";
    conn.send(create_xml).await.expect("send create failed");
    let create_resp = conn.read().await.expect("read create failed");
    let create_response = Response::new(create_resp);
    assert_eq!(create_response.status_code(), Some(201));
    assert!(create_response.id().is_some());

    conn.disconnect().await.expect("disconnect failed");
    server.shutdown().await;
}

#[tokio::test]
async fn reconnect_flow() {
    let server = start_mock().await;
    let Some(server) = server else {
        return;
    };
    let socket_path = server.socket_path().expect("should have socket");

    let config = UnixSocketConfig::new(socket_path);
    let mut conn = UnixSocketConnection::new(config);
    conn.connect().await.expect("connect 1 failed");

    conn.send(b"<get_version/>").await.expect("send failed");
    let resp = conn.read().await.expect("read failed");
    let response = Response::new(resp);
    assert_eq!(response.child_text("version").as_deref(), Some("22.5"));

    conn.disconnect().await.expect("disconnect 1 failed");

    let config2 = UnixSocketConfig::new(server.socket_path().expect("socket"));
    let mut conn2 = UnixSocketConnection::new(config2);
    conn2.connect().await.expect("connect 2 failed");

    conn2
        .send(
            b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>",
        )
        .await
        .expect("send auth failed");
    let auth_resp = conn2.read().await.expect("read auth failed");
    assert_eq!(Response::new(auth_resp).status_code(), Some(200));

    conn2
        .send(b"<get_tasks/>")
        .await
        .expect("send tasks failed");
    let tasks_resp = conn2.read().await.expect("read tasks failed");
    assert_eq!(Response::new(tasks_resp).status_code(), Some(200));

    conn2.disconnect().await.expect("disconnect 2 failed");
    server.shutdown().await;
}

#[tokio::test]
async fn response_timeout_invalidates_connection() {
    let server = match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_5)
        .inject_fault(Fault::once(FaultKind::Delay(Duration::from_millis(250))))
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => server,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("mock server start failed: {error}"),
    };
    let config = UnixSocketConfig::new(server.socket_path().expect("socket path"))
        .with_timeout(Duration::from_millis(50));
    let mut connection = UnixSocketConnection::new(config);
    connection.connect().await.expect("connect");
    connection
        .send(b"<get_version/>")
        .await
        .expect("send request");

    assert!(matches!(
        connection.read().await,
        Err(ConnectionError::Timeout(_))
    ));
    assert!(!connection.is_connected());
    assert!(matches!(
        connection.send(b"<get_version/>").await,
        Err(ConnectionError::NotConnected)
    ));
    assert!(matches!(
        connection.read().await,
        Err(ConnectionError::NotConnected)
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn outbound_timeout_invalidates_connection_and_allows_clean_reconnect() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let socket_path = directory.path().join("outbound-timeout.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind socket");
    let server = tokio::spawn(async move {
        let (first, _) = listener.accept().await.expect("first connection");
        tokio::time::sleep(Duration::from_millis(75)).await;
        drop(first);

        let (mut second, _) = listener.accept().await.expect("second connection");
        let mut request = [0_u8; 64];
        let _ = second.read(&mut request).await.expect("second request");
        second
            .write_all(b"<fresh_response/>")
            .await
            .expect("fresh response");
    });

    let config = UnixSocketConfig::new(&socket_path).with_timeout(Duration::from_millis(50));
    let mut connection = UnixSocketConnection::new(config);
    connection.connect().await.expect("first connect");

    let request = vec![0_u8; 16 * 1024 * 1024];
    assert!(matches!(
        connection.send(&request).await,
        Err(ConnectionError::Timeout(_))
    ));
    assert!(!connection.is_connected());
    assert!(matches!(
        connection.send(b"<request/>").await,
        Err(ConnectionError::NotConnected)
    ));

    connection.connect().await.expect("second connect");
    connection.send(b"<request/>").await.expect("second send");
    assert_eq!(
        connection.read().await.expect("fresh response"),
        b"<fresh_response/>"
    );

    server.await.expect("server task");
}

#[tokio::test]
async fn connect_not_connected_errors() {
    let mut conn = UnixSocketConnection::with_path("/nonexistent/socket.sock");
    assert!(!conn.is_connected());

    let result = conn.send(b"<get_version/>").await;
    assert!(result.is_err());

    let result = conn.read().await;
    assert!(result.is_err());

    let result = conn.connect().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn double_connect_errors() {
    let server = start_mock().await;
    let Some(server) = server else {
        return;
    };
    let socket_path = server.socket_path().expect("should have socket");

    let config = UnixSocketConfig::new(socket_path);
    let mut conn = UnixSocketConnection::new(config);

    conn.connect().await.expect("connect failed");
    let result = conn.connect().await;
    assert!(result.is_err());

    conn.disconnect().await.expect("disconnect failed");
    server.shutdown().await;
}

#[tokio::test]
async fn coalesced_responses_are_returned_one_frame_at_a_time() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let socket_path = directory.path().join("coalesced.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind socket");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept connection");
        let mut request = [0_u8; 64];
        let _ = stream.read(&mut request).await.expect("read request");
        stream
            .write_all(b"<first_response/><second_response/>")
            .await
            .expect("write responses");
    });

    let mut connection = UnixSocketConnection::new(UnixSocketConfig::new(&socket_path));
    connection.connect().await.expect("connect");
    connection.send(b"<request/>").await.expect("send");

    assert_eq!(
        connection.read().await.expect("first response"),
        b"<first_response/>"
    );
    assert_eq!(
        connection.read().await.expect("second response"),
        b"<second_response/>"
    );

    server.await.expect("server task");
}

#[tokio::test]
async fn reconnect_discards_a_pending_response_tail() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let socket_path = directory.path().join("reconnect-tail.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind socket");
    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.expect("first connection");
        let mut request = [0_u8; 64];
        let _ = first.read(&mut request).await.expect("first request");
        first
            .write_all(b"<current_response/><stale_response/>")
            .await
            .expect("first responses");
        drop(first);

        let (mut second, _) = listener.accept().await.expect("second connection");
        let _ = second.read(&mut request).await.expect("second request");
        second
            .write_all(b"<fresh_response/>")
            .await
            .expect("fresh response");
    });

    let mut connection = UnixSocketConnection::new(UnixSocketConfig::new(&socket_path));
    connection.connect().await.expect("first connect");
    connection.send(b"<request/>").await.expect("first send");
    assert_eq!(
        connection.read().await.expect("current response"),
        b"<current_response/>"
    );
    connection.disconnect().await.expect("disconnect");

    connection.connect().await.expect("second connect");
    connection.send(b"<request/>").await.expect("second send");
    assert_eq!(
        connection.read().await.expect("fresh response"),
        b"<fresh_response/>"
    );

    server.await.expect("server task");
}

#[tokio::test]
async fn reconnect_after_partial_response_timeout_discards_parser_state() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let socket_path = directory.path().join("timeout-reconnect.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind socket");
    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.expect("first connection");
        let mut request = [0_u8; 64];
        let _ = first.read(&mut request).await.expect("first request");
        first
            .write_all(b"<stale_response>")
            .await
            .expect("partial response");
        tokio::time::sleep(Duration::from_millis(250)).await;
        drop(first);

        let (mut second, _) = listener.accept().await.expect("second connection");
        let _ = second.read(&mut request).await.expect("second request");
        second
            .write_all(b"<fresh_response/>")
            .await
            .expect("fresh response");
    });

    let config = UnixSocketConfig::new(&socket_path).with_timeout(Duration::from_millis(200));
    let mut connection = UnixSocketConnection::new(config);
    connection.connect().await.expect("first connect");
    connection.send(b"<request/>").await.expect("first send");
    assert!(matches!(
        connection.read().await,
        Err(ConnectionError::Timeout(_))
    ));
    assert!(!connection.is_connected());

    connection.connect().await.expect("second connect");
    connection.send(b"<request/>").await.expect("second send");
    assert_eq!(
        connection.read().await.expect("fresh response"),
        b"<fresh_response/>"
    );

    server.await.expect("server task");
}

#[tokio::test]
async fn malformed_response_fails_without_waiting_for_eof() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let socket_path = directory.path().join("malformed.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind socket");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept connection");
        let mut request = [0_u8; 64];
        let _ = stream.read(&mut request).await.expect("read request");
        stream
            .write_all(b"<response></wrong>")
            .await
            .expect("write response");
    });

    let mut connection = UnixSocketConnection::new(UnixSocketConfig::new(&socket_path));
    connection.connect().await.expect("connect");
    connection.send(b"<request/>").await.expect("send");

    let error = connection.read().await.expect_err("malformed response");
    assert!(matches!(
        error,
        ConnectionError::ReadFailed(ref source)
            if source.kind() == std::io::ErrorKind::InvalidData
    ));
    assert!(!connection.is_connected());
    assert!(matches!(
        connection.send(b"<request/>").await,
        Err(ConnectionError::NotConnected)
    ));

    server.await.expect("server task");
}

#[tokio::test]
async fn response_limit_is_applied_independently_to_coalesced_frames() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let socket_path = directory.path().join("per-frame-limit.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind socket");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept connection");
        let mut request = [0_u8; 64];
        let _ = stream.read(&mut request).await.expect("read request");
        stream
            .write_all(b"<first_response/><oversized-response-without-close")
            .await
            .expect("write responses");
    });

    let first = b"<first_response/>";
    let config = UnixSocketConfig::new(&socket_path).with_max_response_bytes(Some(first.len()));
    let mut connection = UnixSocketConnection::new(config);
    connection.connect().await.expect("connect");
    connection.send(b"<request/>").await.expect("send");

    assert_eq!(connection.read().await.expect("first response"), first);
    let error = connection
        .read()
        .await
        .expect_err("oversized second response");
    assert!(matches!(
        error,
        ConnectionError::ReadFailed(ref source)
            if source.kind() == std::io::ErrorKind::InvalidData
    ));
    assert!(!connection.is_connected());

    server.await.expect("server task");
}
