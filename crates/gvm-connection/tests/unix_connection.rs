#![cfg(feature = "unix-socket-tests")]
#![allow(clippy::print_stdout, clippy::unwrap_used, missing_docs)]

use gvm_connection::{GvmConnection, UnixSocketConfig, UnixSocketConnection};
use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::{Request, Response, XmlCommand};

async fn start_mock() -> MockGmpServer {
    MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_5)
        .credentials("admin", "admin")
        .unix_socket_auto()
        .build()
        .await
        .expect("mock server start failed")
}

#[tokio::test]
async fn connect_and_get_version() {
    let server = start_mock().await;
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
    let socket_path = server.socket_path().expect("should have socket");

    let config = UnixSocketConfig::new(socket_path);
    let mut conn = UnixSocketConnection::new(config);

    conn.connect().await.expect("connect failed");
    let result = conn.connect().await;
    assert!(result.is_err());

    conn.disconnect().await.expect("disconnect failed");
    server.shutdown().await;
}
