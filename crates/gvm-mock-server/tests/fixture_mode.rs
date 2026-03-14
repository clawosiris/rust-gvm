//! Integration tests for Fixture mode.

use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Helper: send XML and read response via Unix socket.
async fn send_recv(stream: &mut UnixStream, xml: &[u8]) -> Vec<u8> {
    stream.write_all(xml).await.expect("write failed");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).await.expect("read failed");
    buf.truncate(n);
    buf
}

/// Helper: start a fixture server.
async fn fixture_server() -> MockGmpServer {
    MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(GmpVersion::V22_5)
        .unix_socket_auto()
        .build()
        .await
        .expect("server start failed")
}

// FIX-020: get_version returns correct version from fixtures
#[tokio::test]
async fn fixture_get_version() {
    let server = fixture_server().await;
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let resp_bytes = send_recv(&mut stream, b"<get_version/>").await;
    let resp = Response::new(resp_bytes);

    assert_eq!(resp.status_code(), Some(200));
    assert_eq!(resp.child_text("version"), Some("22.5".to_string()));

    server.shutdown().await;
}

// FIX-020b: get_version returns different version when configured
#[tokio::test]
async fn fixture_get_version_v22_4() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(GmpVersion::V22_4)
        .unix_socket_auto()
        .build()
        .await
        .expect("server start failed");

    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let resp_bytes = send_recv(&mut stream, b"<get_version/>").await;
    let resp = Response::new(resp_bytes);

    assert_eq!(resp.child_text("version"), Some("22.4".to_string()));

    server.shutdown().await;
}

// FIX-021: authenticate returns role and timezone
#[tokio::test]
async fn fixture_authenticate() {
    let server = fixture_server().await;
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let resp_bytes = send_recv(
        &mut stream,
        b"<authenticate><credentials><username>admin</username><password>pass</password></credentials></authenticate>",
    ).await;
    let resp = Response::new(resp_bytes);

    assert_eq!(resp.status_code(), Some(200));

    // Check that the response contains role and timezone
    let text = resp.as_str().expect("should be valid utf8");
    assert!(text.contains("<role>"), "Should contain role element");
    assert!(text.contains("<timezone>"), "Should contain timezone element");

    server.shutdown().await;
}

// FIX-022: get_tasks returns multiple tasks
#[tokio::test]
async fn fixture_get_tasks_multiple() {
    let server = fixture_server().await;
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let resp_bytes = send_recv(&mut stream, br#"<get_tasks usage_type="scan"/>"#).await;
    let resp = Response::new(resp_bytes);

    assert_eq!(resp.status_code(), Some(200));

    let text = resp.as_str().expect("should be valid utf8");
    // Should contain task elements
    assert!(text.contains("<task "), "Should contain task elements");
    assert!(text.contains("Discovery Scan"), "Should contain fixture task name");
    assert!(text.contains("task_count"), "Should contain task_count");

    server.shutdown().await;
}

// FIX-024: create_task returns 201 with id
#[tokio::test]
async fn fixture_create_task() {
    let server = fixture_server().await;
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let resp_bytes = send_recv(
        &mut stream,
        b"<create_task><name>test</name><target id=\"t1\"/></create_task>",
    )
    .await;
    let resp = Response::new(resp_bytes);

    assert_eq!(resp.status_code(), Some(201));
    assert!(resp.id().is_some(), "Should have id attribute");

    // UUID should be valid
    let id = resp.id().unwrap();
    assert!(id.len() > 10, "ID should be a UUID-like string");

    server.shutdown().await;
}

// FIX: UUID is different each time
#[tokio::test]
async fn fixture_uuids_differ() {
    let server = fixture_server().await;
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let resp1 = send_recv(
        &mut stream,
        b"<create_task><name>t1</name><target id=\"t1\"/></create_task>",
    )
    .await;
    let resp2 = send_recv(
        &mut stream,
        b"<create_task><name>t2</name><target id=\"t1\"/></create_task>",
    )
    .await;

    let r1 = Response::new(resp1);
    let r2 = Response::new(resp2);

    let id1 = r1.id().expect("should have id");
    let id2 = r2.id().expect("should have id");
    assert_ne!(id1, id2, "UUIDs should be different for each create");

    server.shutdown().await;
}

// FIX: Override response works
#[tokio::test]
async fn fixture_override_response() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(GmpVersion::V22_5)
        .override_response(
            "get_tasks",
            r#"<get_tasks_response status="200" status_text="OK"><task_count>0</task_count></get_tasks_response>"#,
        )
        .unix_socket_auto()
        .build()
        .await
        .expect("server start failed");

    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let resp_bytes = send_recv(&mut stream, br#"<get_tasks usage_type="scan"/>"#).await;
    let resp = Response::new(resp_bytes);

    assert_eq!(resp.status_code(), Some(200));
    let text = resp.as_str().expect("valid utf8");
    assert!(
        !text.contains("Discovery Scan"),
        "Should use override, not default fixture"
    );

    server.shutdown().await;
}
