// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Integration tests for basic filtering in stateful mode (FILT-001..005).

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

async fn send_recv(stream: &mut UnixStream, xml: &[u8]) -> Response {
    stream.write_all(xml).await.expect("write failed");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).await.expect("read failed");
    buf.truncate(n);
    Response::new(buf)
}

async fn auth_admin(stream: &mut UnixStream) {
    let resp = send_recv(
        stream,
        b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>",
    )
    .await;
    assert_eq!(resp.status_code(), Some(200));
}

async fn stateful_server() -> Option<MockGmpServer> {
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
        Err(error) => panic!("server start failed: {error}"),
    }
}

async fn connect(server: &MockGmpServer) -> UnixStream {
    let path = server.socket_path().expect("should have socket path");
    UnixStream::connect(path).await.expect("connect failed")
}

async fn create_task(stream: &mut UnixStream, name: &str) -> Response {
    let target = send_recv(
        stream,
        format!(
            "<create_target><name>{name} Target</name><hosts>127.0.0.1</hosts></create_target>"
        )
        .as_bytes(),
    )
    .await;
    let target_id = target.id().expect("target should have id");
    send_recv(
        stream,
        format!("<create_task><name>{name}</name><target id=\"{target_id}\"/></create_task>")
            .as_bytes(),
    )
    .await
}

// FILT-001: Filter by name equality
#[tokio::test]
async fn filter_by_name_equality() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    // Create two tasks with different names (single-word for simple filter)
    create_task(&mut stream, "AlphaTask").await;
    create_task(&mut stream, "BetaTask").await;

    // Filter by name=AlphaTask
    let resp = send_recv(&mut stream, br#"<get_tasks filter="name=AlphaTask"/>"#).await;
    assert_eq!(resp.status_code(), Some(200));
    let text = resp.as_str().expect("utf8");
    assert!(text.contains("AlphaTask"), "Should contain matching task");
    assert!(
        !text.contains("BetaTask"),
        "Should not contain non-matching task"
    );

    server.shutdown().await;
}

// FILT-002: Filter returns empty for no match
#[tokio::test]
async fn filter_no_match_returns_empty() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    create_task(&mut stream, "Existing").await;

    let resp = send_recv(&mut stream, br#"<get_tasks filter="name=Nonexistent"/>"#).await;
    assert_eq!(resp.status_code(), Some(200));
    let text = resp.as_str().expect("utf8");
    assert!(
        text.contains("<task_count>0") || !text.contains("<task "),
        "No tasks should match"
    );

    server.shutdown().await;
}

// FILT-004: No filter returns all
#[tokio::test]
async fn no_filter_returns_all() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    create_task(&mut stream, "Task A").await;
    create_task(&mut stream, "Task B").await;

    let resp = send_recv(&mut stream, b"<get_tasks/>").await;
    assert_eq!(resp.status_code(), Some(200));
    let text = resp.as_str().expect("utf8");
    assert!(text.contains("Task A"));
    assert!(text.contains("Task B"));

    server.shutdown().await;
}

// FILT-005: Trash filter
#[tokio::test]
async fn trash_filter_returns_only_trashed() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    // Create and trash one task
    let create_resp = create_task(&mut stream, "Trashed Task").await;
    let create_text = create_resp.as_str().expect("utf8");
    let marker = "id=\"";
    let start = create_text.find(marker).unwrap() + marker.len();
    let rest = &create_text[start..];
    let end = rest.find('"').unwrap();
    let task_id = &rest[..end];

    // Delete to trash
    send_recv(
        &mut stream,
        format!("<delete_task task_id=\"{task_id}\" ultimate=\"0\"/>").as_bytes(),
    )
    .await;

    // Create another task (not trashed)
    create_task(&mut stream, "Active Task").await;

    // Normal get should only show Active Task
    let normal_resp = send_recv(&mut stream, b"<get_tasks/>").await;
    let normal_text = normal_resp.as_str().expect("utf8");
    assert!(normal_text.contains("Active Task"));
    assert!(!normal_text.contains("Trashed Task"));

    // Trash filter should show only trashed
    let trash_resp = send_recv(&mut stream, br#"<get_tasks trash="1"/>"#).await;
    assert_eq!(trash_resp.status_code(), Some(200));
    let trash_text = trash_resp.as_str().expect("utf8");
    assert!(trash_text.contains("Trashed Task"));
    assert!(!trash_text.contains("Active Task"));

    server.shutdown().await;
}
