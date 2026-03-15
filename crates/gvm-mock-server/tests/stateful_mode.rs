// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Integration tests for Stateful mode.

#![cfg(feature = "unix-socket-tests")]
#![allow(
    clippy::print_stdout,
    clippy::redundant_closure_for_method_calls,
    clippy::unwrap_used,
    missing_docs
)]

use gvm_mock_server::{GmpVersion, MockGmpServer, Resource, ServerMode};
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

async fn stateful_server() -> MockGmpServer {
    MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_5)
        .credentials("admin", "secret")
        .unix_socket_auto()
        .build()
        .await
        .expect("server start failed")
}

async fn connect_and_auth(server: &MockGmpServer) -> UnixStream {
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");
    let resp = send_recv(
        &mut stream,
        b"<authenticate><credentials><username>admin</username><password>secret</password></credentials></authenticate>",
    ).await;
    assert_eq!(resp.status_code(), Some(200), "Auth should succeed");
    stream
}

// STATE-001: Command before auth returns 401
#[tokio::test]
async fn stateful_command_before_auth_returns_401() {
    let server = stateful_server().await;
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let resp = send_recv(&mut stream, br#"<get_tasks usage_type="scan"/>"#).await;
    assert_eq!(resp.status_code(), Some(401));

    server.shutdown().await;
}

// STATE-002: get_version works without auth
#[tokio::test]
async fn stateful_get_version_without_auth() {
    let server = stateful_server().await;
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let resp = send_recv(&mut stream, b"<get_version/>").await;
    assert_eq!(resp.status_code(), Some(200));
    assert_eq!(resp.child_text("version"), Some("22.5".to_string()));

    server.shutdown().await;
}

// STATE-003: Valid credentials authenticate
#[tokio::test]
async fn stateful_auth_success() {
    let server = stateful_server().await;
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let resp = send_recv(
        &mut stream,
        b"<authenticate><credentials><username>admin</username><password>secret</password></credentials></authenticate>",
    ).await;
    assert_eq!(resp.status_code(), Some(200));

    let text = resp.as_str().expect("valid utf8");
    assert!(text.contains("<role>"));
    assert!(text.contains("<timezone>"));

    server.shutdown().await;
}

// STATE-004: Invalid credentials rejected
#[tokio::test]
async fn stateful_auth_failure() {
    let server = stateful_server().await;
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let resp = send_recv(
        &mut stream,
        b"<authenticate><credentials><username>admin</username><password>wrong</password></credentials></authenticate>",
    ).await;
    assert_eq!(resp.status_code(), Some(400));

    server.shutdown().await;
}

// CRUD-T001: Create task
#[tokio::test]
async fn stateful_create_task() {
    let server = stateful_server().await;
    let mut stream = connect_and_auth(&server).await;

    let resp = send_recv(
        &mut stream,
        br#"<create_task><name>Test Task</name><target id="t1"/><config id="c1"/><scanner id="s1"/></create_task>"#,
    ).await;
    assert_eq!(resp.status_code(), Some(201));
    assert!(resp.id().is_some());

    server.shutdown().await;
}

// CRUD-T002: Get created task by ID
#[tokio::test]
async fn stateful_create_then_get_task() {
    let server = stateful_server().await;
    let mut stream = connect_and_auth(&server).await;

    let create_resp = send_recv(
        &mut stream,
        b"<create_task><name>My Task</name><target id=\"t1\"/></create_task>",
    )
    .await;
    let task_id = create_resp.id().expect("should have id");

    let get_resp = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));

    let text = get_resp.as_str().expect("valid utf8");
    assert!(text.contains("My Task"));

    server.shutdown().await;
}

// CRUD-T003: List all tasks
#[tokio::test]
async fn stateful_list_tasks() {
    let server = stateful_server().await;
    let mut stream = connect_and_auth(&server).await;

    send_recv(
        &mut stream,
        b"<create_task><name>Task A</name><target id=\"t1\"/></create_task>",
    )
    .await;
    send_recv(
        &mut stream,
        b"<create_task><name>Task B</name><target id=\"t1\"/></create_task>",
    )
    .await;

    let resp = send_recv(&mut stream, b"<get_tasks/>").await;
    assert_eq!(resp.status_code(), Some(200));

    let text = resp.as_str().expect("valid utf8");
    assert!(text.contains("Task A"));
    assert!(text.contains("Task B"));
    assert!(text.contains("<task_count>2"));

    server.shutdown().await;
}

// CRUD-T004: Empty task list
#[tokio::test]
async fn stateful_empty_task_list() {
    let server = stateful_server().await;
    let mut stream = connect_and_auth(&server).await;

    let resp = send_recv(&mut stream, b"<get_tasks/>").await;
    assert_eq!(resp.status_code(), Some(200));
    let text = resp.as_str().expect("valid utf8");
    assert!(text.contains("<task_count>0"));

    server.shutdown().await;
}

// CRUD-T005: Modify task name
#[tokio::test]
async fn stateful_modify_task() {
    let server = stateful_server().await;
    let mut stream = connect_and_auth(&server).await;

    let create_resp = send_recv(
        &mut stream,
        b"<create_task><name>Old Name</name><target id=\"t1\"/></create_task>",
    )
    .await;
    let task_id = create_resp.id().expect("should have id");

    let modify_resp = send_recv(
        &mut stream,
        format!("<modify_task task_id=\"{task_id}\"><name>New Name</name></modify_task>")
            .as_bytes(),
    )
    .await;
    assert_eq!(modify_resp.status_code(), Some(200));

    let get_resp = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    let text = get_resp.as_str().expect("valid utf8");
    assert!(text.contains("New Name"));

    server.shutdown().await;
}

// CRUD-T007: Delete task to trash
#[tokio::test]
async fn stateful_delete_task_to_trash() {
    let server = stateful_server().await;
    let mut stream = connect_and_auth(&server).await;

    let create_resp = send_recv(
        &mut stream,
        b"<create_task><name>Doomed</name><target id=\"t1\"/></create_task>",
    )
    .await;
    let task_id = create_resp.id().expect("should have id");

    let delete_resp = send_recv(
        &mut stream,
        format!("<delete_task task_id=\"{task_id}\" ultimate=\"0\"/>").as_bytes(),
    )
    .await;
    assert_eq!(delete_resp.status_code(), Some(200));

    // Should not appear in normal list
    let get_resp = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(404));

    server.shutdown().await;
}

// CRUD-T009: Delete nonexistent task
#[tokio::test]
async fn stateful_delete_nonexistent() {
    let server = stateful_server().await;
    let mut stream = connect_and_auth(&server).await;

    let resp = send_recv(
        &mut stream,
        br#"<delete_task task_id="00000000-0000-0000-0000-000000000000" ultimate="0"/>"#,
    )
    .await;
    assert_eq!(resp.status_code(), Some(404));

    server.shutdown().await;
}

// CRUD-T010: Get nonexistent task
#[tokio::test]
async fn stateful_get_nonexistent() {
    let server = stateful_server().await;
    let mut stream = connect_and_auth(&server).await;

    let resp = send_recv(
        &mut stream,
        br#"<get_tasks task_id="00000000-0000-0000-0000-000000000000"/>"#,
    )
    .await;
    assert_eq!(resp.status_code(), Some(404));

    server.shutdown().await;
}

// CRUD-T011: Clone task
#[tokio::test]
async fn stateful_clone_task() {
    let server = stateful_server().await;
    let mut stream = connect_and_auth(&server).await;

    let create_resp = send_recv(
        &mut stream,
        b"<create_task><name>Original</name><target id=\"t1\"/></create_task>",
    )
    .await;
    let task_id = create_resp.id().expect("should have id");

    let clone_resp = send_recv(
        &mut stream,
        format!("<create_task><copy>{task_id}</copy></create_task>").as_bytes(),
    )
    .await;
    assert_eq!(clone_resp.status_code(), Some(201));
    let clone_id = clone_resp.id().expect("should have id");
    assert_ne!(task_id, clone_id);

    // Both should exist
    let resp1 = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(resp1.status_code(), Some(200));

    let resp2 = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{clone_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(resp2.status_code(), Some(200));

    server.shutdown().await;
}

// TASK-001: Start new task
#[tokio::test]
async fn stateful_start_task() {
    let server = stateful_server().await;
    let mut stream = connect_and_auth(&server).await;

    let create_resp = send_recv(
        &mut stream,
        b"<create_task><name>Runnable</name><target id=\"t1\"/></create_task>",
    )
    .await;
    let task_id = create_resp.id().expect("should have id");

    let start_resp = send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(start_resp.status_code(), Some(202));

    // Should have report_id
    let text = start_resp.as_str().expect("valid utf8");
    assert!(text.contains("<report_id>"));

    // Status should be Running
    let get_resp = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    let get_text = get_resp.as_str().expect("valid utf8");
    assert!(get_text.contains("Running"));

    server.shutdown().await;
}

// TASK-002: Stop running task
#[tokio::test]
async fn stateful_stop_task() {
    let server = stateful_server().await;
    let mut stream = connect_and_auth(&server).await;

    let create_resp = send_recv(
        &mut stream,
        b"<create_task><name>Stoppable</name><target id=\"t1\"/></create_task>",
    )
    .await;
    let task_id = create_resp.id().expect("should have id");

    send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;

    let stop_resp = send_recv(
        &mut stream,
        format!("<stop_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(stop_resp.status_code(), Some(200));

    let get_resp = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    let text = get_resp.as_str().expect("valid utf8");
    assert!(text.contains("Stopped"));

    server.shutdown().await;
}

// TASK-003: Resume stopped task
#[tokio::test]
async fn stateful_resume_task() {
    let server = stateful_server().await;
    let mut stream = connect_and_auth(&server).await;

    let create_resp = send_recv(
        &mut stream,
        b"<create_task><name>Resumable</name><target id=\"t1\"/></create_task>",
    )
    .await;
    let task_id = create_resp.id().expect("should have id");

    send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    send_recv(
        &mut stream,
        format!("<stop_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;

    let resume_resp = send_recv(
        &mut stream,
        format!("<resume_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(resume_resp.status_code(), Some(202));

    let get_resp = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    let text = get_resp.as_str().expect("valid utf8");
    assert!(text.contains("Running"));

    server.shutdown().await;
}

// TASK-004: Start already running task → 409
#[tokio::test]
async fn stateful_start_running_task_conflict() {
    let server = stateful_server().await;
    let mut stream = connect_and_auth(&server).await;

    let create_resp = send_recv(
        &mut stream,
        b"<create_task><name>Running</name><target id=\"t1\"/></create_task>",
    )
    .await;
    let task_id = create_resp.id().expect("should have id");

    send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;

    let start2_resp = send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(start2_resp.status_code(), Some(409));

    server.shutdown().await;
}

// SEED: Pre-seeded resources appear
#[tokio::test]
async fn stateful_seed() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_5)
        .credentials("admin", "admin")
        .seed(|store| {
            let mut task = Resource::new("task", "Seeded Task");
            task.set_attr("status", "New");
            store.seed(task);
        })
        .unix_socket_auto()
        .build()
        .await
        .expect("server start failed");

    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    send_recv(
        &mut stream,
        b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>",
    ).await;

    let resp = send_recv(&mut stream, b"<get_tasks/>").await;
    let text = resp.as_str().expect("valid utf8");
    assert!(text.contains("Seeded Task"));
    assert!(text.contains("<task_count>1"));

    server.shutdown().await;
}

// TRASH: Restore from trashcan
#[tokio::test]
async fn stateful_trash_and_restore() {
    let server = stateful_server().await;
    let mut stream = connect_and_auth(&server).await;

    let create_resp = send_recv(
        &mut stream,
        b"<create_task><name>Trashed</name><target id=\"t1\"/></create_task>",
    )
    .await;
    let task_id = create_resp.id().expect("should have id");

    // Delete to trash
    send_recv(
        &mut stream,
        format!("<delete_task task_id=\"{task_id}\" ultimate=\"0\"/>").as_bytes(),
    )
    .await;

    // Restore
    let restore_resp = send_recv(
        &mut stream,
        format!("<restore id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(restore_resp.status_code(), Some(200));

    // Should be back
    let get_resp = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));

    server.shutdown().await;
}
