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

async fn stateful_server() -> Option<MockGmpServer> {
    stateful_server_with_version(GmpVersion::V22_5).await
}

async fn stateful_server_with_version(version: GmpVersion) -> Option<MockGmpServer> {
    build_server(
        MockGmpServer::builder()
            .mode(ServerMode::Stateful)
            .version(version)
            .credentials("admin", "secret")
            .unix_socket_auto(),
    )
    .await
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

// STATE-001: Command before auth returns 401
#[tokio::test]
async fn stateful_command_before_auth_returns_401() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let resp = send_recv(&mut stream, br#"<get_tasks usage_type="scan"/>"#).await;
    assert_eq!(resp.status_code(), Some(401));

    server.shutdown().await;
}

// STATE-002: get_version works without auth
#[tokio::test]
async fn stateful_get_version_without_auth() {
    let Some(server) = stateful_server().await else {
        return;
    };
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
    let Some(server) = stateful_server().await else {
        return;
    };
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

#[tokio::test]
async fn stateful_rejects_unknown_prefixed_commands() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;

    for command in [
        b"<create_not_a_gmp_resource><name>test</name></create_not_a_gmp_resource>".as_slice(),
        b"<get_not_a_gmp_resource/>".as_slice(),
        b"<modify_not_a_gmp_resource not_a_gmp_resource_id=\"id\"/>".as_slice(),
        b"<delete_not_a_gmp_resource not_a_gmp_resource_id=\"id\"/>".as_slice(),
    ] {
        let response = send_recv(&mut stream, command).await;
        assert_eq!(response.status_code(), Some(400));
        assert_eq!(response.status_text().as_deref(), Some("Unknown command"));
    }

    server.shutdown().await;
}

// STATE-004: Invalid credentials rejected
#[tokio::test]
async fn stateful_auth_failure() {
    let Some(server) = stateful_server().await else {
        return;
    };
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
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;

    let target = send_recv(
        &mut stream,
        b"<create_target><name>Test Target</name><hosts>127.0.0.1</hosts></create_target>",
    )
    .await;
    let target_id = target.id().expect("target should have id");
    let resp = send_recv(
        &mut stream,
        format!(
            "<create_task><name>Test Task</name><target id=\"{target_id}\"/><config id=\"daba56c8-73ec-11df-a475-002264764cea\"/><scanner id=\"08b69003-5fc2-4037-a479-93b440211c73\"/></create_task>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(resp.status_code(), Some(201));
    assert!(resp.id().is_some());

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_create_agent_group_task_preserves_agent_group_id() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;

    let create_resp = send_recv(
        &mut stream,
        br#"<create_task><name>Agent Group Task</name><usage_type>scan</usage_type><agent_group id="ag1"/><scanner id="s1"/></create_task>"#,
    )
    .await;
    assert_eq!(create_resp.status_code(), Some(201));
    let task_id = create_resp.id().expect("should have id");

    let get_resp = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));

    let text = get_resp.as_str().expect("valid utf8");
    assert!(text.contains("Agent Group Task"));
    assert!(text.contains("<agent_group_id>ag1</agent_group_id>"));
    assert!(text.contains("<scanner_id>s1</scanner_id>"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_create_oci_image_target_task_preserves_target_id() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;

    let create_resp = send_recv(
        &mut stream,
        br#"<create_task><name>OCI Target Task</name><usage_type>scan</usage_type><oci_image_target id="oci1"/><scanner id="s1"/></create_task>"#,
    )
    .await;
    assert_eq!(create_resp.status_code(), Some(201));
    let task_id = create_resp.id().expect("should have id");

    let get_resp = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));

    let text = get_resp.as_str().expect("valid utf8");
    assert!(text.contains("OCI Target Task"));
    assert!(text.contains("<oci_image_target_id>oci1</oci_image_target_id>"));
    assert!(text.contains("<scanner_id>s1</scanner_id>"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_create_web_application_task_preserves_target_id() {
    let Some(server) = stateful_server_with_version(GmpVersion::V22_8).await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;

    let missing_id = send_recv(
        &mut stream,
        br#"<create_task><name>Invalid Web Task</name><web_application_target/><scanner id="s1"/></create_task>"#,
    )
    .await;
    assert_eq!(missing_id.status_code(), Some(400));
    assert!(missing_id
        .status_text()
        .expect("status text")
        .contains("web_application_target id"));

    let create_resp = send_recv(
        &mut stream,
        br#"<create_task><name>Web Task</name><usage_type>scan</usage_type><web_application_target id="wt1"/><scanner id="s1"/></create_task>"#,
    )
    .await;
    assert_eq!(create_resp.status_code(), Some(201));
    let task_id = create_resp.id().expect("should have id");

    let get_resp = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));

    let text = get_resp.as_str().expect("valid utf8");
    assert!(text.contains("<web_application_target_id>wt1</web_application_target_id>"));
    assert!(text.contains("<scanner_id>s1</scanner_id>"));

    server.shutdown().await;
}

// CRUD-T002: Get created task by ID
#[tokio::test]
async fn stateful_create_then_get_task() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;

    let create_resp = create_task(&mut stream, "My Task").await;
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
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;

    create_task(&mut stream, "Task A").await;
    create_task(&mut stream, "Task B").await;

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
    let Some(server) = stateful_server().await else {
        return;
    };
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
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;

    let create_resp = create_task(&mut stream, "Old Name").await;
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
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;

    let create_resp = create_task(&mut stream, "Doomed").await;
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
    let Some(server) = stateful_server().await else {
        return;
    };
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
    let Some(server) = stateful_server().await else {
        return;
    };
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
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;

    let create_resp = create_task(&mut stream, "Original").await;
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
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;

    let create_resp = create_task(&mut stream, "Runnable").await;
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
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;

    let create_resp = create_task(&mut stream, "Stoppable").await;
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
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;

    let create_resp = create_task(&mut stream, "Resumable").await;
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
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;

    let create_resp = create_task(&mut stream, "Running").await;
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
    let Some(server) = build_server(
        MockGmpServer::builder()
            .mode(ServerMode::Stateful)
            .version(GmpVersion::V22_5)
            .credentials("admin", "admin")
            .seed(|store| {
                let mut task = Resource::new("task", "Seeded Task");
                task.set_attr("status", "New");
                store.seed(task);
            })
            .unix_socket_auto(),
    )
    .await
    else {
        return;
    };

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
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;

    let create_resp = create_task(&mut stream, "Trashed").await;
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
async fn build_server(builder: gvm_mock_server::MockGmpServerBuilder) -> Option<MockGmpServer> {
    match builder.build().await {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server start failed: {error}"),
    }
}
