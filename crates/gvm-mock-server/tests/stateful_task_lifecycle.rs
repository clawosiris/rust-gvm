// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Focused stateful task lifecycle coverage.

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
    assert_eq!(resp.status_code(), Some(200), "admin auth should succeed");
}

async fn create_and_get_id(
    stream: &mut UnixStream,
    create_xml: &[u8],
    create_cmd_name: &str,
) -> String {
    let resp = send_recv(stream, create_xml).await;
    assert_eq!(
        resp.status_code(),
        Some(201),
        "{create_cmd_name} should return 201"
    );

    let text = resp.as_str().expect("create response should be valid utf8");
    let marker = "id=\"";
    let start = text
        .find(marker)
        .expect("response should contain id attribute")
        + marker.len();
    let rest = &text[start..];
    let end = rest.find('"').expect("id attribute should be terminated");
    rest[..end].to_string()
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

fn extract_report_id(text: &str) -> &str {
    let start_marker = "<report_id>";
    let end_marker = "</report_id>";
    let start = text
        .find(start_marker)
        .expect("response should contain <report_id>")
        + start_marker.len();
    let rest = &text[start..];
    let end = rest
        .find(end_marker)
        .expect("report_id should be terminated");
    &rest[..end]
}

#[tokio::test]
async fn task_start_new_task() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let task_id = create_and_get_id(
        &mut stream,
        b"<create_task><name>Lifecycle Start</name><target id=\"t1\"/></create_task>",
        "create_task",
    )
    .await;

    let start_resp = send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(start_resp.status_code(), Some(202));
    let start_text = start_resp.as_str().expect("valid utf8");
    assert!(start_text.contains("<report_id>"));

    let get_resp = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));
    assert!(
        get_resp.as_str().expect("valid utf8").contains("Running"),
        "task should be Running after start_task"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn task_stop_running_task() {
    let Some(server) = stateful_server().await else { return; };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let task_id = create_and_get_id(
        &mut stream,
        b"<create_task><name>Lifecycle Stop</name><target id=\"t1\"/></create_task>",
        "create_task",
    )
    .await;

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
    assert_eq!(get_resp.status_code(), Some(200));
    assert!(
        get_resp.as_str().expect("valid utf8").contains("Stopped"),
        "task should be Stopped after stop_task"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn task_resume_stopped_task() {
    let Some(server) = stateful_server().await else { return; };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let task_id = create_and_get_id(
        &mut stream,
        b"<create_task><name>Lifecycle Resume</name><target id=\"t1\"/></create_task>",
        "create_task",
    )
    .await;

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
    assert_eq!(get_resp.status_code(), Some(200));
    assert!(
        get_resp.as_str().expect("valid utf8").contains("Running"),
        "task should be Running after resume_task"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn task_start_already_running_returns_409() {
    let Some(server) = stateful_server().await else { return; };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let task_id = create_and_get_id(
        &mut stream,
        b"<create_task><name>Lifecycle Start Conflict</name><target id=\"t1\"/></create_task>",
        "create_task",
    )
    .await;

    send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;

    let start_again_resp = send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(start_again_resp.status_code(), Some(409));

    server.shutdown().await;
}

#[tokio::test]
async fn task_stop_already_stopped_returns_409() {
    let Some(server) = stateful_server().await else { return; };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let task_id = create_and_get_id(
        &mut stream,
        b"<create_task><name>Lifecycle Stop Conflict</name><target id=\"t1\"/></create_task>",
        "create_task",
    )
    .await;

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

    let stop_again_resp = send_recv(
        &mut stream,
        format!("<stop_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(stop_again_resp.status_code(), Some(409));

    server.shutdown().await;
}

#[tokio::test]
async fn task_resume_non_stopped_returns_409() {
    let Some(server) = stateful_server().await else { return; };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let task_id = create_and_get_id(
        &mut stream,
        b"<create_task><name>Lifecycle Resume Conflict</name><target id=\"t1\"/></create_task>",
        "create_task",
    )
    .await;

    send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;

    let resume_resp = send_recv(
        &mut stream,
        format!("<resume_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(resume_resp.status_code(), Some(409));

    server.shutdown().await;
}

#[tokio::test]
async fn task_get_shows_current_status() {
    let Some(server) = stateful_server().await else { return; };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let task_id = create_and_get_id(
        &mut stream,
        b"<create_task><name>Status Progression</name><target id=\"t1\"/></create_task>",
        "create_task",
    )
    .await;

    let new_resp = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(new_resp.status_code(), Some(200));
    assert!(new_resp.as_str().expect("valid utf8").contains("New"));

    send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    let running_resp = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(running_resp.status_code(), Some(200));
    assert!(running_resp
        .as_str()
        .expect("valid utf8")
        .contains("Running"));

    send_recv(
        &mut stream,
        format!("<stop_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    let stopped_resp = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(stopped_resp.status_code(), Some(200));
    assert!(stopped_resp
        .as_str()
        .expect("valid utf8")
        .contains("Stopped"));

    server.shutdown().await;
}

#[tokio::test]
async fn task_start_returns_report_id() {
    let Some(server) = stateful_server().await else { return; };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let task_id = create_and_get_id(
        &mut stream,
        b"<create_task><name>Report Id</name><target id=\"t1\"/></create_task>",
        "create_task",
    )
    .await;

    let start_resp = send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(start_resp.status_code(), Some(202));

    let start_text = start_resp.as_str().expect("valid utf8");
    let report_id = extract_report_id(start_text);
    assert_eq!(report_id.len(), 36, "report_id should be a UUID string");
    assert_eq!(
        report_id.chars().filter(|&ch| ch == '-').count(),
        4,
        "report_id should contain UUID hyphens"
    );

    println!("TASK_LIFECYCLE_DONE");

    server.shutdown().await;
}
