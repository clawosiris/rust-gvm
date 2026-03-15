// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Additional broad stateful CRUD coverage for more resource types.

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

#[tokio::test]
async fn matrix_notes_create_list() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let note_id = create_and_get_id(
        &mut stream,
        b"<create_note><name>Matrix Note</name><comment>note</comment></create_note>",
        "create_note",
    )
    .await;

    let list_resp = send_recv(&mut stream, b"<get_notes/>").await;
    assert_eq!(list_resp.status_code(), Some(200));
    let list_text = list_resp.as_str().expect("valid utf8");
    assert!(list_text.contains(&note_id));
    assert!(list_text.contains("Matrix Note"));

    server.shutdown().await;
}

#[tokio::test]
async fn matrix_overrides_create_list() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let override_id = create_and_get_id(
        &mut stream,
        b"<create_override><name>Matrix Override</name><comment>override</comment></create_override>",
        "create_override",
    )
    .await;

    let list_resp = send_recv(&mut stream, b"<get_overrides/>").await;
    assert_eq!(list_resp.status_code(), Some(200));
    let list_text = list_resp.as_str().expect("valid utf8");
    assert!(list_text.contains(&override_id));
    assert!(list_text.contains("Matrix Override"));

    server.shutdown().await;
}

#[tokio::test]
async fn matrix_roles_create_modify() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let role_id = create_and_get_id(
        &mut stream,
        b"<create_role><name>Matrix Role Old</name><comment>role</comment></create_role>",
        "create_role",
    )
    .await;

    let modify_resp = send_recv(
        &mut stream,
        format!("<modify_role role_id=\"{role_id}\"><name>Matrix Role New</name></modify_role>")
            .as_bytes(),
    )
    .await;
    assert_eq!(modify_resp.status_code(), Some(200));

    let get_resp = send_recv(
        &mut stream,
        format!("<get_roles role_id=\"{role_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));
    let get_text = get_resp.as_str().expect("valid utf8");
    assert!(get_text.contains("Matrix Role New"));

    let list_resp = send_recv(&mut stream, b"<get_roles/>").await;
    assert_eq!(list_resp.status_code(), Some(200));
    let list_text = list_resp.as_str().expect("valid utf8");
    assert!(list_text.contains("Matrix Role New"));

    server.shutdown().await;
}

#[tokio::test]
async fn matrix_users_create_get_by_id() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let user_id = create_and_get_id(
        &mut stream,
        b"<create_user><name>Matrix User</name><comment>user</comment></create_user>",
        "create_user",
    )
    .await;

    let get_resp = send_recv(
        &mut stream,
        format!("<get_users user_id=\"{user_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));
    let get_text = get_resp.as_str().expect("valid utf8");
    assert!(get_text.contains(&user_id));
    assert!(get_text.contains("Matrix User"));

    server.shutdown().await;
}

#[tokio::test]
async fn matrix_tickets_create_delete_ultimate() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let ticket_id = create_and_get_id(
        &mut stream,
        b"<create_ticket><name>Matrix Ticket</name><comment>ticket</comment></create_ticket>",
        "create_ticket",
    )
    .await;

    let delete_resp = send_recv(
        &mut stream,
        format!("<delete_ticket ticket_id=\"{ticket_id}\" ultimate=\"1\"/>").as_bytes(),
    )
    .await;
    assert_eq!(delete_resp.status_code(), Some(200));

    let get_resp = send_recv(
        &mut stream,
        format!("<get_tickets ticket_id=\"{ticket_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(404));

    server.shutdown().await;
}

#[tokio::test]
async fn matrix_port_lists_create_list() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let port_list_id = create_and_get_id(
        &mut stream,
        b"<create_port_list><name>Matrix Port List</name><comment>ports</comment></create_port_list>",
        "create_port_list",
    )
    .await;

    let list_resp = send_recv(&mut stream, b"<get_port_lists/>").await;
    assert_eq!(list_resp.status_code(), Some(200));
    let list_text = list_resp.as_str().expect("valid utf8");
    assert!(list_text.contains(&port_list_id));
    assert!(list_text.contains("Matrix Port List"));

    server.shutdown().await;
}

#[tokio::test]
async fn matrix_reports_create_list() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let report_id = create_and_get_id(
        &mut stream,
        b"<create_report><name>Matrix Report</name><comment>report</comment></create_report>",
        "create_report",
    )
    .await;

    let list_resp = send_recv(&mut stream, b"<get_reports/>").await;
    assert_eq!(list_resp.status_code(), Some(200));
    let list_text = list_resp.as_str().expect("valid utf8");
    assert!(list_text.contains(&report_id));
    assert!(list_text.contains("Matrix Report"));

    server.shutdown().await;
}

#[tokio::test]
async fn matrix_tags_create_modify() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let tag_id = create_and_get_id(
        &mut stream,
        b"<create_tag><name>Matrix Tag Old</name><comment>tag</comment></create_tag>",
        "create_tag",
    )
    .await;

    let modify_resp = send_recv(
        &mut stream,
        format!("<modify_tag tag_id=\"{tag_id}\"><name>Matrix Tag New</name></modify_tag>")
            .as_bytes(),
    )
    .await;
    assert_eq!(modify_resp.status_code(), Some(200));

    let get_resp = send_recv(
        &mut stream,
        format!("<get_tags tag_id=\"{tag_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));
    let get_text = get_resp.as_str().expect("valid utf8");
    assert!(get_text.contains("Matrix Tag New"));

    let list_resp = send_recv(&mut stream, b"<get_tags/>").await;
    assert_eq!(list_resp.status_code(), Some(200));
    let list_text = list_resp.as_str().expect("valid utf8");
    assert!(list_text.contains("Matrix Tag New"));

    println!("STATEFUL_MATRIX_MORE_DONE");

    server.shutdown().await;
}
