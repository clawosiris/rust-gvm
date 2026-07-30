// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(
    clippy::print_stdout,
    clippy::redundant_closure_for_method_calls,
    clippy::unwrap_used,
    missing_docs
)]
#![cfg(feature = "unix-socket-tests")]

use gvm_mock_server::{AssetInputProfile, GmpVersion, MockGmpServer, Resource, ServerMode};
use gvm_protocol::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use uuid::Uuid;

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
    build_server(
        MockGmpServer::builder()
            .mode(ServerMode::Stateful)
            .version(GmpVersion::V22_5)
            .credentials("admin", "admin")
            .asset_input_profile(AssetInputProfile::LegacyFlatCompatibility)
            .unix_socket_auto(),
    )
    .await
}

async fn connect(server: &MockGmpServer) -> UnixStream {
    let path = server.socket_path().expect("should have socket path");
    UnixStream::connect(path).await.expect("connect failed")
}

fn extract_id(response: &Response) -> String {
    response
        .id()
        .expect("response should contain id")
        .to_string()
}

#[tokio::test]
async fn get_assets_filters_by_asset_type() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let host_resp = send_recv(
        &mut stream,
        b"<create_asset asset_type=\"host\"><name>192.168.1.1</name></create_asset>",
    )
    .await;
    assert_eq!(host_resp.status_code(), Some(201));

    let os_resp = send_recv(
        &mut stream,
        b"<create_asset><asset_type>os</asset_type><value>Ubuntu</value></create_asset>",
    )
    .await;
    assert_eq!(os_resp.status_code(), Some(201));

    let list_resp = send_recv(&mut stream, b"<get_assets asset_type=\"host\"/>").await;
    assert_eq!(list_resp.status_code(), Some(200));
    let text = list_resp.as_str().expect("valid utf8");
    assert!(text.contains("192.168.1.1"));
    assert!(text.contains("<type>host</type>"));
    assert!(!text.contains("Ubuntu"));

    server.shutdown().await;
}

#[tokio::test]
async fn get_results_and_nvts_return_stateful_resources() {
    let result_id = Uuid::new_v4();
    let nvt_id = Uuid::new_v4();
    let report_id = Uuid::new_v4();

    let Some(server) = build_server(
        MockGmpServer::builder()
            .mode(ServerMode::Stateful)
            .version(GmpVersion::V22_5)
            .credentials("admin", "admin")
            .seed(move |store| {
                let mut result = Resource::with_id("result", "Test Result", result_id);
                result.set_attr("host", "192.168.1.1");
                result.set_attr("port", "443/tcp");
                result.set_attr("threat", "High");
                result.set_attr("severity", "8.5");
                result.set_attr("report_id", &report_id.to_string());
                store.seed(result);

                let mut nvt = Resource::with_id("nvt", "Test NVT", nvt_id);
                nvt.set_attr("family", "General");
                store.seed(nvt);
            })
            .unix_socket_auto(),
    )
    .await
    else {
        return;
    };

    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let results_resp = send_recv(&mut stream, b"<get_results/>").await;
    assert_eq!(results_resp.status_code(), Some(200));
    let results_text = results_resp.as_str().expect("valid utf8");
    assert!(results_text.contains(&result_id.to_string()));
    assert!(results_text.contains("Test Result"));
    assert!(results_text.contains("<result_count>1"));

    let nvts_resp = send_recv(&mut stream, b"<get_nvts/>").await;
    assert_eq!(nvts_resp.status_code(), Some(200));
    let nvts_text = nvts_resp.as_str().expect("valid utf8");
    assert!(nvts_text.contains(&nvt_id.to_string()));
    assert!(nvts_text.contains("Test NVT"));
    assert!(nvts_text.contains("<nvt_count>1"));

    server.shutdown().await;
}

#[tokio::test]
async fn create_and_modify_note_uses_text_payload() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let create_resp = send_recv(
        &mut stream,
        b"<create_note><text>Initial note</text><nvt oid=\"1.3.6.1.4.1.25623.1.0.12345\"/><hosts>192.168.1.1</hosts></create_note>",
    )
    .await;
    assert_eq!(create_resp.status_code(), Some(201));
    let note_id = extract_id(&create_resp);

    let modify_resp = send_recv(
        &mut stream,
        format!(
            "<modify_note note_id=\"{note_id}\"><text>Updated note</text><hosts>192.168.1.2</hosts></modify_note>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(modify_resp.status_code(), Some(200));

    let get_resp = send_recv(
        &mut stream,
        format!("<get_notes note_id=\"{note_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));
    let text = get_resp.as_str().expect("valid utf8");
    assert!(text.contains("Updated note"));
    assert!(text.contains("<hosts>192.168.1.2</hosts>"));
    assert!(text.contains("<nvt_oid>1.3.6.1.4.1.25623.1.0.12345</nvt_oid>"));

    server.shutdown().await;
}

#[tokio::test]
async fn create_and_modify_ticket_handles_comment_and_status() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let create_resp = send_recv(
        &mut stream,
        b"<create_ticket><result id=\"11111111-1111-1111-1111-111111111111\"/><assigned_to><user id=\"22222222-2222-2222-2222-222222222222\"/></assigned_to><open_note>Please investigate</open_note><comment>Investigating</comment></create_ticket>",
    )
    .await;
    assert_eq!(create_resp.status_code(), Some(201));
    let ticket_id = extract_id(&create_resp);

    let modify_resp = send_recv(
        &mut stream,
        format!(
            "<modify_ticket ticket_id=\"{ticket_id}\"><comment>Resolved</comment><status>closed</status><assigned_to><user id=\"33333333-3333-3333-3333-333333333333\"/></assigned_to></modify_ticket>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(modify_resp.status_code(), Some(200));

    let get_resp = send_recv(
        &mut stream,
        format!("<get_tickets ticket_id=\"{ticket_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));
    let text = get_resp.as_str().expect("valid utf8");
    assert!(text.contains("<comment>Resolved</comment>"));
    assert!(text.contains("<status>closed</status>"));
    assert!(text.contains("<result id=\"11111111-1111-1111-1111-111111111111\">"));
    assert!(text.contains("<assigned_to id=\"33333333-3333-3333-3333-333333333333\">"));

    server.shutdown().await;
}

#[tokio::test]
async fn get_report_by_id_returns_nested_results() {
    let report_id = Uuid::new_v4();
    let result_id = Uuid::new_v4();

    let Some(server) = build_server(
        MockGmpServer::builder()
            .mode(ServerMode::Stateful)
            .version(GmpVersion::V22_5)
            .credentials("admin", "admin")
            .seed(move |store| {
                let report = Resource::with_id("report", "Report Name", report_id);
                store.seed(report);

                let mut result = Resource::with_id("result", "Test Finding", result_id);
                result.set_attr("report_id", &report_id.to_string());
                result.set_attr("host", "192.168.1.1");
                result.set_attr("port", "443/tcp");
                result.set_attr("threat", "High");
                result.set_attr("severity", "8.5");
                store.seed(result);
            })
            .unix_socket_auto(),
    )
    .await
    else {
        return;
    };

    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let resp = send_recv(
        &mut stream,
        format!("<get_reports report_id=\"{report_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(resp.status_code(), Some(200));
    let text = resp.as_str().expect("valid utf8");
    assert!(text.contains("<results max=\"100\" start=\"1\">"));
    assert!(text.contains(&result_id.to_string()));
    assert!(text.contains("<full>1</full><filtered>1</filtered>"));

    server.shutdown().await;
}
async fn build_server(builder: gvm_mock_server::MockGmpServerBuilder) -> Option<MockGmpServer> {
    match builder.build().await {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server start failed: {error}"),
    }
}
