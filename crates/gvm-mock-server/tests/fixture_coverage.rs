// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Tests for expanded fixture coverage.
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
    stream.write_all(xml).await.expect("write");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).await.expect("read");
    buf.truncate(n);
    Response::new(buf)
}

async fn server() -> Option<(MockGmpServer, UnixStream)> {
    server_with_version(GmpVersion::V22_5).await
}

async fn server_with_version(version: GmpVersion) -> Option<(MockGmpServer, UnixStream)> {
    let s = build_server(
        MockGmpServer::builder()
            .mode(ServerMode::Fixture)
            .version(version)
            .unix_socket_auto(),
    )
    .await?;
    let path = s.socket_path().unwrap().to_owned();
    let stream = UnixStream::connect(&path).await.expect("connect");
    Some((s, stream))
}

#[tokio::test]
async fn fixture_delete_task() {
    let Some((server, mut s)) = server().await else {
        return;
    };
    let r = send_recv(&mut s, br#"<delete_task task_id="x" ultimate="0"/>"#).await;
    assert_eq!(r.status_code(), Some(200));
    server.shutdown().await;
}

#[tokio::test]
async fn fixture_modify_task() {
    let Some((server, mut s)) = server().await else {
        return;
    };
    let r = send_recv(
        &mut s,
        br#"<modify_task task_id="x"><name>n</name></modify_task>"#,
    )
    .await;
    assert_eq!(r.status_code(), Some(200));
    server.shutdown().await;
}

#[tokio::test]
async fn fixture_start_task() {
    let Some((server, mut s)) = server().await else {
        return;
    };
    let r = send_recv(&mut s, br#"<start_task task_id="x"/>"#).await;
    assert_eq!(r.status_code(), Some(202));
    server.shutdown().await;
}

#[tokio::test]
async fn fixture_stop_task() {
    let Some((server, mut s)) = server().await else {
        return;
    };
    let r = send_recv(&mut s, br#"<stop_task task_id="x"/>"#).await;
    assert_eq!(r.status_code(), Some(200));
    server.shutdown().await;
}

#[tokio::test]
async fn fixture_get_alerts() {
    let Some((server, mut s)) = server().await else {
        return;
    };
    let r = send_recv(&mut s, b"<get_alerts/>").await;
    assert!(r.is_success());
    server.shutdown().await;
}

#[tokio::test]
async fn fixture_get_credentials() {
    let Some((server, mut s)) = server().await else {
        return;
    };
    let r = send_recv(&mut s, b"<get_credentials/>").await;
    assert!(r.is_success());
    server.shutdown().await;
}

#[tokio::test]
async fn fixture_get_filters() {
    let Some((server, mut s)) = server().await else {
        return;
    };
    let r = send_recv(&mut s, b"<get_filters/>").await;
    assert!(r.is_success());
    server.shutdown().await;
}

#[tokio::test]
async fn fixture_get_info_respects_secinfo_type_and_filters() {
    let Some((server, mut s)) = server().await else {
        return;
    };

    let r = send_recv(&mut s, br#"<get_info name="Mock NVT one" type="NVT"/>"#).await;
    assert!(r.is_success());
    let body = r.as_str().expect("fixture response should be utf8");
    assert!(body.contains("<nvt id=\"1.3.6.1.4.1.25623.1\">"));
    assert!(body.contains("<nvt_count>1<filtered>1</filtered></nvt_count>"));
    assert!(!body.contains("Mock NVT two"));

    let r = send_recv(
        &mut s,
        br#"<get_info info_id="oval:org.example:def:1" type="OVALDEF"/>"#,
    )
    .await;
    assert!(r.is_success());
    let body = r.as_str().expect("fixture response should be utf8");
    assert!(body.contains("<ovaldef id=\"oval:org.example:def:1\">"));
    assert!(body.contains("<ovaldef_count>1<filtered>1</filtered></ovaldef_count>"));
    assert!(!body.contains("Mock OVAL definition two"));

    server.shutdown().await;
}

#[tokio::test]
async fn fixture_get_reports() {
    let Some((server, mut s)) = server().await else {
        return;
    };
    let r = send_recv(&mut s, b"<get_reports/>").await;
    assert!(r.is_success());
    server.shutdown().await;
}

#[tokio::test]
async fn fixture_get_report_drill_downs() {
    for (command, marker) in [
        ("get_report_vulns", "<vuln "),
        ("get_report_tls_certificates", "<tls_certificate "),
        ("get_report_errors", "<error "),
        ("get_report_closed_cves", "<closed_cve "),
    ] {
        let Some((server, mut s)) = server_with_version(GmpVersion::V22_8).await else {
            return;
        };
        let request = format!("<{command} report_id=\"report-1\"/>");
        let r = send_recv(&mut s, request.as_bytes()).await;
        assert!(r.is_success(), "{command} should succeed");
        assert!(r.as_str().expect("utf8").contains(marker));
        server.shutdown().await;
    }
}

#[tokio::test]
async fn fixture_get_timezones_and_credential_stores() {
    let Some((server, mut s)) = server_with_version(GmpVersion::V22_8).await else {
        return;
    };

    let r = send_recv(&mut s, b"<get_timezones/>").await;
    assert!(r.is_success());
    assert!(r.as_str().expect("utf8").contains("UTC"));

    let r = send_recv(&mut s, b"<get_credential_stores/>").await;
    assert!(r.is_success());
    assert!(r.as_str().expect("utf8").contains("Local credential store"));

    let r = send_recv(
        &mut s,
        b"<get_credential_stores details=\"1\"><credential_store_id>local</credential_store_id></get_credential_stores>",
    )
    .await;
    assert!(r.is_success());
    assert!(r.as_str().expect("utf8").contains("Local credential store"));

    server.shutdown().await;
}

#[tokio::test]
async fn fixture_get_schedules() {
    let Some((server, mut s)) = server().await else {
        return;
    };
    let r = send_recv(&mut s, b"<get_schedules/>").await;
    assert!(r.is_success());
    server.shutdown().await;
}

#[tokio::test]
async fn fixture_get_port_lists() {
    let Some((server, mut s)) = server().await else {
        return;
    };
    let r = send_recv(&mut s, b"<get_port_lists/>").await;
    assert!(r.is_success());
    server.shutdown().await;
}
async fn build_server(builder: gvm_mock_server::MockGmpServerBuilder) -> Option<MockGmpServer> {
    match builder.build().await {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("start: {error}"),
    }
}
