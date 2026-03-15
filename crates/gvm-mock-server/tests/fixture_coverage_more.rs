//! Tests for additional fixture resource coverage.

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

async fn server() -> MockGmpServer {
    MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(GmpVersion::V22_5)
        .unix_socket_auto()
        .build()
        .await
        .expect("server start failed")
}

async fn assert_fixture_contains(command: &[u8], tag: &str) {
    let server = server().await;
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let response = send_recv(&mut stream, command).await;
    assert_eq!(response.status_code(), Some(200));

    let body = response.as_str().expect("response should be valid utf8");
    assert!(body.contains(tag), "response body should contain {tag}");

    server.shutdown().await;
}

#[tokio::test]
async fn fixture_get_notes_contains_note_tag() {
    assert_fixture_contains(b"<get_notes/>", "<note ").await;
}

#[tokio::test]
async fn fixture_get_overrides_contains_override_tag() {
    assert_fixture_contains(b"<get_overrides/>", "<override ").await;
}

#[tokio::test]
async fn fixture_get_roles_contains_role_tag() {
    assert_fixture_contains(b"<get_roles/>", "<role ").await;
}

#[tokio::test]
async fn fixture_get_users_contains_user_tag() {
    assert_fixture_contains(b"<get_users/>", "<user ").await;
}

#[tokio::test]
async fn fixture_get_tickets_contains_ticket_tag() {
    assert_fixture_contains(b"<get_tickets/>", "<ticket ").await;
}

#[tokio::test]
async fn fixture_get_tags_contains_tag_tag() {
    assert_fixture_contains(b"<get_tags/>", "<tag ").await;
}

#[tokio::test]
async fn fixture_get_reports_contains_report_tag() {
    assert_fixture_contains(b"<get_reports/>", "<report ").await;
}

#[tokio::test]
async fn fixture_get_schedules_contains_schedule_tag() {
    assert_fixture_contains(b"<get_schedules/>", "<schedule ").await;
}

#[tokio::test]
async fn fixture_get_port_lists_contains_port_list_tag() {
    assert_fixture_contains(b"<get_port_lists/>", "<port_list ").await;
}

#[tokio::test]
async fn fixture_get_filters_contains_filter_tag() {
    assert_fixture_contains(b"<get_filters/>", "<filter ").await;
}

#[tokio::test]
async fn fixture_get_credentials_contains_credential_tag() {
    assert_fixture_contains(b"<get_credentials/>", "<credential ").await;
}

#[tokio::test]
async fn fixture_get_alerts_contains_alert_tag() {
    assert_fixture_contains(b"<get_alerts/>", "<alert ").await;
}
