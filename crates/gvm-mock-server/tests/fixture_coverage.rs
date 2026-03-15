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
    let s = build_server(
        MockGmpServer::builder()
            .mode(ServerMode::Fixture)
            .version(GmpVersion::V22_5)
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
async fn fixture_get_reports() {
    let Some((server, mut s)) = server().await else {
        return;
    };
    let r = send_recv(&mut s, b"<get_reports/>").await;
    assert!(r.is_success());
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
