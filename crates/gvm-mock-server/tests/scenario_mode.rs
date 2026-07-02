// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(
    clippy::print_stdout,
    clippy::redundant_closure_for_method_calls,
    clippy::unwrap_used,
    missing_docs
)]
#![cfg(feature = "unix-socket-tests")]

use gvm_mock_server::{GmpVersion, MockGmpServer, ScenarioMode, ScenarioStep};
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

fn step(expect_command: &str, respond_xml: Option<&str>) -> ScenarioStep {
    ScenarioStep {
        expect_command: expect_command.to_string(),
        respond_xml: respond_xml.map(str::to_string),
    }
}

#[tokio::test]
async fn scen_001_exact_sequence_strict() {
    let Some(server) = (match MockGmpServer::builder()
        .version(GmpVersion::V22_5)
        .scenario(
            ScenarioMode::Strict,
            vec![
                step(
                    "get_version",
                    Some(r#"<get_version_response status="200"><hello/></get_version_response>"#),
                ),
                step(
                    "get_tasks",
                    Some(r#"<get_tasks_response status="200"><world/></get_tasks_response>"#),
                ),
            ],
        )
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server start failed: {error}"),
    }) else {
        return;
    };
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let resp1 = send_recv(&mut stream, b"<get_version/>").await;
    assert_eq!(resp1.status_code(), Some(200));
    assert!(
        resp1.as_str().expect("valid utf8").contains("<hello/>"),
        "expected scripted get_version response"
    );

    let resp2 = send_recv(&mut stream, b"<get_tasks/>").await;
    assert_eq!(resp2.status_code(), Some(200));
    assert!(
        resp2.as_str().expect("valid utf8").contains("<world/>"),
        "expected scripted get_tasks response"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn scen_002_strict_mismatch() {
    let Some(server) = (match MockGmpServer::builder()
        .version(GmpVersion::V22_5)
        .scenario(
            ScenarioMode::Strict,
            vec![step(
                "get_version",
                Some(r#"<get_version_response status="200"><hello/></get_version_response>"#),
            )],
        )
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server start failed: {error}"),
    }) else {
        return;
    };
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let resp = send_recv(&mut stream, b"<get_tasks/>").await;
    assert_eq!(resp.status_code(), Some(400));

    server.shutdown().await;
}

#[tokio::test]
async fn scen_003_lenient_mismatch_fallback() {
    let Some(server) = (match MockGmpServer::builder()
        .version(GmpVersion::V22_5)
        .scenario(
            ScenarioMode::Lenient,
            vec![step(
                "get_version",
                Some(r#"<get_version_response status="200"><hello/></get_version_response>"#),
            )],
        )
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server start failed: {error}"),
    }) else {
        return;
    };
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let fallback = send_recv(&mut stream, b"<get_tasks/>").await;
    assert_eq!(fallback.status_code(), Some(200));

    let scripted = send_recv(&mut stream, b"<get_version/>").await;
    assert_eq!(scripted.status_code(), Some(200));
    assert!(
        scripted.as_str().expect("valid utf8").contains("<hello/>"),
        "expected scripted response after lenient mismatch"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn scen_004_exhausted() {
    let Some(server) = (match MockGmpServer::builder()
        .version(GmpVersion::V22_5)
        .scenario(
            ScenarioMode::Strict,
            vec![step(
                "get_version",
                Some(r#"<get_version_response status="200"><hello/></get_version_response>"#),
            )],
        )
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server start failed: {error}"),
    }) else {
        return;
    };
    let path = server.socket_path().expect("should have socket path");
    let mut stream = UnixStream::connect(path).await.expect("connect failed");

    let first = send_recv(&mut stream, b"<get_version/>").await;
    assert_eq!(first.status_code(), Some(200));
    assert!(
        first.as_str().expect("valid utf8").contains("<hello/>"),
        "expected scripted response before exhaustion"
    );

    let exhausted = send_recv(&mut stream, b"<get_version/>").await;
    assert_eq!(exhausted.status_code(), Some(400));

    server.shutdown().await;
}
