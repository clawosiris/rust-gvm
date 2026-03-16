// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![cfg(feature = "unix-socket-tests")]
#![allow(
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::redundant_closure_for_method_calls,
    clippy::unwrap_used,
    missing_docs
)]

use gvm_gmp::commands::authentication::authenticate;
use gvm_gmp::commands::features::get_features;
use gvm_gmp::commands::report_configs::{create_report_config, get_report_configs};
use gvm_gmp::commands::targets::{create_target, CreateTargetOpts};
use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::{Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

async fn stateful_server(version: GmpVersion) -> Option<MockGmpServer> {
    let server = match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(version)
        .credentials("admin", "admin")
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => server,
        Err(error) if error.to_string().contains("Permission denied") => {
            eprintln!("Skipping: sandbox restriction");
            return None;
        }
        Err(error) => panic!("Failed to start server: {error}"),
    };

    Some(server)
}

async fn connect(server: &MockGmpServer) -> UnixStream {
    let path = server.socket_path().expect("should have socket path");
    UnixStream::connect(path).await.expect("connect failed")
}

async fn send_recv(stream: &mut UnixStream, request: impl Request) -> Response {
    stream
        .write_all(&request.to_bytes())
        .await
        .expect("write failed");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = vec![0_u8; 64 * 1024];
    let n = stream.read(&mut buf).await.expect("read failed");
    buf.truncate(n);
    Response::new(buf)
}

async fn authenticate_admin(stream: &mut UnixStream) {
    let response = send_recv(stream, authenticate("admin", "admin")).await;
    assert_eq!(response.status_code(), Some(200));
}

async fn assert_version_gated_rejected(version: GmpVersion) {
    let Some(server) = stateful_server(version).await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate_admin(&mut stream).await;

    let expected_create =
        format!("Command 'create_report_config' is not available in GMP {version}");
    let create_response = send_recv(
        &mut stream,
        create_report_config("Version Gated Config", "report-format-1"),
    )
    .await;
    assert_eq!(create_response.status_code(), Some(400));
    assert_eq!(
        create_response.status_text().as_deref(),
        Some(expected_create.as_str())
    );

    let expected_list = format!("Command 'get_report_configs' is not available in GMP {version}");
    let list_response = send_recv(&mut stream, get_report_configs()).await;
    assert_eq!(list_response.status_code(), Some(400));
    assert_eq!(
        list_response.status_text().as_deref(),
        Some(expected_list.as_str())
    );

    let expected_features = format!("Command 'get_features' is not available in GMP {version}");
    let features_response = send_recv(&mut stream, get_features()).await;
    assert_eq!(features_response.status_code(), Some(400));
    assert_eq!(
        features_response.status_text().as_deref(),
        Some(expected_features.as_str())
    );

    server.shutdown().await;
}

async fn assert_version_gated_accepted(version: GmpVersion) {
    let Some(server) = stateful_server(version).await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate_admin(&mut stream).await;

    let create_response = send_recv(
        &mut stream,
        create_report_config("Version Gated Config", "report-format-1"),
    )
    .await;
    assert_eq!(create_response.status_code(), Some(201));
    assert!(create_response.id().is_some());

    let list_response = send_recv(&mut stream, get_report_configs()).await;
    assert_eq!(list_response.status_code(), Some(200));
    let list_text = list_response.as_str().expect("valid utf8");
    assert!(list_text.contains("Version Gated Config"));

    let features_response = send_recv(&mut stream, get_features()).await;
    assert_eq!(features_response.status_code(), Some(200));

    server.shutdown().await;
}

#[tokio::test]
async fn version_22_4_rejects_report_config() {
    assert_version_gated_rejected(GmpVersion::V22_4).await;
}

#[tokio::test]
async fn version_22_5_rejects_report_config() {
    assert_version_gated_rejected(GmpVersion::V22_5).await;
}

#[tokio::test]
async fn version_22_6_accepts_report_config() {
    assert_version_gated_accepted(GmpVersion::V22_6).await;
}

#[tokio::test]
async fn version_22_7_accepts_report_config() {
    assert_version_gated_accepted(GmpVersion::V22_7).await;
}

#[tokio::test]
async fn base_commands_work_on_all_versions() {
    for version in [
        GmpVersion::V22_4,
        GmpVersion::V22_5,
        GmpVersion::V22_6,
        GmpVersion::V22_7,
    ] {
        let Some(server) = stateful_server(version).await else {
            return;
        };
        let mut stream = connect(&server).await;
        authenticate_admin(&mut stream).await;

        let response = send_recv(
            &mut stream,
            create_target(
                &format!("Base Target {}", version.as_str()),
                CreateTargetOpts {
                    hosts: vec!["127.0.0.1".to_string()],
                    ..CreateTargetOpts::default()
                },
            ),
        )
        .await;
        assert_eq!(response.status_code(), Some(201));

        server.shutdown().await;
    }
}
