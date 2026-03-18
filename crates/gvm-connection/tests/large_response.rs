// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![cfg(feature = "large-response-tests")]
#![allow(clippy::unwrap_used, missing_docs)]

use gvm_connection::{GvmConnection, UnixSocketConfig, UnixSocketConnection};
use gvm_gmp::commands::reports::get_report;
use gvm_gmp::commands::scan_configs::{get_scan_configs, GetScanConfigsOpts};
use gvm_gmp::commands::targets::{create_target, CreateTargetOpts};
use gvm_gmp::commands::tasks::{create_task, start_task, CreateTaskOpts};
use gvm_gmp::types::EntityId;
use gvm_mock_server::{GmpVersion, LargeReportConfig, MockGmpServer, ServerMode};
use gvm_protocol::{Request, Response};

async fn start_mock(config: LargeReportConfig) -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_5)
        .credentials("admin", "admin")
        .large_report(config)
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("mock server start failed: {error}"),
    }
}

async fn send(conn: &mut UnixSocketConnection, request: impl Request) -> Response {
    conn.send(&request.to_bytes())
        .await
        .expect("send should succeed");
    Response::new(conn.read().await.expect("read should succeed"))
}

async fn authenticate(conn: &mut UnixSocketConnection) {
    let response = send(
        conn,
        b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>"
            .as_slice(),
    )
    .await;
    assert_eq!(response.status_code(), Some(200));
}

fn extract_first_config_id(xml: &str) -> EntityId {
    let marker = "<config id=\"";
    let start = xml
        .find(marker)
        .expect("scan config response should contain a config id")
        + marker.len();
    let end = xml[start..]
        .find('"')
        .expect("config id should terminate with a quote");
    xml[start..start + end].parse().expect("valid entity id")
}

async fn create_large_report(conn: &mut UnixSocketConnection) -> (EntityId, Vec<u8>) {
    authenticate(conn).await;

    let target_response = send(
        conn,
        create_target(
            "large-test",
            CreateTargetOpts {
                hosts: vec!["10.0.0.0/24".to_string()],
                ..CreateTargetOpts::default()
            },
        ),
    )
    .await;
    assert_eq!(target_response.status_code(), Some(201));
    let target_id: EntityId = target_response
        .id()
        .expect("target id")
        .parse()
        .expect("valid target id");

    let scanner_response = send(
        conn,
        b"<create_scanner><name>large-response-scanner</name></create_scanner>".as_slice(),
    )
    .await;
    assert_eq!(scanner_response.status_code(), Some(201));
    let scanner_id: EntityId = scanner_response
        .id()
        .expect("scanner id")
        .parse()
        .expect("valid scanner id");

    let config_create_response = send(
        conn,
        b"<create_config><name>large-response-config</name></create_config>".as_slice(),
    )
    .await;
    assert_eq!(config_create_response.status_code(), Some(201));

    let config_response = send(conn, get_scan_configs(GetScanConfigsOpts::default())).await;
    assert_eq!(config_response.status_code(), Some(200));
    let config_id = extract_first_config_id(
        config_response
            .as_str()
            .expect("get_scan_configs response should be utf8"),
    );

    let task_response = send(
        conn,
        create_task(
            "large-response-task",
            &config_id,
            &target_id,
            &scanner_id,
            CreateTaskOpts::default(),
        ),
    )
    .await;
    assert_eq!(task_response.status_code(), Some(201));
    let task_id: EntityId = task_response
        .id()
        .expect("task id")
        .parse()
        .expect("entity id");

    let start_response = send(conn, start_task(&task_id)).await;
    assert_eq!(start_response.status_code(), Some(202));
    let report_id: EntityId = start_response
        .child_text("report_id")
        .expect("report_id")
        .parse()
        .expect("entity id");

    conn.send(&get_report(&report_id).to_bytes())
        .await
        .expect("get_report send should succeed");
    let bytes = conn.read().await.expect("get_report read should succeed");
    (report_id, bytes)
}

#[tokio::test]
async fn test_large_report_10mb() {
    let server = start_mock(LargeReportConfig {
        result_count: 5_000,
        result_payload_bytes: 2_048,
    })
    .await;
    let Some(server) = server else {
        return;
    };

    let config = UnixSocketConfig::new(server.socket_path().expect("socket path"))
        .with_max_response_bytes(Some(32 * 1024 * 1024));
    let mut conn = UnixSocketConnection::new(config);
    conn.connect().await.expect("connect should succeed");

    let (_, bytes) = create_large_report(&mut conn).await;
    let text = std::str::from_utf8(&bytes).expect("response should be utf8");

    assert!(
        bytes.len() >= 10 * 1024 * 1024,
        "response too small: {}",
        bytes.len()
    );
    assert!(text.contains("<get_reports_response status=\"200\""));
    assert!(text.contains("<results"));

    server.shutdown().await;
}

#[tokio::test]
async fn test_large_report_deterministic() {
    let server = start_mock(LargeReportConfig {
        result_count: 100,
        result_payload_bytes: 512,
    })
    .await;
    let Some(server) = server else {
        return;
    };

    let config = UnixSocketConfig::new(server.socket_path().expect("socket path"));
    let mut conn = UnixSocketConnection::new(config);
    conn.connect().await.expect("connect should succeed");

    let (report_id, first) = create_large_report(&mut conn).await;
    let second = send(&mut conn, get_report(&report_id))
        .await
        .data()
        .to_vec();

    assert_eq!(first, second);

    server.shutdown().await;
}

#[tokio::test]
async fn test_large_report_result_count() {
    let server = start_mock(LargeReportConfig {
        result_count: 1_000,
        result_payload_bytes: 512,
    })
    .await;
    let Some(server) = server else {
        return;
    };

    let config = UnixSocketConfig::new(server.socket_path().expect("socket path"));
    let mut conn = UnixSocketConnection::new(config);
    conn.connect().await.expect("connect should succeed");

    let (_, bytes) = create_large_report(&mut conn).await;
    let text = std::str::from_utf8(&bytes).expect("response should be utf8");
    assert!(
        text.contains("<result_count><full>1000</full><filtered>1000</filtered></result_count>")
    );

    server.shutdown().await;
}

#[tokio::test]
async fn test_large_report_parseable() {
    let server = start_mock(LargeReportConfig {
        result_count: 500,
        result_payload_bytes: 512,
    })
    .await;
    let Some(server) = server else {
        return;
    };

    let config = UnixSocketConfig::new(server.socket_path().expect("socket path"));
    let mut conn = UnixSocketConnection::new(config);
    conn.connect().await.expect("connect should succeed");

    let (_, bytes) = create_large_report(&mut conn).await;
    let response = Response::new(bytes);
    assert!(response.is_success());
    assert_eq!(response.status_code(), Some(200));

    server.shutdown().await;
}
