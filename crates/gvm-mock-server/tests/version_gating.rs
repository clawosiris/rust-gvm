// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::redundant_closure_for_method_calls,
    clippy::unwrap_used,
    missing_docs
)]
#![cfg(feature = "unix-socket-tests")]

use gvm_gmp::commands::agent_groups::{create_agent_group, get_agent_groups, CreateAgentGroupOpts};
use gvm_gmp::commands::authentication::authenticate;
use gvm_gmp::commands::features::get_features;
use gvm_gmp::commands::integration_configs::{
    get_integration_config, get_integration_configs, modify_integration_config,
};
use gvm_gmp::commands::report_configs::{create_report_config, get_report_configs};
use gvm_gmp::commands::reports::{get_report_cves, get_report_hosts};
use gvm_gmp::commands::targets::{create_target, CreateTargetOpts};
use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::{Request, Response, XmlCommand};
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
        Err(error)
            if error.to_string().contains("Permission denied")
                || error.to_string().contains("Operation not permitted") =>
        {
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

    let create_response = send_recv(
        &mut stream,
        create_report_config("Version Gated Config", "report-format-1"),
    )
    .await;
    assert_eq!(create_response.status_code(), Some(400));
    let create_text = create_response.status_text().unwrap();
    assert!(
        create_text.contains("create_report_config"),
        "expected create_report_config in status_text, got: {create_text}"
    );

    let list_response = send_recv(&mut stream, get_report_configs()).await;
    assert_eq!(list_response.status_code(), Some(400));
    let list_text = list_response.status_text().unwrap();
    assert!(
        list_text.contains("get_report_configs"),
        "expected get_report_configs in status_text, got: {list_text}"
    );

    let features_response = send_recv(&mut stream, get_features()).await;
    assert_eq!(features_response.status_code(), Some(400));
    let features_text = features_response.status_text().unwrap();
    assert!(
        features_text.contains("get_features"),
        "expected get_features in status_text, got: {features_text}"
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
        GmpVersion::V22_8,
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

#[tokio::test]
async fn version_22_7_rejects_next_commands() {
    let Some(server) = stateful_server(GmpVersion::V22_7).await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate_admin(&mut stream).await;

    let response = send_recv(&mut stream, get_integration_configs(Default::default())).await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response
        .status_text()
        .unwrap()
        .contains("get_integration_configs"));

    let response = send_recv(&mut stream, get_agent_groups(Default::default())).await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response.status_text().unwrap().contains("get_agent_groups"));

    let response = send_recv(
        &mut stream,
        get_report_hosts(
            &id("00000000-0000-0000-0000-000000000200"),
            Default::default(),
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response.status_text().unwrap().contains("get_report_hosts"));

    server.shutdown().await;
}

#[tokio::test]
async fn version_22_8_accepts_next_commands() {
    let Some(server) = stateful_server(GmpVersion::V22_8).await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate_admin(&mut stream).await;

    let get_response = send_recv(
        &mut stream,
        get_integration_config(&id("00000000-0000-0000-0000-000000000100"), Some(true)),
    )
    .await;
    assert_eq!(get_response.status_code(), Some(200));

    let list_response = send_recv(&mut stream, get_integration_configs(Default::default())).await;
    assert_eq!(list_response.status_code(), Some(200));
    assert!(list_response
        .as_str()
        .expect("utf8")
        .contains("Default Integration Config"));

    let agent_group_response = send_recv(
        &mut stream,
        create_agent_group(
            "Version Gated Agent Group",
            &[id("agent-1")],
            "0 */5 * * *",
            CreateAgentGroupOpts::default(),
        ),
    )
    .await;
    assert_eq!(agent_group_response.status_code(), Some(201));

    let agent_groups_response = send_recv(&mut stream, get_agent_groups(Default::default())).await;
    assert_eq!(agent_groups_response.status_code(), Some(200));
    assert!(agent_groups_response
        .as_str()
        .expect("utf8")
        .contains("Version Gated Agent Group"));

    let modify_response = send_recv(
        &mut stream,
        modify_integration_config(
            &id("00000000-0000-0000-0000-000000000100"),
            gvm_gmp::commands::integration_configs::ModifyIntegrationConfigOpts {
                service_url: Some("https://updated.example".into()),
                ..Default::default()
            },
        ),
    )
    .await;
    assert_eq!(modify_response.status_code(), Some(200));

    let modified_get_response = send_recv(
        &mut stream,
        get_integration_config(&id("00000000-0000-0000-0000-000000000100"), Some(true)),
    )
    .await;
    let modified_xml = modified_get_response.as_str().expect("utf8");
    assert!(modified_xml.contains("<service_url>https://updated.example</service_url>"));
    assert!(modified_xml.contains("<service_cacert>MOCK-CA-CERT</service_cacert>"));
    assert!(
        modified_xml.contains("<oidc_provider_client_id>mock-client-id</oidc_provider_client_id>")
    );

    let missing_uuid_response =
        send_recv(&mut stream, XmlCommand::new("modify_integration_config")).await;
    assert_eq!(missing_uuid_response.status_code(), Some(400));
    assert!(missing_uuid_response
        .status_text()
        .expect("status text")
        .contains("uuid"));

    let report_helper = send_recv(
        &mut stream,
        get_report_cves(
            &id("00000000-0000-0000-0000-000000000200"),
            Default::default(),
        ),
    )
    .await;
    assert_eq!(report_helper.status_code(), Some(404));

    server.shutdown().await;
}

fn id(value: &str) -> gvm_gmp::EntityId {
    gvm_gmp::EntityId::new(value).expect("valid id")
}
