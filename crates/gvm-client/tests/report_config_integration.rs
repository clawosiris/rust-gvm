// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![cfg(feature = "unix-socket-tests")]
#![allow(missing_docs)]

use gvm_client::{Gmp226Commands, GmpVersioned};
use gvm_connection::UnixSocketConnection;
use gvm_gmp::commands::authentication::authenticate;
use gvm_gmp::responses::{CreateReportConfigResponse, GetReportConfigsResponse};
use gvm_mock_server::{GmpVersion as MockVersion, MockGmpServer, ServerMode};

async fn stateful_server() -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_6)
        .credentials("admin", "admin")
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server should start: {error}"),
    }
}

fn unix_connection(server: &MockGmpServer) -> UnixSocketConnection {
    UnixSocketConnection::with_path(server.socket_path().expect("unix socket path"))
}

#[tokio::test]
async fn clone_report_config_round_trips_through_stateful_mock() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    let auth_response = client
        .call(authenticate("admin", "admin"))
        .await
        .expect("authenticate should succeed");
    assert_eq!(auth_response.status_code(), Some(200));

    let mut client = match client {
        GmpVersioned::V226(client) => client,
        other => panic!("expected V226 client, got {other:?}"),
    };

    let create_response = client
        .create_report_config("Stateful Report Config", "report-format-1")
        .await
        .expect("create_report_config should succeed");
    let created = CreateReportConfigResponse::from_response(&create_response)
        .expect("create_report_config response should parse");

    let clone_response = client
        .clone_report_config(created.id.as_str())
        .await
        .expect("clone_report_config should clone existing report config");
    let cloned = CreateReportConfigResponse::from_response(&clone_response)
        .expect("clone_report_config response should parse");
    assert_ne!(cloned.id, created.id);

    let get_response = client
        .get_report_configs()
        .await
        .expect("report configs should be fetchable");
    let fetched = GetReportConfigsResponse::from_response(&get_response)
        .expect("get_report_configs response should parse");
    let cloned_config = fetched
        .items
        .iter()
        .find(|config| config.meta.id == cloned.id)
        .expect("cloned report config should be listed");
    assert_eq!(cloned_config.meta.name, "Stateful Report Config");

    let history = server.command_history();
    let command = history
        .iter()
        .find(|command| {
            command.command_name() == "create_report_config"
                && std::str::from_utf8(command.raw_xml()).expect("valid UTF-8 command")
                    == format!(
                        "<create_report_config><copy>{}</copy></create_report_config>",
                        created.id
                    )
        })
        .expect("report config clone recorded");
    assert_eq!(command.command_name(), "create_report_config");
    assert_eq!(
        std::str::from_utf8(command.raw_xml()).expect("valid UTF-8 command"),
        format!(
            "<create_report_config><copy>{}</copy></create_report_config>",
            created.id
        )
    );

    server.shutdown().await;
}
