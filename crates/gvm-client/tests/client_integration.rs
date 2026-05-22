// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![cfg(feature = "unix-socket-tests")]
#![allow(missing_docs)]

use gvm_client::{GmpClient, GmpNextCommands, GmpVersioned, GvmError};
use gvm_connection::{ConnectionError, GvmConnection, UnixSocketConnection};
use gvm_gmp::commands::authentication::authenticate;
use gvm_gmp::commands::reports::get_report_hosts;
use gvm_gmp::commands::scan_configs::ConfigOpts;
use gvm_gmp::commands::scanners::ScannerOpts;
use gvm_gmp::commands::system::get_timezones;
use gvm_gmp::commands::targets::{
    create_target, delete_target, get_targets, CreateTargetOpts, GetTargetsOpts,
};
use gvm_gmp::commands::tasks::{create_task, delete_task, get_task, start_task, stop_task};
use gvm_gmp::types::EntityId;
use gvm_gmp::types::GmpVersion;
use gvm_mock_server::{GmpVersion as MockVersion, MockGmpServer, ServerMode};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn socket_path() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("gvmc-{}-{unique}.sock", std::process::id()))
}

async fn stateful_server() -> Option<MockGmpServer> {
    stateful_server_with_version(MockVersion::V22_5).await
}

async fn stateful_server_with_version(version: MockVersion) -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(version)
        .unix_socket(socket_path())
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server should start: {error}"),
    }
}

async fn fixture_server_with_version_response(version_xml: &str) -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .unix_socket(socket_path())
        .override_response(
            "get_version",
            &format!(
                "<get_version_response status=\"200\" status_text=\"OK\"><version>{version_xml}</version></get_version_response>"
            ),
        )
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server should start: {error}"),
    }
}

async fn fixture_server(version: MockVersion) -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(version)
        .unix_socket(socket_path())
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
async fn connect_negotiates_version_22_5() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);

    let client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    assert_eq!(client.version(), GmpVersion(22, 5));
    assert!(client.connection().is_connected());

    server.shutdown().await;
}

#[tokio::test]
async fn connect_negotiates_supported_versions() {
    for (mock_version, expected, matcher) in [
        (MockVersion::V22_4, GmpVersion(22, 4), 224_u16),
        (MockVersion::V22_5, GmpVersion(22, 5), 225_u16),
        (MockVersion::V22_6, GmpVersion(22, 6), 226_u16),
        (MockVersion::V22_7, GmpVersion(22, 7), 227_u16),
        (MockVersion::V22_8, GmpVersion(22, 8), 228_u16),
    ] {
        let Some(server) = stateful_server_with_version(mock_version).await else {
            return;
        };
        let connection = unix_connection(&server);
        let client = GmpVersioned::connect(connection)
            .await
            .expect("client should connect");

        assert_eq!(client.version(), expected);
        match (matcher, client) {
            (224, GmpVersioned::V224(_))
            | (225, GmpVersioned::V225(_))
            | (226, GmpVersioned::V226(_))
            | (227, GmpVersioned::V227(_))
            | (228, GmpVersioned::Next(_)) => {}
            (_, other) => panic!("unexpected versioned client: {other:?}"),
        }

        server.shutdown().await;
    }
}

#[tokio::test]
async fn unsupported_version_returns_error() {
    let Some(server) = fixture_server_with_version_response("21.4").await else {
        return;
    };
    let connection = unix_connection(&server);

    let error = GmpClient::connect(connection)
        .await
        .expect_err("unsupported version should fail");
    assert!(matches!(error, GvmError::UnsupportedVersion(21, 4)));

    server.shutdown().await;
}

#[tokio::test]
async fn authenticate_succeeds() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    let response = client
        .call(authenticate("admin", "admin"))
        .await
        .expect("authenticate should succeed");

    assert_eq!(response.status_code(), Some(200));
    assert_eq!(
        response.root_element_name().as_deref(),
        Some("authenticate_response")
    );

    server.shutdown().await;
}

#[tokio::test]
async fn create_target_and_get_targets_succeed() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(authenticate("admin", "admin"))
        .await
        .expect("authenticate should succeed");

    let create_response = client
        .call(create_target(
            "Integration Target",
            CreateTargetOpts {
                hosts: vec!["127.0.0.1".to_string()],
                ..CreateTargetOpts::default()
            },
        ))
        .await
        .expect("create_target should succeed");
    assert_eq!(create_response.status_code(), Some(201));
    assert!(create_response.id().is_some());

    let list_response = client
        .call(get_targets(GetTargetsOpts {
            details: Some(true),
            ..GetTargetsOpts::default()
        }))
        .await
        .expect("get_targets should succeed");
    assert_eq!(list_response.status_code(), Some(200));
    assert!(list_response
        .as_str()
        .expect("valid UTF-8 XML")
        .contains("Integration Target"));

    server.shutdown().await;
}

#[tokio::test]
async fn server_error_maps_to_gvm_error() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    let error = client
        .call(b"<get_targets/>".as_slice())
        .await
        .expect_err("unauthenticated request should fail");

    match error {
        GvmError::Server { status, message } => {
            assert_eq!(status, 401);
            assert_eq!(message, "Not authenticated");
        }
        other => panic!("expected server error, got {other:?}"),
    }

    server.shutdown().await;
}

#[tokio::test]
async fn versioned_enum_returns_v225_for_default_mock_server() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);

    let client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    assert!(matches!(client, GmpVersioned::V225(_)));
    assert_eq!(client.version(), GmpVersion(22, 5));

    server.shutdown().await;
}

#[tokio::test]
async fn unsupported_next_command_rejected_before_send() {
    let Some(server) = stateful_server_with_version(MockVersion::V22_7).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(authenticate("admin", "admin"))
        .await
        .expect("authenticate should succeed");

    let error = client
        .call(get_report_hosts(
            &EntityId::new("report-1").expect("valid id"),
            Default::default(),
        ))
        .await
        .expect_err("22.7 should reject next-only command");

    match error {
        GvmError::UnsupportedCommand {
            command,
            version,
            required,
        } => {
            assert_eq!(command, "get_report_hosts");
            assert_eq!(version, GmpVersion(22, 7));
            assert_eq!(required, "22.8");
        }
        other => panic!("expected unsupported command error, got {other:?}"),
    }

    let error = client
        .call(get_timezones())
        .await
        .expect_err("22.7 should reject get_timezones");
    assert!(matches!(
        error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8"
        } if command == "get_timezones"
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn next_commands_work_on_v22_8() {
    let Some(server) = stateful_server_with_version(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(authenticate("admin", "admin"))
        .await
        .expect("authenticate should succeed");

    let mut client = match client {
        GmpVersioned::Next(client) => client,
        other => panic!("expected Next client, got {other:?}"),
    };

    let integration_config_id =
        EntityId::new("00000000-0000-0000-0000-000000000100").expect("valid id");
    let get_response = client
        .get_integration_config(&integration_config_id, Some(true))
        .await
        .expect("get_integration_config should succeed");
    assert_eq!(get_response.status_code(), Some(200));

    let list_response = client
        .get_integration_configs(Default::default())
        .await
        .expect("get_integration_configs should succeed");
    assert_eq!(list_response.status_code(), Some(200));

    let modify_response = client
        .modify_integration_config(
            &integration_config_id,
            gvm_client::ModifyIntegrationConfigOpts {
                service_url: Some("https://updated.example".into()),
                ..Default::default()
            },
        )
        .await
        .expect("modify_integration_config should succeed");
    assert_eq!(modify_response.status_code(), Some(200));

    let report_id = EntityId::new("00000000-0000-0000-0000-000000000200").expect("valid id");
    let helper_error = client
        .get_report_hosts(&report_id, Default::default())
        .await
        .expect_err("missing report should return server error");
    assert!(matches!(helper_error, GvmError::Server { status: 404, .. }));

    server.shutdown().await;
}

#[tokio::test]
async fn typed_rest_support_gap_helpers_parse_fixture_responses() {
    let Some(server) = fixture_server(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    let report_id = EntityId::new("report-1").expect("valid id");

    let vulns = client
        .get_report_vulns(&report_id, Default::default())
        .await
        .expect("report vulns should parse");
    assert_eq!(vulns.items.len(), 1);
    assert_eq!(vulns.items[0].severity.as_deref(), Some("8.2"));

    let tls = client
        .get_report_tls_certificates(&report_id, Default::default())
        .await
        .expect("report tls certs should parse");
    assert_eq!(tls.items[0].issuer.as_deref(), Some("CN=Example CA"));

    let errors = client
        .get_report_errors(&report_id, Default::default())
        .await
        .expect("report errors should parse");
    assert_eq!(errors.items[0].nvt_name.as_deref(), Some("Ping Host"));

    let closed_cves = client
        .get_report_closed_cves(&report_id, Default::default())
        .await
        .expect("closed cves should parse");
    assert_eq!(closed_cves.items[0].cve.as_deref(), Some("CVE-2025-9999"));

    let timezones = client
        .get_timezones()
        .await
        .expect("timezones should parse");
    assert!(timezones
        .items
        .iter()
        .any(|timezone| timezone.name == "UTC"));

    let stores = client
        .get_credential_stores()
        .await
        .expect("credential stores should parse");
    assert_eq!(stores.items[0].name, "Local credential store");

    server.shutdown().await;
}

#[tokio::test]
async fn full_crud_lifecycle_succeeds() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(authenticate("admin", "admin"))
        .await
        .expect("authenticate should succeed");

    let target_response = client
        .call(create_target(
            "Lifecycle Target",
            CreateTargetOpts {
                hosts: vec!["127.0.0.1".to_string()],
                ..CreateTargetOpts::default()
            },
        ))
        .await
        .expect("create_target should succeed");
    let target_id = target_response.id().expect("target id");

    let config_id = "550e8400-e29b-41d4-a716-446655440001"
        .parse()
        .expect("entity id");
    let scanner_id = "550e8400-e29b-41d4-a716-446655440002"
        .parse()
        .expect("entity id");
    let target_entity_id = target_id.parse().expect("entity id");

    let task_response = client
        .call(create_task(
            "Lifecycle Task",
            &config_id,
            &target_entity_id,
            &scanner_id,
            Default::default(),
        ))
        .await
        .expect("create_task should succeed");
    let task_id = task_response.id().expect("task id");
    let task_entity_id = task_id.parse().expect("entity id");

    let start_response = client
        .call(start_task(&task_entity_id))
        .await
        .expect("start_task should succeed");
    assert_eq!(start_response.status_code(), Some(202));
    assert!(start_response.child_text("report_id").is_some());

    let get_response = client
        .call(get_task(&task_entity_id))
        .await
        .expect("get_task should succeed");
    let body = get_response.as_str().expect("utf8");
    assert!(body.contains(&task_id));
    assert!(body.contains("Running"));

    let stop_response = client
        .call(stop_task(&task_entity_id))
        .await
        .expect("stop_task should succeed");
    assert_eq!(stop_response.status_code(), Some(200));

    let delete_task_response = client
        .call(delete_task(&task_entity_id, true))
        .await
        .expect("delete_task should succeed");
    assert_eq!(delete_task_response.status_code(), Some(200));

    let delete_target_response = client
        .call(delete_target(&target_entity_id, true))
        .await
        .expect("delete_target should succeed");
    assert_eq!(delete_target_response.status_code(), Some(200));

    server.shutdown().await;
}

async fn typed_scan_config_lifecycle(client: &mut GmpClient<UnixSocketConnection>) {
    let created_config = client
        .create_scan_config(
            "Typed Config",
            None,
            ConfigOpts {
                comment: Some("created".into()),
                usage_type: Some("scan".into()),
            },
        )
        .await
        .expect("create_scan_config should succeed");
    let config_id = created_config.id;

    let fetched_config = client
        .get_scan_config(&config_id)
        .await
        .expect("get_scan_config should succeed");
    assert_eq!(fetched_config.items.len(), 1);
    assert_eq!(fetched_config.items[0].meta.id, config_id);
    assert_eq!(fetched_config.items[0].meta.name, "Typed Config");

    client
        .modify_scan_config(
            &config_id,
            ConfigOpts {
                comment: Some("updated".into()),
                usage_type: Some("scan".into()),
            },
        )
        .await
        .expect("modify_scan_config should succeed");

    let updated_config = client
        .get_scan_config(&config_id)
        .await
        .expect("get_scan_config after modify should succeed");
    assert_eq!(
        updated_config.items[0].meta.comment.as_deref(),
        Some("updated")
    );

    client
        .sync_scan_config(&config_id)
        .await
        .expect("sync_scan_config should succeed");

    let cloned_config = client
        .clone_scan_config(&config_id)
        .await
        .expect("clone_scan_config should succeed");
    let cloned_config_id = cloned_config.id;
    let cloned_config_response = client
        .get_scan_config(&cloned_config_id)
        .await
        .expect("get cloned config should succeed");
    assert_eq!(cloned_config_response.items[0].meta.name, "Typed Config");

    client
        .delete_scan_config(&cloned_config_id, true)
        .await
        .expect("delete cloned config should succeed");
    client
        .delete_scan_config(&config_id, true)
        .await
        .expect("delete original config should succeed");
}

async fn typed_scanner_lifecycle(client: &mut GmpClient<UnixSocketConnection>) {
    let created_scanner = client
        .create_scanner("Typed Scanner", ScannerOpts::default())
        .await
        .expect("create_scanner should succeed");
    let scanner_id = created_scanner.id;

    let fetched_scanner = client
        .get_scanner(&scanner_id)
        .await
        .expect("get_scanner should succeed");
    assert_eq!(fetched_scanner.items.len(), 1);
    assert_eq!(fetched_scanner.items[0].meta.id, scanner_id);
    assert_eq!(fetched_scanner.items[0].meta.name, "Typed Scanner");

    client
        .modify_scanner(
            &scanner_id,
            ScannerOpts {
                comment: Some("updated".into()),
                host: Some("127.0.0.1".into()),
                port: Some(9390),
                ..Default::default()
            },
        )
        .await
        .expect("modify_scanner should succeed");

    let updated_scanner = client
        .get_scanner(&scanner_id)
        .await
        .expect("get_scanner after modify should succeed");
    assert_eq!(
        updated_scanner.items[0].meta.comment.as_deref(),
        Some("updated")
    );
    assert_eq!(updated_scanner.items[0].host.as_deref(), Some("127.0.0.1"));
    assert_eq!(updated_scanner.items[0].port, Some(9390));

    client
        .verify_scanner(&scanner_id)
        .await
        .expect("verify_scanner should succeed");

    let cloned_scanner = client
        .clone_scanner(&scanner_id)
        .await
        .expect("clone_scanner should succeed");
    let cloned_scanner_id = cloned_scanner.id;
    let cloned_scanner_response = client
        .get_scanner(&cloned_scanner_id)
        .await
        .expect("get cloned scanner should succeed");
    assert_eq!(cloned_scanner_response.items[0].meta.name, "Typed Scanner");

    client
        .delete_scanner(&cloned_scanner_id, true)
        .await
        .expect("delete cloned scanner should succeed");
    client
        .delete_scanner(&scanner_id, true)
        .await
        .expect("delete original scanner should succeed");
}

#[tokio::test]
async fn typed_scan_config_and_scanner_helpers_cover_full_lifecycle() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    typed_scan_config_lifecycle(&mut client).await;
    typed_scanner_lifecycle(&mut client).await;

    server.shutdown().await;
}

#[tokio::test]
async fn disconnect_leaves_transport_disconnected() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .disconnect()
        .await
        .expect("disconnect should succeed");

    assert!(!client.connection().is_connected());

    server.shutdown().await;
}

#[tokio::test]
async fn send_after_disconnect_returns_connection_error() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .disconnect()
        .await
        .expect("disconnect should succeed");

    let error = client
        .send(get_targets(Default::default()))
        .await
        .expect_err("sending after disconnect should fail");
    match error {
        GvmError::Connection(ConnectionError::NotConnected) => {}
        other => panic!("expected connection error, got {other:?}"),
    }

    server.shutdown().await;
}
